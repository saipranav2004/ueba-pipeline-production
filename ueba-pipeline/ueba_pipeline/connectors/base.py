"""
ueba_pipeline/connectors/base.py

Canonical cross-IDP event shape and connector interface. See
docs/MULTI_IDP_ARCHITECTURE.md for the design rationale -- in short: Entra,
Okta, Ping, and Google Workspace share almost no field names with each
other or with the Windows-Event-Log schema `parsing/normalize.py` already
handles, so a dictionary-of-field-maps keyed by (channel, event_id) doesn't
generalize. Each IDP gets its own connector; all of them converge on
CanonicalIdentityEvent for cross-IDP correlation while keeping their own
native fields available for source-specific feature extraction.

This module intentionally does NOT try to be the one true schema for every
possible identity signal (group membership changes, privileged-role grants,
etc.) -- it covers the sign-in/authentication event, which is the one
event type every IDP in scope actually has an equivalent of. Non-auth event
types (Entra directory audit logs, Okta group-lifecycle events, ...) are a
separate, source-specific concern for each connector's own `fields`/
`raw_event` payload, the same way AD's 5136/4728 aren't folded into
NormalizedEvent's core shape either.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Protocol, runtime_checkable


@dataclass
class CanonicalIdentityEvent:
    """The cross-IDP-comparable subset of a sign-in/authentication event.

    Every field here must be answerable, or explicitly None, from EVERY
    connector -- that's the test of whether something belongs at this layer
    versus in `fields`/`raw_event`. `conditionalAccessStatus` (Entra-only,
    no AD equivalent) is correctly NOT here; it lives in `fields` for the
    entra_id connector only. `user` and `event_time` are the two fields an
    eventual cross-IDP feature (e.g. correlating an Entra sign-in with an
    on-prem Kerberos logon for the same human) would join on.
    """

    source: str                       # "ad_windows" or "entra_id"
    event_time: Optional[datetime]
    user: Optional[str]               # normalized identity key -- see normalize_username_cross_idp
    source_ip: Optional[str]
    success: Optional[bool]
    mfa_used: Optional[bool]
    risk_hint: Optional[float]        # 0-1 if the IDP supplies its own risk score, else None
    application: Optional[str]        # what the user signed into, if applicable
    location: Optional[str]           # free-text (city/region) if the IDP resolves it; AD/on-prem sources leave this None
    fields: Dict[str, Any] = field(default_factory=dict)      # canonical-ish, source-specific extras
    raw_event: Dict[str, Any] = field(default_factory=dict)   # untouched original payload


def normalize_username_cross_idp(raw: Optional[str]) -> Optional[str]:
    """
    Cross-IDP identity key. Deliberately SEPARATE from
    parsing.normalize.normalize_username rather than reusing it directly:
    that function's rules (strip NetBIOS prefix, strip machine accounts
    ending in '$', drop SYSTEM/ANONYMOUS LOGON) are Windows/AD-specific.
    Entra/Okta/Ping/Google Workspace identities are UPN/email-shaped and
    have no NetBIOS prefix or '$'-suffixed machine-account convention --
    applying AD's stripping rules to them would be silently wrong (e.g. an
    Entra user whose UPN happens to contain '$' is not a machine account).

    Currently only handles the one rule that IS genuinely universal: strip
    a domain/UPN suffix and lowercase, so "JSmith@Contoso.com" (Entra),
    "jsmith@contoso.onmicrosoft.com" (Okta via Entra federation), and
    "jsmith" (AD SAM name) can converge to the same join key. This is a
    real, unverified assumption -- it assumes UPN-prefix == SAM-name
    across all four IDPs for a given human, which holds for standard
    hybrid-identity setups but is NOT guaranteed (an org could have a
    dedicated Okta username unrelated to their AD SAM name). Flagged here
    rather than silently assumed correct; needs validation against a real
    hybrid-identity tenant before any cross-IDP feature depends on it.
    """
    if not raw:
        return None
    return raw.strip().split("@")[0].lower()


@runtime_checkable
class IdentityConnector(Protocol):
    """Interface every IDP connector implements. See
    docs/MULTI_IDP_ARCHITECTURE.md §3 for why fetch_events is left
    deliberately unopinionated about transport/pagination."""

    source_name: str

    def fetch_events(self, since: datetime, until: datetime) -> Iterable[Dict[str, Any]]:
        """Yields raw, source-native event dicts in [since, until)."""
        ...

    def normalize(self, raw_event: Dict[str, Any]) -> Optional[CanonicalIdentityEvent]:
        """Maps one raw event to the canonical shape, or None if the event
        type isn't a sign-in/auth event this connector models (mirrors
        NormalizedEvent's "unknown" event_type for unmapped Windows events
        -- an unrecognized event is a documented gap, not a crash)."""
        ...
