"""Resolve host-scoped events to the identity responsible for them.

WHY
---
This is an *identity* threat-detection product: the entity an analyst triages is
an account, not a workstation. But a large share of the highest-signal telemetry
carries no account at all -- Sysmon ProcessAccess (EID 10) and ProcessCreate
(EID 1) name a host and an image, never the user whose session spawned them.

Attributing those to the hostname would put the signal on the wrong entity and
split the engine across two entity spaces. All alerting is over accounts, so
``_rollup`` would then rank a mixed population of users and hosts, and a host --
absent from the ``(entity, window)`` map that counts how many tests each entity
received -- would get an under-corrected Sidak and compete unfairly for the top of
the queue.

WHAT THIS DOES
--------------
Builds a causal map of interactive/remote logon sessions from 4624 events (which
carry *both* ``target_user_name`` and ``computer_name``), then resolves a
host-scoped event at time T on host H to the account most recently logged on to H
at or before T. Standard UEBA practice; it is how any SIEM pivots endpoint
telemetry onto an identity.

Unresolved events keep the host as the entity rather than being dropped: a
process opening lsass on a host nobody is logged into is not less interesting.

PURITY
------
The resolver is built fresh from the batch inside ``score()`` and holds no
cross-call state, so scoring stays a pure function of its input (see engine.py's
state contract). It is deliberately *not* fitted at train time and carried
forward: a stale session map would silently misattribute months later.

LIMITS, STATED
--------------
- Logon *type* is not distinguished beyond excluding service/batch logons: a
  console session and an RDP session both bind. Multi-user hosts (RDS/Citrix)
  therefore bind to the most recent logon, which is a coin flip. Real deployments
  resolve this with 4634/4647 logoff correlation and session GUIDs; this
  implementation does not, because the simulator emits no reliable logoff stream
  to validate it against and an unvalidated correlation is worse than a stated
  approximation.
- ``session_ttl_hours`` bounds how long a logon is assumed to still own the host.
  It is a stated assumption, not a tuned parameter, and it was not swept against
  the benchmark.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Logon types that bind a user to a host for the purpose of owning the processes
# on it. 2 = interactive (console), 10 = remote interactive (RDP), 7 = unlock,
# 11 = cached interactive. Excluded: 3 (network -- a file-share touch does not
# make you the owner of that host's processes), 4 (batch) and 5 (service), which
# are machine-driven and would bind service accounts to every host they touch.
_SESSION_LOGON_TYPES = {"2", "7", "10", "11"}

DEFAULT_SESSION_TTL_HOURS = 12.0


@dataclass
class SessionResolver:
    """Causal host -> account resolution from 4624 logon events."""

    session_ttl_hours: float = DEFAULT_SESSION_TTL_HOURS
    # host -> ascending list of (logon_time, account)
    _logons: dict[str, list[tuple[datetime, str]]] = field(default_factory=dict)

    def fit(self, events, norm) -> SessionResolver:
        """Index every session-binding logon in ``events``. O(n log n)."""
        acc: dict[str, list[tuple[datetime, str]]] = {}
        for e in events:
            if e.event_time is None or e.event_type != "4624":
                continue
            if str(e.fields.get("logon_type", "")) not in _SESSION_LOGON_TYPES:
                continue
            host = norm(e.computer_name)
            user = norm(e.fields.get("target_user_name"))
            if not host or not user or user.endswith("$"):
                continue
            acc.setdefault(host, []).append((e.event_time, user))
        self._logons = {h: sorted(v) for h, v in acc.items()}
        return self

    def resolve(self, host: str, when: datetime) -> str | None:
        """Account owning ``host`` at ``when``, or None if unknown/expired."""
        sessions = self._logons.get(host)
        if not sessions or when is None:
            return None
        i = bisect.bisect_right(sessions, (when, "\uffff")) - 1
        if i < 0:
            return None
        logon_time, user = sessions[i]
        if when - logon_time > timedelta(hours=self.session_ttl_hours):
            return None
        return user

    @property
    def n_hosts(self) -> int:
        return len(self._logons)
