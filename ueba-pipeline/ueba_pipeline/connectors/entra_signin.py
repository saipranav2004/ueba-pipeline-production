"""
ueba_pipeline/connectors/entra_signin.py

IdentityConnector for Microsoft Entra ID sign-in logs (Microsoft Graph `signIn`
resource, /v1.0/auditLogs/signIns). The field mapping in `normalize()` follows
Microsoft's published schema (Microsoft Learn, "signIn resource type",
graph/api/resources/signin). `fetch_events()` uses the MSAL client-credentials
flow and Graph `@odata.nextLink` pagination (Microsoft Learn, "List signIns",
graph-rest-1.0). The Graph client dependencies (`msal`, `requests`) are optional
and imported lazily, so the core pipeline does not require them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

from ueba_pipeline.connectors.base import CanonicalIdentityEvent, normalize_username_cross_idp

# Risk levels straight from Microsoft's documented enum for riskLevelDuringSignIn
# (signIn resource type): none, low, medium, high, hidden, unknownFutureValue.
# "hidden" specifically means the tenant lacks Entra ID Premium P2 -- NOT that
# risk is low. Mapping it to None (unknown) rather than 0.0 (safe) matters:
# treating a licensing gap as "confirmed safe" would silently blind the model
# for every non-P2 tenant rather than making the gap visible.
_RISK_LEVEL_TO_HINT = {
    "none": 0.0,
    "low": 0.33,
    "medium": 0.66,
    "high": 1.0,
    "hidden": None,
    "unknownFutureValue": None,
}


class EntraSignInConnector:
    source_name = "entra_id"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        # Stored, not used yet -- see fetch_events. Kept in __init__ (rather
        # than omitted) so the constructor signature this connector will
        # actually need is decided now, not deferred to when someone wires
        # up the real client and has to guess whether auth config belongs
        # here or in a separate factory.
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    # Microsoft Graph v1.0 sign-in endpoint. v1.0 (not beta) is used because
    # this connector maps only v1.0-stable fields; beta exposes more
    # risk-detection detail but is not contract-stable.
    _GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def fetch_events(self, since: datetime, until: datetime) -> Iterable[Dict[str, Any]]:
        """Fetch sign-in events in [since, until) from Microsoft Graph.

        Uses the MSAL client-credentials flow (app-only) to acquire a token for
        the ``.default`` scope, then pages the ``/auditLogs/signIns`` endpoint
        following ``@odata.nextLink`` until exhausted, yielding raw sign-in
        objects for ``normalize()``. Requires the app registration to hold
        ``AuditLog.Read.All`` + ``Directory.Read.All`` (admin-consented).

        429/503 responses are honored via ``Retry-After`` with exponential
        backoff, since Graph throttles report endpoints. ``$top=999`` minimizes
        round-trips. Requires ``msal`` and ``requests`` (declared optional in
        requirements.txt); imported lazily so the core pipeline does not depend
        on them.

        Verified against Microsoft Learn "List signIns" (graph-rest-1.0), which
        documents the ``createdDateTime`` ``$filter`` and the ``@odata.nextLink``
        paging contract.
        """
        try:
            import msal
            import requests
        except ImportError as exc:  # pragma: no cover - environment-dependent
            raise RuntimeError(
                "EntraSignInConnector.fetch_events requires 'msal' and "
                "'requests'. Install with: pip install msal requests"
            ) from exc

        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        token_result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" not in token_result:
            raise RuntimeError(
                f"Entra token acquisition failed: "
                f"{token_result.get('error')}: {token_result.get('error_description')}"
            )
        headers = {"Authorization": f"Bearer {token_result['access_token']}"}

        since_iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        until_iso = until.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        url = (
            f"{self._GRAPH_BASE}/auditLogs/signIns"
            f"?$filter=createdDateTime ge {since_iso} and createdDateTime lt {until_iso}"
            f"&$top=999"
        )

        import time as _time
        backoff = 1.0
        while url:
            resp = requests.get(url, headers=headers, timeout=60)
            if resp.status_code in (429, 503):
                retry_after = float(resp.headers.get("Retry-After", backoff))
                _time.sleep(retry_after)
                backoff = min(backoff * 2, 60.0)
                continue
            resp.raise_for_status()
            backoff = 1.0
            payload = resp.json()
            for event in payload.get("value", []):
                yield event
            url = payload.get("@odata.nextLink")

    def normalize(self, raw_event: Dict[str, Any]) -> Optional[CanonicalIdentityEvent]:
        """Maps one Graph API signIn object. Field names below are exactly
        as documented at Microsoft Learn's signIn resource type reference
        (v1.0): id, createdDateTime, appDisplayName, appId, ipAddress,
        clientAppUsed, conditionalAccessStatus, isInteractive, deviceDetail,
        location, riskDetail/riskLevelAggregated/riskLevelDuringSignIn/
        riskState/riskEventTypes, resourceDisplayName, resourceId, status
        (errorCode/failureReason/additionalDetails), userDisplayName,
        userId, userPrincipalName."""
        if "userPrincipalName" not in raw_event or "createdDateTime" not in raw_event:
            return None  # not a shape this connector recognizes

        event_time = self._parse_graph_timestamp(raw_event["createdDateTime"])
        status = raw_event.get("status") or {}
        error_code = status.get("errorCode")
        success = (error_code == 0) if error_code is not None else None

        # authenticationMethodsUsed / authenticationDetails carry MFA info
        # in the more detailed (beta / P2) payload; the stable v1.0 shape
        # documented here doesn't guarantee it, so this stays best-effort
        # and explicitly None (unknown) rather than guessed as False.
        mfa_used = self._infer_mfa_used(raw_event)

        risk_level = raw_event.get("riskLevelDuringSignIn")
        risk_hint = _RISK_LEVEL_TO_HINT.get(risk_level) if risk_level else None

        location = None
        loc = raw_event.get("location")
        if isinstance(loc, dict):
            city = loc.get("city")
            country = loc.get("countryOrRegion")
            if city or country:
                location = ", ".join(p for p in (city, country) if p)

        return CanonicalIdentityEvent(
            source=self.source_name,
            event_time=event_time,
            user=normalize_username_cross_idp(raw_event.get("userPrincipalName")),
            source_ip=raw_event.get("ipAddress"),
            success=success,
            mfa_used=mfa_used,
            risk_hint=risk_hint,
            application=raw_event.get("appDisplayName"),
            location=location,
            fields={
                "conditional_access_status": raw_event.get("conditionalAccessStatus"),
                "is_interactive": raw_event.get("isInteractive"),
                "client_app_used": raw_event.get("clientAppUsed"),
                "risk_level_during_signin": risk_level,
                "risk_state": raw_event.get("riskState"),
                "risk_detail": raw_event.get("riskDetail"),
                "failure_reason": status.get("failureReason"),
                "resource_display_name": raw_event.get("resourceDisplayName"),
            },
            raw_event=raw_event,
        )

    @staticmethod
    def _parse_graph_timestamp(ts: str) -> Optional[datetime]:
        """Graph API timestamps are Z-suffixed ISO 8601 WITHOUT the 7-digit
        sub-microsecond precision Windows Event Log uses (see Microsoft's
        own example captures: "2023-12-01T16:03:32Z") -- deliberately not
        reusing parsing.normalize._parse_iso, which was written around
        that 7-digit format and has never been checked against Graph's
        plain-seconds timestamps."""
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _infer_mfa_used(raw_event: Dict[str, Any]) -> Optional[bool]:
        methods = raw_event.get("authenticationMethodsUsed")
        if isinstance(methods, list):
            return len(methods) > 1 or any(
                m for m in methods if m and m.lower() not in ("password",)
            )
        return None
