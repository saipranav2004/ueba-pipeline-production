"""
tests/unit/test_entra_connector.py -- exercises EntraSignInConnector.normalize()
against hand-built payloads shaped like Microsoft Graph's documented signIn
resource (see connectors/entra_signin.py). Values below are fabricated for this test,
not copied from any live tenant or from Microsoft's own example captures.
"""
import sys
from datetime import timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.connectors.entra_signin import EntraSignInConnector


def _connector():
    return EntraSignInConnector(tenant_id="t", client_id="c", client_secret="s")


def test_normalizes_a_successful_low_risk_signin():
    raw = {
        "id": "sample-id-1",
        "createdDateTime": "2026-03-14T09:12:05Z",
        "userPrincipalName": "avasquez@fabrikam.com",
        "appDisplayName": "Microsoft 365",
        "ipAddress": "198.51.100.20",
        "clientAppUsed": "Browser",
        "isInteractive": True,
        "conditionalAccessStatus": "success",
        "riskLevelDuringSignIn": "none",
        "riskState": "none",
        "status": {"errorCode": 0, "failureReason": None},
        "location": {"city": "Austin", "countryOrRegion": "US"},
    }

    event = _connector().normalize(raw)

    assert event is not None
    assert event.source == "entra_id"
    assert event.user == "avasquez"
    assert event.success is True
    assert event.risk_hint == 0.0
    assert event.location == "Austin, US"
    assert event.event_time.tzinfo is not None
    assert event.event_time.tzinfo == timezone.utc
    assert event.fields["conditional_access_status"] == "success"
    assert event.raw_event is raw  # original payload preserved untouched


def test_normalizes_a_failed_high_risk_signin():
    raw = {
        "id": "sample-id-2",
        "createdDateTime": "2026-03-14T03:41:52Z",
        "userPrincipalName": "DPatel@fabrikam.com",
        "appDisplayName": "Azure Portal",
        "ipAddress": "203.0.113.77",
        "isInteractive": True,
        "conditionalAccessStatus": "failure",
        "riskLevelDuringSignIn": "high",
        "status": {"errorCode": 50126, "failureReason": "Invalid credentials"},
    }

    event = _connector().normalize(raw)

    assert event.user == "dpatel"
    assert event.success is False
    assert event.risk_hint == 1.0
    assert event.fields["failure_reason"] == "Invalid credentials"
    assert event.location is None  # not provided -- must not be fabricated


def test_hidden_risk_level_is_none_not_zero():
    """A tenant without Entra ID Premium P2 gets riskLevelDuringSignIn=
    "hidden" for every event, per Microsoft's documented enum. Mapping
    that to 0.0 would silently tell the model every sign-in is confirmed
    safe for the entire tenant -- it must come through as unknown."""
    raw = {
        "createdDateTime": "2026-03-14T09:00:00Z",
        "userPrincipalName": "user@fabrikam.com",
        "riskLevelDuringSignIn": "hidden",
        "status": {"errorCode": 0},
    }
    event = _connector().normalize(raw)
    assert event.risk_hint is None


def test_non_signin_shaped_payload_returns_none():
    event = _connector().normalize({"someOtherField": "not a sign-in"})
    assert event is None


def test_cross_idp_username_key_strips_upn_suffix_and_lowercases():
    from ueba_pipeline.connectors.base import normalize_username_cross_idp
    assert normalize_username_cross_idp("JSmith@Contoso.com") == "jsmith"
    assert normalize_username_cross_idp(None) is None


def test_fetch_events_paginates_via_nextlink():
    """fetch_events follows @odata.nextLink across pages (mocked msal+requests,
    no live tenant)."""
    import sys, types
    from datetime import datetime, timezone

    class _Resp:
        def __init__(self, data, status=200, headers=None):
            self._d, self.status_code, self.headers = data, status, headers or {}
        def json(self): return self._d
        def raise_for_status(self):
            if self.status_code >= 400: raise RuntimeError(f"HTTP {self.status_code}")

    msal_mod = types.ModuleType("msal")
    class _App:
        def __init__(self, **kw): pass
        def acquire_token_for_client(self, scopes): return {"access_token": "tok"}
    msal_mod.ConfidentialClientApplication = _App

    pages = [
        {"value": [{"userPrincipalName": "a@x.com", "createdDateTime": "2025-01-06T09:00:00Z",
                    "status": {"errorCode": 0}}], "@odata.nextLink": "https://graph/next"},
        {"value": [{"userPrincipalName": "b@x.com", "createdDateTime": "2025-01-06T10:00:00Z",
                    "status": {"errorCode": 0}}]},
    ]
    req_mod = types.ModuleType("requests")
    state = {"i": 0}
    def _get(url, headers=None, timeout=None):
        r = _Resp(pages[state["i"]]); state["i"] += 1; return r
    req_mod.get = _get

    sys.modules["msal"] = msal_mod
    sys.modules["requests"] = req_mod
    try:
        conn = _connector()
        events = list(conn.fetch_events(
            datetime(2025, 1, 6, tzinfo=timezone.utc),
            datetime(2025, 1, 7, tzinfo=timezone.utc)))
        assert [e["userPrincipalName"] for e in events] == ["a@x.com", "b@x.com"]
    finally:
        sys.modules.pop("msal", None)
        sys.modules.pop("requests", None)
