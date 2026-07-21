"""Causality guarantees for the per-(entity, hour) feature vectors.

A feature is causal when its value for a window depends only on events at or
before that window. Non-causal features are not merely optimistic — they are
unavailable at inference, so a model that learns them behaves differently in
production than it did on the bench.

The generic guard (`test_window_features_ignore_future_events`) recomputes every
window against a truncated event stream and asserts nothing changes. It covers
features that do not exist yet, so a future extractor that reaches forward fails
here rather than in a benchmark nobody re-derives.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ueba_pipeline.config.schema import CapabilityConfig
from ueba_pipeline.features.aggregate import build_user_windows
from ueba_pipeline.features.manifest import build_capability_manifest
from ueba_pipeline.parsing.normalize import NormalizedEvent

BASE = datetime(2025, 3, 3, 9, 0, tzinfo=timezone.utc)


def _event(event_type: str, offset_minutes: int, **fields) -> NormalizedEvent:
    channel = fields.pop("channel", "Security")
    return NormalizedEvent(
        event_time=BASE + timedelta(minutes=offset_minutes),
        ingest_time=None,
        channel=channel,
        event_id=event_type,
        event_type=event_type,
        group=fields.pop("group", None),
        computer_name=fields.pop("computer_name", "WS-01"),
        outcome=None,
        keywords=[],
        fields=fields,
    )


def _kerberos_logon(offset_minutes: int, src_ip: str) -> NormalizedEvent:
    """A Type-3 Kerberos logon — the event the ticket indicators score."""
    return _event(
        "4624",
        offset_minutes,
        target_user_name="alice",
        target_user_name_norm="alice",
        logon_type=3,
        auth_package="Kerberos",
        src_ip=src_ip,
        group="auth",
    )


def _tgt_issued(offset_minutes: int, src_ip: str) -> NormalizedEvent:
    return _event(
        "4768",
        offset_minutes,
        target_user_name="alice",
        target_user_name_norm="alice",
        src_ip=src_ip,
        group="kerberos",
    )


def _manifest(events):
    # These fixtures are tiny and exercise feature causality, not the capability
    # gate, so admit a group on a single event (min_events_for_capability=1).
    return build_capability_manifest(
        events, CapabilityConfig(bootstrap_min_events=1, min_events_for_capability=1))


def _windows_by_start(events, window_hours: float = 1.0):
    manifest = _manifest(events)
    return {
        (w.user, w.window_start): w
        for w in build_user_windows(events, manifest, window_hours)
    }


def test_ticket_indicator_ignores_later_legitimate_issuance():
    """A ticket issued *after* a logon must not make that logon look familiar.

    The account authenticates from 10.0.0.99 having never held a ticket from it,
    then hours later is legitimately issued one from the same address. Building
    the address history over the whole batch would retroactively excuse the
    earlier logon; only a causal history keeps it flagged.
    """
    logon_then_issuance = [
        _tgt_issued(0, "10.0.0.5"),
        _kerberos_logon(10, "10.0.0.99"),
        _tgt_issued(200, "10.0.0.99"),
    ]
    windows = _windows_by_start(logon_then_issuance)
    first_hour = [w for (_, start), w in windows.items() if start == BASE.replace(minute=0)]
    assert first_hour, "expected a window covering the logon"
    assert first_hour[0].values["f_golden_ticket_flag"] == 1.0, (
        "logon from an address with no prior ticket must stay flagged even though "
        "the account is issued a ticket from that address later in the batch"
    )


def test_ticket_indicator_respects_prior_issuance():
    """The mirror case: a ticket issued *before* the logon does excuse it."""
    issuance_then_logon = [
        _tgt_issued(0, "10.0.0.99"),
        _kerberos_logon(10, "10.0.0.99"),
    ]
    windows = _windows_by_start(issuance_then_logon)
    window = next(iter(windows.values()))
    assert window.values["f_golden_ticket_flag"] == 0.0, (
        "a logon from an address the account already held a ticket from is not "
        "a forged-ticket candidate"
    )


def test_window_features_ignore_future_events():
    """No window's features may change when later events are withheld.

    This is the general statement of causality, applied to every feature the
    manifest exposes rather than to the two ticket indicators specifically.
    """
    events = [
        _tgt_issued(0, "10.0.0.5"),
        _kerberos_logon(5, "10.0.0.5"),
        _kerberos_logon(70, "10.0.0.99"),
        _event("4625", 75, target_user_name="alice", target_user_name_norm="alice",
               src_ip="10.0.0.99", group="auth"),
        _tgt_issued(200, "10.0.0.99"),
        _kerberos_logon(205, "10.0.0.99"),
    ]

    # The manifest is pinned from the full stream so that truncation changes only
    # the feature values under test, never which feature groups are available.
    manifest = _manifest(events)
    full = {
        (w.user, w.window_start): w
        for w in build_user_windows(events, manifest, 1.0)
    }

    for cut in range(1, len(events)):
        prefix = events[:cut]
        horizon = prefix[-1].event_time.replace(minute=0, second=0, microsecond=0)
        truncated = {
            (w.user, w.window_start): w
            for w in build_user_windows(prefix, manifest, 1.0)
        }
        for key, window in truncated.items():
            # Only windows that are already complete in the prefix are comparable;
            # the window still receiving events legitimately differs.
            if key[1] >= horizon:
                continue
            assert window.values == full[key].values, (
                f"window {key} changed when events after it were withheld "
                f"(prefix of {cut} events) — a feature is reading ahead"
            )


@pytest.mark.parametrize("window_hours", [1.0, 4.0])
def test_causality_holds_across_window_sizes(window_hours: float):
    """Causality is a property of the extractors, not of the bucket width."""
    events = [
        _kerberos_logon(0, "10.0.0.99"),
        _tgt_issued(500, "10.0.0.99"),
    ]
    manifest = _manifest(events)
    windows = build_user_windows(events, manifest, window_hours)
    first = min(windows, key=lambda w: w.window_start)
    assert first.values["f_golden_ticket_flag"] == 1.0
