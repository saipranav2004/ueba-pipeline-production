"""Behavioural identity typing (identity/typing.py).

Guards the decision rule that separates automated identities from people on
timestamp shape alone, using synthetic streams whose ground truth is known by
construction. The thresholds are measured on the simulator (docs/identities.md);
these tests pin the *logic* — that each automation style is caught and that a
person (including a weekend-working one) is not.
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.identity.typing import classify_identity

_MON = datetime(2025, 1, 6)  # a Monday, so weekday()/weekend logic is unambiguous


def _scheduled(hour, days=20, per_day=2, weekends=True):
    """A batch job firing at a fixed clock hour each day (razor-tight)."""
    out = []
    for d in range(days):
        day = _MON + timedelta(days=d)
        if not weekends and day.weekday() >= 5:
            continue
        for i in range(per_day):
            out.append(day + timedelta(hours=hour, minutes=i))
    return out


def _round_the_clock(days=20, per_day=6):
    """A monitoring agent firing at spread-out hours, seven days a week."""
    out = []
    for d in range(days):
        day = _MON + timedelta(days=d)
        for i in range(per_day):
            out.append(day + timedelta(hours=(i * 4 + d) % 24, minutes=7))
    return out


def _human(days=20, per_day=4):
    """A person: weekday work-hour band with jitter, weekends off."""
    out = []
    for d in range(days):
        day = _MON + timedelta(days=d)
        if day.weekday() >= 5:            # weekends off
            continue
        for i in range(per_day):
            out.append(day + timedelta(hours=9 + i, minutes=(d * 13) % 60))
    return out


def test_scheduled_job_types_automated():
    p = classify_identity("svc_backup", _scheduled(hour=2))
    assert p.kind == "automated"
    assert "scheduled" in p.reason


def test_round_the_clock_agent_types_automated():
    p = classify_identity("svc_monitor", _round_the_clock())
    assert p.kind == "automated"
    assert "round-the-clock" in p.reason


def test_person_types_human():
    p = classify_identity("alice", _human())
    assert p.kind == "human"
    assert p.weekend_active_ratio == 0.0


def test_weekend_working_person_stays_human():
    """A person who also works weekends keeps a daytime band, so weekend activity
    alone must not retype them — this is the false positive the rule guards."""
    times = _human()
    for d in range(20):                  # substantial Saturday/Sunday daytime work
        day = _MON + timedelta(days=d)
        if day.weekday() >= 5:
            times += [day + timedelta(hours=10), day + timedelta(hours=13),
                      day + timedelta(hours=16)]
    p = classify_identity("busy_alice", times)
    assert p.weekend_active_ratio > 0.15  # would trip a naive weekend-only rule
    assert p.kind == "human"              # but the daytime band keeps them human


def test_sparse_identity_is_unknown():
    p = classify_identity("newcomer", [_MON + timedelta(hours=1),
                                       _MON + timedelta(hours=2)])
    assert p.kind == "unknown"


def test_profile_serialises_to_plain_types():
    p = classify_identity("svc_backup", _scheduled(hour=2))
    d = p.to_dict()
    assert d["kind"] == "automated" and isinstance(d["periodicity_p"], float)
