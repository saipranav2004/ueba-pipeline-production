"""NHI temporal-deviation detector (identity/nhi_detector.py).

Pins the properties the track's correctness rests on: who it admits, that the
hour is treated as circular, that scoring is pure and causal, and that a schedule
deviation outscores ordinary jitter.
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.identity.nhi_detector import NHITemporalDetector

_MON = datetime(2025, 1, 6)   # a Monday


class _Ev:
    """Minimal stand-in for a NormalizedEvent: the detector reads time + account."""

    def __init__(self, user, when):
        self.event_time = when
        self.event_type = "4624"
        self.computer_name = "HOST1"
        self.fields = {"target_user_name_norm": user}


def _scheduled(user, hour, days=30, per_day=3, jitter_min=0):
    """A job firing at a fixed clock hour every day."""
    out = []
    for d in range(days):
        for i in range(per_day):
            t = _MON + timedelta(days=d, hours=hour, minutes=i * 2 + jitter_min)
            out.append(_Ev(user, t))
    return out


def _spread(user, days=30, per_day=8):
    """A round-the-clock agent: activity in every hour."""
    return [_Ev(user, _MON + timedelta(days=d, hours=(i * 3 + d) % 24))
            for d in range(days) for i in range(per_day)]


def test_admits_scheduled_identity_only():
    """A concentrated schedule is admitted; a round-the-clock agent is not."""
    det = NHITemporalDetector().fit(_scheduled("svc_batch", 2) + _spread("svc_agent"))
    assert "svc_batch" in det.covered
    assert "svc_agent" not in det.covered


def test_sparse_identity_is_not_admitted():
    """Concentration on a handful of events is an artifact, not a schedule."""
    det = NHITemporalDetector().fit(_scheduled("svc_rare", 3, days=5, per_day=2))
    assert "svc_rare" not in det.covered


def test_off_schedule_activity_outscores_adjacent_hour_jitter():
    """The circular kernel is load-bearing: a one-hour slip is ordinary, an
    afternoon appearance for a 02:00 job is not."""
    det = NHITemporalDetector().fit(_scheduled("svc_batch", 2))
    jitter = det._surprise("svc_batch", 3)     # adjacent hour
    far = det._surprise("svc_batch", 14)       # across the clock
    assert far > jitter * 3


def test_hour_distance_is_circular():
    """23:00 and 00:00 are adjacent, not 23 hours apart."""
    det = NHITemporalDetector().fit(_scheduled("svc_night", 0))
    wrap = det._surprise("svc_night", 23)      # one hour before midnight
    far = det._surprise("svc_night", 12)       # true opposite side
    assert wrap < far


def test_score_is_pure():
    """Scoring must not mutate the baseline: re-scoring gives the same answer."""
    det = NHITemporalDetector().fit(_scheduled("svc_batch", 2))
    test = [_Ev("svc_batch", _MON + timedelta(days=40, hours=15))]
    first = det.score(test)
    second = det.score(test)
    assert [a.p_value for a in first] == [a.p_value for a in second]
    assert [a.surprise for a in first] == [a.surprise for a in second]


def test_deviation_is_ranked_above_routine_activity():
    """An identity used off-schedule ranks above one that kept to its schedule."""
    train = _scheduled("svc_a", 2) + _scheduled("svc_b", 5)
    det = NHITemporalDetector().fit(train)
    test = ([_Ev("svc_a", _MON + timedelta(days=40, hours=2, minutes=m)) for m in range(3)]
            + [_Ev("svc_b", _MON + timedelta(days=40, hours=15, minutes=m)) for m in range(3)])
    ranked = det.score(test)
    assert ranked[0].entity == "svc_b"        # the off-schedule one leads
    assert ranked[0].surprise > ranked[-1].surprise


def test_uncovered_identity_is_never_scored():
    """Identities outside the covered cohort produce no alerts at all."""
    det = NHITemporalDetector().fit(_scheduled("svc_batch", 2) + _spread("svc_agent"))
    out = det.score([_Ev("svc_agent", _MON + timedelta(days=40, hours=13))])
    assert [a.entity for a in out] == []
