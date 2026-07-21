"""Tests for the volumetric behavioral detector."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.models.volumetric_detector import VolumetricDetector, _is_signature_feature


def _w(user, **feats):
    return SimpleNamespace(user=user, values=feats)


def _baseline(n=30):
    # alice: stable low counts; bob: stable higher counts.
    out = []
    for i in range(n):
        out.append(_w("alice", f_logon_count=3.0 + (i % 2), f_unique_src=1.0))
        out.append(_w("bob", f_logon_count=20.0 + (i % 3), f_unique_src=4.0))
    return out


def test_signature_features_are_excluded():
    assert _is_signature_feature("f_golden_ticket_flag")
    assert _is_signature_feature("f_spray_max_targets_per_ip")
    assert not _is_signature_feature("f_logon_count")


def test_fit_drops_signature_features():
    det = VolumetricDetector().fit(
        _baseline() + [_w("alice", f_logon_count=3.0, f_dcsync_flag=1.0)]
    )
    assert "f_logon_count" in det.feature_order
    assert "f_dcsync_flag" not in det.feature_order


def test_per_entity_anomaly_scores_higher_than_baseline():
    det = VolumetricDetector().fit(_baseline())
    normal = det.score(_w("alice", f_logon_count=3.0, f_unique_src=1.0))
    # A spike that is high *for alice* even though bob runs at this level.
    spike = det.score(_w("alice", f_logon_count=40.0, f_unique_src=30.0))
    assert spike > normal


def test_cold_start_entity_uses_global_fallback():
    det = VolumetricDetector().fit(_baseline())
    # Unknown entity -> global stats, should not raise and returns a float.
    score = det.score(_w("carol", f_logon_count=100.0, f_unique_src=50.0))
    assert isinstance(score, float)


def test_score_requires_fit():
    det = VolumetricDetector()
    try:
        det.score(_w("alice", f_logon_count=1.0))
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass
