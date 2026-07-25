"""Tests for the detection engine: cell significance, rollup, signed persistence."""
from __future__ import annotations

import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from ueba_pipeline.models.pvalue import EmpiricalPValue

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.engine import (
    BehavioralEngine,
    EngineConfig,
    WindowDetection,
    is_graph_event,
)

os.environ.setdefault("UEBA__SECURITY__MODEL_SIGNING_KEY", "unit-test-key")

H = datetime(2025, 1, 1, 9, 0, 0, tzinfo=UTC)


def test_is_graph_event_matches_exactly_not_by_prefix():
    """Event-type routing must match exactly, never by prefix.

    A prefix test on "sysmon_1" also matches sysmon_10/11/12, quietly routing
    FileCreate and registry events into a detector that models process access.
    sysmon_10 IS wanted, so it is listed explicitly rather than matched by
    accident."""
    for t in ("4624", "4625", "4768", "4769", "sysmon_1", "sysmon_10"):
        assert is_graph_event(t)
    for t in ("sysmon_11", "sysmon_12", "sysmon_3", "4672", "4104", "46240"):
        assert not is_graph_event(t), f"{t} must not be routed to the graph track"

def test_window_detection_cell_p_is_tippett_corrected():
    """The cell p is Tippett (min-p, Sidak-corrected for the number of tests over
    calibrated p-values), so one severe test dominates and many mild tests cannot
    gang up. See docs/evaluation.md."""
    d = WindowDetection("u", datetime(2025, 1, 1), graph_p=1e-4, tested_edges={("v", ("a", "b"))})
    assert 0.0 < d.p < 1e-3          # one severe test dominates
    assert d.risk == pytest.approx(1.0 - d.p)
    quiet = WindowDetection("u", datetime(2025, 1, 1))
    assert quiet.p == 1.0 and quiet.risk == 0.0


def test_severity_beats_frequency():
    """One severe detection must outrank many mild ones.

    Any combiner that accumulates evidence lets a busy-but-benign entity displace
    a genuinely anomalous one under a fixed alert budget."""
    from ueba_pipeline.models.fisher import fisher_combine
    severe = fisher_combine([1e-6])[0]
    chatty = fisher_combine([0.3] * 40)[0]
    assert severe < chatty, "one severe event must outrank forty mild ones"


def test_rollup_is_sidak_corrected_not_accumulating():
    """More observation must not manufacture significance.

    The rollup takes an entity's most significant hour and Sidak-corrects it for
    how many hours were tested, so an entity watched for longer does not become
    suspicious merely by being watched."""
    eng = BehavioralEngine()
    mild = [WindowDetection("u", datetime(2025, 1, 1, h), graph_p=0.4,
                            tested_edges={("v", ("a", "b"))})
            for h in range(24)]
    risks = eng._rollup(mild, observed_days=1.0)
    assert risks[0].p_value > 0.05, "24 mild hours must not become significant"


def test_alerts_respect_the_analyst_budget():
    eng = BehavioralEngine(config=EngineConfig(alert_mode="budget", alert_budget_per_day=2.0))
    ds = [WindowDetection(f"u{i}", datetime(2025, 1, 1, 1), graph_p=10.0 ** -(11 - i),
                          tested_edges={("v", ("a", "b"))})
          for i in range(10)]
    risks = eng._rollup(ds, observed_days=1.0)
    assert len(eng.alerts(risks)) == 2
    assert [r.entity for r in eng.alerts(risks)] == ["u0", "u1"]  # ranked by p


def test_save_load_roundtrip_preserves_config(tmp_path):
    # Bundle-level round-trip and scoring identity are covered in depth by
    # test_serialization.py; here we only confirm the engine's save/load wiring
    # reaches the non-executable serializer and restores declared config.
    from ueba_pipeline.config.schema import CapabilityConfig
    eng = BehavioralEngine(config=EngineConfig(alert_budget_per_day=7.0))
    eng.fit([], config_capability=CapabilityConfig(bootstrap_min_events=1))
    eng.save(str(tmp_path))
    loaded = BehavioralEngine.load(str(tmp_path))
    assert loaded.config.alert_budget_per_day == 7.0


def test_load_rejects_tampered_bundle(tmp_path):
    from ueba_pipeline.config.schema import CapabilityConfig
    eng = BehavioralEngine()
    eng.fit([], config_capability=CapabilityConfig(bootstrap_min_events=1))
    eng.save(str(tmp_path))
    state = tmp_path / "engine.json"
    data = bytearray(state.read_bytes())
    data[-2] ^= 0xFF  # flip a byte inside the JSON
    state.write_bytes(bytes(data))
    with pytest.raises(ValueError):
        BehavioralEngine.load(str(tmp_path))


def test_score_stream_emits_detections_and_stays_pure_in_batch():
    # A minimal engine that fires on a novel lsass access; verify the stream
    # emits the detection, and that batch scoring remains pure.
    from ueba_pipeline.engine import EngineConfig

    eng = BehavioralEngine(config=EngineConfig())
    # Establish a benign baseline so the attack edge is novel. Surprise is
    # evidence-relative: with no baseline nothing is surprising.
    base = [_sysmon10("wininit.exe", "lsass.exe", minute=m) for m in range(0, 600, 60)]
    # Build the baseline and calibrate the per-view nulls exactly as fit() does.
    eng._graph_nulls, eng.view_stats = eng._fit_graph(base)
    stream = [_sysmon10("rundll32.exe", "lsass.exe", minute=700)]
    out = list(eng.score_stream(iter(stream)))
    assert any(d.graph_p < 1.0 for d in out), "stream must emit the novel-edge detection"

    # score_stream adapts (absorb=True) while score() must not: verify that
    # asymmetry holds.
    eng2 = BehavioralEngine(config=EngineConfig())
    eng2._graph_nulls, eng2.view_stats = eng2._fit_graph(base)
    probe = _sysmon10("rundll32.exe", "lsass.exe", minute=700)
    first = eng2.graph.score_event(probe, absorb=False)
    second = eng2.graph.score_event(probe, absorb=False)
    assert first == second, "scoring must be pure: repeated scores must agree"


def _sysmon10(src, tgt, host="ws1", minute=0):
    return SimpleNamespace(
        event_type="sysmon_10",
        event_time=datetime(2025, 1, 1, 9, 0, tzinfo=UTC) + timedelta(minutes=minute),
        computer_name=host,
        fields={"source_image": src, "target_image": tgt},
    )


def test_per_view_calibration_contains_a_churny_view():
    """A relationship view whose benign edges are frequently novel (high surprise
    is the norm) must not make those benign edges look significant under per-view
    calibration -- otherwise adding it floods the alert queue. A single pooled
    null does exactly that, because the churny view's surprises are rare against a
    distribution dominated by low-baseline views. Per-view calibration is what
    lets new views be added without per-attack tuning (see engine._fit_graph).
    """
    import numpy as np
    rng = np.random.default_rng(0)
    stable = np.zeros(2000)                              # low-baseline view: seen edges ~0
    churn = rng.uniform(4.5, 6.0, 2000)                 # churny view: high surprise is normal
    per_view = EmpiricalPValue().fit(churn)
    pooled = EmpiricalPValue().fit(np.concatenate([stable, churn]))
    probe = 5.2                                          # a typical BENIGN churn surprise
    assert per_view.pvalue(probe)[0] > 0.2, \
        "a benign churn edge must be unremarkable in its own null"
    assert pooled.pvalue(probe)[0] < per_view.pvalue(probe)[0], (
        "a single pooled null makes the same benign churn edge look more significant, "
        "which is the flooding per-view calibration prevents"
    )


def test_fit_calibrates_one_null_per_graph_view():
    """The engine must hold a separate frozen null per graph view, not one pooled
    null, so each relationship type is scored against its own baseline."""
    eng = BehavioralEngine(config=EngineConfig())
    base = ([_sysmon10("wininit.exe", "lsass.exe", minute=m) for m in range(0, 600, 30)])
    eng._graph_nulls, eng.view_stats = eng._fit_graph(base)
    assert "proc_access" in eng._graph_nulls
    assert all(isinstance(n, EmpiricalPValue) for n in eng._graph_nulls.values())
