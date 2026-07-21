"""LANL adapter + per-auth ROC harness, exercised on a synthetic LANL-format
fixture. Locks in the plumbing (adapter mapping, red-team matching, causal split,
per-view calibrated scoring, ROC) so the `lanl-eval` path stays runnable; it does
NOT assert real-world performance (the fixture is detectable by construction)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))


def test_lanl_adapter_maps_auth_and_matches_redteam(tmp_path):
    from make_lanl_fixture import generate
    from ueba_pipeline.evaluation.lanl_adapter import load_lanl

    generate(str(tmp_path), n_users=120, days=3, seed=3)
    ds = load_lanl(str(tmp_path / "auth.txt"), str(tmp_path / "redteam.txt"))

    assert ds.events, "adapter produced no events"
    # event_type must be the exact code the engine routes as a graph event.
    from ueba_pipeline.engine import is_graph_event
    assert all(is_graph_event(e.event_type) for e in ds.events)
    # at least one event matches a red-team label
    assert any(ds.is_malicious(e) for e in ds.events), "no auth matched a red-team label"


def test_lanl_roc_recovers_embedded_lateral_movement(tmp_path):
    from make_lanl_fixture import generate
    from ueba_pipeline.evaluation.lanl_adapter import load_lanl
    from ueba_pipeline.evaluation.benchmark import lanl_roc_eval

    generate(str(tmp_path), n_users=200, days=4, seed=11)
    ds = load_lanl(str(tmp_path / "auth.txt"), str(tmp_path / "redteam.txt"))
    res = lanl_roc_eval(ds.events, ds.is_malicious, contamination="none")

    assert res.n_malicious > 0
    # The fixture's lateral movement uses novel hosts by construction, so the
    # calibrated edge-novelty detector must recover it with high AUC.
    assert res.auc > 0.8, f"AUC too low ({res.auc}); harness may be miscalibrated"
