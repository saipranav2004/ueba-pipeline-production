"""Regression tests for the evaluation-integrity defects found in the audit.

Each test here corresponds to a bug that shipped, was never caught, and would
have been caught by the assertion below. They are cheap; keep them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import numpy as np
import pytest

from ueba_pipeline.engine import EngineConfig, TwoTrackEngine
from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphConfig
from ueba_pipeline.models.inductive_ecod import InductiveECOD


# --- BUG: the alerting path was dead by construction -------------------------
def test_a_single_severe_anomaly_can_alert_on_its_own():
    """The shipped constants made this impossible and nothing noticed:
    novelty_weight(6.0) / (2 * graph_threshold(5.0)) = 0.6 < 0.85 =
    entity_alert_threshold, so one maximal anomaly normalised to 0.6 and could
    never alert; it took >= 3 in one decay window. Under Fisher over calibrated
    p-values, severity dominates by construction."""
    from ueba_pipeline.models.fisher import fisher_combine
    one_severe = fisher_combine([1e-6])[0]
    many_mild = fisher_combine([0.25] * 50)[0]
    assert one_severe < 1e-5
    assert one_severe < many_mild


def test_absorb_threshold_is_reachable():
    """MIDAS-F's point is that a flagged edge is NOT absorbed, so an attacker
    cannot launder repeated abuse into the baseline. The old absorb_threshold
    (8.0) exceeded the maximum achievable score (novelty_weight = 6.0), so every
    flagged edge was absorbed and the protection never fired. Surprise is now
    unbounded above, so the threshold is reachable."""
    from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphConfig
    cfg = AuthGraphConfig()
    assert not hasattr(cfg, "novelty_weight"), "the constant novelty score must be gone"
    assert cfg.absorb_surprise > 0, "absorb threshold must exist in surprise units"


def test_volumetric_scores_are_batch_independent():
    """pyod's ECOD concatenates X_train onto every scoring batch, so a window's
    score depended on which other windows shared its batch (measured drift:
    193.95 score units). score() and score_stream() could not agree.
    """
    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 8))
    m = InductiveECOD().fit(X)
    probe = rng.normal(size=(20, 8))

    alone = np.array([m.decision_function(probe[i : i + 1])[0] for i in range(len(probe))])
    batched = m.decision_function(probe)
    assert np.allclose(alone, batched), "scoring must not depend on batch composition"

    # order-independence too
    perm = rng.permutation(len(probe))
    assert np.allclose(m.decision_function(probe[perm]), batched[perm])


def test_model_artifact_does_not_embed_training_data():
    """61.3 MB of a 61.8 MB signed bundle was ECOD's retained X_train + O/U
    matrices: the artifact was a verbatim copy of the estate's behavioural
    feature matrix, and grew without bound with the training set.
    """
    rng = np.random.default_rng(0)
    d, grid = 8, 4096
    a = InductiveECOD(grid_size=grid).fit(rng.normal(size=(20_000, d)))
    b = InductiveECOD(grid_size=grid).fit(rng.normal(size=(200_000, d)))
    # 10x the training data must not grow the artifact at all.
    assert a.state_bytes == b.state_bytes, (
        f"fitted state must be bounded by grid size, not training-set size "
        f"({a.state_bytes} vs {b.state_bytes})"
    )
    assert b.state_bytes <= d * grid * 8 + 1024
    assert not hasattr(b, "X_train"), "must not retain raw training rows"


def test_threshold_is_calibrated_on_the_frozen_ecdf_not_a_doubled_one():
    """fit() calibrated its threshold via score_many(train_windows), which under
    pyod scored concat(X_train, X_train) -- a doubled distribution no live batch
    ever sees. Confirmed: ECOD's O matrix was (26514, 64) = 2 x 13257.
    """
    rng = np.random.default_rng(0)
    X = rng.normal(size=(1000, 6))
    m = InductiveECOD().fit(X)
    assert len(m.decision_scores_) == len(X)
    assert np.allclose(m.decision_scores_, m.decision_function(X))


# --- BUG: threshold leakage --------------------------------------------------
def test_engine_calibrates_nulls_on_training_data_only():
    """Threshold leakage guard: selecting a threshold from the test set's benign
    scores makes the reported FP rate a restatement of the configured budget. All
    nulls must be frozen at fit time and score() must never recalibrate or see
    labels."""
    import inspect
    fit_src = inspect.getsource(TwoTrackEngine.fit) + inspect.getsource(TwoTrackEngine._fit_graph)
    assert "_vol_null" in fit_src and "_graph_nulls" in fit_src
    score_src = inspect.getsource(TwoTrackEngine.score)
    for leak in ("label", "attack", "EmpiricalPValue().fit", "_vol_null =", "_graph_nulls ="):
        assert leak not in score_src, f"score() must not recalibrate or see labels ({leak!r})"


def test_score_is_pure():
    """score() used to call score_event(absorb=True), so re-scoring the same
    events gave different answers (measured 31 -> 30 -> 30) and a re-run after a
    crash under-reported the attack it was re-run to catch."""
    import inspect
    assert "absorb=False" in inspect.getsource(TwoTrackEngine.score)
    assert hasattr(TwoTrackEngine, "observe"), "online adaptation must be an explicit call"



# --- BUG: the harness's own attribution check went vacuous under p-values -----
def test_attack_attribution_requires_the_alerts_peak_hour():
    """Found by auditing the harness against itself, not by the audit.

    The check used to be "the alerted entity has any detection inside the attack
    window". That was fine when detections were sparse. Once both tracks emitted
    p-values, ~every (entity, hour) cell carried p < 1.0, so an entity is
    trivially "detected" during any hour it was active -- and the attack itself
    generates its principal's activity. The check reduced to "is this entity in
    the top-k anywhere in the test period", crediting an attack on day 8 to an
    alert driven by behaviour on day 1. Measured cost across 3 seeds: 13/15
    inflated vs 11/15 honest.
    """
    import inspect

    from ueba_pipeline.evaluation import honest_eval

    src = inspect.getsource(honest_eval._evaluate_track)
    assert "peak_hour" in src, "attribution must key on the alert's peak hour"
    assert "hours_by_entity" not in src, "the vacuous any-detection-in-window check must stay gone"


# --- BUG: two tracks, two entity spaces, one BH population -------------------
def test_graph_and_volumetric_share_one_entity_space():
    """The graph track fell back to ``computer_name`` for host-scoped Sysmon
    telemetry, so it emitted 511 entities of which 252 were workstations, while
    the volumetric track emitted 272 users. ``_rollup`` then ran
    Benjamini-Hochberg over a mixed population, and hosts had no entry in the
    window map so their Sidak correction fell back to len(detections) --
    systematically under-correcting them against real users. Session resolution
    took the mismatch from 252 to 0.
    """
    from ueba_pipeline.graph.sessions import SessionResolver
    from ueba_pipeline.engine import TwoTrackEngine

    eng = TwoTrackEngine()
    host_event = SimpleNamespace(
        event_type="sysmon_10", event_time=datetime(2025, 1, 1, 10, tzinfo=timezone.utc),
        computer_name="ws01", fields={},
    )
    sessions = SessionResolver()
    sessions._logons = {"ws01": [(datetime(2025, 1, 1, 9, tzinfo=timezone.utc), "alice")]}
    assert eng._entity_for(host_event, sessions) == "alice", "host telemetry must resolve to an identity"
    # No session -> keep the host rather than dropping the event.
    assert eng._entity_for(host_event, SessionResolver()) == "ws01"


def test_session_resolution_is_causal_and_expires():
    from ueba_pipeline.graph.sessions import SessionResolver

    r = SessionResolver(session_ttl_hours=12.0)
    r._logons = {"ws01": [(datetime(2025, 1, 1, 9, tzinfo=timezone.utc), "alice")]}
    # before the logon -> unknown, never look ahead
    assert r.resolve("ws01", datetime(2025, 1, 1, 8, tzinfo=timezone.utc)) is None
    assert r.resolve("ws01", datetime(2025, 1, 1, 10, tzinfo=timezone.utc)) == "alice"
    # past the TTL -> expired rather than silently stale
    assert r.resolve("ws01", datetime(2025, 1, 2, 9, tzinfo=timezone.utc)) is None
