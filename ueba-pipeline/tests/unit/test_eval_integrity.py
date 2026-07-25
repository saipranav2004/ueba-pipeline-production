"""Evaluation-integrity invariants.

Each assertion here pins a property the detection and evaluation paths must hold
for their reported numbers to mean anything: severity must dominate frequency,
nulls must be frozen at fit, scoring must be pure, attribution must be strict,
and every entity must be corrected against one population. They are cheap to run
and expensive to lose.
"""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from ueba_pipeline.engine import BehavioralEngine
from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphConfig


# --- severity must dominate frequency ----------------------------------------
def test_a_single_severe_anomaly_can_alert_on_its_own():
    """One maximally anomalous event must be able to alert by itself.

    An alerting rule that requires several coincident anomalies is a frequency
    detector: a single decisive event -- the one an intrusion actually produces
    -- would never surface. Combining calibrated p-values makes severity dominate
    by construction."""
    from ueba_pipeline.models.fisher import fisher_combine
    one_severe = fisher_combine([1e-6])[0]
    many_mild = fisher_combine([0.25] * 50)[0]
    assert one_severe < 1e-5
    assert one_severe < many_mild


def test_absorb_threshold_is_reachable():
    """The non-absorption threshold must be reachable by a real score.

    MIDAS-F's protection is that a flagged edge is NOT folded into the baseline,
    so an attacker cannot launder repeated abuse into normality. That only holds
    if the threshold sits inside the achievable score range: surprise is
    unbounded above and the threshold is expressed in the same nats, so a
    sufficiently anomalous edge always trips it."""
    cfg = AuthGraphConfig()
    assert not hasattr(cfg, "novelty_weight"), "the constant novelty score must be gone"
    assert cfg.absorb_surprise > 0, "absorb threshold must exist in surprise units"





# --- nulls frozen at fit, never recalibrated on test --------------------------
def test_engine_calibrates_nulls_on_training_data_only():
    """Threshold leakage guard: selecting a threshold from the test set's benign
    scores makes the reported FP rate a restatement of the configured budget. All
    nulls must be frozen at fit time and score() must never recalibrate or see
    labels."""
    import inspect
    fit_src = (inspect.getsource(BehavioralEngine.fit)
               + inspect.getsource(BehavioralEngine._fit_graph))
    assert "_graph_nulls" in fit_src
    score_src = inspect.getsource(BehavioralEngine.score)
    for leak in ("label", "attack", "EmpiricalPValue().fit", "_graph_nulls ="):
        assert leak not in score_src, f"score() must not recalibrate or see labels ({leak!r})"


def test_score_is_pure():
    """Batch scoring must be a pure function of the events it is given.

    If scoring mutates the baseline, re-scoring the same events returns different
    answers and a re-run after a crash under-reports the very activity it was
    re-run to catch. Online adaptation is therefore an explicit separate call."""
    import inspect
    assert "absorb=False" in inspect.getsource(BehavioralEngine.score)
    assert hasattr(BehavioralEngine, "observe"), "online adaptation must be an explicit call"



# --- attribution must be strict, not coincidental -----------------------------
def test_attack_attribution_requires_the_alerts_peak_hour():
    """An attack counts as detected only if the alert's PEAK hour falls inside it.

    Under p-value scoring nearly every (entity, hour) cell carries p < 1.0, so a
    looser "the entity had any detection during the window" check is satisfied by
    mere activity -- and the attack generates its own principal's activity. That
    check degenerates into "is this entity in the top-k anywhere in the test
    period", which would credit a day-8 attack to an alert driven by day-1
    behaviour. The peak hour is also what the product shows an analyst.
    """
    import inspect

    from ueba_pipeline.evaluation import honest_eval

    src = inspect.getsource(honest_eval._evaluate_detections)
    assert "peak_hour" in src, "attribution must key on the alert's peak hour"
    assert "hours_by_entity" not in src, "the vacuous any-detection-in-window check must stay gone"


# --- one entity space across all telemetry ------------------------------------
def test_host_scoped_telemetry_resolves_into_the_identity_space():
    """Host-scoped telemetry must resolve to the account that owns the session.

    Sysmon names a host and an image but no user. Left as hosts, the rollup would
    run Benjamini-Hochberg over a mixed host/user population, and hosts -- absent
    from the per-entity window map -- would take a weaker Sidak correction than
    real users. Resolving the logged-on owner keeps one population. An
    unattributable event keeps the host rather than being dropped.
    """
    from ueba_pipeline.engine import BehavioralEngine
    from ueba_pipeline.graph.sessions import SessionResolver

    eng = BehavioralEngine()
    host_event = SimpleNamespace(
        event_type="sysmon_10", event_time=datetime(2025, 1, 1, 10, tzinfo=UTC),
        computer_name="ws01", fields={},
    )
    sessions = SessionResolver()
    sessions._logons = {"ws01": [(datetime(2025, 1, 1, 9, tzinfo=UTC), "alice")]}
    assert eng._entity_for(host_event, sessions) == "alice", \
        "host telemetry must resolve to an identity"
    # No session -> keep the host rather than dropping the event.
    assert eng._entity_for(host_event, SessionResolver()) == "ws01"


def test_session_resolution_is_causal_and_expires():
    from ueba_pipeline.graph.sessions import SessionResolver

    r = SessionResolver(session_ttl_hours=12.0)
    r._logons = {"ws01": [(datetime(2025, 1, 1, 9, tzinfo=UTC), "alice")]}
    # before the logon -> unknown, never look ahead
    assert r.resolve("ws01", datetime(2025, 1, 1, 8, tzinfo=UTC)) is None
    assert r.resolve("ws01", datetime(2025, 1, 1, 10, tzinfo=UTC)) == "alice"
    # past the TTL -> expired rather than silently stale
    assert r.resolve("ws01", datetime(2025, 1, 2, 9, tzinfo=UTC)) is None
