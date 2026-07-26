"""Every queue returned by ``score_queues`` must be renderable by one printer.

The engine ships four separately budgeted queues, and they deliberately do NOT
share a concrete alert type: the execution queue is a relational rollup that
counts surprising edges, the deviation queues name the signal that fired.
Flattening them would discard the part an analyst reads.

What they must share is the *rendering contract* -- the fields a consumer needs
to display or forward an alert without knowing which queue produced it. That
contract was broken once: ``cmd_score`` read ``.signal``, which only the
deviation queues have, so the documented quickstart crashed with an
``AttributeError`` the moment the execution queue fired. No unit test drove the
CLI's printer with an execution alert, so nothing caught it. This does.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ueba_pipeline.cli.main import queue_line
from ueba_pipeline.config.schema import CapabilityConfig
from ueba_pipeline.engine import BehavioralEngine, EngineConfig
from ueba_pipeline.parsing.normalize import NormalizedEvent

BASE = datetime(2025, 4, 1, 8, 0, tzinfo=UTC)

# The fields a consumer of score_queues is allowed to depend on. Adding to this
# set is a deliberate widening of the contract; every queue must satisfy it.
CONTRACT = ("entity", "p_value", "top_hour", "n_windows", "alerted", "evidence")


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    monkeypatch.setenv("UEBA__SECURITY__MODEL_SIGNING_KEY", "0" * 64)


def _exec_event(user: str, image: str, when: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_time=when, ingest_time=None, channel="Microsoft-Windows-Sysmon/Operational",
        event_id="1", event_type="sysmon_1", group="process",
        computer_name="DC01", outcome=None, keywords=[],
        fields={"user_norm": user, "image": image},
    )


def _pipe_event(user: str, pipe: str, when: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_time=when, ingest_time=None, channel="Microsoft-Windows-Sysmon/Operational",
        event_id="17", event_type="sysmon_17", group="process",
        computer_name="WS-01", outcome=None, keywords=[],
        fields={"user_norm": user, "pipe_name": rf"\\.\pipe\{pipe}"},
    )


def _logon(user: str, src: str, when: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_time=when, ingest_time=None, channel="Security", event_id="4624",
        event_type="4624", group="auth", computer_name="FS01", outcome="success",
        keywords=[],
        fields={"target_user_name": user, "workstation": src, "logon_type": "3"},
    )


def _estate() -> list[NormalizedEvent]:
    """A routine baseline plus one account running a program it never has.

    Kept small and hand-built rather than simulator-generated so the test states
    exactly which behaviour it expects to surface.
    """
    events: list[NormalizedEvent] = []
    for day in range(6):
        for hour in range(9, 17):
            t = BASE + timedelta(days=day, hours=hour - 8)
            for user in ("alice", "bob", "carol"):
                events.append(_exec_event(user, r"C:\Windows\System32\cmd.exe", t))
                events.append(_logon(user, "ws-01", t + timedelta(minutes=1)))
                events.append(_pipe_event(user, "srvsvc", t + timedelta(minutes=2)))
    # The anomaly: an account whose only program has ever been cmd.exe reaches for
    # the directory-extraction tool. No new relationship, only a new program.
    events.append(_exec_event("alice", r"C:\Windows\System32\ntdsutil.exe",
                              BASE + timedelta(days=6, hours=3)))
    # And a pipe no account here has ever served -- the PsExec shape.
    events.append(_pipe_event("bob", "psexesvc-ws-02-4471",
                              BASE + timedelta(days=6, hours=4)))
    events.sort(key=lambda e: e.event_time)
    return events


def _fitted() -> tuple[BehavioralEngine, list[NormalizedEvent]]:
    events = _estate()
    split = int(len(events) * 0.8)
    engine = BehavioralEngine(EngineConfig()).fit(
        events[:split], config_capability=CapabilityConfig(bootstrap_min_events=1))
    return engine, events[split:]


def test_every_queue_alert_satisfies_the_rendering_contract():
    engine, test_events = _fitted()
    queues = engine.score_queues(test_events)
    assert queues, "no queue was scored; the fixture no longer exercises this path"

    for name, alerts in queues.items():
        for a in alerts:
            missing = [f for f in CONTRACT if not hasattr(a, f)]
            assert not missing, f"{name} queue alert {type(a).__name__} lacks {missing}"


def test_the_cli_printer_renders_an_alert_from_every_queue():
    """The regression itself: the printer must not reach for a queue-specific field."""
    engine, test_events = _fitted()
    queues = engine.score_queues(test_events)

    rendered = 0
    for name, alerts in queues.items():
        for a in alerts:
            line = queue_line(a)          # would raise AttributeError before the fix
            assert a.entity in line, f"{name} queue line does not name its entity"
            rendered += 1
    assert rendered, "no alert was rendered; the fixture no longer exercises this path"


def test_the_pipe_queue_is_scored_separately_from_execution():
    """The fifth queue must exist as its own list with its own budget.

    `pipe` cannot share either existing queue -- inside the relational queue it
    cost six headline detections, and inside the execution queue `proc_exec`
    displaced it from 3/6 to 0/6 -- so a regression that quietly folds it into
    another queue would undo the measurement that justified it.
    """
    engine, test_events = _fitted()
    queues = engine.score_queues(test_events)
    assert "pipe" in queues, "the pipe queue is no longer scored"
    assert "execution" in queues
    assert queues["pipe"] is not queues["execution"]
    assert engine.config.pipe_budget_per_day > 0
    for a in queues["pipe"]:
        assert a.evidence.startswith("hits=")


def test_a_zero_pipe_budget_disables_the_queue_entirely():
    engine, test_events = _fitted()
    engine.config.pipe_budget_per_day = 0.0
    assert "pipe" not in engine.score_queues(test_events)


def test_the_execution_queue_is_scored_and_carries_its_own_evidence():
    """Guards the specific queue that broke the printer: it must actually appear."""
    engine, test_events = _fitted()
    queues = engine.score_queues(test_events)
    assert "execution" in queues, "the execution queue is no longer scored"
    for a in queues["execution"]:
        # A relational rollup counts edges; it has no `signal`, and that is correct.
        assert a.evidence.startswith("hits=")
        assert not hasattr(a, "signal")
