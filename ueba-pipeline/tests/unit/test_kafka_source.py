"""
Tests for KafkaEventSource. These use a fake ``confluent_kafka`` module injected
into sys.modules so the real broker/library is not required, and verify the
contract that matters for correctness:

  * events are normalized through the SAME path as the file source;
  * offsets are committed only AFTER an event is consumed downstream
    (at-least-once, not at-most-once);
  * malformed JSON is quarantined (counted, committed, not raised);
  * partition EOF terminates read() in replay mode (stop_on_eof=True);
  * a genuine consume error is surfaced, not silently swallowed.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


# --- Fake confluent_kafka --------------------------------------------------

class _FakeError:
    def __init__(self, code):
        self._code = code

    def code(self):
        return self._code

    def __str__(self):
        return f"FakeError({self._code})"


class _FakeMessage:
    def __init__(self, value=None, error=None):
        self._value = value
        self._error = error
        self.committed = False

    def value(self):
        return self._value

    def error(self):
        return self._error

    def topic(self):
        return "events"

    def partition(self):
        return 0


class _FakeKafkaError:
    _PARTITION_EOF = -191


def _install_fake_kafka(messages, commit_log):
    """Install a fake confluent_kafka whose Consumer yields `messages` in order,
    recording commits into `commit_log` so tests can assert commit ordering."""
    mod = types.ModuleType("confluent_kafka")

    class _FakeConsumer:
        def __init__(self, config):
            self.config = config
            self._it = iter(messages)

        def subscribe(self, topics):
            self._topics = topics

        def poll(self, timeout):
            try:
                return next(self._it)
            except StopIteration:
                return None

        def commit(self, msg, asynchronous=False):
            msg.committed = True
            commit_log.append(msg)

        def close(self):
            self.closed = True

    mod.Consumer = _FakeConsumer
    mod.KafkaError = _FakeKafkaError
    sys.modules["confluent_kafka"] = mod
    return mod


@pytest.fixture(autouse=True)
def _cleanup_fake_kafka():
    yield
    sys.modules.pop("confluent_kafka", None)


# --- Tests -----------------------------------------------------------------

def _valid_event_json():
    # A minimal 4624 logon envelope the normalizer accepts.
    return (
        '{"EventID": 4624, "TimeCreated": "2025-01-06T09:00:00Z", '
        '"TargetUserName": "alice", "IpAddress": "10.0.0.5", '
        '"LogonType": 3, "WorkstationName": "WS1", "Channel": "Security"}'
    )


def test_kafka_source_normalizes_and_commits_after_yield():
    from ueba_pipeline.ingestion.source import KafkaEventSource, IngestStats

    commit_log = []
    eof = _FakeMessage(error=_FakeError(_FakeKafkaError._PARTITION_EOF))
    msgs = [_FakeMessage(value=_valid_event_json().encode()), eof]
    _install_fake_kafka(msgs, commit_log)

    stats = IngestStats()
    src = KafkaEventSource(["b:9092"], "events", "g", stats=stats, stop_on_eof=True)

    seen = []
    for ne in src.read():
        # At the moment the caller receives the event, it must NOT yet be
        # committed -- commit happens only when the generator resumes.
        assert not msgs[0].committed, "committed before downstream processing (at-most-once!)"
        seen.append(ne)

    assert len(seen) == 1
    assert stats.total_records == 1
    assert msgs[0].committed, "event was never committed after processing"


def test_kafka_source_quarantines_malformed_json():
    from ueba_pipeline.ingestion.source import KafkaEventSource, IngestStats

    commit_log = []
    eof = _FakeMessage(error=_FakeError(_FakeKafkaError._PARTITION_EOF))
    msgs = [_FakeMessage(value=b"{not json"), _FakeMessage(value=_valid_event_json().encode()), eof]
    _install_fake_kafka(msgs, commit_log)

    stats = IngestStats()
    src = KafkaEventSource(["b:9092"], "events", "g", stats=stats, stop_on_eof=True)
    seen = list(src.read())

    assert len(seen) == 1                       # only the valid record yielded
    assert stats.unrecognized_envelope == 1     # malformed one counted
    assert len(commit_log) == 2                 # BOTH committed (bad one skipped forward)


def test_kafka_source_stops_on_partition_eof():
    from ueba_pipeline.ingestion.source import KafkaEventSource

    commit_log = []
    eof = _FakeMessage(error=_FakeError(_FakeKafkaError._PARTITION_EOF))
    msgs = [_FakeMessage(value=_valid_event_json().encode()), eof]
    _install_fake_kafka(msgs, commit_log)

    src = KafkaEventSource(["b:9092"], "events", "g", stop_on_eof=True)
    seen = list(src.read())  # must terminate, not block
    assert len(seen) == 1


def test_kafka_source_raises_on_real_error():
    from ueba_pipeline.ingestion.source import KafkaEventSource

    commit_log = []
    bad = _FakeMessage(error=_FakeError(-1))  # not EOF
    _install_fake_kafka([bad], commit_log)

    src = KafkaEventSource(["b:9092"], "events", "g", stop_on_eof=True)
    with pytest.raises(RuntimeError, match="Kafka consume error"):
        list(src.read())


def test_kafka_config_disables_autocommit_and_passes_security():
    from ueba_pipeline.ingestion.source import KafkaEventSource

    _install_fake_kafka([], [])
    src = KafkaEventSource(
        ["b:9092"], "events", "g",
        extra_config={"security.protocol": "SASL_SSL", "sasl.mechanism": "SCRAM-SHA-512"},
    )
    cfg = src._build_config()
    assert cfg["enable.auto.commit"] is False          # at-least-once
    assert cfg["security.protocol"] == "SASL_SSL"       # hardening passthrough
    assert cfg["group.id"] == "g"
