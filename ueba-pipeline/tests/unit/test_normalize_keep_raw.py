"""
tests/unit/test_normalize_keep_raw.py

Covers the memory-scale optimization on NormalizedEvent:
  - keep_raw=False drops raw_event_data without affecting parsed fields,
  - keep_raw=True (default) preserves it,
  - slots=True is in effect (no per-instance __dict__),
  - feature-relevant fields are identical regardless of keep_raw.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.parsing.normalize import normalize_event


def _raw_4624():
    return {
        "winlog": {
            "channel": "Security",
            "event_id": 4624,
            "event_data": {
                "SubjectUserName": "alice",
                "TargetUserName": "alice",
                "LogonType": "3",
                "IpAddress": "10.0.0.5",
                "AuthenticationPackageName": "Kerberos",
            },
        },
        "@timestamp": "2025-01-06T10:00:00.000Z",
    }


def test_keep_raw_true_preserves_raw_event_data():
    ev = normalize_event(_raw_4624(), keep_raw=True)
    assert ev is not None
    assert ev.raw_event_data  # non-empty
    assert ev.raw_event_data.get("SubjectUserName") == "alice"


def test_keep_raw_false_drops_raw_event_data():
    ev = normalize_event(_raw_4624(), keep_raw=False)
    assert ev is not None
    assert ev.raw_event_data == {}


def test_parsed_fields_identical_regardless_of_keep_raw():
    a = normalize_event(_raw_4624(), keep_raw=True)
    b = normalize_event(_raw_4624(), keep_raw=False)
    # The canonical fields feature extraction reads must be identical.
    assert a.event_type == b.event_type
    assert a.fields == b.fields
    assert a.event_time == b.event_time


def test_default_keeps_raw():
    ev = normalize_event(_raw_4624())
    assert ev.raw_event_data  # default keep_raw=True


def test_normalized_event_uses_slots():
    ev = normalize_event(_raw_4624(), keep_raw=False)
    # slots=True => no __dict__ attribute.
    assert not hasattr(ev, "__dict__")
