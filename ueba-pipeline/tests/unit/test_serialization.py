"""The non-executable persistence bundle must round-trip the engine exactly and
must refuse tampered or code-bearing input.

A model swap that changes scores by even a little is a silent regression, so the
central test asserts bit-for-bit identical scoring before and after a save/load.
The security tests assert the two properties the format exists to provide:
integrity (a mutated bundle is rejected) and non-execution (no bundle file can
carry a Python object that runs on load).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from ueba_pipeline.config.schema import CapabilityConfig
from ueba_pipeline.engine import EngineConfig, BehavioralEngine
from ueba_pipeline.parsing.normalize import NormalizedEvent

SIGNING_KEY = "0" * 64
BASE = datetime(2025, 4, 1, 8, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    monkeypatch.setenv("UEBA__SECURITY__MODEL_SIGNING_KEY", SIGNING_KEY)


def _event(event_type, minute, group, **fields):
    return NormalizedEvent(
        event_time=BASE + timedelta(minutes=minute),
        ingest_time=None, channel="Security", event_id=event_type,
        event_type=event_type, group=group,
        computer_name=fields.pop("computer_name", "WS-01"),
        outcome=None, keywords=[], fields=fields,
    )


def _synthetic_estate():
    """A small estate exercising several relationship views."""
    events = []
    for day in range(6):
        for hour in range(3):
            minute = day * 1440 + hour * 60
            for user, host in (("alice", "WS-01"), ("bob", "WS-02"), ("svc_sql", "DB-01")):
                events.append(_event("4624", minute, "auth",
                                      target_user_name=user, target_user_name_norm=user,
                                      logon_type=3, auth_package="Kerberos",
                                      src_ip="10.0.0.5", workstation=host,
                                      computer_name="DC-01"))
                events.append(_event("4768", minute + 1, "kerberos",
                                      target_user_name=user, target_user_name_norm=user,
                                      src_ip="10.0.0.5", ticket_enc_type="0x12",
                                      pre_auth_type="2", computer_name="DC-01"))
                events.append(_event("sysmon_1", minute + 2, "sysmon_process",
                                      image="C:/Windows/explorer.exe",
                                      computer_name=host))
    return events


def _train_engine() -> BehavioralEngine:
    engine = BehavioralEngine(config=EngineConfig(null_calibration_fraction=0.3))
    engine.fit(_synthetic_estate(), config_capability=CapabilityConfig(bootstrap_min_events=1))
    return engine


def test_save_load_scores_are_bit_identical(tmp_path):
    engine = _train_engine()
    test_events = _synthetic_estate()

    _, before = engine.score(test_events)
    engine.save(str(tmp_path / "bundle"))
    reloaded = BehavioralEngine.load(str(tmp_path / "bundle"))
    _, after = reloaded.score(test_events)

    p_before = sorted((r.entity, r.p_value) for r in before)
    p_after = sorted((r.entity, r.p_value) for r in after)
    assert [e for e, _ in p_before] == [e for e, _ in p_after]
    assert np.allclose([p for _, p in p_before], [p for _, p in p_after], atol=0.0, rtol=0.0)


def test_bundle_contains_no_pickle(tmp_path):
    """The format's whole point: nothing on disk is a pickle."""
    engine = _train_engine()
    bundle = tmp_path / "bundle"
    engine.save(str(bundle))

    names = os.listdir(bundle)
    assert "engine.json" in names
    assert "manifest.sig" in names
    assert not any(n.endswith(".pkl") for n in names), names
    # The JSON must parse as plain data — no object hooks, no code.
    state = json.loads((bundle / "engine.json").read_text(encoding="utf-8"))
    assert state["serialization_version"]
    assert "graph" in state and "graph_nulls" in state


def test_tampered_state_is_rejected(tmp_path):
    engine = _train_engine()
    bundle = tmp_path / "bundle"
    engine.save(str(bundle))

    state_path = bundle / "engine.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["config"]["alert_budget_per_day"] = 999.0        # flip one field
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(ValueError, match="signature verification failed"):
        BehavioralEngine.load(str(bundle))


def test_tampered_array_is_rejected(tmp_path):
    engine = _train_engine()
    bundle = tmp_path / "bundle"
    engine.save(str(bundle))

    npy = next(p for p in bundle.glob("*.npy"))
    raw = bytearray(npy.read_bytes())
    raw[-1] ^= 0xFF                                         # corrupt one byte
    npy.write_bytes(bytes(raw))

    with pytest.raises(ValueError, match="signature verification failed"):
        BehavioralEngine.load(str(bundle))


def test_wrong_signing_key_is_rejected(tmp_path, monkeypatch):
    engine = _train_engine()
    bundle = tmp_path / "bundle"
    engine.save(str(bundle))

    monkeypatch.setenv("UEBA__SECURITY__MODEL_SIGNING_KEY", "f" * 64)
    with pytest.raises(ValueError, match="signature verification failed"):
        BehavioralEngine.load(str(bundle))


def test_load_rejects_object_bearing_npy(tmp_path):
    """A .npy that encodes a Python object is the numpy code-execution vector.

    The signature would stop an outsider, but the format must also refuse such a
    file structurally (allow_pickle=False), so even a correctly signed bundle
    cannot smuggle an object through the array loader.
    """
    engine = _train_engine()
    bundle = tmp_path / "bundle"
    engine.save(str(bundle))

    npy = next(p for p in bundle.glob("*.npy"))
    # An object array can only be written with allow_pickle=True; loading it back
    # with allow_pickle=False (what load_engine does) must raise.
    np.save(npy, np.array([{"payload": "not a number"}], dtype=object), allow_pickle=True)
    # Re-sign so the failure is the array loader, not the integrity check.
    from ueba_pipeline.models.serialization import _bundle_signature, _SIG_NAME
    files = {p.name: p.read_bytes() for p in bundle.glob("*") if p.name != _SIG_NAME}
    (bundle / _SIG_NAME).write_bytes(_bundle_signature(files))

    with pytest.raises(ValueError):
        BehavioralEngine.load(str(bundle))


def test_version_mismatch_is_rejected(tmp_path):
    engine = _train_engine()
    bundle = tmp_path / "bundle"
    engine.save(str(bundle))

    state_path = bundle / "engine.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["serialization_version"] = "0.0.1"
    blob = json.dumps(state, sort_keys=True).encode("utf-8")
    state_path.write_bytes(blob)
    # Re-sign so the version check is what fires, not the integrity check.
    from ueba_pipeline.models.serialization import _bundle_signature, _SIG_NAME
    files = {p.name: p.read_bytes() for p in bundle.glob("*") if p.name != _SIG_NAME}
    (bundle / _SIG_NAME).write_bytes(_bundle_signature(files))

    with pytest.raises(ValueError, match="serialization version"):
        BehavioralEngine.load(str(bundle))
