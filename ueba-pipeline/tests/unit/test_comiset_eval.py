"""COMISET evaluation: the chunked archive streamer and the labelled per-view /
ROC evaluation, exercised hermetically on a synthetic archive built to the real
COMISET on-disk format (leading split/spanning marker + zip64-style local header +
one raw-deflate NDJSON member).
"""
from __future__ import annotations

import json
import struct
import zlib

import pytest

from ueba_pipeline.evaluation.comiset_adapter import iter_comiset_archive
from ueba_pipeline.evaluation.comiset_eval import (
    evaluate_comiset, is_malicious, load_comiset_graph_events,
)


def _make_comiset_zip(path, records):
    """Write records as a COMISET-shaped .zip: the leading ``PK\\x07\\x08`` spanning
    marker, one deflate-compressed NDJSON member, no central directory (the
    raw-inflate reader does not need it — that is the point of streaming)."""
    ndjson = ("\n".join(json.dumps(r) for r in records) + "\n").encode("utf-8")
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    body = comp.compress(ndjson) + comp.flush()
    name = b"dataset.json"
    lfh = (b"PK\x03\x04" + struct.pack("<HHHHH", 20, 0, 8, 0, 0)
           + struct.pack("<III", zlib.crc32(ndjson) & 0xFFFFFFFF, len(body), len(ndjson))
           + struct.pack("<HH", len(name), 0) + name)
    path.write_bytes(b"PK\x07\x08" + lfh + body)


def _sec(eid, minute, user, ws, ip="10.0.0.5", tech=None, **extra):
    s = {"event_id": eid, "log_name": "Security", "host_name": "dc01.lab",
         "@timestamp": f"2022-11-16T09:{minute:02d}:00.000Z",
         "TargetUserName": user, "IpAddress": ip, "WorkstationName": ws, **extra}
    if tech:
        s["rule_technique_id"] = tech
    return {"_index": "logs-endpoint-winevent-security-2022.11.16", "_source": s}


def _records():
    recs = []
    # a benign population of remote logons from stable devices, several days/hours
    for m in range(40):
        recs.append(_sec("4624", m % 60, f"user{m % 6}", f"ws{m % 6}", LogonType="3"))
    # a Sysmon process-access (proc_access view) benign
    recs.append({"_index": "sysmon", "_source": {
        "event_id": "10", "log_name": "Microsoft-Windows-Sysmon/Operational",
        "host_name": "dc01.lab", "@timestamp": "2022-11-16T09:30:00.000Z",
        "SourceImage": "C:/Windows/System32/svchost.exe",
        "TargetImage": "C:/Windows/System32/lsass.exe", "GrantedAccess": "0x1000"}})
    # labelled-malicious logons from a never-seen device (novel user_src edge)
    for m in range(3):
        recs.append(_sec("4624", 50 + m, "attacker", "evil-host", ip="10.9.9.9",
                         LogonType="3", tech="T1021.002"))
    # a non-graph event that must be dropped
    recs.append({"_index": "additional", "_source": {
        "event_id": "8001", "log_name": "Microsoft-Windows-Store/Operational",
        "host_name": "dc01.lab", "@timestamp": "2022-11-16T09:05:00.000Z"}})
    return recs


def test_chunked_streamer_round_trips_synthetic_archive(tmp_path):
    p = tmp_path / "comiset.zip"
    _make_comiset_zip(p, _records())
    got = list(iter_comiset_archive(p, read_chunk_bytes=64))   # tiny chunks force line-splitting
    assert len(got) == len(_records())
    assert got[0]["_source"]["event_id"] == "4624"


def test_loader_keeps_graph_events_and_injects_labels(tmp_path):
    p = tmp_path / "comiset.zip"
    _make_comiset_zip(p, _records())
    events = list(load_comiset_graph_events(iter_comiset_archive(p)))
    # the Store 8001 record is dropped as non-graph
    assert all(e.event_type != "unknown" for e in events)
    mal = [e for e in events if is_malicious(e)]
    assert len(mal) == 3 and all(e.fields["rule_technique_id"] == "T1021.002" for e in mal)


def test_evaluate_comiset_reports_novelty_and_counts(tmp_path):
    p = tmp_path / "comiset.zip"
    _make_comiset_zip(p, _records())
    report = evaluate_comiset(str(p), max_events=10_000, max_uncompressed_bytes=1 << 20,
                              train_fraction=0.6)
    assert report.n_graph_events == 44          # 40 benign 4624 + 1 sysmon10 + 3 malicious
    assert report.n_malicious == 3
    assert "Security" in report.channel_mix
    # the production held-out calibration ran and reported a rate for the user_src view
    assert "user_src" in report.view_novelty
    assert 0.0 <= report.view_novelty["user_src"]["novel_rate"] <= 1.0
    # rendering must not raise
    assert "COMISET real-data evaluation" in report.render()


@pytest.fixture(autouse=True)
def _signing_key(monkeypatch):
    # Non-numeric so the config env-override parser keeps it a string; the eval
    # never signs a bundle, it only needs load_config() to validate.
    monkeypatch.setenv("UEBA__SECURITY__MODEL_SIGNING_KEY", "deadbeef" * 8)
