"""The OTRF real-telemetry adapter.

The offline tests run against synthetic records written in OTRF's exact flat
schema, covering the three event-time field names and the timestamp formats real
captures use. They pin the ingestion contract against real Windows event shapes.

The networked test (opt-in via UEBA_RUN_OTRF_DOWNLOAD=1) downloads a real OTRF
DCSync capture and asserts the engine projects the same behavioural graph edge on
genuine telemetry that it does on the simulator. It is skipped by default so the
suite stays hermetic and offline-safe.
"""
from __future__ import annotations

import json
import os

import pytest

from ueba_pipeline.evaluation import otrf_adapter
from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector, AuthGraphConfig
from ueba_pipeline.parsing.normalize import normalize_event


# ── synthetic OTRF-schema records (flat NXLog/Mordor shape) ──────────────────
def _sysmon10(source_image, target_image, time_field, time_value):
    """A Sysmon ProcessAccess record, timestamp under a chosen field name."""
    rec = {
        "EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational",
        "Hostname": "HOST01.corp.local",
        "SourceImage": source_image, "TargetImage": target_image,
        "GrantedAccess": "0x1010", "SourceUser": "CORP\\attacker",
    }
    rec[time_field] = time_value
    return rec


def _dcsync_4662(time_value):
    """A real-shaped DCSync 4662: the Replicating-Directory-Changes GUID in
    Properties, actor in SubjectUserName."""
    return {
        "EventID": 4662, "Channel": "Security", "Hostname": "DC01.corp.local",
        "@timestamp": time_value,
        "SubjectUserName": "pgustavo", "SubjectDomainName": "CORP",
        "AccessMask": "0x100", "ObjectType": "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}",
        "Properties": "%%7688\r\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}\r\n",
    }


def test_flat_records_parse_through_the_production_parser():
    records = [
        _sysmon10("C:\\Windows\\explorer.exe", "C:\\Windows\\system32\\lsass.exe",
                  "EventTime", "2020-08-05 02:10:02"),
        _sysmon10("C:\\Temp\\rundll32.exe", "C:\\Windows\\system32\\lsass.exe",
                  "@timestamp", "2023-07-19T09:02:18.927Z"),
        _sysmon10("C:\\Temp\\procdump.exe", "C:\\Windows\\system32\\lsass.exe",
                  "TimeCreated", "2020-10-18 07:50:06.220"),
    ]
    events = [normalize_event(r) for r in records]
    assert all(e is not None for e in events)
    # Every record must carry a parsed event_time. Real captures place the event
    # time under any of three field names, in either of two formats; an
    # unparsed timestamp silently removes the event from every window.
    assert all(e.event_time is not None for e in events), (
        "a real OTRF timestamp field or format failed to parse"
    )
    assert all(e.event_type == "sysmon_10" for e in events)


def test_iso_timestamp_variants_parse():
    """Every ISO-8601 shape real Windows exports emit must parse."""
    from ueba_pipeline.parsing.normalize import _parse_iso
    assert _parse_iso("2023-07-19T09:02:18.927Z") is not None
    assert _parse_iso("2020-08-05T06:10:03.798Z") is not None
    # 7-digit Windows fraction, truncated to microseconds, still parses.
    assert _parse_iso("2023-07-19T09:02:18.1234567Z") is not None


def test_adapter_reads_events_from_a_json_source(tmp_path):
    source = tmp_path / "capture.json"
    records = [
        _dcsync_4662("2020-08-05T06:10:03.798Z"),
        _sysmon10("a.exe", "b.exe", "@timestamp", "2020-08-05T06:10:04.100Z"),
    ]
    source.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")

    events = list(otrf_adapter.read_otrf_events(source))
    assert len(events) == 2
    assert {e.event_type for e in events} == {"4662", "sysmon_10"}


def test_dcsync_projects_the_dir_op_edge_on_flat_records(tmp_path):
    """The behavioural signal the engine uses for DCSync must fire on the real
    event shape: a dir_op edge (actor -> adobjaccess), no signature involved."""
    source = tmp_path / "dcsync.json"
    source.write_text(json.dumps(_dcsync_4662("2020-08-05T06:10:03.798Z")),
                      encoding="utf-8")

    graph = AuthGraphAnomalyDetector(config=AuthGraphConfig())
    edges = [
        (view, edge)
        for event in otrf_adapter.read_otrf_events(source)
        for view, edge in graph.edges_for(event)
    ]
    assert ("dir_op", ("pgustavo", "adobjaccess")) in edges, (
        "the DCSync 4662 did not project the behavioural dir_op edge"
    )


def test_curated_manifest_is_well_formed():
    assert otrf_adapter.OTRF_DATASETS
    for dataset in otrf_adapter.OTRF_DATASETS:
        assert dataset.expected_views, dataset.name
        assert dataset.url.startswith("https://")
        assert otrf_adapter.dataset_by_name(dataset.name) is dataset


@pytest.mark.skipif(
    os.environ.get("UEBA_RUN_OTRF_DOWNLOAD") != "1",
    reason="networked test; set UEBA_RUN_OTRF_DOWNLOAD=1 to run against real OTRF data",
)
def test_real_otrf_dcsync_download_and_projection(tmp_path):
    dataset = otrf_adapter.dataset_by_name("dcsync")
    try:
        local = otrf_adapter.download_otrf_dataset(dataset, tmp_path)
    except Exception as exc:  # offline / rate-limited: skip rather than fail
        pytest.skip(f"could not download OTRF dataset: {exc}")

    events = [e for e in otrf_adapter.read_otrf_events(local) if e.event_time]
    assert events, "no events parsed from the real capture"

    graph = AuthGraphAnomalyDetector(config=AuthGraphConfig())
    views = {view for e in events for view, _ in graph.edges_for(e)}
    for expected in dataset.expected_views:
        assert expected in views, (
            f"expected graph view {expected!r} did not project on the real "
            f"{dataset.name} capture; got {sorted(views)}"
        )
