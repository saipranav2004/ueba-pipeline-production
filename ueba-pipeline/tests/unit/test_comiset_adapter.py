"""COMISET adapter: the ES/HELK envelope unwrap must feed the production parser.

The fixtures marked "real" are verbatim ``_source`` records captured from the
COMISET lab archive (Zenodo 15375146), trimmed of ETL/pipeline noise but with
their envelope and event structure intact — so these tests exercise the adapter
against genuine record shapes, not an invented one. The Security-4624 fixture is
constructed to the *same verified flat-HELK schema* (event fields flattened to
``_source`` top level under their Windows names) to prove the adapter reaches the
engine's ``user_src`` view; the opt-in ``stream_comiset_head`` test validates that
schema against the live archive when a network run is requested.
"""
from __future__ import annotations

import json
import os

import pytest

from ueba_pipeline.evaluation.comiset_adapter import (
    comiset_source_to_raw,
    read_comiset_events,
    stream_comiset_head,
)
from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector

# --- real records captured from Comiset23_Lab_Environment_Dataset.zip ----------
# WMI 5857 -> maps to the "wmi" group; TaskScheduler 200 -> "task_scheduler";
# Store 8001 -> no field map, so event_type "unknown" (the graceful path).
_REAL_WMI_5857 = {
    "_index": "logs-endpoint-winevent-additional-2022.11.16", "_type": "_doc",
    "_id": "bf6aebfdcb73ca347f60a315d1e140e122649893", "_score": 1,
    "_source": {
        "ProviderName": "StorageWMI", "type": "wineventlog",
        "@timestamp": "2022-11-16T08:19:31.225Z",
        "host_name": "desktop-4pvps6e.phoenix.local", "HostProcess": "wmiprvse.exe",
        "ProviderPath": "%SystemRoot%\\System32\\storagewmi.dll",
        "z_elastic_ecs": {"event": {"code": "5857",
                                    "provider": "Microsoft-Windows-WMI-Activity"}},
        "event_id": "5857", "ProcessID": "3024",
        "log_name": "Microsoft-Windows-WMI-Activity/Operational", "Code": "0x0",
    },
}
_REAL_TASK_200 = {
    "_index": "logs-endpoint-winevent-additional-2022.11.16", "_type": "_doc",
    "_id": "0ed58b1fdabd643ae1f6be17baeff7899d1b9446", "_score": 1,
    "_source": {
        "ActionName": "network state change task handler", "type": "wineventlog",
        "@timestamp": "2022-11-16T08:17:21.615Z",
        "host_name": "desktop-4pvps6e.phoenix.local",
        "TaskInstanceId": "{83001FFA-9F5C-4337-B3A8-1AF90FC65D6C}", "EnginePID": "4452",
        "event_id": "200", "log_name": "Microsoft-Windows-TaskScheduler/Operational",
        "TaskName": "\\microsoft\\windows\\settingsync\\networkstatechangetask",
    },
}
_REAL_STORE_8001 = {
    "_index": "logs-endpoint-winevent-additional-2022.11.16", "_type": "_doc",
    "_id": "fa6b285c520d9480bf0a0e9046cd9c9336604e59", "_score": 1,
    "_source": {
        "Message": "ServiceBeginAcquireLicenseImpl", "type": "wineventlog",
        "@timestamp": "2022-11-16T08:23:41.123Z",
        "host_name": "desktop-4pvps6e.phoenix.local",
        "event_id": "8001", "log_name": "Microsoft-Windows-Store/Operational",
    },
}
# Constructed to the verified real COMISET field names (HELK renames LogonType to
# lower-case ``logon_type`` and drops IpAddress; WorkstationName survives), for a
# Security 4624 remote logon the streamed prefix does not reach.
_SECURITY_4624 = {
    "_index": "logs-endpoint-winevent-security-2022.11.16", "_type": "_doc",
    "_id": "deadbeef", "_score": 1,
    "_source": {
        "type": "wineventlog", "@timestamp": "2022-11-16T09:00:00.000Z",
        "host_name": "dc01.phoenix.local", "event_id": "4624", "log_name": "Security",
        "TargetUserName": "jsmith", "TargetDomainName": "PHOENIX",
        "logon_type": "3", "WorkstationName": "WS-JSMITH",
        "AuthenticationPackageName": "Kerberos",
        "z_elastic_ecs": {"event": {
            "code": "4624", "provider": "Microsoft-Windows-Security-Auditing"}},
    },
}
# Real COMISET Sysmon-10 field names: SourceImage/TargetImage are renamed by HELK
# to process_path/target_process_path; GrantedAccess/SourceUser/TargetUser survive.
_SYSMON_10 = {
    "_index": "logs-endpoint-winevent-sysmon-2022.11.16", "_type": "_doc",
    "_id": "s10", "_score": 1,
    "_source": {
        "type": "wineventlog", "@timestamp": "2022-11-16T09:10:00.000Z",
        "host_name": "ws-victim.phoenix.local", "event_id": "10",
        "log_name": "Microsoft-Windows-Sysmon/Operational",
        "process_path": "C:/Windows/System32/rundll32.exe",
        "target_process_path": "C:/Windows/System32/lsass.exe",
        "GrantedAccess": "0x1fffff", "SourceUser": "PHOENIX\\attacker",
        "TargetUser": "NT AUTHORITY\\SYSTEM", "rule_technique_id": "T1003.001",
        "z_elastic_ecs": {"event": {"code": "10", "provider": "Microsoft-Windows-Sysmon"}},
    },
}


def _write_ndjson(tmp_path, records):
    p = tmp_path / "comiset_sample.ndjson"
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return p


def test_source_unwrap_adds_envelope_aliases_without_dropping_fields():
    raw = comiset_source_to_raw(_REAL_WMI_5857)
    # HELK envelope names are aliased to what the flat parser reads...
    assert raw["EventID"] == "5857"
    assert raw["Channel"] == "Microsoft-Windows-WMI-Activity/Operational"
    assert raw["Hostname"] == "desktop-4pvps6e.phoenix.local"
    assert raw["EventTime"] == "2022-11-16T08:19:31.225Z"
    # ...and nothing is renamed away (never-silently-drop contract).
    assert raw["event_id"] == "5857" and raw["ProviderName"] == "StorageWMI"


def test_record_without_source_is_passed_through_untouched():
    stray = {"not": "an es record"}
    assert comiset_source_to_raw(stray) is stray


def test_real_records_normalise_through_the_production_parser(tmp_path):
    path = _write_ndjson(tmp_path, [_REAL_WMI_5857, _REAL_TASK_200, _REAL_STORE_8001])
    events = list(read_comiset_events(path))
    assert len(events) == 3
    by_id = {e.event_id: e for e in events}

    # channel + time survived the unwrap on real records
    assert by_id["5857"].channel == "Microsoft-Windows-WMI-Activity/Operational"
    assert by_id["5857"].group == "wmi"
    assert by_id["5857"].event_time is not None

    # a mapped event extracts its canonical field from the flattened top level
    assert by_id["200"].event_type == "task_200"
    assert by_id["200"].group == "task_scheduler"
    assert by_id["200"].fields.get("task_name", "").endswith("networkstatechangetask")

    # an unmapped channel degrades to "unknown" rather than being dropped
    assert by_id["8001"].event_type == "unknown"


def test_security_logon_reaches_the_user_src_view(tmp_path):
    """The adapter must carry a Security 4624 all the way to a graph edge.

    This only works once HELK's lower-case ``logon_type`` is aliased back to
    ``LogonType`` (the remote-logon filter reads it); it is the field-rename that
    silently produced zero edges before the alias table existed.
    """
    path = _write_ndjson(tmp_path, [_SECURITY_4624])
    (event,) = list(read_comiset_events(path))
    assert event.event_type == "4624"
    assert event.group == "auth"
    assert event.fields.get("target_user_name") == "jsmith"
    assert event.fields.get("logon_type") == 3          # alias restored + cast to int

    edges = AuthGraphAnomalyDetector().edges_for(event)
    views = {view for view, _ in edges}
    assert "user_src" in views, edges
    # keyed on the device identity (WorkstationName), the only source COMISET carries
    (_, (src, dst)), = [(v, e) for v, e in edges if v == "user_src"]
    assert src == "jsmith" and dst == "ws-jsmith"


def test_sysmon10_reaches_the_proc_access_view(tmp_path):
    """proc_access is the one view COMISET's lab exercises richly, and it only
    fires once HELK's process_path/target_process_path are aliased to
    SourceImage/TargetImage."""
    path = _write_ndjson(tmp_path, [_SYSMON_10])
    (event,) = list(read_comiset_events(path))
    assert event.event_type == "sysmon_10"
    assert event.fields.get("source_image", "").endswith("rundll32.exe")
    assert event.fields.get("target_image", "").endswith("lsass.exe")

    edges = AuthGraphAnomalyDetector().edges_for(event)
    proc = [(v, e) for v, e in edges if v == "proc_access"]
    assert proc, edges
    (_, (src, dst)), = proc
    assert src.endswith("|rundll32.exe") and dst == "lsass.exe"


@pytest.mark.skipif(
    os.environ.get("UEBA_RUN_COMISET_DOWNLOAD") != "1",
    reason="opt-in: streams a prefix of the ~4.9GB COMISET lab archive over the network",
)
def test_real_comiset_head_streams_and_parses():
    """Stream the head of the live COMISET lab archive and confirm real records
    flow through the production parser. Ingestion correctness, not detection."""
    from ueba_pipeline.evaluation.comiset_adapter import COMISET_FILES

    n = mapped = 0
    for record in stream_comiset_head(COMISET_FILES["lab"], max_uncompressed_bytes=8 * 1024 * 1024):
        raw = comiset_source_to_raw(record)
        assert "EventID" in raw and "Channel" in raw
        from ueba_pipeline.parsing.normalize import normalize_event
        event = normalize_event(raw)
        if event is not None:
            n += 1
            mapped += event.event_type != "unknown"
        if n >= 500:
            break
    assert n >= 500, f"expected to parse many real records, got {n}"
