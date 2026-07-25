"""Parsing and edge projection for the telemetry that was being dropped.

An audit found 14 of 43 parsed event types feeding neither the graph nor the
feature path, and a further set that the parser did not recognise at all -- the
largest single bucket in a generated estate was `unknown`. These tests pin the
field maps and edge projections added for the highest-value of them, and the
normalisation choices those projections depend on.
"""
from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from ueba_pipeline.graph.auth_graph_anomaly import (
    AuthGraphAnomalyDetector,
    _pipe_name,
    _registry_class,
)
from ueba_pipeline.parsing.normalize import normalize_event

WHEN = datetime(2025, 1, 6, tzinfo=UTC)


def _ev(event_type, **fields):
    return SimpleNamespace(event_type=event_type, computer_name="WS-01",
                           event_time=WHEN, fields=fields)


# --- normalisation -----------------------------------------------------------
def test_pipe_name_strips_local_and_remote_forms_to_one_key():
    """The same pipe reached locally and over SMB must not look like two."""
    assert _pipe_name(r"\\.\pipe\srvsvc") == "srvsvc"
    assert _pipe_name(r"\\FS01\pipe\srvsvc") == "srvsvc"
    assert _pipe_name(r"\\.\PIPE\SrvSvc") == "srvsvc"
    assert _pipe_name("") == ""
    assert _pipe_name(None) == ""


def test_registry_class_truncates_to_a_location_not_a_value():
    """Raw TargetObject is near-unique per event; the class must be stable."""
    run = _registry_class(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Teams")
    other = _registry_class(r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Slack")
    assert run == other, "two values in one location must share a class"
    assert run == r"hkcu\software\microsoft\windows"
    # A different hive is a different location even at the same path.
    assert _registry_class(r"HKLM\SOFTWARE\Microsoft\Windows\X") != run
    assert _registry_class("") == ""


# --- edge projection ---------------------------------------------------------
def test_pipe_edges_are_keyed_on_the_account():
    d = AuthGraphAnomalyDetector()
    for et in ("sysmon_17", "sysmon_18"):
        ev = _ev(et, user_norm="mgowda", pipe_name=r"\\.\pipe\srvsvc")
        assert d.edges_for(ev) == [("pipe", ("mgowda", "srvsvc"))]


def test_registry_edges_are_keyed_on_the_account_and_class():
    d = AuthGraphAnomalyDetector()
    ev = _ev("sysmon_13", user_norm="jbehera",
             target_object=r"HKLM\SYSTEM\CurrentControlSet\Services\Foo\ImagePath")
    assert d.edges_for(ev) == [
        ("reg", ("jbehera", r"hklm\system\currentcontrolset\services"))]


def test_share_edges_use_the_subject_as_actor():
    """5140/5145 name the actor in SubjectUserName; the share is the object."""
    d = AuthGraphAnomalyDetector()
    for et in ("5140", "5145"):
        ev = _ev(et, subject_user_name="bghosh", share_name=r"\\FS01\Finance$")
        assert d.edges_for(ev) == [("share", ("bghosh", r"\\fs01\finance$"))]


def test_machine_accounts_are_excluded_from_the_new_views():
    """Consistent with every other view: machine accounts are not modelled here."""
    d = AuthGraphAnomalyDetector()
    assert d.edges_for(_ev("sysmon_17", user_norm="ws-01$", pipe_name=r"\\.\pipe\x")) == []
    assert d.edges_for(_ev("sysmon_13", user_norm="dc01$", target_object=r"HKLM\A\B\C")) == []
    assert d.edges_for(_ev("5145", subject_user_name="fs01$", share_name=r"\\x\y")) == []


def test_incomplete_events_project_no_edge():
    d = AuthGraphAnomalyDetector()
    assert d.edges_for(_ev("sysmon_17", user_norm="a", pipe_name="")) == []
    assert d.edges_for(_ev("sysmon_13", user_norm="", target_object=r"HKLM\A")) == []
    assert d.edges_for(_ev("5140", subject_user_name="a", share_name="")) == []


# --- parsing -----------------------------------------------------------------
def _raw(channel, event_id, data):
    """Flat NXLog-style envelope: fields sit beside the header, not nested."""
    return {"Channel": channel, "EventID": event_id, "EventTime": "2025-01-06T00:00:00Z",
            "Hostname": "WS-01.nexovate.local", **data}


def test_named_pipe_and_share_events_no_longer_parse_as_unknown():
    """These were the largest recoverable slice of the `unknown` bucket."""
    cases = [
        ("Microsoft-Windows-Sysmon/Operational", "17", "sysmon_17",
         {"PipeName": r"\\.\pipe\srvsvc", "User": "NEXOVATE\\mgowda",
          "Image": r"C:\Windows\explorer.exe"}, "pipe_name"),
        ("Microsoft-Windows-Sysmon/Operational", "13", "sysmon_13",
         {"TargetObject": r"HKCU\SOFTWARE\X\Run\A", "EventType": "SetValue",
          "User": "NEXOVATE\\mgowda"}, "target_object"),
        ("Security", "5145", "5145",
         {"SubjectUserName": "bghosh", "ShareName": r"\\FS01\Finance$",
          "RelativeTargetName": "Q1.xlsx", "AccessMask": "0x1"}, "share_name"),
    ]
    for channel, eid, expected_type, data, key_field in cases:
        ne = normalize_event(_raw(channel, eid, data))
        assert ne is not None, f"{channel}/{eid} dropped entirely"
        assert ne.event_type == expected_type, f"{channel}/{eid} -> {ne.event_type}"
        assert ne.fields.get(key_field), f"{expected_type} missing {key_field}"
