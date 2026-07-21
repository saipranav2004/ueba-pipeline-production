"""
sysmon_generator_extended.py

Extended Sysmon event generators for:
  EID 6  — Driver Loaded
  EID 12 — RegistryEvent (Object Create/Delete)
  EID 13 — RegistryEvent (Value Set)
  EID 14 — RegistryEvent (Key/Value Rename)
  EID 15 — FileCreateStreamHash (alternate data streams / MOTW)
  EID 17 — PipeEvent (Pipe Created)
  EID 18 — PipeEvent (Pipe Connected)

All field names verified against:
  ultimatewindowssecurity.com Event 90012 / 90013 live XML (2017-05-11)
  Microsoft Q&A Sysmon schema event templates (2021-12-30):
    EID 12/13: RuleName EventType UtcTime ProcessGuid ProcessId Image
               TargetObject [Details for 13] [NewName for 14] User
  SwiftOnSecurity/sysmon-config DATA comment: confirmed field list
  gravwell.io Sysmon registry event series (2021-11-02)
  Splunk Security Content Dataset 45512fa5 (EID 7/15 schema)
"""

from __future__ import annotations
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus, ProcessRecord, _new_guid, stable_agent_id, stable_ephemeral_id
from generators.sysmon_generator import _SYSMON_TASKS, sha256_hash, md5_hash
from core.time_engine import utc_now_str
from config.company import DOMAIN_NETBIOS


def _sysmon_env(
    event_id:   str,
    computer:   str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Sysmon Winlogbeat envelope — same structure as sysmon_generator.py."""
    ts_str     = utc_now_str(utc_dt)
    ingest_dt  = utc_dt + timedelta(seconds=bus._rng.randint(1, 5))
    rid        = bus.next_record_id(f"Sysmon:{computer}")
    return {
        "@timestamp": ts_str,
        "@metadata": {"beat": "winlogbeat", "type": "_doc", "version": "9.4.2"},
        "log": {"level": "information"},
        "host": {"name": computer},
        "agent": {
            "type":         "winlogbeat",
            "version":      "9.4.2",
            "name":         computer.split(".")[0],
            "id":           stable_agent_id(computer),
            "ephemeral_id": stable_ephemeral_id(computer, bus._sim_seed),
        },
        "ecs": {"version": "8.0.0"},
        "event": {
            "code":     event_id,
            "kind":     "event",
            "provider": "Microsoft-Windows-Sysmon",
            "action":   _SYSMON_TASKS.get(event_id, ""),
            "created":  utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       "Microsoft-Windows-Sysmon/Operational",
            "provider_name": "Microsoft-Windows-Sysmon",
            "provider_guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
            "computer_name": computer,
            "task":          _SYSMON_TASKS.get(event_id, ""),
            "opcode":        "Info",
            "record_id":     rid,
            "version":       2,
            "keywords":      [],
            "event_data":    event_data,
        },
    }


def _utcstr(dt: datetime) -> str:
    """7-digit fractional precision for WindowsSystemTime fields."""
    us_str  = f"{dt.microsecond:06d}"
    seventh = (dt.microsecond * 7 + dt.second * 13) % 10
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + us_str + str(seventh) + "Z"


def _hashes(path: str) -> str:
    sha = sha256_hash(path)
    md5 = md5_hash(path)
    return f"SHA256={sha},MD5={md5}"


def _user(proc: ProcessRecord, domain: str = DOMAIN_NETBIOS) -> str:
    return f"{domain}\\{proc.user}" if "\\" not in proc.user else proc.user


# ── EID 6 — Driver Loaded ────────────────────────────────────────────────────
def gen_eid6(
    driver_image:  str,
    computer:      str,
    utc_dt:        datetime,
    bus:           EventBus,
    signed:        bool = True,
    signature:     str = "Microsoft Windows",
    sig_status:    str = "Valid",
) -> Dict[str, Any]:
    """
    Sysmon EID 6 Driver Loaded.
    Verified fields from SwiftOnSecurity/sysmon-config DATA comment:
      UtcTime, ImageLoaded, Hashes, Signed, Signature, SignatureStatus.
    Generated when a driver (kernel module) is loaded.
    Normal: Microsoft-signed drivers. Suspicious: unsigned or revoked.
    """
    ed = {
        "RuleName":        "-",
        "UtcTime":         _utcstr(utc_dt),
        "ImageLoaded":     driver_image,
        "Hashes":          _hashes(driver_image),
        "Signed":          "true" if signed else "false",
        "Signature":       signature if signed else "",
        "SignatureStatus": sig_status if signed else "Unsigned",
    }
    return _sysmon_env("6", computer, utc_dt, bus, ed)


# ── EID 12 — Registry Object Create/Delete ───────────────────────────────────
def gen_eid12(
    proc:          ProcessRecord,
    target_object: str,
    event_type:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 12 RegistryEvent (Object create and delete).
    Verified fields from Microsoft Q&A Sysmon schema (2021-12-30) and
    ultimatewindowssecurity.com Event 90012 live capture (2017-05-11):
      RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image,
      TargetObject, User.
    EventType values: 'CreateKey', 'DeleteKey', 'CreateValue', 'DeleteValue'.
    TargetObject uses abbreviated registry root names:
      HKLM = HKEY_LOCAL_MACHINE
      HKU  = HKEY_USERS
    """
    ed = {
        "RuleName":     "-",
        "EventType":    event_type,
        "UtcTime":      _utcstr(utc_dt),
        "ProcessGuid":  proc.process_guid,
        "ProcessId":    str(proc.process_id),
        "Image":        proc.image,
        "TargetObject": target_object,
        "User":         _user(proc),
    }
    return _sysmon_env("12", proc.computer, utc_dt, bus, ed)


# ── EID 13 — Registry Value Set ──────────────────────────────────────────────
def gen_eid13(
    proc:          ProcessRecord,
    target_object: str,
    details:       str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 13 RegistryEvent (Value Set).
    Verified fields from ultimatewindowssecurity.com Event 90013 live XML
    (2017-05-11) and Microsoft Q&A schema:
      RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image,
      TargetObject, Details, User.
    EventType is always 'SetValue'.
    Details: the actual value written (for DWORD/QWORD; string for others).
    """
    ed = {
        "RuleName":     "-",
        "EventType":    "SetValue",
        "UtcTime":      _utcstr(utc_dt),
        "ProcessGuid":  proc.process_guid,
        "ProcessId":    str(proc.process_id),
        "Image":        proc.image,
        "TargetObject": target_object,
        "Details":      details,
        "User":         _user(proc),
    }
    return _sysmon_env("13", proc.computer, utc_dt, bus, ed)


# ── EID 14 — Registry Key/Value Rename ───────────────────────────────────────
def gen_eid14(
    proc:          ProcessRecord,
    target_object: str,
    new_name:      str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 14 RegistryEvent (Key and Value Rename).
    Verified fields from Microsoft Q&A Sysmon schema and gravwell.io
    Sysmon registry series (2021-11-02):
      RuleName, EventType, UtcTime, ProcessGuid, ProcessId, Image,
      TargetObject, NewName, User.
    EventType is always 'RenameKey'.
    NewName: the new path after rename.
    """
    ed = {
        "RuleName":     "-",
        "EventType":    "RenameKey",
        "UtcTime":      _utcstr(utc_dt),
        "ProcessGuid":  proc.process_guid,
        "ProcessId":    str(proc.process_id),
        "Image":        proc.image,
        "TargetObject": target_object,
        "NewName":      new_name,
        "User":         _user(proc),
    }
    return _sysmon_env("14", proc.computer, utc_dt, bus, ed)


# ── EID 15 — FileCreateStreamHash (Alternate Data Streams / MOTW) ────────────
def gen_eid15(
    proc:            ProcessRecord,
    target_filename: str,
    contents:        str,
    utc_dt:          datetime,
    bus:             EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 15 FileCreateStreamHash.
    Verified fields from marcusedmondson.substack.com Sysmon parse guide
    and SwiftOnSecurity/sysmon-config EID 15 comment:
      RuleName, UtcTime, ProcessGuid, ProcessId, Image, TargetFilename,
      CreationUtcTime, Hash, User, Contents.
    Generated when a file is created with a named stream (ADS).
    Most common: Zone.Identifier stream (Mark-of-the-Web) when a file
    is downloaded from the internet. Contents field contains the stream data.
    """
    ed = {
        "RuleName":        "-",
        "UtcTime":         _utcstr(utc_dt),
        "ProcessGuid":     proc.process_guid,
        "ProcessId":       str(proc.process_id),
        "Image":           proc.image,
        "TargetFilename":  target_filename,
        "CreationUtcTime": _utcstr(utc_dt),
        "Hash":            f"SHA256={sha256_hash(target_filename)}",
        "User":            _user(proc),
        "Contents":        contents,
    }
    return _sysmon_env("15", proc.computer, utc_dt, bus, ed)


# ── EID 17 — Pipe Created ────────────────────────────────────────────────────
def gen_eid17(
    proc:      ProcessRecord,
    pipe_name: str,
    utc_dt:    datetime,
    bus:       EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 17 PipeEvent (Pipe Created).
    Verified fields from SwiftOnSecurity/sysmon-config DATA comment:
      UtcTime, ProcessGuid, ProcessId, PipeName, Image, User.
    Normal: Windows system pipes (\\.\\pipe\\svcctl, \\.\\pipe\\lsarpc).
    Suspicious: random-name pipes used by Cobalt Strike / Metasploit.
    """
    ed = {
        "RuleName":    "-",
        "UtcTime":     _utcstr(utc_dt),
        "ProcessGuid": proc.process_guid,
        "ProcessId":   str(proc.process_id),
        "PipeName":    pipe_name,
        "Image":       proc.image,
        "User":        _user(proc),
    }
    return _sysmon_env("17", proc.computer, utc_dt, bus, ed)


# ── EID 18 — Pipe Connected ──────────────────────────────────────────────────
def gen_eid18(
    proc:      ProcessRecord,
    pipe_name: str,
    utc_dt:    datetime,
    bus:       EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 18 PipeEvent (Pipe Connected).
    Same fields as EID 17; generated when a client connects to a named pipe.
    Verified: SwiftOnSecurity/sysmon-config DATA comment confirms identical
    field set to EID 17.
    """
    ed = {
        "RuleName":    "-",
        "UtcTime":     _utcstr(utc_dt),
        "ProcessGuid": proc.process_guid,
        "ProcessId":   str(proc.process_id),
        "PipeName":    pipe_name,
        "Image":       proc.image,
        "User":        _user(proc),
    }
    return _sysmon_env("18", proc.computer, utc_dt, bus, ed)