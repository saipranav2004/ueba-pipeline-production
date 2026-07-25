"""
wmi_defender_generators.py

Generators for:
  WMI Activity Operational Log:  5857 5858 5861
  Windows Defender Operational:  1116 1117 5007

All field names verified against:
  NXLog live JSON capture (2019-02-24): EID 5858 fields confirmed
  Tales of a Threat Hunter blog (2018-03-02): EID 5857/5861 field enumeration
  NXLog WMI auditing documentation (nxlog.co/news-and-blog/posts/wmi-auditing)
  neuberger6.rssing.com WMI provider template (Microsoft template XML)
  darkoperator.com Sysmon 6.10 WMI tracking (5859/5860/5861 payloads)
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus, stable_agent_id, stable_ephemeral_id
from core.time_engine import utc_now_str

_WMI_TASKS: dict[str, str] = {
    "5857": "WMI Activity",
    "5858": "WMI Activity",
    "5860": "WMI Activity",
    "5861": "WMI Activity",
}

_DEFENDER_TASKS: dict[str, str] = {
    "1116": "Malware Detection",
    "1117": "Malware Remediation",
    "1118": "Malware Quarantine",
    "1119": "Malware Remediation Success",
    "5007": "Configuration Changed",
}


def _wmi_envelope(
    event_id:   str,
    computer:   str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: dict[str, Any],
    level:      str = "information",
) -> dict[str, Any]:
    """
    Winlogbeat envelope for Microsoft-Windows-WMI-Activity/Operational events.
    Provider GUID: {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
    Verified from NXLog live JSON (2019-02-24) and Microsoft provider template.
    Channel: Microsoft-Windows-WMI-Activity/Operational
    """
    ts_str     = utc_now_str(utc_dt)
    ingest_dt  = utc_dt + timedelta(seconds=bus._rng.randint(1, 4))
    rid        = bus.next_record_id(f"WMI:{computer}")
    return {
        "@timestamp": ts_str,
        "@metadata": {"beat": "winlogbeat", "type": "_doc", "version": "9.4.2"},
        "log": {"level": level},
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
            "code":    event_id,
            "kind":    "event",
            "provider":"Microsoft-Windows-WMI-Activity",
            "action":   _WMI_TASKS.get(event_id, "WMI Activity"),
            "created": utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       "Microsoft-Windows-WMI-Activity/Operational",
            "provider_name": "Microsoft-Windows-WMI-Activity",
            "provider_guid": "{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}",
            "computer_name": computer,
            "task":          _WMI_TASKS.get(event_id, "WMI Activity"),
            "opcode":        "Info",
            "record_id":     rid,
            "version":       0,
            "keywords":      [],
            "event_data":    event_data,
        },
    }


def gen_wmi_5857(
    provider_name: str,
    host_process:  str,
    process_id:    int,
    provider_path: str,
    computer:      str,
    utc_dt:        datetime,
    bus:           EventBus,
    result_code:   str = "0x0",
) -> dict[str, Any]:
    """
    WMI EID 5857 — WMI provider started.
    Verified fields from Microsoft provider XML template (neuberger6.rssing.com):
      ProviderName, Code, HostProcess, ProcessID, ProviderPath.
    Generated every time WMI activity is detected (high frequency).
    Normal: CIMWin32 provider (Win32_Process, Win32_Service queries).
    Suspicious: unknown ProviderPath in temp directories.
    """
    ed = {
        "ProviderName": provider_name,
        "Code":         result_code,
        "HostProcess":  host_process,
        "ProcessID":    str(process_id),
        "ProviderPath": provider_path,
    }
    return _wmi_envelope("5857", computer, utc_dt, bus, ed, "information")


def gen_wmi_5858(
    operation:      str,
    user:           str,
    client_machine: str,
    client_pid:     int,
    result_code:    str,
    computer:       str,
    utc_dt:         datetime,
    bus:            EventBus,
) -> dict[str, Any]:
    """
    WMI EID 5858 — WMI error / operation failure.
    Verified from NXLog live JSON capture (2019-02-24):
      ActivityID, Channel, Message containing:
      'Id = {UUID}; ClientMachine = HOST; User = NT AUTHORITY\\SYSTEM;
       ClientProcessId = NNNN; Component = Unknown;
       Operation = Start IWbemServices::ExecQuery - root\\cimv2 : SELECT ...;
       ResultCode = 0x...; PossibleCause = Unknown'
    The UserData element wraps the structured fields in production logs.
    """
    activity_id = bus.new_guid()
    message = (
        f"Id = {activity_id}; ClientMachine = {client_machine.split('.')[0]}; "
        f"User = {user}; ClientProcessId = {client_pid}; "
        f"Component = Unknown; Operation = {operation}; "
        f"ResultCode = {result_code}; PossibleCause = Unknown"
    )
    ed = {
        "ActivityID":      activity_id,
        "ClientMachine":   client_machine,
        "User":            user,
        "ClientProcessId": str(client_pid),
        "Component":       "Unknown",
        "Operation":       operation,
        "ResultCode":      result_code,
        "PossibleCause":   "Unknown",
    }
    ev = _wmi_envelope("5858", computer, utc_dt, bus, ed, "error")
    ev["message"] = message
    return ev


def gen_wmi_5861(
    namespace:      str,
    filter_name:    str,
    consumer_name:  str,
    consumer_type:  str,
    query:          str,
    computer:       str,
    utc_dt:         datetime,
    bus:            EventBus,
) -> dict[str, Any]:
    """
    WMI EID 5861 — WMI FilterToConsumerBinding created (permanent subscription).
    Verified from Tales of a Threat Hunter (2018-03-02) and
    darkoperator.com WMI tracking:
    PossibleCause field contains the full binding XML under UserData.
    This is the most important WMI persistence detection event.
    """
    possible_cause = (
        f'binding EventFilter:\r\ninstance of __EventFilter\r\n{{\r\n'
        f'Name = "{filter_name}";\r\nNameSpace = "{namespace}";\r\n'
        f'Query = "{query}";\r\n}};\r\n'
        f'Perm. Consumer:\r\ninstance of {consumer_type}\r\n{{\r\n'
        f'Name = "{consumer_name}";\r\n}};\r\n'
        f'PossibleCause = Permanent WMI Subscription'
    )
    ed = {
        "Namespace":    namespace,
        "FilterName":   filter_name,
        "ConsumerName": consumer_name,
        "ConsumerType": consumer_type,
        "Query":        query,
        "PossibleCause":possible_cause,
    }
    return _wmi_envelope("5861", computer, utc_dt, bus, ed, "information")


# ════════════════════════════════════════════════════════════════════════════
# WINDOWS DEFENDER OPERATIONAL LOG
# ════════════════════════════════════════════════════════════════════════════

def _defender_envelope(
    event_id:   str,
    computer:   str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: dict[str, Any],
    level:      str = "warning",
) -> dict[str, Any]:
    """
    Winlogbeat envelope for Windows Defender Operational events.
    Provider GUID: {11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}
    Channel: Microsoft-Windows-Windows Defender/Operational
    """
    ts_str     = utc_now_str(utc_dt)
    ingest_dt  = utc_dt + timedelta(seconds=bus._rng.randint(1, 5))
    rid        = bus.next_record_id(f"Defender:{computer}")
    return {
        "@timestamp": ts_str,
        "@metadata": {"beat": "winlogbeat", "type": "_doc", "version": "9.4.2"},
        "log": {"level": level},
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
            "code":    event_id,
            "kind":    "event",
            "provider":"Microsoft-Windows-Windows Defender",
            "action":  _DEFENDER_TASKS.get(event_id, ""),
            "created": utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       "Microsoft-Windows-Windows Defender/Operational",
            "provider_name": "Microsoft-Windows-Windows Defender",
            "provider_guid": "{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}",
            "computer_name": computer,
            "task":          _DEFENDER_TASKS.get(event_id, ""),
            "opcode":        "Info",
            "record_id":     rid,
            "version":       0,
            "keywords":      [],
            "event_data":    event_data,
        },
    }


def gen_defender_1116(
    threat_name:      str,
    severity:         str,
    category:         str,
    path:             str,
    detection_user:   str,
    process_name:     str,
    computer:         str,
    utc_dt:           datetime,
    bus:              EventBus,
    action_taken:     str = "0",
    threat_id:        str = "",
) -> dict[str, Any]:
    """
    Windows Defender EID 1116 — Malware detected.
    Fields inferred from Microsoft Defender event schema and Splunk
    Security Content Defender detection rules. Common fields:
    Threat Name, Category, Severity, Path, Detection User, Process Name,
    Action Taken (0=unknown/detected not yet remediated).
    """
    if not threat_id:
        threat_id = str(bus._rng.randint(2000, 9999))
    ed = {
        "Product Name":          "Microsoft Defender Antivirus",
        "Product Version":       "4.18.24010.12",
        "Threat ID":             threat_id,
        "Threat Name":           threat_name,
        "Severity ID":           _severity_id(severity),
        "Severity Name":         severity,
        "Category ID":           _category_id(category),
        "Category Name":         category,
        "Path":                  path,
        "Detection User":        detection_user,
        "Process Name":          process_name,
        "Security intelligence Version": "1.403.827.0",
        "Engine Version":        "1.1.24010.12",
        "Action ID":             action_taken,
        "Action Name":           "Detected" if action_taken == "0" else "Quarantine",
        "Error Code":            "0x00000000",
        "Error Description":     "The operation completed successfully.",
        "State":                 "1",
        "Source ID":             "3",
        "Source Name":           "Real-Time Protection",
        "FWLink":                f"https://go.microsoft.com/fwlink/?linkid=37020&name={threat_name}",
    }
    return _defender_envelope("1116", computer, utc_dt, bus, ed, "warning")


def gen_defender_1117(
    threat_name:  str,
    severity:     str,
    category:     str,
    path:         str,
    action_taken: str,
    computer:     str,
    utc_dt:       datetime,
    bus:          EventBus,
    threat_id:    str = "",
) -> dict[str, Any]:
    """
    Windows Defender EID 1117 — Malware action taken (quarantine/remove/allow).
    Follows EID 1116. Action ID: 2=Quarantine, 3=Remove, 6=Allow.
    """
    if not threat_id:
        threat_id = str(bus._rng.randint(2000, 9999))
    _ACTION_NAMES = {"2": "Quarantine", "3": "Remove", "6": "Allow", "8": "UserDefined", "9": "NoAction"}
    ed = {
        "Product Name":          "Microsoft Defender Antivirus",
        "Product Version":       "4.18.24010.12",
        "Threat ID":             threat_id,
        "Threat Name":           threat_name,
        "Severity ID":           _severity_id(severity),
        "Severity Name":         severity,
        "Category ID":           _category_id(category),
        "Category Name":         category,
        "Path":                  path,
        "Action ID":             action_taken,
        "Action Name":           _ACTION_NAMES.get(action_taken, "Quarantine"),
        "Error Code":            "0x00000000",
        "Error Description":     "The operation completed successfully.",
        "Security intelligence Version": "1.403.827.0",
        "Engine Version":        "1.1.24010.12",
        "State":                 "2",
    }
    return _defender_envelope("1117", computer, utc_dt, bus, ed, "information")


def gen_defender_5007(
    old_value:     str,
    new_value:     str,
    setting_name:  str,
    computer:      str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> dict[str, Any]:
    """
    Windows Defender EID 5007 — Configuration changed.
    Verified from neuberger6.rssing.com blog (2017-10-16):
    'Once that is set we should see an entry in the eventlog indicating
    that the settings of Windows Defender where modified. The event Id
    should be 5007 and the data is structured to make it easy to parse.'
    Fields: Old Value, New Value (contain setting path and values).
    Setting path format: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\...
    """
    ed = {
        "Old Value": f"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\{setting_name} = {old_value}",
        "New Value": f"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\{setting_name} = {new_value}",
    }
    return _defender_envelope("5007", computer, utc_dt, bus, ed, "information")


def _severity_id(severity: str) -> str:
    return {"Low": "1", "Moderate": "2", "High": "4", "Severe": "5", "Critical": "5"}.get(severity, "4")


def _category_id(category: str) -> str:
    return {
        "Trojan":           "8",
        "Ransomware":       "19",
        "HackTool":         "34",
        "PUP":              "1",
        "Backdoor":         "11",
        "Worm":             "9",
        "Exploit":          "16",
        "Spyware":          "10",
        "PasswordStealer":  "18",
        "Adware":           "2",
    }.get(category, "8")
