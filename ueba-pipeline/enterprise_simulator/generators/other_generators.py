"""
dns_generator.py — Windows DNS Server Analytical Log events (EID 256/257).
powershell_generator.py — PowerShell Operational Log (EID 4103/4104).
task_scheduler_generator.py — Task Scheduler Operational Log (EID 106/200/201/4698).

All in one file for brevity; each section is clearly delimited.
Field names verified from:
  DNS:  NXLog Platform Documentation live JSON (2026-04-13) + cybersecthreat/DFIR GitHub
  PS:   Psmths/windows-forensic-artifacts live XML (2023-11-06) + NXLog (2020-01-29)
  Task: NXLog live JSON (2022-02-27) + Splunk Security Content f8c777f8 (2024-03-04)
"""

from __future__ import annotations
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus, LogonSession, ProcessRecord, _new_guid, stable_agent_id, stable_ephemeral_id
from core.employees import user_sid as _user_sid
from core.time_engine import utc_now_str
from config.company import DOMAIN_NETBIOS, DOMAIN_FQDN


# ══════════════════════════════════════════════════════════════════════════════
# DNS SERVER ANALYTICAL LOG — EID 256 / 257
# ══════════════════════════════════════════════════════════════════════════════

_QTYPE_MAP = {
    "A":     "1",
    "AAAA":  "28",
    "MX":    "15",
    "TXT":   "16",
    "CNAME": "5",
    "NS":    "2",
    "SOA":   "6",
    "PTR":   "12",
    "SRV":   "33",
    "ANY":   "255",
}


def _dns_envelope(
    event_id:   str,
    dns_server: str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Winlogbeat envelope for DNS Server Analytical events.
    Provider GUID: {EB79061A-A566-4698-9119-3ED2807060E7}
    Verified from NXLog production capture (2026-04-13).
    """
    ts_str    = utc_now_str(utc_dt)
    ingest_dt = utc_dt + timedelta(seconds=bus._rng.randint(1, 4))
    record_key = f"DNS:{dns_server}"
    rid        = bus.next_record_id(record_key)

    return {
        "@timestamp": ts_str,
        "@metadata": {
            "beat":    "winlogbeat",
            "type":    "_doc",
            "version": "9.4.2",
        },
        "log": {"level": "information"},
        "host": {"name": dns_server},
        "agent": {
            "type":         "winlogbeat",
            "version":      "9.4.2",
            "name":         dns_server.split(".")[0],
            "id":           stable_agent_id(dns_server),
            "ephemeral_id": stable_ephemeral_id(dns_server, bus._sim_seed),
        },
        "ecs": {"version": "8.0.0"},
        "event": {
            "code":     event_id,
            "kind":     "event",
            "provider": "Microsoft-Windows-DNSServer",
            "action":   "LOOK_UP",
            "created":  utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       "Microsoft-Windows-DNS-Server/Analytical",
            "provider_name": "Microsoft-Windows-DNSServer",
            "provider_guid": "{EB79061A-A566-4698-9119-3ED2807060E7}",
            "computer_name": dns_server,
            "task":          "LOOK_UP",
            "opcode":        "Info",
            "record_id":     rid,
            "version":       0,
            "keywords":      [],
            "event_data":    event_data,
        },
    }


def gen_dns_256(
    client_ip:     str,
    qname:         str,
    dns_server:    str,
    dns_server_ip: str,
    utc_dt:        datetime,
    bus:           EventBus,
    qtype:         str = "A",
    rcode:         str = "0",
    tcp:           str = "0",
) -> Dict[str, Any]:
    """
    DNS EID 256 — Query Received (LOOK_UP).
    Field names verified from NXLog live JSON:
      TCP, InterfaceIP, Source, Destination, RD, QNAME, QTYPE, XID,
      Port, Flags, AA, AD, DNSSEC, RCODE, Scope, Zone, PolicyName.
    Source: docs.nxlog.co/integrations/dns/dns-monitoring-windows.html (2026-04-13)
    """
    event_data = {
        "TCP":         tcp,
        "InterfaceIP": dns_server_ip,
        "Source":      client_ip,
        "Destination": dns_server_ip,
        "RD":          "1",
        "QNAME":       qname if qname.endswith(".") else qname + ".",
        "QTYPE":       _QTYPE_MAP.get(qtype.upper(), "1"),
        "XID":         str(bus._rng.randint(1000, 65535)),
        "Port":        str(bus._rng.randint(49152, 65535)),
        "Flags":       "33152",
        "AA":          "0",
        "AD":          "0",
        "DNSSEC":      "0",
        "RCODE":       rcode,
        "Scope":       "Default",
        "Zone":        "..Cache" if rcode == "0" else "",
        "PolicyName":  "NULL",
    }
    return _dns_envelope("256", dns_server, utc_dt, bus, event_data)


def gen_dns_257(
    client_ip:     str,
    qname:         str,
    dns_server:    str,
    dns_server_ip: str,
    resolved_ip:   str,
    utc_dt:        datetime,
    bus:           EventBus,
    qtype:         str = "A",
    rcode:         str = "0",
) -> Dict[str, Any]:
    """DNS EID 257 — Query Response sent back to client."""
    event_data = {
        "TCP":         "0",
        "InterfaceIP": dns_server_ip,
        "Source":      dns_server_ip,
        "Destination": client_ip,
        "RD":          "1",
        "QNAME":       qname if qname.endswith(".") else qname + ".",
        "QTYPE":       _QTYPE_MAP.get(qtype.upper(), "1"),
        "XID":         str(bus._rng.randint(1000, 65535)),
        "Port":        str(bus._rng.randint(49152, 65535)),
        "Flags":       "33152",
        "AA":          "0",
        "AD":          "0",
        "DNSSEC":      "0",
        "RCODE":       rcode,
        "Scope":       "Default",
        "Zone":        "..Cache" if rcode == "0" else "",
        "PolicyName":  "NULL",
        "PacketData":  _fake_packet_data(qname, resolved_ip),
    }
    return _dns_envelope("257", dns_server, utc_dt, bus, event_data)


def _fake_packet_data(qname: str, resolved_ip: str) -> str:
    """Deterministic fake hex packet data for EID 257."""
    h = hashlib.md5(f"{qname}{resolved_ip}".encode()).hexdigest().upper()
    return f"0x{h[:4]}818000010002000000000{h[4:20]}"


# ══════════════════════════════════════════════════════════════════════════════
# POWERSHELL OPERATIONAL LOG — EID 4103 / 4104
# ══════════════════════════════════════════════════════════════════════════════

_PS_TASKS: Dict[str, str] = {
    "4103": "Pipeline Execution Details",
    "4104": "Execute a Remote Command",
    "4105": "Command Start",
    "4106": "Command Stop",
}


def _ps_envelope(
    event_id:   str,
    computer:   str,
    user_sid:   str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: Dict[str, Any],
    level:      int = 5,
    activity_id: str = "",
    process_id: int = 0,
    thread_id:  int = 0,
) -> Dict[str, Any]:
    """
    Winlogbeat envelope for PowerShell Operational events.
    Provider GUID (WinPS 5.1): {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
    Verified from Psmths/windows-forensic-artifacts (2023-11-06) and
    NXLog live JSON (2020-01-29).
    """
    ts_str     = utc_now_str(utc_dt)
    ingest_dt  = utc_dt + timedelta(seconds=bus._rng.randint(1, 5))
    record_key = f"PowerShell:{computer}"
    rid        = bus.next_record_id(record_key)
    if not activity_id:
        activity_id = bus.new_guid()
    if not process_id:
        process_id = bus._rng.randint(1000, 9999)
    if not thread_id:
        thread_id = bus._rng.randint(1000, 9999)

    level_str = {5: "Verbose", 4: "Informational", 3: "Warning", 2: "Error"}.get(level, "Verbose")

    return {
        "@timestamp": ts_str,
        "@metadata": {
            "beat":    "winlogbeat",
            "type":    "_doc",
            "version": "9.4.2",
        },
        "log":   {"level": level_str.lower()},
        "host":  {"name": computer},
        "agent": {
            "type":         "winlogbeat",
            "version":      "9.4.2",
            "name":         computer.split(".")[0],
            "id":           stable_agent_id(computer),
            "ephemeral_id": stable_ephemeral_id(computer, bus._sim_seed),
        },
        "ecs":   {"version": "8.0.0"},
        "event": {
            "code":     event_id,
            "kind":     "event",
            "provider": "Microsoft-Windows-PowerShell",
            "action":   _PS_TASKS.get(event_id, ""),
            "created":  utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       "Microsoft-Windows-PowerShell/Operational",
            "provider_name": "Microsoft-Windows-PowerShell",
            "provider_guid": "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}",
            "computer_name": computer,
            "task":          _PS_TASKS.get(event_id, ""),
            "opcode":        "To be used when operation is just executing a method",
            "record_id":     rid,
            "version":       1,
            "keywords":      [],
            "activity_id":   activity_id,
            "process": {
                "pid":    process_id,
                "thread": {"id": thread_id},
            },
            "user": {"identifier": user_sid},
            "event_data": event_data,
        },
    }


def gen_ps_4104(
    computer:          str,
    user_sam:          str,
    user_sid:          str,
    script_block_text: str,
    script_block_id:   str,
    utc_dt:            datetime,
    bus:               EventBus,
    path:              str = "",
    message_number:    int = 1,
    message_total:     int = 1,
    process_id:        int = 0,
    activity_id:       str = "",
) -> Dict[str, Any]:
    """
    PowerShell EID 4104 Script Block Logging.
    Field names verified from Psmths/windows-forensic-artifacts live XML
    (2023-11-06): MessageNumber, MessageTotal, ScriptBlockText,
    ScriptBlockId, Path are the exact Data Name= values.

    Level=3 (Warning) is auto-generated by PowerShell engine when
    ScriptBlockText contains suspicious keywords — verified from
    TrustedSec Part 3 (2026-04-07).
    """
    # Determine level: 3=Warning if suspicious keywords present
    _suspicious = [
        "iex", "invoke-expression", "downloadstring", "net.webclient",
        "-encodedcommand", "-enc", "invoke-mimikatz", "bypass", "hidden",
        "amsibypass", "reflection.assembly", "sekurlsa", "procdump",
        "minidumpwritedump", "comsvcs",
    ]
    text_lower = script_block_text.lower()
    level      = 3 if any(kw in text_lower for kw in _suspicious) else 5

    event_data = {
        "MessageNumber":  str(message_number),
        "MessageTotal":   str(message_total),
        "ScriptBlockText":script_block_text,
        "ScriptBlockId":  script_block_id,
        "Path":           path,
    }
    return _ps_envelope(
        event_id     = "4104",
        computer     = computer,
        user_sid     = user_sid,
        utc_dt       = utc_dt,
        bus          = bus,
        event_data   = event_data,
        level        = level,
        activity_id  = activity_id,
        process_id   = process_id,
    )


def gen_ps_4103(
    computer:        str,
    user_sam:        str,
    user_sid:        str,
    command_name:    str,
    payload:         str,
    runspace_id:     str,
    utc_dt:          datetime,
    bus:             EventBus,
    host_application:str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    host_name:       str = "ConsoleHost",
    pipeline_id:     str = "1",
    process_id:      int = 0,
    activity_id:     str = "",
) -> Dict[str, Any]:
    """
    PowerShell EID 4103 Module Pipeline Execution.
    Field names verified from NXLog live JSON (2020-01-29):
    AccountName, UserID, Category, Payload, ActivityID,
    ContextInfo_Host Name, ContextInfo_Host Application,
    ContextInfo_Runspace ID, ContextInfo_Command Name, etc.
    """
    event_data = {
        "AccountName":                    user_sam,
        "UserID":                         user_sid,
        "Category":                       "Executing Pipeline",
        "Payload":                        payload,
        "ActivityID":                     activity_id or bus.new_guid(),
        "ContextInfo_Severity":           "Informational",
        "ContextInfo_Host Name":          host_name,
        "ContextInfo_Host Version":       "5.1.19041.1",
        "ContextInfo_Host ID":            runspace_id,
        "ContextInfo_Host Application":   host_application,
        "ContextInfo_Engine Version":     "5.1.19041.1",
        "ContextInfo_Runspace ID":        runspace_id,
        "ContextInfo_Pipeline ID":        pipeline_id,
        "ContextInfo_Command Name":       command_name,
        "ContextInfo_Command Type":       "Cmdlet",
        "ContextInfo_Script Name":        "",
        "ContextInfo_Command Path":       "",
        "ContextInfo_Sequence Number":    pipeline_id,
        "ContextInfo_User":               f"{DOMAIN_NETBIOS}\\{user_sam}",
        "ContextInfo_Connected User":     "",
        "ContextInfo_Shell ID":           "Microsoft.PowerShell",
    }
    return _ps_envelope(
        event_id    = "4103",
        computer    = computer,
        user_sid    = user_sid,
        utc_dt      = utc_dt,
        bus         = bus,
        event_data  = event_data,
        level       = 4,
        activity_id = activity_id,
        process_id  = process_id,
    )


# ══════════════════════════════════════════════════════════════════════════════
# TASK SCHEDULER OPERATIONAL LOG — EID 106 / 200 / 201 / 4698
# ══════════════════════════════════════════════════════════════════════════════

_TASK_TASK_NAMES: Dict[str, str] = {
    "106": "Task Registration",
    "200": "Action started",
    "201": "Action completed",
    "4698": "Other Object Access Events",
}

def _task_envelope(
    event_id:   str,
    computer:   str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: Dict[str, Any],
    channel:    str = "Microsoft-Windows-TaskScheduler/Operational",
    provider:   str = "Microsoft-Windows-TaskScheduler",
    provider_guid: str = "{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}",
    task:       str = "",
) -> Dict[str, Any]:
    """
    Winlogbeat envelope for Task Scheduler Operational events.
    Provider GUID: {DE7B24EA-73C8-4A09-985D-5BDADCFA9017}
    Verified from NXLog live JSON (2022-02-27) and palantir/windows-event-forwarding.
    """
    ts_str     = utc_now_str(utc_dt)
    ingest_dt  = utc_dt + timedelta(seconds=bus._rng.randint(1, 4))
    record_key = f"TaskScheduler:{computer}"
    rid        = bus.next_record_id(record_key)

    return {
        "@timestamp": ts_str,
        "@metadata": {"beat": "winlogbeat", "type": "_doc", "version": "9.4.2"},
        "log":   {"level": "information"},
        "host":  {"name": computer},
        "agent": {
            "type":         "winlogbeat",
            "version":      "9.4.2",
            "name":         computer.split(".")[0],
            "id":           stable_agent_id(computer),
            "ephemeral_id": stable_ephemeral_id(computer, bus._sim_seed),
        },
        "ecs":   {"version": "8.0.0"},
        "event": {
            "code":     event_id,
            "kind":     "event",
            "provider": provider,
            "action":   task or _TASK_TASK_NAMES.get(event_id, ""),
            "created":  utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       channel,
            "provider_name": provider,
            "provider_guid": provider_guid,
            "computer_name": computer,
            "task":          task or _TASK_TASK_NAMES.get(event_id, ""),
            "opcode":        "Info",
            "record_id":     rid,
            "version":       0,
            "keywords":      [],
            "event_data":    event_data,
        },
    }


def gen_task_106(
    task_name:    str,
    user_context: str,
    computer:     str,
    utc_dt:       datetime,
    bus:          EventBus,
) -> Dict[str, Any]:
    """
    Task Scheduler EID 106 — Task Registered.
    Field names verified from NXLog live JSON (2022-02-27):
    TaskName and UserContext are the exact Data Name= values.
    """
    event_data = {
        "TaskName":    task_name,
        "UserContext": user_context,
    }
    return _task_envelope("106", computer, utc_dt, bus, event_data)


def gen_task_200(
    task_name:       str,
    action_name:     str,
    task_instance_id:str,
    computer:        str,
    utc_dt:          datetime,
    bus:             EventBus,
) -> Dict[str, Any]:
    """
    Task Scheduler EID 200 — Action Started.
    Field names verified from Splunk Security Content Dataset f8c777f8 (2024-03-04):
    TaskName, ActionName, TaskInstanceId, EnginePID are the exact Data Name= values.
    """
    event_data = {
        "TaskName":       task_name,
        "ActionName":     action_name,
        "TaskInstanceId": task_instance_id,
        "EnginePID":      str(bus._rng.randint(400, 2000)),
    }
    return _task_envelope("200", computer, utc_dt, bus, event_data)


def gen_task_201(
    task_name:       str,
    action_name:     str,
    task_instance_id:str,
    result_code:     str,
    computer:        str,
    utc_dt:          datetime,
    bus:             EventBus,
) -> Dict[str, Any]:
    """Task Scheduler EID 201 — Action Completed."""
    event_data = {
        "TaskName":       task_name,
        "ActionName":     action_name,
        "TaskInstanceId": task_instance_id,
        "ResultCode":     result_code,
    }
    return _task_envelope("201", computer, utc_dt, bus, event_data)


def gen_task_4698(
    actor_session:  LogonSession,
    task_name:      str,
    task_content:   str,
    utc_dt:         datetime,
    bus:            EventBus,
) -> Dict[str, Any]:
    """
    Security Log EID 4698 — Scheduled Task Created.
    Uses Security channel and provider.
    Field names verified from Velociraptor ScheduledTasks artifact:
    SubjectUserName, TaskName, TaskContent are exact Data Name= values.
    """
    event_data = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TaskName":          task_name,
        "TaskContent":       task_content,
    }
    # EID 4698 goes to Security channel not TaskScheduler
    ev = _task_envelope(
        event_id       = "4698",
        computer       = actor_session.computer,
        utc_dt         = utc_dt,
        bus            = bus,
        event_data     = event_data,
        channel        = "Security",
        provider       = "Microsoft-Windows-Security-Auditing",
        provider_guid  = "{54849625-5478-4994-A5BA-3E3B0328C30D}",
    )
    ev["winlog"]["keywords"] = ["Audit Success"]
    ev["event"]["outcome"]   = "success"
    return ev


def build_task_content_xml(
    task_name:   str,
    command:     str,
    arguments:   str,
    trigger:     str = "PT1H",      # ISO 8601 duration — every 1 hour
    run_as_user: str = "SYSTEM",
    logon_type:  str = "InteractiveToken",
) -> str:
    """
    Builds a realistic Windows Task XML blob for the TaskContent field of 4698.
    Schema matches Windows Task Scheduler XML format.
    """
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-06T00:00:00</Date>
    <Author>{DOMAIN_NETBIOS}\\{run_as_user}</Author>
    <Description>Automated task: {task_name}</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition><Interval>{trigger}</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <StartBoundary>2025-01-06T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{run_as_user}</UserId>
      <LogonType>{logon_type}</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>"""