"""
sysmon_generator.py — Generates Sysmon Operational log events in
Winlogbeat 9.x Kafka JSON format.

All ProcessGuids and LogonIds are sourced from the shared EventBus so
that Sysmon EID 1 events reference the same session as their paired
Security 4624 event. Parent-child process chains use stable ProcessGuids
(not PIDs) to avoid the PID-reuse ambiguity documented in our field catalog.

Event IDs covered:
  EID 1  — Process Creation
  EID 3  — Network Connection
  EID 7  — Image Loaded (DLL)
  EID 8  — CreateRemoteThread (Code Injection)
  EID 10 — Process Access (LSASS etc.)
  EID 11 — File Creation
  EID 22 — DNS Query (per-process)
  EID 23 — File Delete Archived
"""

from __future__ import annotations
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus, LogonSession, ProcessRecord, sha256_hash, md5_hash, imphash, _new_guid, stable_agent_id, stable_ephemeral_id
from core.time_engine import utc_now_str, jitter_ts
from config.company import DOMAIN_NETBIOS, DOMAIN_FQDN


# ── Sysmon task names from Sysmon manifest (verified) ────────────────────────
_SYSMON_TASKS: Dict[str, str] = {
    '1':  'Process Create (rule: ProcessCreate)',
    '2':  'File creation time changed (rule: FileCreateTime)',
    '3':  'Network connection detected (rule: NetworkConnect)',
    '4':  'Sysmon service state changed',
    '5':  'Process terminated (rule: ProcessTerminate)',
    '6':  'Driver loaded (rule: DriverLoad)',
    '7':  'Image loaded (rule: ImageLoad)',
    '8':  'CreateRemoteThread detected (rule: CreateRemoteThread)',
    '9':  'RawAccessRead detected (rule: RawAccessRead)',
    '10': 'Process accessed (rule: ProcessAccess)',
    '11': 'File created (rule: FileCreate)',
    '12': 'Registry object added or deleted (rule: RegistryEvent)',
    '13': 'Registry value set (rule: RegistryEvent)',
    '14': 'Registry object renamed (rule: RegistryEvent)',
    '15': 'File stream created (rule: FileCreateStreamHash)',
    '17': 'Pipe Created (rule: PipeEvent)',
    '18': 'Pipe Connected (rule: PipeEvent)',
    '22': 'Dns query (rule: DnsQuery)',
    '23': 'File Delete archived (rule: FileDelete)',
}

# ── Sysmon envelope ───────────────────────────────────────────────────────────
def _sysmon_envelope(
    event_id:   str,
    computer:   str,
    utc_dt:     datetime,
    bus:        EventBus,
    event_data: Dict[str, Any],
    rule_name:  str = "-",
) -> Dict[str, Any]:
    """
    Builds the Winlogbeat Kafka envelope for Sysmon events.
    Provider GUID verified: {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
    """
    ts_str     = utc_now_str(utc_dt)
    ingest_dt  = utc_dt + timedelta(seconds=bus._rng.randint(1, 6))
    record_key = f"Sysmon:{computer}"
    rid        = bus.next_record_id(record_key)

    return {
        "@timestamp": ts_str,
        "@metadata": {
            "beat":    "winlogbeat",
            "type":    "_doc",
            "version": "9.4.2",
        },
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
            "version":       5,
            "keywords":      [],
            "event_data":    event_data,
        },
    }


def _hashes(image: str) -> str:
    """Produces a Sysmon-format hash string from a file path."""
    sha = sha256_hash(image)
    md5 = md5_hash(image)
    imp = imphash(image)
    return f"SHA256={sha},MD5={md5},IMPHASH={imp}"


def _utc_time_str(dt: datetime) -> str:
    """Sysmon UtcTime format: '2024-04-28 22:08:22.025'"""
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


# ── EID 1 — Process Creation ──────────────────────────────────────────────────
def gen_eid1(
    proc:       ProcessRecord,
    user_domain: str,
    utc_dt:     datetime,
    bus:        EventBus,
    rule_name:  str = "-",
) -> Dict[str, Any]:
    """
    Sysmon EID 1 Process Creation.
    Verified field names from Splunk Security Content Dataset b375f4d1
    (2020-10-08) and ultimatewindowssecurity.com Event 90001 (2024-04-28).
    OriginalFileName derived from image basename — same as Image unless masquerading.
    """
    image_basename = os.path.basename(proc.image) if proc.image else "unknown.exe"
    user_str       = f"{user_domain}\\{proc.user}" if "\\" not in proc.user else proc.user

    event_data = {
        "RuleName":          rule_name,
        "UtcTime":           _utc_time_str(utc_dt),
        "ProcessGuid":       proc.process_guid,
        "ProcessId":         str(proc.process_id),
        "Image":             proc.image,
        "FileVersion":       _pe_version(proc.image),
        "Description":       _pe_description(proc.image),
        "Product":           _pe_product(proc.image),
        "Company":           _pe_company(proc.image),
        "OriginalFileName":  image_basename,      # same as Image — not masquerading
        "CommandLine":       proc.command_line,
        "CurrentDirectory":  _working_dir(proc.image),
        "User":              user_str,
        "LogonGuid":         bus.new_guid(),
        "LogonId":           proc.logon_id,
        "TerminalSessionId": "1",
        "IntegrityLevel":    proc.integrity_level,
        "Hashes":            _hashes(proc.image),
        "ParentProcessGuid": proc.parent_process_guid,
        "ParentProcessId":   str(
            (bus.get_process(proc.parent_process_guid).process_id
             if bus.get_process(proc.parent_process_guid) else bus.new_pid())
        ),
        "ParentImage":       proc.parent_image,
        "ParentCommandLine": (
            bus.get_process(proc.parent_process_guid).command_line
            if bus.get_process(proc.parent_process_guid) else proc.parent_image
        ),
        "ParentUser":        user_str,
    }
    return _sysmon_envelope("1", proc.computer, utc_dt, bus, event_data, rule_name)


# ── EID 3 — Network Connection ────────────────────────────────────────────────
def gen_eid3(
    proc:          ProcessRecord,
    user_domain:   str,
    dest_ip:       str,
    dest_port:     int,
    dest_hostname: str,
    utc_dt:        datetime,
    bus:           EventBus,
    protocol:      str = "tcp",
    initiated:     bool = True,
    src_ip:        str = "",
) -> Dict[str, Any]:
    """
    Sysmon EID 3 Network Connection.
    Verified field names from ultimatewindowssecurity.com Event 90003
    (lab capture) and Splunk Security Content Dataset 01d84dff (2022-09-15).
    """
    src_port    = bus.new_src_port()
    dest_is_ext = not (
        dest_ip.startswith("10.") or
        dest_ip.startswith("172.16.") or
        dest_ip.startswith("192.168.")
    )
    user_str = f"{user_domain}\\{proc.user}" if "\\" not in proc.user else proc.user

    event_data = {
        "RuleName":            "-",
        "UtcTime":             _utc_time_str(utc_dt),
        "ProcessGuid":         proc.process_guid,
        "ProcessId":           str(proc.process_id),
        "Image":               proc.image,
        "User":                user_str,
        "Protocol":            protocol,
        "Initiated":           "true" if initiated else "false",
        "SourceIsIpv6":        "false",
        "SourceIp":            (src_ip if src_ip else
                               # Derive from active session for this user
                               next((s.src_ip for s in bus._sessions.values()
                                     if s.samaccountname == proc.user and s.active),
                                    proc.computer.split(".")[0])),
        "SourceHostname":      proc.computer,
        "SourcePort":          str(src_port),
        "SourcePortName":      "",
        "DestinationIsIpv6":   "false",
        "DestinationIp":       dest_ip,
        "DestinationHostname": dest_hostname,
        "DestinationPort":     str(dest_port),
        "DestinationPortName": _port_name(dest_port),
    }
    return _sysmon_envelope("3", proc.computer, utc_dt, bus, event_data)


# ── EID 7 — Image Loaded ──────────────────────────────────────────────────────
def gen_eid7(
    proc:         ProcessRecord,
    dll_path:     str,
    user_domain:  str,
    utc_dt:       datetime,
    bus:          EventBus,
    signed:       bool = True,
    signature:    str = "Microsoft Windows",
    sig_status:   str = "Valid",
) -> Dict[str, Any]:
    """
    Sysmon EID 7 Image Loaded.
    Verified field names from ultimatewindowssecurity.com Event 90007
    (2017-04-28) and Splunk Security Content Dataset 45512fa5 (2023-09-12).
    """
    dll_basename = os.path.basename(dll_path) if dll_path else "unknown.dll"
    user_str     = f"{user_domain}\\{proc.user}" if "\\" not in proc.user else proc.user

    event_data = {
        "RuleName":         "-",
        "UtcTime":          _utc_time_str(utc_dt),
        "ProcessGuid":      proc.process_guid,
        "ProcessId":        str(proc.process_id),
        "Image":            proc.image,
        "ImageLoaded":      dll_path,
        "FileVersion":      _pe_version(dll_path),
        "Description":      _pe_description(dll_path),
        "Product":          _pe_product(dll_path),
        "Company":          _pe_company(dll_path),
        "OriginalFileName": dll_basename,
        "Hashes":           _hashes(dll_path),
        "Signed":           "true" if signed else "false",
        "Signature":        signature if signed else "",
        "SignatureStatus":  sig_status if signed else "Unsigned",
        "User":             user_str,
    }
    return _sysmon_envelope("7", proc.computer, utc_dt, bus, event_data)


# ── EID 8 — CreateRemoteThread ────────────────────────────────────────────────
def gen_eid8(
    source_proc:   ProcessRecord,
    target_proc:   ProcessRecord,
    user_domain:   str,
    utc_dt:        datetime,
    bus:           EventBus,
    start_address: str = "",
    start_module:  str = "",
    start_function:str = "",
) -> Dict[str, Any]:
    """
    Sysmon EID 8 CreateRemoteThread — code injection.
    Verified field names from Splunk Security Content Dataset df7a786c
    (2022-10-27 live XML).
    """
    if not start_address:
        rnd = bus._rng.randint(0x00007FFF00000000, 0x00007FFFFFFFFFFF)
        start_address = hex(rnd)

    src_user = f"{user_domain}\\{source_proc.user}" if "\\" not in source_proc.user else source_proc.user
    tgt_user = f"{user_domain}\\{target_proc.user}" if "\\" not in target_proc.user else target_proc.user

    event_data = {
        "RuleName":         "-",
        "UtcTime":          _utc_time_str(utc_dt),
        "SourceProcessGuid":source_proc.process_guid,
        "SourceProcessId":  str(source_proc.process_id),
        "SourceImage":      source_proc.image,
        "TargetProcessGuid":target_proc.process_guid,
        "TargetProcessId":  str(target_proc.process_id),
        "TargetImage":      target_proc.image,
        "NewThreadId":      str(bus._rng.randint(1000, 9999)),
        "StartAddress":     start_address,
        "StartModule":      start_module,
        "StartFunction":    start_function,
        "SourceUser":       src_user,
        "TargetUser":       tgt_user,
    }
    return _sysmon_envelope("8", source_proc.computer, utc_dt, bus, event_data)


# ── EID 10 — Process Access ───────────────────────────────────────────────────
def gen_eid10(
    source_proc:    ProcessRecord,
    target_proc:    ProcessRecord,
    user_domain:    str,
    utc_dt:         datetime,
    bus:            EventBus,
    granted_access: str = "0x1400",
    call_trace:     str = "",
) -> Dict[str, Any]:
    """
    Sysmon EID 10 Process Access.
    GrantedAccess values from TrustedSec/SysmonCommunityGuide and
    Splunk LSASS hunting blog (confirmed field names from Dataset 659cd5a8).
    Normal access mask 0x1400 = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED
    (benign — used by EDR and AV). Credential dumping = 0x1fffff.
    """
    if not call_trace:
        call_trace = (
            f"C:\\Windows\\SYSTEM32\\ntdll.dll+0x{bus._rng.randint(0xa000, 0xffff):x}|"
            f"C:\\Windows\\system32\\KERNELBASE.dll+0x{bus._rng.randint(0x1000, 0x9fff):x}|"
            f"{source_proc.image}+0x{bus._rng.randint(0x1000, 0x9fff):x}"
        )

    src_user = f"{user_domain}\\{source_proc.user}" if "\\" not in source_proc.user else source_proc.user
    tgt_user = f"{user_domain}\\{target_proc.user}" if "\\" not in target_proc.user else target_proc.user

    event_data = {
        "RuleName":          "-",
        "UtcTime":           _utc_time_str(utc_dt),
        "SourceProcessGUID": source_proc.process_guid,
        "SourceProcessId":   str(source_proc.process_id),
        "SourceThreadId":    str(bus._rng.randint(1000, 9999)),
        "SourceImage":       source_proc.image,
        "TargetProcessGUID": target_proc.process_guid,
        "TargetProcessId":   str(target_proc.process_id),
        "TargetImage":       target_proc.image,
        "GrantedAccess":     granted_access,
        "CallTrace":         call_trace,
        "SourceUser":        src_user,
        "TargetUser":        tgt_user,
    }
    return _sysmon_envelope("10", source_proc.computer, utc_dt, bus, event_data)


# ── EID 11 — File Creation ────────────────────────────────────────────────────
def gen_eid11(
    proc:         ProcessRecord,
    target_file:  str,
    user_domain:  str,
    utc_dt:       datetime,
    bus:          EventBus,
) -> Dict[str, Any]:
    """
    Sysmon EID 11 File Creation.
    Verified field list from BHIS Sysmon breakdown and defensiveorigins.com.
    """
    user_str = f"{user_domain}\\{proc.user}" if "\\" not in proc.user else proc.user
    event_data = {
        "RuleName":         "-",
        "UtcTime":          _utc_time_str(utc_dt),
        "ProcessGuid":      proc.process_guid,
        "ProcessId":        str(proc.process_id),
        "Image":            proc.image,
        "TargetFilename":   target_file,
        "CreationUtcTime":  _utc_time_str(utc_dt),
        "Hashes":           _hashes(target_file),
        "User":             user_str,
    }
    return _sysmon_envelope("11", proc.computer, utc_dt, bus, event_data)


# ── EID 22 — DNS Query ────────────────────────────────────────────────────────
def gen_eid22(
    proc:          ProcessRecord,
    query_name:    str,
    query_results: str,
    user_domain:   str,
    utc_dt:        datetime,
    bus:           EventBus,
    query_status:  str = "0",
) -> Dict[str, Any]:
    """
    Sysmon EID 22 DNS Query.
    TrustedSec SysmonCommunityGuide confirms: generated when process calls
    Windows DnsQuery_* API (dnsapi.dll). Not generated for raw socket DNS.
    Field names verified from gravwell.io Sysmon Part 1.
    """
    user_str = f"{user_domain}\\{proc.user}" if "\\" not in proc.user else proc.user
    event_data = {
        "RuleName":     "-",
        "UtcTime":      _utc_time_str(utc_dt),
        "ProcessGuid":  proc.process_guid,
        "ProcessId":    str(proc.process_id),
        "QueryName":    query_name,
        "QueryStatus":  query_status,
        "QueryResults": query_results,
        "Image":        proc.image,
        "User":         user_str,
    }
    return _sysmon_envelope("22", proc.computer, utc_dt, bus, event_data)


# ── EID 23 — File Delete Archived ────────────────────────────────────────────
def gen_eid23(
    proc:         ProcessRecord,
    target_file:  str,
    user_domain:  str,
    utc_dt:       datetime,
    bus:          EventBus,
    is_executable: bool = False,
) -> Dict[str, Any]:
    """Sysmon EID 23 File Delete (archived for forensics)."""
    user_str = f"{user_domain}\\{proc.user}" if "\\" not in proc.user else proc.user
    event_data = {
        "RuleName":      "-",
        "UtcTime":       _utc_time_str(utc_dt),
        "ProcessGuid":   proc.process_guid,
        "ProcessId":     str(proc.process_id),
        "Image":         proc.image,
        "TargetFilename":target_file,
        "Hashes":        _hashes(target_file),
        "IsExecutable":  "true" if is_executable else "false",
        "Archived":      "true",
        "User":          user_str,
    }
    return _sysmon_envelope("23", proc.computer, utc_dt, bus, event_data)


# ── PE metadata helpers ───────────────────────────────────────────────────────
_PE_META: Dict[str, Dict[str, str]] = {
    "cmd.exe":         {"desc": "Windows Command Processor",      "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "powershell.exe":  {"desc": "Windows PowerShell",             "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "powershell_ise.exe":{"desc":"Windows PowerShell ISE",        "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "mstsc.exe":       {"desc": "Remote Desktop Connection",      "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "mmc.exe":         {"desc": "Microsoft Management Console",   "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "svchost.exe":     {"desc": "Host Process for Windows Services","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation",  "ver": "10.0.19041.1"},
    "lsass.exe":       {"desc": "Local Security Authority Process","product":"Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "explorer.exe":    {"desc": "Windows Explorer",               "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "taskhostw.exe":   {"desc": "Host Process for Windows Tasks", "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "chrome.exe":      {"desc": "Google Chrome",                  "product": "Google Chrome",                        "company": "Google LLC",            "ver": "120.0.6099.130"},
    "EXCEL.EXE":       {"desc": "Microsoft Excel",                "product": "Microsoft Office",                     "company": "Microsoft Corporation", "ver": "16.0.17726.20078"},
    "WINWORD.EXE":     {"desc": "Microsoft Word",                 "product": "Microsoft Office",                     "company": "Microsoft Corporation", "ver": "16.0.17726.20078"},
    "OUTLOOK.EXE":     {"desc": "Microsoft Outlook",              "product": "Microsoft Office",                     "company": "Microsoft Corporation", "ver": "16.0.17726.20078"},
    "POWERPNT.EXE":    {"desc": "Microsoft PowerPoint",           "product": "Microsoft Office",                     "company": "Microsoft Corporation", "ver": "16.0.17726.20078"},
    "Teams.exe":       {"desc": "Microsoft Teams",                "product": "Microsoft Teams",                      "company": "Microsoft Corporation", "ver": "1.7.0.22134"},
    "devenv.exe":      {"desc": "Microsoft Visual Studio",        "product": "Microsoft Visual Studio",              "company": "Microsoft Corporation", "ver": "17.8.34330.188"},
    "code.exe":        {"desc": "Visual Studio Code",             "product": "Visual Studio Code",                   "company": "Microsoft Corporation", "ver": "1.85.2"},
    "python.exe":      {"desc": "Python",                         "product": "Python",                               "company": "Python Software Foundation","ver": "3.11.7"},
    "node.exe":        {"desc": "Node.js: Server-side JavaScript","product": "Node.js",                              "company": "Node.js Foundation",    "ver": "20.11.0"},
    "git.exe":         {"desc": "Git",                            "product": "Git",                                  "company": "The Git Development Community","ver": "2.43.0"},
    "putty.exe":       {"desc": "PuTTY SSH, Telnet and Rlogin Client","product":"PuTTY suite",                      "company": "Simon Tatham",          "ver": "0.80.0"},
    "mshta.exe":       {"desc": "Microsoft (R) HTML Application host","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","ver":"11.0.19041.1"},
    "wscript.exe":     {"desc": "Microsoft (R) Windows Based Script Host","product":"Microsoft® Windows® Operating System","company":"Microsoft Corporation","ver":"5.812.10240.16384"},
    "regsvr32.exe":    {"desc": "Microsoft(C) Register Server",  "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "rundll32.exe":    {"desc": "Windows host process (Rundll32)","product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "certutil.exe":    {"desc": "CertUtil",                       "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "bitsadmin.exe":   {"desc": "BITS administration utility",   "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "7.8.19041.1"},
    "wmic.exe":        {"desc": "WMI command-line interface",     "product": "Microsoft® Windows® Operating System", "company": "Microsoft Corporation", "ver": "10.0.19041.1"},
    "psexec.exe":      {"desc": "Execute processes remotely",     "product": "Sysinternals PsExec",                 "company": "Sysinternals",          "ver": "2.43"},
}


def _pe_field(image: str, field: str, default: str) -> str:
    basename = os.path.basename(image) if image else ""
    meta     = _PE_META.get(basename, {})
    return meta.get(field, default)


def _pe_version(image: str)     -> str: return _pe_field(image, "ver",  "")
def _pe_description(image: str) -> str: return _pe_field(image, "desc", "")
def _pe_product(image: str)     -> str: return _pe_field(image, "product", "")
def _pe_company(image: str)     -> str: return _pe_field(image, "company", "")


def _working_dir(image: str) -> str:
    """Returns a realistic CurrentDirectory for a given executable."""
    _DIRS = {
        "powershell.exe":   "C:\\Windows\\System32\\",
        "cmd.exe":          "C:\\Windows\\System32\\",
        "mstsc.exe":        "C:\\Windows\\System32\\",
        "mmc.exe":          "C:\\Windows\\System32\\",
        "chrome.exe":       "C:\\Program Files\\Google\\Chrome\\Application\\",
        "EXCEL.EXE":        "C:\\Program Files\\Microsoft Office\\root\\Office16\\",
        "WINWORD.EXE":      "C:\\Program Files\\Microsoft Office\\root\\Office16\\",
        "OUTLOOK.EXE":      "C:\\Program Files\\Microsoft Office\\root\\Office16\\",
        "Teams.exe":        "C:\\Users\\Default\\AppData\\Local\\Microsoft\\Teams\\current\\",
        "code.exe":         "C:\\Program Files\\Microsoft VS Code\\",
        "devenv.exe":       "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\Common7\\IDE\\",
        "python.exe":       "C:\\Python311\\",
        "node.exe":         "C:\\Program Files\\nodejs\\",
        "git.exe":          "C:\\Program Files\\Git\\cmd\\",
    }
    basename = os.path.basename(image) if image else ""
    return _DIRS.get(basename, "C:\\Windows\\System32\\")


def _port_name(port: int) -> str:
    """Returns well-known port name for common destination ports."""
    _NAMES = {
        80: "http", 443: "https", 445: "microsoft-ds",
        3389: "ms-wbt-server", 22: "ssh", 25: "smtp",
        389: "ldap", 636: "ldaps", 88: "kerberos",
        135: "epmap", 139: "netbios-ssn", 53: "domain",
        3306: "mysql", 1433: "ms-sql-s", 5985: "wsman",
        5986: "wsmans",
    }
    return _NAMES.get(port, "")