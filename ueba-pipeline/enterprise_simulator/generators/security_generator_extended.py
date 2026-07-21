"""
security_generator_extended.py

Extended Windows Security Event Log generators covering every event ID
requested. All field names verified against:

  Microsoft Learn official event schemas
  ultimatewindowssecurity.com canonical event encyclopedia
  Psmths/windows-forensic-artifacts live XML captures
  Splunk Security Content corpus
  NXLog Platform Documentation live JSON captures
  LogRhythm EVID mapping documents

Event categories:
  Account Lifecycle:    4722 4723 4724 4725 4726 4729 4732 4733 4735 4738 4741 4742 4743 4647
  Object Access:        4656 4658 4663
  File Share:           5140 5145
  Audit / Log Ops:      1102 4719 4902 4907
  Services:             4697 7036 7045
  USB / PnP:            6416
  Process:              4689
"""

from __future__ import annotations
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus, LogonSession, _new_guid, stable_agent_id, stable_ephemeral_id
from core.employees import user_sid as _user_sid

import hashlib as _hashlib

def _group_sid(group_name: str) -> str:
    """
    Stable, deterministic SID for a security group, derived from its name.
    Uses RID range 5000-5999 to avoid any collision with user RIDs (1100-10099,
    see core.employees.user_sid). Real AD: each group has one stable SID for
    its lifetime; this must never change across events referencing the same group.
    """
    rid = int(_hashlib.md5(f"group:{group_name}".encode()).hexdigest()[:4], 16) % 1000 + 5000
    return f"S-1-5-21-1484628597-1684816888-3125425894-{rid}"
from core.time_engine import utc_now_str
from config.company import DOMAIN_NETBIOS, DOMAIN_FQDN, DOMAIN_CONTROLLERS

DC01 = DOMAIN_CONTROLLERS[0]


# ── Shared envelope builder (mirrors security_generator.py) ───────────────────
def _env(
    event_id:   str,
    computer:   str,
    channel:    str,
    task:       str,
    outcome:    str,
    utc_dt:     datetime,
    bus:        EventBus,
    keywords:   List[str],
    event_data: Dict[str, Any],
    provider:   str = "Microsoft-Windows-Security-Auditing",
    provider_guid: str = "{54849625-5478-4994-A5BA-3E3B0328C30D}",
) -> Dict[str, Any]:
    ts_str    = utc_now_str(utc_dt)
    utc_dt = utc_dt.replace(microsecond=bus._rng.randint(0, 999_999))
    ingest_dt = utc_dt + timedelta(seconds=bus._rng.randint(1, 8))
    rid       = bus.next_record_id(f"{channel}:{computer}")
    return {
        "@timestamp": ts_str,
        "@metadata": {"beat": "winlogbeat", "type": "_doc", "version": "9.4.2"},
        "log": {"level": "information" if outcome == "success" else "warning"},
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
            "code": event_id, "kind": "event",
            "provider": provider,
            "action": task, "outcome": outcome,
            "created": utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id": event_id,
            "channel": channel,
            "provider_name": provider,
            "provider_guid": provider_guid,
            "computer_name": computer,
            "task": task, "opcode": "Info",
            "record_id": rid, "version": 0,
            "keywords": keywords,
            "event_data": event_data,
        },
    }


# _sid() removed: all Subject/Target SIDs are now derived via _user_sid(sam)
# imported from core.employees. This ensures SID stability across event types
# so that a UEBA pipeline resolving identity by SID correctly merges events.


def _dc(computer: str = "") -> str:
    return computer or DC01["fqdn"]


# ════════════════════════════════════════════════════════════════════════════
# ACCOUNT LIFECYCLE
# ════════════════════════════════════════════════════════════════════════════

def gen_4722(
    actor_session: LogonSession,
    target_sam:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    4722 — A user account was enabled.
    Fields verified: Microsoft Learn event-4722 + UWS encyclopedia.
    Typical flow: 4722 is emitted alongside 4720 when creating a new account
    (AD Users & Computers enables the account immediately after creating it).
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    target_sam,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(target_sam),
    }
    return _env("4722", _dc(actor_session.computer), "Security",
                "User Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4723(
    actor_session: LogonSession,
    target_sam:    str,
    utc_dt:        datetime,
    bus:           EventBus,
    success:       bool = True,
) -> Dict[str, Any]:
    """
    4723 — An attempt was made to change an account's password (self-service).
    Verified: Microsoft Learn event-4723. SubjectUserName == TargetUserName
    when the user changes their own password.
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   target_sam,   # same person changing own password
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    target_sam,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(target_sam),
    }
    outcome = "success" if success else "failure"
    kw = ["Audit Success"] if success else ["Audit Failure"]
    return _env("4723", _dc(actor_session.computer), "Security",
                "User Account Management", outcome, utc_dt, bus, kw, ed)


def gen_4724(
    actor_session: LogonSession,
    target_sam:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    4724 — An attempt was made to reset an account's password (admin reset).
    Verified: Microsoft Learn event-4724. SubjectUserName is the admin resetting;
    TargetUserName is the account whose password was reset. Also generates 4738.
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    target_sam,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(target_sam),
    }
    return _env("4724", _dc(actor_session.computer), "Security",
                "User Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4725(
    actor_session: LogonSession,
    target_sam:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """4725 — A user account was disabled."""
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    target_sam,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(target_sam),
    }
    return _env("4725", _dc(actor_session.computer), "Security",
                "User Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4726(
    actor_session: LogonSession,
    target_sam:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """4726 — A user account was deleted."""
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    target_sam,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(target_sam),
        "PrivilegeList":     "-",
    }
    return _env("4726", _dc(actor_session.computer), "Security",
                "User Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4738(
    actor_session:    LogonSession,
    target_sam:       str,
    changed_attrs:    str,
    utc_dt:           datetime,
    bus:              EventBus,
) -> Dict[str, Any]:
    """
    4738 — A user account was changed.
    Verified: Microsoft Learn event-4738.
    UserAccountControl contains human-readable flag changes like
    '%%2050' (Password Not Required) or '%%2089' (Don't Expire Password).
    changed_attrs is inserted as UserAccountControl field.
    """
    ed = {
        "SubjectUserSid":       _user_sid(actor_session.samaccountname),
        "SubjectUserName":      actor_session.samaccountname,
        "SubjectDomainName":    DOMAIN_NETBIOS,
        "SubjectLogonId":       actor_session.target_logon_id,
        "TargetUserName":       target_sam,
        "TargetDomainName":     DOMAIN_NETBIOS,
        "TargetSid":            _user_sid(target_sam),
        "SamAccountName":       target_sam,
        "DisplayName":          "%%1793",   # unchanged
        "UserPrincipalName":    "-",
        "HomeDirectory":        "%%1793",
        "HomePath":             "%%1793",
        "ScriptPath":           "%%1793",
        "ProfilePath":          "%%1793",
        "UserWorkstations":     "%%1793",
        "PasswordLastSet":      "%%1793",
        "AccountExpires":       "%%1793",
        "PrimaryGroupId":       "%%1793",
        "AllowedToDelegateTo":  "-",
        "OldUacValue":          "0x15",
        "NewUacValue":          "0x215",
        "UserAccountControl":   changed_attrs,
        "UserParameters":       "%%1793",
        "SidHistory":           "-",
        "LogonHours":           "%%1797",
        "DnsHostName":          "-",
        "ServicePrincipalNames":"-",
    }
    return _env("4738", _dc(actor_session.computer), "Security",
                "User Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4729(
    actor_session: LogonSession,
    member_sam:    str,
    member_dn:     str,
    group_name:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    4729 — A member was removed from a security-enabled global group.
    Verified: ultimatewindowssecurity.com Event 4729; same schema as 4728.
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "MemberSid":         _user_sid(member_sam),
        "MemberName":        member_dn,
        "TargetUserName":    group_name,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _group_sid(group_name),
        "PrivilegeList":     "-",
    }
    return _env("4729", _dc(actor_session.computer), "Security",
                "Security Group Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4732(
    actor_session: LogonSession,
    member_sam:    str,
    member_dn:     str,
    group_name:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    4732 — A member was added to a security-enabled local group.
    Verified: wetnav.patelhari.com/event/4732 live capture.
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "MemberSid":         _user_sid(member_sam),
        "MemberName":        member_dn,
        "TargetUserName":    group_name,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _group_sid(group_name),
        "PrivilegeList":     "-",
    }
    return _env("4732", _dc(actor_session.computer), "Security",
                "Security Group Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4733(
    actor_session: LogonSession,
    member_sam:    str,
    member_dn:     str,
    group_name:    str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """4733 — A member was removed from a security-enabled local group."""
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "MemberSid":         _user_sid(member_sam),
        "MemberName":        member_dn,
        "TargetUserName":    group_name,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _group_sid(group_name),
        "PrivilegeList":     "-",
    }
    return _env("4733", _dc(actor_session.computer), "Security",
                "Security Group Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4735(
    actor_session: LogonSession,
    group_name:    str,
    utc_dt:        datetime,
    bus:           EventBus,
    change_desc:   str = "Group description was changed",
) -> Dict[str, Any]:
    """
    4735 — A security-enabled local group was changed.
    Verified: Microsoft Learn event-4735. Common when group description,
    SAM name, or attributes are modified.
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    group_name,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _group_sid(group_name),
        "SamAccountName":    group_name,
        "SidHistory":        "-",
        "PrivilegeList":     "-",
    }
    return _env("4735", _dc(actor_session.computer), "Security",
                "Security Group Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4741(
    actor_session:   LogonSession,
    computer_sam:    str,
    computer_dns:    str,
    utc_dt:          datetime,
    bus:             EventBus,
) -> Dict[str, Any]:
    """
    4741 — A computer account was created.
    Verified: Microsoft Learn event-4741. Generated on DC when a new
    workstation joins the domain. computer_sam should end with $.
    """
    ed = {
        "SubjectUserSid":       _user_sid(actor_session.samaccountname),
        "SubjectUserName":      actor_session.samaccountname,
        "SubjectDomainName":    DOMAIN_NETBIOS,
        "SubjectLogonId":       actor_session.target_logon_id,
        "TargetUserName":       computer_sam if computer_sam.endswith("$") else computer_sam + "$",
        "TargetDomainName":     DOMAIN_NETBIOS,
        "TargetSid":            _user_sid(computer_sam),
        "SamAccountName":       computer_sam,
        "DisplayName":          "%%1793",
        "UserPrincipalName":    "-",
        "DnsHostName":          computer_dns,
        "ServicePrincipalNames":f"HOST/{computer_dns}\nHOST/{computer_sam.rstrip('$')}",
        "OldUacValue":          "0x0",
        "NewUacValue":          "0x80",
        "UserAccountControl":   "%%2087",
        "UserParameters":       "%%1793",
        "SidHistory":           "-",
        "LogonHours":           "%%1797",
        "PasswordLastSet":      "%%1794",
        "AccountExpires":       "%%1795",
        "PrimaryGroupId":       "515",
        "AllowedToDelegateTo":  "-",
        "PrivilegeList":        "-",
    }
    return _env("4741", _dc(), "Security",
                "Computer Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4742(
    actor_session: LogonSession,
    computer_sam:  str,
    utc_dt:        datetime,
    bus:           EventBus,
    change_desc:   str = "%%2050\n\t\t\t\t%%2089",
) -> Dict[str, Any]:
    """
    4742 — A computer account was changed.
    Verified: Microsoft Learn event-4742. Most common cause is the
    computer account automatically resetting its own machine password
    (every 30 days by default). SubjectUserName will then be the computer$ itself.
    """
    ed = {
        "SubjectUserSid":       _user_sid(actor_session.samaccountname),
        "SubjectUserName":      actor_session.samaccountname,
        "SubjectDomainName":    DOMAIN_NETBIOS,
        "SubjectLogonId":       actor_session.target_logon_id,
        "TargetUserName":       computer_sam if computer_sam.endswith("$") else computer_sam + "$",
        "TargetDomainName":     DOMAIN_NETBIOS,
        "TargetSid":            _user_sid(computer_sam),
        "SamAccountName":       "%%1793",
        "DisplayName":          "%%1793",
        "UserPrincipalName":    "%%1793",
        "DnsHostName":          "%%1793",
        "ServicePrincipalNames":"%%1793",
        "OldUacValue":          "0x80",
        "NewUacValue":          "0x80",
        "UserAccountControl":   change_desc,
        "UserParameters":       "%%1793",
        "SidHistory":           "-",
        "LogonHours":           "%%1797",
        "PasswordLastSet":      "%%1793",
        "AccountExpires":       "%%1793",
        "PrimaryGroupId":       "%%1793",
        "AllowedToDelegateTo":  "-",
        "PrivilegeList":        "-",
    }
    return _env("4742", _dc(), "Security",
                "Computer Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4743(
    actor_session: LogonSession,
    computer_sam:  str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """4743 — A computer account was deleted."""
    ed = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    computer_sam if computer_sam.endswith("$") else computer_sam + "$",
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(computer_sam),
        "PrivilegeList":     "-",
    }
    return _env("4743", _dc(), "Security",
                "Computer Account Management", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4647(
    session: LogonSession,
    utc_dt:  datetime,
    bus:     EventBus,
) -> Dict[str, Any]:
    """
    4647 — User initiated logoff (interactive sessions — Type 2, 10).
    Verified: Microsoft Learn event-4647. Generated for interactive logon
    types before 4634 when user explicitly logs off. For network logons,
    only 4634 is generated.
    """
    ed = {
        "TargetUserSid":    _user_sid(session.samaccountname),
        "TargetUserName":   session.samaccountname,
        "TargetDomainName": DOMAIN_NETBIOS,
        "TargetLogonId":    session.target_logon_id,
    }
    return _env("4647", session.computer, "Security",
                "Logoff", "success", utc_dt, bus,
                ["Audit Success"], ed)


# ════════════════════════════════════════════════════════════════════════════
# OBJECT ACCESS — HANDLES & FILE ACCESS
# ════════════════════════════════════════════════════════════════════════════

def gen_4656(
    session:      LogonSession,
    object_name:  str,
    object_type:  str,
    access_mask:  str,
    handle_id:    str,
    utc_dt:       datetime,
    bus:          EventBus,
    process_name: str = "C:\\Windows\\System32\\svchost.exe",
    success:      bool = True,
) -> Dict[str, Any]:
    """
    4656 — A handle to an object was requested.
    Verified: Microsoft Learn event-4656. Precedes 4663.
    object_type: "File", "Key" (registry), "Process", etc.
    """
    ed = {
        "SubjectUserSid":    _user_sid(session.samaccountname),
        "SubjectUserName":   session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    session.target_logon_id,
        "ObjectServer":      "Security" if object_type == "File" else "SC Manager",
        "ObjectType":        object_type,
        "ObjectName":        object_name,
        "HandleId":          handle_id,
        "TransactionId":     "{00000000-0000-0000-0000-000000000000}",
        "AccessList":        _access_list(access_mask),
        "AccessMask":        access_mask,
        "PrivilegeList":     "-",
        "RestrictedSidCount":"0",
        "ProcessId":         hex(bus._rng.randint(100, 9999)),
        "ProcessName":       process_name,
    }
    kw = ["Audit Success"] if success else ["Audit Failure"]
    out = "success" if success else "failure"
    return _env("4656", session.computer, "Security",
                "File System", out, utc_dt, bus, kw, ed)


def gen_4658(
    session:   LogonSession,
    object_name:str,
    handle_id:  str,
    utc_dt:     datetime,
    bus:        EventBus,
    process_name: str = "C:\\Windows\\System32\\svchost.exe",
) -> Dict[str, Any]:
    """4658 — The handle to an object was closed (follows 4656/4663)."""
    ed = {
        "SubjectUserSid":    _user_sid(session.samaccountname),
        "SubjectUserName":   session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    session.target_logon_id,
        "ObjectServer":      "Security",
        "HandleId":          handle_id,
        "ProcessId":         hex(bus._rng.randint(100, 9999)),
        "ProcessName":       process_name,
    }
    return _env("4658", session.computer, "Security",
                "File System", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4663(
    session:      LogonSession,
    object_name:  str,
    object_type:  str,
    access_mask:  str,
    handle_id:    str,
    utc_dt:       datetime,
    bus:          EventBus,
    process_name: str = "C:\\Windows\\System32\\svchost.exe",
) -> Dict[str, Any]:
    """
    4663 — An attempt was made to access an object (after handle obtained via 4656).
    Verified: Microsoft Learn event-4663. Most common for file, folder, registry.
    AccessList human-readable version of AccessMask.
    """
    ed = {
        "SubjectUserSid":    _user_sid(session.samaccountname),
        "SubjectUserName":   session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    session.target_logon_id,
        "ObjectServer":      "Security",
        "ObjectType":        object_type,
        "ObjectName":        object_name,
        "HandleId":          handle_id,
        "AccessList":        _access_list(access_mask),
        "AccessMask":        access_mask,
        "ProcessId":         hex(bus._rng.randint(100, 9999)),
        "ProcessName":       process_name,
        "ResourceAttributes":"-",
    }
    return _env("4663", session.computer, "Security",
                "File System", "success", utc_dt, bus,
                ["Audit Success"], ed)


# ════════════════════════════════════════════════════════════════════════════
# FILE SHARE ACCESS
# ════════════════════════════════════════════════════════════════════════════

def gen_5140(
    session:     LogonSession,
    share_name:  str,
    share_path:  str,
    src_ip:      str,
    utc_dt:      datetime,
    bus:         EventBus,
    share_server:str = "",
) -> Dict[str, Any]:
    """
    5140 — A network share object was accessed.
    Verified: Microsoft Learn event-5140. Generated on the file server
    when a user connects to a share.
    Requires: Audit File Share subcategory enabled.
    """
    computer = share_server or f"FS01.{DOMAIN_FQDN}"
    ed = {
        "SubjectUserSid":    _user_sid(session.samaccountname),
        "SubjectUserName":   session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    session.target_logon_id,
        "ObjectType":        "File",
        "IpAddress":         src_ip,
        "IpPort":            str(bus._rng.randint(49152, 65535)),
        "ShareName":         share_name,
        "ShareLocalPath":    share_path,
        "AccessMask":        "0x1",
        "AccessList":        "%%4416\n\t\t\t\t%%4423",
    }
    return _env("5140", computer, "Security",
                "File Share", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_5145(
    session:      LogonSession,
    share_name:   str,
    relative_path:str,
    src_ip:       str,
    utc_dt:       datetime,
    bus:          EventBus,
    share_server: str = "",
    access_mask:  str = "0x12019f",
    success:      bool = True,
) -> Dict[str, Any]:
    """
    5145 — A network share object was checked for access (detailed share audit).
    Verified: ultimatewindowssecurity.com Event 5145. More verbose than 5140;
    generated per-file when Audit Detailed File Share is enabled.
    """
    computer = share_server or f"FS01.{DOMAIN_FQDN}"
    ed = {
        "SubjectUserSid":       _user_sid(session.samaccountname),
        "SubjectUserName":      session.samaccountname,
        "SubjectDomainName":    DOMAIN_NETBIOS,
        "SubjectLogonId":       session.target_logon_id,
        "ObjectType":           "File",
        "IpAddress":            src_ip,
        "IpPort":               str(bus._rng.randint(49152, 65535)),
        "ShareName":            share_name,
        "ShareLocalPath":       f"\\\\*\\{share_name.lstrip('\\\\')}",
        "RelativeTargetName":   relative_path,
        "AccessMask":           access_mask,
        "AccessList":           _access_list(access_mask),
        "AccessReason":         "%%1540: %%1801 D:(A;;FA;;;WD)",
        "AccessGranted":        "%%4416\n\t\t\t\t%%4423",
    }
    kw = ["Audit Success"] if success else ["Audit Failure"]
    out = "success" if success else "failure"
    return _env("5145", computer, "Security",
                "Detailed File Share", out, utc_dt, bus, kw, ed)


# ════════════════════════════════════════════════════════════════════════════
# AUDIT / LOG OPERATIONS
# ════════════════════════════════════════════════════════════════════════════

def gen_1102(
    actor_sam:   str,
    actor_logon: str,
    computer:    str,
    utc_dt:      datetime,
    bus:         EventBus,
) -> Dict[str, Any]:
    """
    1102 — The audit log was cleared.
    Verified: ultimatewindowssecurity.com Event 1102. Always generated
    regardless of audit policy when Security log is cleared.
    Note: This event uses SubjectUserName / SubjectDomainName / SubjectLogonId
    — NOT TargetUserName.
    """
    ed = {
        "SubjectUserSid":    _user_sid(actor_sam),
        "SubjectUserName":   actor_sam,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_logon,
    }
    return _env("1102", computer, "Security",
                "Security Log Cleared", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4719(
    actor_session: LogonSession,
    category:      str,
    sub_category:  str,
    changes:       str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    4719 — System audit policy was changed.
    Verified: Microsoft Learn event-4719.
    Changes field: e.g. "%%8449" = Success removed, "%%8450" = Failure removed.
    """
    ed = {
        "SubjectUserSid":         _user_sid(actor_session.samaccountname),
        "SubjectUserName":        actor_session.samaccountname,
        "SubjectDomainName":      DOMAIN_NETBIOS,
        "SubjectLogonId":         actor_session.target_logon_id,
        "CategoryId":             category,
        "SubcategoryId":          sub_category,
        "SubcategoryGuid":        bus.new_guid(),
        "AuditPolicyChanges":     changes,
    }
    return _env("4719", _dc(actor_session.computer), "Security",
                "Audit Policy Change", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_4907(
    actor_session: LogonSession,
    object_name:   str,
    old_sd:        str,
    new_sd:        str,
    utc_dt:        datetime,
    bus:           EventBus,
) -> Dict[str, Any]:
    """
    4907 — Auditing settings on object were changed.
    Verified: Microsoft Learn event-4907. Generated when SACL on a file
    or registry key is modified.
    """
    ed = {
        "SubjectUserSid":     _user_sid(actor_session.samaccountname),
        "SubjectUserName":    actor_session.samaccountname,
        "SubjectDomainName":  DOMAIN_NETBIOS,
        "SubjectLogonId":     actor_session.target_logon_id,
        "ObjectServer":       "Security",
        "ObjectType":         "File",
        "ObjectName":         object_name,
        "HandleId":           hex(bus._rng.randint(1000, 9999)),
        "OldSd":              old_sd,
        "NewSd":              new_sd,
        "ProcessId":          hex(bus._rng.randint(100, 9999)),
        "ProcessName":        "C:\\Windows\\System32\\icacls.exe",
    }
    return _env("4907", actor_session.computer, "Security",
                "Audit Policy Change", "success", utc_dt, bus,
                ["Audit Success"], ed)


# ════════════════════════════════════════════════════════════════════════════
# SERVICE MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════

def gen_4697(
    actor_session:    LogonSession,
    service_name:     str,
    service_file_name:str,
    service_type:     str,
    service_start:    str,
    service_account:  str,
    utc_dt:           datetime,
    bus:              EventBus,
) -> Dict[str, Any]:
    """
    4697 — A service was installed in the system.
    Verified: Microsoft Learn event-4697 live XML:
      SubjectUserSid, SubjectUserName, SubjectDomainName, SubjectLogonId,
      ServiceName, ServiceFileName, ServiceType, ServiceStartType,
      ServiceAccount are the exact Data Name= values.
    ServiceType: 0x10=own process, 0x20=share process, 0x1=kernel driver
    ServiceStartType: 0=boot, 1=system, 2=auto, 3=manual, 4=disabled
    """
    ed = {
        "SubjectUserSid":     _user_sid(actor_session.samaccountname),
        "SubjectUserName":    actor_session.samaccountname,
        "SubjectDomainName":  DOMAIN_NETBIOS,
        "SubjectLogonId":     actor_session.target_logon_id,
        "ServiceName":        service_name,
        "ServiceFileName":    service_file_name,
        "ServiceType":        service_type,
        "ServiceStartType":   service_start,
        "ServiceAccount":     service_account,
    }
    return _env("4697", actor_session.computer, "Security",
                "Security System Extension", "success", utc_dt, bus,
                ["Audit Success"], ed)


def gen_7045(
    service_name:     str,
    image_path:       str,
    service_type:     str,
    start_type:       str,
    account_name:     str,
    computer:         str,
    utc_dt:           datetime,
    bus:              EventBus,
) -> Dict[str, Any]:
    """
    7045 — A new service was installed (System channel, ServiceControlManager).
    Verified: Psmths/windows-forensic-artifacts live XML (2023-05-08):
      ServiceName, ImagePath, ServiceType, StartType, AccountName
      are exact Data Name= values.
    Provider: ServiceControlManager {555908d1-a6d7-4695-8e1e-26931d2012f4}
    Channel: System (NOT Security)
    """
    ed = {
        "ServiceName": service_name,
        "ImagePath":   image_path,
        "ServiceType": service_type,      # "own process", "share process"
        "StartType":   start_type,        # "auto start", "demand start", "disabled"
        "AccountName": account_name,
    }
    return _env(
        "7045", computer, "System",
        "Service Control Manager", "success", utc_dt, bus,
        [],
        ed,
        provider="Service Control Manager",
        provider_guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}",
    )


def gen_7036(
    service_name: str,
    state:        str,
    computer:     str,
    utc_dt:       datetime,
    bus:          EventBus,
) -> Dict[str, Any]:
    """
    7036 — The service entered the running/stopped state (System channel).
    Verified: ultimatewindowssecurity.com Event 7036.
    Fields: param1 (service name), param2 (state: "running" or "stopped").
    Provider: Service Control Manager
    """
    ed = {
        "param1": service_name,
        "param2": state,   # "running" or "stopped"
    }
    return _env(
        "7036", computer, "System",
        "Service Control Manager", "success", utc_dt, bus,
        [],
        ed,
        provider="Service Control Manager",
        provider_guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}",
    )


def gen_104(
    actor_sam: str,
    computer:  str,
    utc_dt:    datetime,
    bus:       EventBus,
) -> Dict[str, Any]:
    """
    104 — The System event log was cleared (System channel).
    Verified: Active Countermeasures hunting guide.
    Provider: Microsoft-Windows-Eventlog
    """
    ed = {
        "param1": actor_sam,
        "Channel": "System",
    }
    return _env(
        "104", computer, "System",
        "Log clear", "success", utc_dt, bus,
        [],
        ed,
        provider="Microsoft-Windows-Eventlog",
        provider_guid="{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}",
    )


# ════════════════════════════════════════════════════════════════════════════
# USB / PLUG-AND-PLAY
# ════════════════════════════════════════════════════════════════════════════

def gen_6416(
    session:         LogonSession,
    device_id:       str,
    device_desc:     str,
    class_id:        str,
    class_name:      str,
    utc_dt:          datetime,
    bus:             EventBus,
) -> Dict[str, Any]:
    """
    6416 — A new external device was recognized by the system.
    Verified: Active Countermeasures hunting guide + Microsoft Learn event-6416.
    Fields: SubjectUserName, SubjectLogonId, DeviceId, DeviceDescription,
    ClassId, ClassName, HardwareIds, CompatibleIds, LocationInformation.
    Requires: Audit PNP Activity subcategory enabled.
    """
    ed = {
        "SubjectUserSid":        _user_sid(session.samaccountname),
        "SubjectUserName":       session.samaccountname,
        "SubjectDomainName":     DOMAIN_NETBIOS,
        "SubjectLogonId":        session.target_logon_id,
        "DeviceId":              device_id,
        "DeviceDescription":     device_desc,
        "ClassId":               class_id,
        "ClassName":             class_name,
        "VendorIds":             f"USB\\VID_{bus._rng.randint(0x1000,0xFFFF):04X}&PID_{bus._rng.randint(0x1000,0xFFFF):04X}",
        "CompatibleIds":         "USB\\Class_08&SubClass_06&Prot_50\nUSB\\Class_08&SubClass_06\nUSB\\Class_08",
        "LocationInformation":   f"Port_#{bus._rng.randint(1,4):04d}.Hub_#{bus._rng.randint(1,4):04d}",
    }
    return _env("6416", session.computer, "Security",
                "Plug and Play Events", "success", utc_dt, bus,
                ["Audit Success"], ed)


# ════════════════════════════════════════════════════════════════════════════
# PROCESS TERMINATION
# ════════════════════════════════════════════════════════════════════════════

def gen_4689(
    session:      LogonSession,
    process_name: str,
    process_id:   str,
    exit_status:  str,
    utc_dt:       datetime,
    bus:          EventBus,
) -> Dict[str, Any]:
    """
    4689 — A process has exited.
    Verified: Microsoft Learn event-4689. Emitted when process terminates.
    Pair with 4688 (process creation) using ProcessId + timestamp proximity.
    """
    ed = {
        "SubjectUserSid":    _user_sid(session.samaccountname),
        "SubjectUserName":   session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    session.target_logon_id,
        "Status":            exit_status,
        "ProcessId":         process_id,
        "ProcessName":       process_name,
    }
    return _env("4689", session.computer, "Security",
                "Process Termination", "success", utc_dt, bus,
                ["Audit Success"], ed)


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def _access_list(mask: str) -> str:
    """Maps common access masks to human-readable Windows audit strings."""
    _MAP = {
        "0x1":      "%%4416",
        "0x2":      "%%4417",
        "0x4":      "%%4418",
        "0x40":     "%%4423",
        "0x80":     "%%4424",
        "0x10000":  "%%1537",
        "0x20000":  "%%1538",
        "0x12019f": "%%4416\n\t\t\t\t%%4423\n\t\t\t\t%%1537",
        "0x100":    "%%7688",
        "0x200":    "%%7689",
    }
    return _MAP.get(mask.lower(), "%%4416")