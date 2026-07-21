"""
security_generator.py — Generates Windows Security Event Log events
in Winlogbeat 9.x Kafka JSON format, exactly as verified from real logs
(Winlogbeat 9.4.2, Nexovate Solutions lab capture).

Every event dict is self-consistent:
  - TargetLogonId from a real LogonSession in the EventBus
  - UPN format for Kerberos, SAM for NTLM (matches real Windows behaviour)
  - LogonType, AuthPackage, and IpAddress are internally consistent
  - 4772/4634 logoffs reference the original 4624's TargetLogonId
"""

from __future__ import annotations
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.event_bus import EventBus, LogonSession, _new_guid, stable_agent_id, stable_ephemeral_id
from core.employees import user_sid as _user_sid, stable_seed as _stable_seed
from core.time_engine import utc_now_str, jitter_ts
from config.company import (
    DOMAIN_NETBIOS, DOMAIN_FQDN, EXTERNAL_DOMAIN,
    DOMAIN_CONTROLLERS,
)


# ── Shared field value maps ───────────────────────────────────────────────────
_LOGON_TYPE_NAMES = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    8:  "NetworkCleartext",
    9:  "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

_ENCRYPTION_TYPES = {
    "AES256": "0x12",
    "AES128": "0x11",
    "RC4":    "0x17",
    "DES":    "0x03",
}

_REPLICATION_GUIDS = [
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2",
]

DC01 = DOMAIN_CONTROLLERS[0]
DC02 = DOMAIN_CONTROLLERS[1]


def _envelope(
    event_id: str,
    computer: str,
    channel: str,
    task: str,
    outcome: str,
    utc_dt: datetime,
    bus: EventBus,
    keywords: List[str],
    event_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Builds the full Winlogbeat Kafka JSON envelope.
    Structure verified from kafka_logs_2.txt (DC01.das.com, Winlogbeat 9.4.2).
    """
    record_key = f"{channel}:{computer}"
    rid        = bus.next_record_id(record_key)

    # Add sub-second jitter: real Windows events rarely fall on exact second
    # boundaries. Jitter is a deterministic hash (reproducible across runs given
    # the same seed) rather than an extra RNG draw. `rid` (this host/channel's
    # monotonic EventRecordID counter) is included so two events can never share
    # identical jitter -- it is unique per call by construction.
    us_jitter = int(hashlib.md5(
        f"{utc_dt.isoformat()}{event_id}{record_key}{rid}".encode()
    ).hexdigest()[:5], 16) % 1_000_000
    utc_dt_jittered = utc_dt.replace(microsecond=us_jitter)
    ts_str = utc_now_str(utc_dt_jittered)
    # ingest time is a few seconds after event time (Winlogbeat batch delay)
    ingest_dt  = utc_dt_jittered + timedelta(seconds=bus._rng.randint(1, 8))

    return {
        "@timestamp":   ts_str,
        "@metadata": {
            "beat":    "winlogbeat",
            "type":    "_doc",
            "version": "9.4.2",
        },
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
            "code":     event_id,
            "kind":     "event",
            "provider": "Microsoft-Windows-Security-Auditing",
            "action":   task,
            "outcome":  outcome,
            "created":  utc_now_str(ingest_dt),
        },
        "winlog": {
            "event_id":      event_id,
            "channel":       channel,
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
            "computer_name": computer,
            "task":          task,
            "opcode":        "Info",
            "record_id":     rid,
            "version":       2,
            "keywords":      keywords,
            "event_data":    event_data,
        },
    }


# ── 4624 — Successful Logon ───────────────────────────────────────────────────
def gen_4624(
    session: LogonSession,
    utc_dt:  datetime,
    bus:     EventBus,
    target_user_sid: str = "S-1-0-0",  # callers must supply real per-user SID
) -> Dict[str, Any]:
    """
    Generates a 4624 Successful Logon event.
    ImpersonationLevel is string-decoded (Winlogbeat decodes %%1840 → 'Impersonation').
    """
    computer = session.computer
    sam      = session.samaccountname

    # UPN format for TargetUserName in Kerberos sessions, SAM for NTLM
    target_un = (f"{sam}@{DOMAIN_FQDN.upper()}"
                 if session.auth_package == "Kerberos"
                 else sam)

    # Elevated token only for IT admins and executive
    elevated = "Yes" if session.is_elevated else "No"

    # WorkstationName is "-" for Network (Type 3) Kerberos per real Windows behaviour
    ws_name = ("-"
               if session.logon_type == 3 and session.auth_package == "Kerberos"
               else session.workstation)

    # IpPort: 0 for local/interactive logons, random ephemeral for remote
    ip_port = str(bus.new_src_port()) if session.logon_type in {3, 9, 10} else "0"

    event_data = {
        "SubjectUserSid":           "S-1-5-18",
        "SubjectUserName":          f"{computer.split('.')[0]}$",
        "SubjectDomainName":        DOMAIN_NETBIOS,
        "SubjectLogonId":           "0x3e7",
        "TargetUserSid":            target_user_sid,
        "TargetUserName":           target_un,
        "TargetDomainName":         DOMAIN_NETBIOS,
        "TargetLogonId":            session.target_logon_id,
        "TargetLinkedLogonId":      "0x0",
        "TargetOutboundUserName":   "-",
        "TargetOutboundDomainName": "-",
        "LogonType":                str(session.logon_type),
        "LogonProcessName":         _logon_process(session.auth_package, session.logon_type),
        "AuthenticationPackageName":session.auth_package,
        "WorkstationName":          ws_name,
        "IpAddress":                _format_ip(session.src_ip),
        "IpPort":                   ip_port,
        "LogonGuid":                session.logon_guid,
        "ElevatedToken":            elevated,
        "ImpersonationLevel":       "Impersonation",
        "VirtualAccount":           "No",
        "RestrictedAdminMode":      "-",
        "LmPackageName":            _lm_package(session.auth_package),
        "KeyLength":                "0",
        "TransmittedServices":      "-",
        "ProcessId":                "0x4",
        "ProcessName":              "C:\\Windows\\System32\\svchost.exe",
    }

    return _envelope(
        event_id   = "4624",
        computer   = computer,
        channel    = "Security",
        task       = "Logon",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4634 — Account Logoff ─────────────────────────────────────────────────────
def gen_4634(
    session: LogonSession,
    utc_dt:  datetime,
    bus:     EventBus,
) -> Dict[str, Any]:
    """4634 Logoff — references the TargetLogonId from the paired 4624."""
    event_data = {
        "TargetUserSid":    _user_sid(session.samaccountname),
        "TargetUserName":   session.samaccountname,
        "TargetDomainName": DOMAIN_NETBIOS,
        "TargetLogonId":    session.target_logon_id,
        "LogonType":        str(session.logon_type),
    }
    return _envelope(
        event_id   = "4634",
        computer   = session.computer,
        channel    = "Security",
        task       = "Logoff",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4625 — Failed Logon ───────────────────────────────────────────────────────
def gen_4625(
    samaccountname: str,
    src_ip:         str,
    computer:       str,
    logon_type:     int,
    utc_dt:         datetime,
    bus:            EventBus,
    sub_status:     str = "0xc000006a",     # wrong password
    auth_package:   str = "NTLM",
    workstation:    str = "-",
) -> Dict[str, Any]:
    """4625 Logon Failure."""
    _FAILURE_REASONS = {
        "0xc000006a": "Unknown user name or bad password.",
        "0xc0000064": "User logon with misspelled or bad user account.",
        "0xc0000234": "User account has been automatically locked.",
        "0xc0000072": "User account is disabled.",
        "0xc000006f": "User logon outside authorized hours.",
    }
    event_data = {
        "SubjectUserSid":           "S-1-5-18",
        "SubjectUserName":          f"{computer.split('.')[0]}$",
        "SubjectDomainName":        DOMAIN_NETBIOS,
        "SubjectLogonId":           "0x3e7",
        "TargetUserSid":            "S-1-0-0",
        "TargetUserName":           samaccountname,
        "TargetDomainName":         DOMAIN_NETBIOS,
        "LogonType":                str(logon_type),
        "LogonProcessName":         "NtLmSsp " if auth_package == "NTLM" else "Kerberos",
        "AuthenticationPackageName":auth_package,
        "WorkstationName":          workstation,
        "IpAddress":                _format_ip(src_ip),
        "IpPort":                   str(bus.new_src_port()),
        "Status":                   "0xc000006d",
        "SubStatus":                sub_status,
        "FailureReason":            _FAILURE_REASONS.get(sub_status, "Unknown error."),
        "LmPackageName":            "-",
        "KeyLength":                "0",
        "TransmittedServices":      "-",
        "ProcessId":                "0x0",
        "ProcessName":              "-",
    }
    return _envelope(
        event_id   = "4625",
        computer   = computer,
        channel    = "Security",
        task       = "Logon",
        outcome    = "failure",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Failure"],
        event_data = event_data,
    )


# ── 4672 — Special Logon (Privileged) ────────────────────────────────────────
def gen_4672(
    session: LogonSession,
    utc_dt:  datetime,
    bus:     EventBus,
    privilege_list: str = "SeSecurityPrivilege\nSeTakeOwnershipPrivilege\nSeLoadDriverPrivilege\nSeBackupPrivilege\nSeRestorePrivilege\nSeDebugPrivilege",
) -> Dict[str, Any]:
    """4672 Special Logon — emitted alongside 4624 for privileged sessions."""
    event_data = {
        "SubjectUserSid":    _user_sid(session.samaccountname),
        "SubjectUserName":   session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    session.target_logon_id,
        "PrivilegeList":     privilege_list,
    }
    return _envelope(
        event_id   = "4672",
        computer   = session.computer,
        channel    = "Security",
        task       = "Special Logon",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4648 — Explicit Credential Logon ─────────────────────────────────────────
def gen_4648(
    session:        LogonSession,
    target_user:    str,
    target_server:  str,
    utc_dt:         datetime,
    bus:            EventBus,
) -> Dict[str, Any]:
    """4648 — RunAs / PSCredential / WMI explicit credential use."""
    event_data = {
        "SubjectUserSid":      "S-1-5-18",
        "SubjectUserName":     session.samaccountname,
        "SubjectDomainName":   DOMAIN_NETBIOS,
        "SubjectLogonId":      session.target_logon_id,
        "TargetUserName":      target_user,
        "TargetDomainName":    DOMAIN_NETBIOS,
        "TargetServerName":    target_server,
        "TargetInfo":          target_server,
        "TargetLogonGuid":     "{00000000-0000-0000-0000-000000000000}",
        "LogonGuid":           "{00000000-0000-0000-0000-000000000000}",
        "IpAddress":           _format_ip(session.src_ip),
        "IpPort":              str(bus.new_src_port()),
        "ProcessId":           "0x348",
        "ProcessName":         "C:\\Windows\\System32\\lsass.exe",
    }
    return _envelope(
        event_id   = "4648",
        computer   = session.computer,
        channel    = "Security",
        task       = "Logon",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4768 — Kerberos TGT Request ──────────────────────────────────────────────
# ── Kerberos realism: weighted ticket-options and encryption types ────────────
# Distributions from EvidenceForge kerberos_realism.yaml
# Source: github.com/Cisco-Talos/EvidenceForge/blob/main/
#         src/evidenceforge/config/activity/kerberos_realism.yaml
_KERBEROS_TGT_TICKET_OPTIONS = [
    ("0x40810010", 60),   # forwardable + renewable + canonicalize (most common)
    ("0x40810000", 20),   # forwardable + renewable
    ("0x40000010", 10),   # renewable + canonicalize
    ("0x50800000",  5),   # renewable + ok-as-delegate
    ("0x10",        5),   # canonicalize only
]
_KERBEROS_TGS_TICKET_OPTIONS = [
    ("0x40810010", 55),
    ("0x40810000", 25),
    ("0x40000010", 12),
    ("0x50800000",  5),
    ("0x10",        3),
]
# Kerberos ticket encryption type is a per-account property, not per-request
# noise: in Active Directory it is governed by the account's
# msDS-SupportedEncryptionTypes, essentially constant for that account. This
# generator therefore assigns an encryption type deterministically per identity
# (see _account_supported_enc_type), rather than drawing one per 4768/4769 event.
#
# Computer-backed SPNs on a modern-OS fleet (every server here is Windows Server
# 2019/2022) auto-configure AES on domain join, so their tickets are AES. The
# realistic source of RC4 exposure is USER-backed service accounts that were
# never hardened — which is exactly why such accounts are Kerberoasting targets,
# a property of account TYPE (user vs. computer), not server age. The two tables
# below encode that split; attack injection forces RC4 explicitly via gen_4769's
# enc_type override to model a deliberately under-configured, Kerberoastable
# account.
_KERBEROS_ENC_TYPES = [
    ("0x12", 70),   # AES256-CTS-HMAC-SHA1-96
    ("0x11", 20),   # AES128-CTS-HMAC-SHA1-96
    ("0x17", 10),   # RC4-HMAC (legacy compatibility) — user-backed accounts only
]
_COMPUTER_BACKED_SPN_ENC_TYPES = [
    ("0x12", 85),   # AES256 — modern default
    ("0x11", 15),   # AES128 — GPO-restricted minority, still no RC4
]

# Base seed for encryption-type assignment, deliberately independent of
# bus._rng and of the CLI --seed. This governs which SPNs/accounts are
# "legacy" (RC4/AES128-only) vs. "modern" (AES256) for the lifetime of a
# given identity string — it does not need to vary with the simulation's
# other randomness, only to be stable within a run and reproducible across
# runs of this codebase.
_ENC_TYPE_ASSIGNMENT_SEED = 0x4B455242  # arbitrary constant ("KERB" in hex-ish)


def _spn_identity_key(service_name: str) -> str:
    """
    Extracts a stable per-account identity key from a full SPN string, so
    "cifs/FS01.nexovate.local" and (hypothetically) "cifs/FS01.nexovate.local"
    requested again both resolve to the same underlying account ("FS01").
    Handles the SPN classes actually produced by this generator: cifs/,
    MSSQLSvc/ (host:port), http/, ldap/, TERMSRV/, and bare machine accounts
    like "DC01$".
    """
    name = service_name
    if "/" in name:
        name = name.split("/", 1)[1]
    name = name.split(":")[0]          # drop :1433-style port suffix
    name = name.split(".")[0]          # drop .nexovate.local suffix
    name = name.rstrip("$")
    return name.upper()


def _account_supported_enc_type(identity_key: str, computer_backed: bool = True) -> str:
    """
    Deterministic per-account encryption type. `computer_backed=True` (every SPN
    this generator produces) excludes RC4, matching an all-modern-OS fleet.
    `computer_backed=False` models user-backed service accounts that can be
    RC4-capable and therefore Kerberoastable.
    """
    seed = _stable_seed(_ENC_TYPE_ASSIGNMENT_SEED, f"enctype:{identity_key}")
    local_rng = random.Random(seed)
    table = _COMPUTER_BACKED_SPN_ENC_TYPES if computer_backed else _KERBEROS_ENC_TYPES
    vals, wts = zip(*table)
    return local_rng.choices(list(vals), weights=list(wts), k=1)[0]


def _pick_ticket_options(rng, for_tgt=True):
    pool = _KERBEROS_TGT_TICKET_OPTIONS if for_tgt else _KERBEROS_TGS_TICKET_OPTIONS
    vals, wts = zip(*pool)
    return rng.choices(list(vals), weights=list(wts), k=1)[0]



def gen_4768(
    samaccountname: str,
    src_ip:         str,
    utc_dt:         datetime,
    bus:            EventBus,
    pre_auth_type:  str = "2",
    enc_type:       Optional[str] = None,
    status:         str = "0x0",
    logon_guid:     str = "",
) -> Dict[str, Any]:
    """4768 Kerberos AS-REQ — only generated on Domain Controllers.

    EncryptionType is a deterministic per-account property, not a per-request
    draw (see the _KERBEROS_ENC_TYPES comment above). Two cases:
      - pre_auth_type != "0" (pre-auth enabled — the normal-traffic case): TGT
        encryption is governed by the krbtgt account's keys, which default to AES
        at domain functional level >= 2008. Deterministically AES256.
      - pre_auth_type == "0" (AS-REP roasting target): the AS-REP is encrypted
        with the requesting account's own key material, which follows that
        account's msDS-SupportedEncryptionTypes — looked up deterministically per
        account, so a vulnerable account is consistently vulnerable rather than
        RC4-by-chance.
    `enc_type`, if explicitly passed, still overrides both cases — this
    preserves the ability for a future attack-injection caller to force a
    specific encryption type (e.g. RC4) on a specific event.
    """
    if not logon_guid:
        logon_guid = bus.new_guid()
    computer = DC01["fqdn"]
    if enc_type is not None:
        resolved_enc_type = enc_type
    elif pre_auth_type == "0":
        resolved_enc_type = _account_supported_enc_type(
            samaccountname.upper(), computer_backed=False
        )
    else:
        resolved_enc_type = "0x12"  # krbtgt-governed, AES256, DFL >= 2008
    event_data = {
        "TargetUserName":       samaccountname,
        "TargetDomainName":     DOMAIN_NETBIOS,
        "TargetSid":            _user_sid(samaccountname),
        "ServiceName":          "krbtgt",
        "ServiceSid":           "S-1-5-21-1484628597-1684816888-3125425894-502",
        "TicketOptions":        _pick_ticket_options(bus._rng, for_tgt=True),
        "Status":               status,
        "EncryptionType":       resolved_enc_type,
        "PreAuthType":          pre_auth_type,
        "IpAddress":            _format_ip_v6(src_ip),
        "IpPort":               str(bus.new_src_port()),
        "CertIssuerName":       "",
        "CertSerialNumber":     "",
        "LogonGuid":            logon_guid,
    }
    return _envelope(
        event_id   = "4768",
        computer   = computer,
        channel    = "Security",
        task       = "Kerberos Authentication Service",
        outcome    = "success" if status == "0x0" else "failure",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"] if status == "0x0" else ["Audit Failure"],
        event_data = event_data,
    )


# ── 4769 — Kerberos TGS Request ──────────────────────────────────────────────
def gen_4769(
    samaccountname: str,
    service_name:   str,
    service_sid:    str,
    src_ip:         str,
    utc_dt:         datetime,
    bus:            EventBus,
    enc_type:       Optional[str] = None,
    ticket_options: str = "0x40800000",
    status:         str = "0x0",
    logon_guid:     str = "",
) -> Dict[str, Any]:
    """4769 Kerberos TGS-REQ — only generated on Domain Controllers.

    TicketEncryptionType is looked up deterministically per target SPN
    (see _KERBEROS_ENC_TYPES comment above) instead of drawn randomly on
    every request — a given service consistently supports whatever
    encryption types its account is actually configured for. `enc_type`,
    if explicitly passed, overrides the lookup (used by attack-injection
    callers that need to force a specific encryption type on a specific
    event, e.g. a deliberately RC4-only Kerberoasting target).
    """
    if not logon_guid:
        logon_guid = bus.new_guid()
    computer = DC01["fqdn"]
    resolved_enc_type = (
        enc_type if enc_type is not None
        else _account_supported_enc_type(_spn_identity_key(service_name))
    )
    event_data = {
        "TargetUserName":       f"{samaccountname}@{DOMAIN_FQDN.upper()}",
        "TargetDomainName":     DOMAIN_FQDN.upper(),
        "ServiceName":          service_name,
        "ServiceSid":           service_sid,
        "TicketOptions":        _pick_ticket_options(bus._rng, for_tgt=False),
        "TicketEncryptionType": resolved_enc_type,
        "IpAddress":            _format_ip_v6(src_ip),
        "IpPort":               str(bus.new_src_port()),
        "Status":               status,
        "LogonGuid":            logon_guid,
        "TransmittedServices":  "-",
    }
    return _envelope(
        event_id   = "4769",
        computer   = computer,
        channel    = "Security",
        task       = "Kerberos Service Ticket Operations",
        outcome    = "success" if status == "0x0" else "failure",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"] if status == "0x0" else ["Audit Failure"],
        event_data = event_data,
    )


# ── 4771 — Kerberos Pre-Auth Failure ─────────────────────────────────────────
def gen_4771(
    samaccountname: str,
    src_ip:         str,
    utc_dt:         datetime,
    bus:            EventBus,
    status:         str = "0x18",
) -> Dict[str, Any]:
    """4771 Kerberos pre-authentication failure (wrong password)."""
    computer = DC01["fqdn"]
    event_data = {
        "TargetUserName":  samaccountname,
        "TargetSid":       _user_sid(samaccountname),
        "ServiceName":     f"krbtgt/{DOMAIN_NETBIOS}",
        "TicketOptions":   _pick_ticket_options(bus._rng, for_tgt=True),
        "Status":          status,
        "EncryptionType":  "0x17",
        "PreAuthType":     "2",
        "IpAddress":       _format_ip_v6(src_ip),
        "IpPort":          str(bus.new_src_port()),
    }
    return _envelope(
        event_id   = "4771",
        computer   = computer,
        channel    = "Security",
        task       = "Kerberos Authentication Service",
        outcome    = "failure",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Failure"],
        event_data = event_data,
    )


# ── 4776 — NTLM Credential Validation ────────────────────────────────────────
def gen_4776(
    samaccountname: str,
    workstation:    str,
    utc_dt:         datetime,
    bus:            EventBus,
    status:         str = "0x0",
    computer:       str = "",
) -> Dict[str, Any]:
    """4776 NTLM validation — generated on DC for domain accounts."""
    if not computer:
        computer = DC01["fqdn"]
    event_data = {
        "PackageName":   "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
        "TargetUserName":samaccountname,
        "Workstation":   workstation,
        "Status":        status,
    }
    return _envelope(
        event_id   = "4776",
        computer   = computer,
        channel    = "Security",
        task       = "Credential Validation",
        outcome    = "success" if status == "0x0" else "failure",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"] if status == "0x0" else ["Audit Failure"],
        event_data = event_data,
    )


# ── 4740 — Account Lockout ────────────────────────────────────────────────────
def gen_4740(
    samaccountname: str,
    caller_computer:str,
    utc_dt:         datetime,
    bus:            EventBus,
) -> Dict[str, Any]:
    """4740 Account locked out after too many failed attempts."""
    computer = DC01["fqdn"]
    event_data = {
        "TargetUserName":    samaccountname,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(samaccountname),
        "SubjectUserName":   f"{caller_computer}$",
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    "0x3e7",
        "CallerComputerName":caller_computer,
    }
    return _envelope(
        event_id   = "4740",
        computer   = computer,
        channel    = "Security",
        task       = "User Account Management",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4728/4732/4756 — Group Membership Change ─────────────────────────────────
def gen_group_change(
    actor_session:  LogonSession,
    member_sam:     str,
    member_dn:      str,
    group_name:     str,
    group_sid:      str,
    utc_dt:         datetime,
    bus:            EventBus,
    event_id:       str = "4728",   # 4728=global, 4732=local, 4756=universal
) -> Dict[str, Any]:
    """Group member added — 4728 (global), 4732 (local), 4756 (universal)."""
    task_names = {
        "4728": "Security Group Management",
        "4732": "Security Group Management",
        "4756": "Security Group Management",
    }
    event_data = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "MemberSid":         _user_sid(member_sam),
        "MemberName":        member_dn,
        "TargetUserName":    group_name,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         group_sid,
        "PrivilegeList":     "-",
    }
    return _envelope(
        event_id   = event_id,
        computer   = DC01["fqdn"],
        channel    = "Security",
        task       = task_names.get(event_id, "Security Group Management"),
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4720 — User Account Created ──────────────────────────────────────────────
def gen_4720(
    actor_session:  LogonSession,
    new_user_sam:   str,
    new_user_dn:    str,
    utc_dt:         datetime,
    bus:            EventBus,
) -> Dict[str, Any]:
    """4720 — A new user account was created."""
    event_data = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "TargetUserName":    new_user_sam,
        "TargetDomainName":  DOMAIN_NETBIOS,
        "TargetSid":         _user_sid(new_user_sam),
        "SamAccountName":    new_user_sam,
        "DisplayName":       new_user_dn,
        "UserPrincipalName": f"{new_user_sam}@{DOMAIN_FQDN}",
        "PasswordLastSet":   "%%1794",
        "AccountExpires":    "%%1795",
        "PrimaryGroupId":    "513",
        "AllowedToDelegateTo":"-",
        "OldUacValue":       "0x0",
        "NewUacValue":       "0x15",
        "UserAccountControl":"%%2080\n\t\t\t\t%%2082\n\t\t\t\t%%2084",
        "UserParameters":    "-",
        "SidHistory":        "-",
    }
    return _envelope(
        event_id   = "4720",
        computer   = DC01["fqdn"],
        channel    = "Security",
        task       = "User Account Management",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 4662 — Object Access (used for DCSync detection) ─────────────────────────
def gen_4662(
    actor_session: LogonSession,
    object_dn:     str,
    utc_dt:        datetime,
    bus:           EventBus,
    is_dcsync:     bool = False,
) -> Dict[str, Any]:
    """4662 AD object access — legitimate admin or DCSync variant."""
    if is_dcsync:
        props = (
            "%%{19195a5b-6da0-11d0-a285-00aa003049e2}\n"
            f"%%{{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}}"
        )
    else:
        props = "%%{19195a5b-6da0-11d0-a285-00aa003049e2}"

    event_data = {
        "SubjectUserSid":    _user_sid(actor_session.samaccountname),
        "SubjectUserName":   actor_session.samaccountname,
        "SubjectDomainName": DOMAIN_NETBIOS,
        "SubjectLogonId":    actor_session.target_logon_id,
        "ObjectServer":      "DS",
        "ObjectType":        "%%{19195a5b-6da0-11d0-a285-00aa003049e2}",
        "ObjectName":        object_dn,
        "OperationType":     "Object Access",
        "HandleId":          "0x0",
        "AccessList":        "%%7688\n\t\t\t\t%%7687",
        "AccessMask":        "0x100",
        "Properties":        props,
        "AdditionalInfo":    "-",
        "AdditionalInfo2":   "",
    }
    return _envelope(
        event_id   = "4662",
        computer   = DC01["fqdn"],
        channel    = "Security",
        task       = "Directory Service Access",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── 5136 — AD Attribute Modified ─────────────────────────────────────────────
# Verified AD schema class GUIDs (stable per schema version):
# Source: Microsoft Active Directory Schema technical reference
_AD_SCHEMA_GUIDS: Dict[str, str] = {
    "user":               "{BF967ABA-0DE6-11D0-A285-00AA003049E2}",
    "computer":           "{BF967A86-0DE6-11D0-A285-00AA003049E2}",
    "group":              "{BF967A9C-0DE6-11D0-A285-00AA003049E2}",
    "organizationalUnit": "{BF967AA5-0DE6-11D0-A285-00AA003049E2}",
    "groupPolicyContainer":"{F30E3BBE-9FF0-11D1-B603-0000F80367C1}",
    "Default":            "{BF967ABA-0DE6-11D0-A285-00AA003049E2}",
}


def gen_5136(
    actor_session:   LogonSession,
    object_dn:       str,
    object_class:    str,
    attribute_name:  str,
    attribute_value: str,
    utc_dt:          datetime,
    bus:             EventBus,
    operation:       str = "Value Added",
) -> Dict[str, Any]:
    """5136 — Directory Service object attribute modification."""
    event_data = {
        "SubjectUserSid":           _user_sid(actor_session.samaccountname),
        "SubjectUserName":          actor_session.samaccountname,
        "SubjectDomainName":        DOMAIN_NETBIOS,
        "SubjectLogonId":           actor_session.target_logon_id,
        "DSName":                   DOMAIN_FQDN,
        "SchemaIDGUID":             _AD_SCHEMA_GUIDS.get(object_class,
                                        _AD_SCHEMA_GUIDS["Default"]),
        "ObjectDN":                 object_dn,
        "ObjectGUID":               bus.new_guid(),   # AD object GUID - unique per object
        "ObjectClass":              object_class,
        "AttributeLDAPDisplayName": attribute_name,
        "AttributeSyntaxOID":       "2.5.5.17",
        "AttributeValue":           attribute_value,
        "OperationType":            operation,
    }
    return _envelope(
        event_id   = "5136",
        computer   = DC01["fqdn"],
        channel    = "Security",
        task       = "Directory Service Changes",
        outcome    = "success",
        utc_dt     = utc_dt,
        bus        = bus,
        keywords   = ["Audit Success"],
        event_data = event_data,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────
def _logon_process(auth_package: str, logon_type: int) -> str:
    """Returns the LogonProcessName — mirrors real Windows behaviour."""
    if auth_package == "NTLM":
        return "NtLmSsp "          # trailing space is real (confirmed from logs)
    if logon_type == 2:
        return "User32 "
    if logon_type == 7:
        return "User32 "
    return "Kerberos"


def _lm_package(auth_package: str) -> str:
    """Returns LmPackageName — '-' for Kerberos, NTLM V2 for NTLM."""
    if auth_package == "NTLM":
        return "NTLM V2"
    return "-"


def _format_ip(ip: str) -> str:
    """Returns IP as Winlogbeat delivers it — plain IPv4 for 4624."""
    if ip and ip.startswith("::ffff:"):
        return ip[7:]
    return ip or "-"


def _format_ip_v6(ip: str) -> str:
    """Kerberos events (4768/4769/4771) use ::ffff: prefix for IPv4."""
    if ip and "." in ip and not ip.startswith("::"):
        return f"::ffff:{ip}"
    return ip or "::1"