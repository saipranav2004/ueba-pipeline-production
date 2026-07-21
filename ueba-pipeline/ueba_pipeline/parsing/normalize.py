"""
parsing/normalize.py — Winlogbeat/NXLog JSON → canonical NormalizedEvent.

Two envelope shapes are handled:

- "winlog" nested (Winlogbeat) — what enterprise_simulator emits for all
  channels. A production deployment could have NXLog shipping some channels
  separately, so the flat shape below is also handled.
- flat NXLog-style — top-level EventID/Channel/event_data-equivalent keys.

Design rule enforced throughout: never silently drop a record. Anything that
does not match a known (channel, event_id) mapping still produces a
NormalizedEvent with event_type="unknown" and the raw event_data preserved, so
the capability-manifest bootstrap scan sees the true shape of what a deployment
produces, including sources without a specific field mapping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# ── Constants ──────────────────────────────────────────────────────────────
SYSTEM_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
NULL_VALUES = {"-", "", None, "0x0000000000000000",
               "{00000000-0000-0000-0000-000000000000}"}

# (channel, event_id) -> logical feature group, used by features/manifest.py to
# decide which feature groups are available for a deployment.
EVENT_GROUP: Dict[tuple[str, str], str] = {}


def _register_group(channel: str, event_ids: list[str], group: str) -> None:
    for eid in event_ids:
        EVENT_GROUP[(channel, eid)] = group


_register_group("Security", [
    "4624", "4625", "4634", "4647", "4648", "4672", "4740",
], "auth")
_register_group("Security", [
    "4768", "4769", "4771", "4776",
], "kerberos")
_register_group("Security", [
    "4662", "5136",
], "privilege_ad")
_register_group("Security", [
    "4720", "4722", "4723", "4724", "4725", "4726", "4728", "4729",
    "4732", "4733", "4735", "4738", "4741", "4742", "4743",
], "account_lifecycle")
_register_group("Microsoft-Windows-Sysmon/Operational", [
    "1", "3", "7", "8", "10", "11", "22", "23",
], "sysmon_process")
_register_group("Microsoft-Windows-DNS-Server/Analytical", ["256", "257"], "dns")
_register_group("Microsoft-Windows-PowerShell/Operational", ["4103", "4104"], "powershell")
_register_group("Microsoft-Windows-TaskScheduler/Operational",
                 ["106", "140", "141", "142", "200", "201", "129"], "task_scheduler")
_register_group("Microsoft-Windows-WMI-Activity/Operational",
                 ["5857", "5858", "5861"], "wmi")
_register_group("Microsoft-Windows-Windows Defender/Operational",
                 ["1116", "1117", "5007"], "defender")


@dataclass(slots=True)
class NormalizedEvent:
    """Canonical, typed representation of one log event.

    `fields` holds event-type-specific canonical fields (see
    _EVENT_FIELD_MAPS below); `raw_event_data` retains the original
    event_data dict for anything a specific mapping doesn't cover and for
    audit/debugging. On the batch training path, where tens of millions of
    events are held in memory at once, `raw_event_data` can be dropped after
    normalization (it is not read by any feature extractor) via
    normalize_event(..., keep_raw=False) — it is ~2 KB/event, roughly half the
    footprint. dataclass slots=True removes the per-instance __dict__ overhead,
    which matters at that event count.
    """

    event_time: Optional[datetime]
    ingest_time: Optional[str]
    channel: str
    event_id: str
    event_type: str          # exact key, e.g. "4624" or "sysmon_10"; "unknown" if unmapped
    group: Optional[str]      # feature group this event contributes to, or None
    computer_name: Optional[str]
    outcome: Optional[str]
    keywords: list
    fields: Dict[str, Any] = field(default_factory=dict)
    raw_event_data: Dict[str, Any] = field(default_factory=dict)
    parse_warnings: list = field(default_factory=list)


# ── Typed casters ───────────────────────────────────────────────────────────
def normalize_ip(ip: Optional[str]) -> Optional[str]:
    if not ip or ip in NULL_VALUES:
        return None
    ip = ip.strip()
    if ip.startswith("::ffff:"):
        return ip[7:]
    if ip == "::1":
        return "127.0.0.1"
    return ip


def normalize_username(username: Optional[str]) -> Optional[str]:
    """
    Two Windows identity formats appear across the ingested log sources, and both
    must normalise to the same key or a user's identity fragments into two
    separate behavioural baselines:
    - UPN: "jsmith@CORP.LOCAL" (Security-log Kerberos events, e.g. 4768/4769)
    - NetBIOS: "NEXOVATE\\jsmith" (Sysmon's User field, TaskScheduler's
      UserContext, Sysmon EID 10 SourceUser)
    """
    if not username or username in NULL_VALUES:
        return None
    name = username.strip()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    elif "@" in name:
        name = name.split("@")[0]
    name = name.strip().lower()
    if name.endswith("$"):
        return None  # machine account — excluded from user behavioral model
    if name in {"system", "-", "anonymous logon", "local service",
                "network service"}:
        return None
    return name


def entity_key(value: Any) -> str:
    """Stable lookup key for an entity -- an account or a host -- in the model.

    Deliberately more permissive than :func:`normalize_username`, which returns
    ``None`` for machine and system accounts because they are excluded from the
    *user* behavioural baseline. The engine keys detections on hosts and machine
    accounts as well, so this variant always returns a string. A UPN suffix is
    stripped so ``alice@corp.local`` and ``alice`` resolve to one entity.
    """
    if value is None:
        return ""
    return str(value).strip().lower().split("@")[0]


def hex_to_int(value: Optional[str]) -> Optional[int]:
    if value is None or value in NULL_VALUES:
        return None
    try:
        return int(value, 16) if str(value).startswith("0x") else int(value)
    except (ValueError, TypeError):
        return None


# Matches an ISO-8601 timestamp so the fractional seconds can be separated from
# the timezone. Used only by the fallback path below.
_ISO_TS_RE = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2}(?::\d{2})?)?$"
)


def _parse_iso(ts: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp, tolerant of the shapes real log shippers emit.

    Python 3.11+ ``datetime.fromisoformat`` already handles a trailing ``Z``, a
    space date/time separator, and 1-6 fractional digits, which covers every
    well-formed timestamp the pipeline ingests (Winlogbeat, NXLog, OTRF/Mordor).
    It is tried first.

    The fallback exists for two remaining cases: Windows' 7-digit (100-ns)
    fractional seconds, which have more precision than ``datetime`` can hold, and
    older Python versions whose ``fromisoformat`` rejects ``Z``. Both are handled
    by truncating the fraction to microseconds and normalising the timezone, then
    retrying. (An earlier hand-rolled split mangled a short fraction with a
    timezone -- e.g. ``.927Z`` became ``.927+00+00:00`` -- which silently dropped
    every event carrying that common format; the regex separates the two fields
    correctly.)
    """
    if not ts:
        return None
    s = ts.strip()
    try:
        return datetime.fromisoformat(s)
    except (ValueError, IndexError):
        pass
    m = _ISO_TS_RE.match(s)
    if not m:
        return None
    head = m.group("head")
    frac = (m.group("frac") or "")[:6]           # truncate 7th+ digit; μs is the floor
    tz = m.group("tz") or "+00:00"
    if tz == "Z":
        tz = "+00:00"
    if len(tz) == 5 and ":" not in tz:           # +0000 -> +00:00
        tz = f"{tz[:3]}:{tz[3:]}"
    cleaned = f"{head}.{frac}{tz}" if frac else f"{head}{tz}"
    try:
        return datetime.fromisoformat(cleaned)
    except (ValueError, IndexError):
        return None


# ── Per-event-type canonical field extraction ───────────────────────────────
# Declarative field maps: canonical_name -> raw event_data key. Applied
# generically, then a small set of per-event-id derived-flag functions adds
# the behavioral flags called out explicitly (e.g.
# asrep_roast_flag). This trades a little indirection for not having ~60
# near-identical parsing functions.

_FIELD_MAPS: Dict[str, Dict[str, str]] = {
    "4624": {
        "target_user_name": "TargetUserName", "target_user_sid": "TargetUserSid",
        "target_domain": "TargetDomainName", "target_logon_id": "TargetLogonId",
        "subject_user_name": "SubjectUserName", "subject_logon_id": "SubjectLogonId",
        "logon_type": "LogonType", "logon_process": "LogonProcessName",
        "auth_package": "AuthenticationPackageName", "lm_package": "LmPackageName",
        "impersonation": "ImpersonationLevel", "elevated_token": "ElevatedToken",
        "src_ip": "IpAddress", "src_port": "IpPort", "workstation": "WorkstationName",
        "logon_guid": "LogonGuid", "process_name": "ProcessName",
        "process_id": "ProcessId",
    },
    "4625": {
        "target_user_name": "TargetUserName", "target_user_sid": "TargetUserSid",
        "logon_type": "LogonType", "workstation": "WorkstationName",
        "src_ip": "IpAddress", "src_port": "IpPort", "status": "Status",
        "sub_status": "SubStatus", "failure_reason": "FailureReason",
        "auth_package": "AuthenticationPackageName",
    },
    "4768": {
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
        "service_name": "ServiceName", "ticket_options": "TicketOptions",
        "ticket_enc_type": "EncryptionType", "pre_auth_type": "PreAuthType",
        "status": "Status", "src_ip": "IpAddress", "src_port": "IpPort",
    },
    "4769": {
        "target_user_name": "TargetUserName", "service_name": "ServiceName",
        "service_sid": "ServiceSid", "ticket_options": "TicketOptions",
        "ticket_enc_type": "TicketEncryptionType", "status": "Status",
        "src_ip": "IpAddress", "src_port": "IpPort",
        "transited_services": "TransmittedServices", "logon_guid": "LogonGuid",
    },
    "4771": {
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
        "service_name": "ServiceName", "status": "Status",
        "pre_auth_type": "PreAuthType", "src_ip": "IpAddress", "src_port": "IpPort",
    },
    "4776": {
        "target_user_name": "TargetUserName", "workstation": "Workstation",
        "status": "Status",
    },
    "4648": {
        "subject_user_name": "SubjectUserName", "target_user_name": "TargetUserName",
        "target_server": "TargetServerName", "src_ip": "IpAddress",
        "src_port": "IpPort", "process_name": "ProcessName",
        "subject_logon_id": "SubjectLogonId",
    },
    "4672": {
        "subject_user_name": "SubjectUserName", "subject_logon_id": "SubjectLogonId",
        "privilege_list": "PrivilegeList",
    },
    "4740": {
        "target_user_name": "TargetUserName", "subject_user_name": "SubjectUserName",
        "caller_computer": "CallerComputerName",
    },
    # Account lifecycle family (4720/4722/4724/4725/4726) -- create, enable,
    # password-reset, disable, delete. All share the same Subject*/Target* schema.
    "4720": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "subject_domain": "SubjectDomainName", "subject_logon_id": "SubjectLogonId",
        "target_user_name": "TargetUserName", "target_domain": "TargetDomainName",
        "target_sid": "TargetSid",
    },
    "4722": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4724": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4725": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4726": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "subject_domain": "SubjectDomainName", "subject_logon_id": "SubjectLogonId",
        "target_user_name": "TargetUserName", "target_domain": "TargetDomainName",
        "target_sid": "TargetSid",
    },
    # Group membership family (4728/4729/4732/4738) -- member added/removed from
    # security groups, account attribute changed. MemberSid/MemberName is who was
    # added; TargetUserName is the GROUP (e.g. "Domain Admins"), not the member.
    # Feature attribution keys on SubjectUserName -- who performed the add.
    "4728": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "subject_domain": "SubjectDomainName", "subject_logon_id": "SubjectLogonId",
        "member_sid": "MemberSid", "member_name": "MemberName",
        "target_user_name": "TargetUserName", "target_domain": "TargetDomainName",
        "target_sid": "TargetSid",
    },
    "4729": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "member_sid": "MemberSid", "member_name": "MemberName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4732": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "subject_domain": "SubjectDomainName", "subject_logon_id": "SubjectLogonId",
        "member_sid": "MemberSid", "member_name": "MemberName",
        "target_user_name": "TargetUserName", "target_domain": "TargetDomainName",
        "target_sid": "TargetSid",
    },
    "4738": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    # Computer account lifecycle (4741/4742/4743) -- same shape as
    # 4720/4738/4726 but for machine accounts.
    "4741": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4742": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4743": {
        "subject_user_sid": "SubjectUserSid", "subject_user_name": "SubjectUserName",
        "target_user_name": "TargetUserName", "target_sid": "TargetSid",
    },
    "4662": {
        "subject_user_name": "SubjectUserName", "subject_logon_id": "SubjectLogonId",
        "object_type": "ObjectType", "object_name": "ObjectName",
        "access_mask": "AccessMask", "properties": "Properties",
    },
    "5136": {
        "subject_user_name": "SubjectUserName", "subject_logon_id": "SubjectLogonId",
        "object_dn": "ObjectDN", "object_class": "ObjectClass",
        "attribute_name": "AttributeLDAPDisplayName",
        "attribute_value": "AttributeValue", "operation_type": "OperationType",
    },
    # Sysmon
    "sysmon_1": {
        "process_guid": "ProcessGuid", "process_id": "ProcessId",
        "image": "Image", "original_file_name": "OriginalFileName",
        "command_line": "CommandLine", "current_directory": "CurrentDirectory",
        "user": "User", "integrity_level": "IntegrityLevel",
        "parent_process_guid": "ParentProcessGuid", "parent_image": "ParentImage",
        "parent_command_line": "ParentCommandLine", "hashes": "Hashes",
    },
    "sysmon_3": {
        "process_guid": "ProcessGuid", "image": "Image", "user": "User",
        "protocol": "Protocol", "initiated": "Initiated",
        "src_ip": "SourceIp", "src_port": "SourcePort",
        "dst_ip": "DestinationIp", "dst_port": "DestinationPort",
        "dst_hostname": "DestinationHostname",
    },
    "sysmon_7": {
        "process_guid": "ProcessGuid", "image": "Image",
        "image_loaded": "ImageLoaded", "signed": "Signed",
        "signature_status": "SignatureStatus", "original_file_name": "OriginalFileName",
    },
    "sysmon_8": {
        "source_image": "SourceImage", "target_image": "TargetImage",
        "target_process_guid": "TargetProcessGuid", "start_module": "StartModule",
        "source_user": "SourceUser", "target_user": "TargetUser",
    },
    "sysmon_10": {
        "source_image": "SourceImage", "target_image": "TargetImage",
        "granted_access": "GrantedAccess", "call_trace": "CallTrace",
        "source_user": "SourceUser", "target_user": "TargetUser",
    },
    "sysmon_11": {
        "process_guid": "ProcessGuid", "image": "Image",
        "target_filename": "TargetFilename", "user": "User",
    },
    "sysmon_22": {
        "process_guid": "ProcessGuid", "query_name": "QueryName",
        "query_status": "QueryStatus", "image": "Image", "user": "User",
    },
    # DNS analytical
    "dns_256": {
        "src_ip": "Source", "qname": "QNAME", "qtype": "QTYPE",
        "tcp": "TCP", "rcode": "RCODE",
    },
    # PowerShell
    "4104": {
        "script_block_text": "ScriptBlockText", "script_block_id": "ScriptBlockId",
        "path": "Path",
    },
    "4103": {
        "account_name": "AccountName", "payload": "Payload",
        "command_name": "ContextInfo_Command Name",
        "host_application": "ContextInfo_Host Application",
        "host_name": "ContextInfo_Host Name",
    },
    # Task Scheduler
    "task_106": {"task_name": "TaskName", "user_context": "UserContext"},
    "task_200": {"task_name": "TaskName", "action_name": "ActionName",
                 "task_instance_id": "TaskInstanceId"},
    "task_201": {"task_name": "TaskName", "result_code": "ResultCode",
                 "task_instance_id": "TaskInstanceId"},
    # WMI
    "wmi_5857": {"operation": "Operation", "user": "User"},
    "wmi_5861": {"query": "Query", "consumer": "Consumer", "user": "User"},
    # Defender
    "defender_1116": {"threat_name": "ThreatName", "severity": "Severity",
                       "path": "Path"},
    "defender_1117": {"threat_name": "ThreatName", "action": "ActionTaken"},
}

_INT_FIELDS = {"logon_type", "src_port", "process_id", "granted_access_int"}
_HEX_FIELDS = {"process_id", "src_port"}  # process_id often hex-string "0x91c"


def _event_type_key(channel: str, event_id: str) -> str:
    """Resolves the lookup key into _FIELD_MAPS, disambiguating channels that
    reuse small numeric event IDs (Sysmon EID 1 vs Security EID 1, DNS 256
    vs anything else, WMI/Defender/TaskScheduler numeric collisions)."""
    if "Sysmon" in channel:
        return f"sysmon_{event_id}"
    if "DNS-Server" in channel:
        return f"dns_{event_id}"
    if "TaskScheduler" in channel:
        return f"task_{event_id}"
    if "WMI-Activity" in channel:
        return f"wmi_{event_id}"
    if "Windows Defender" in channel:
        return f"defender_{event_id}"
    return event_id  # Security channel event IDs are used as-is


def _extract_envelope(raw: dict) -> Optional[dict]:
    """Handles both the Winlogbeat-nested and flat-NXLog envelope shapes.
    Returns None (caller quarantines) if neither shape is recognizable."""
    if "winlog" in raw:
        winlog = raw.get("winlog", {})
        event = raw.get("event", {})
        return {
            "event_time_raw": raw.get("@timestamp"),
            "ingest_time_raw": event.get("created"),
            "channel": winlog.get("channel"),
            "event_id": winlog.get("event_id"),
            "computer_name": winlog.get("computer_name")
                              or raw.get("host", {}).get("name"),
            "outcome": event.get("outcome"),
            "keywords": winlog.get("keywords", []),
            "event_data": winlog.get("event_data", {}),
        }
    if "EventID" in raw or "event_id" in raw:
        # Flat NXLog-style shape. Real shippers disagree on the event-time field:
        # NXLog writes `EventTime`, Winlogbeat/Logstash `@timestamp`, and some
        # Windows exports only `TimeCreated`. All three appear across public
        # Windows datasets (e.g. OTRF/Mordor captures use each in different runs),
        # so all three are accepted; the first present wins.
        return {
            "event_time_raw": (raw.get("EventTime") or raw.get("@timestamp")
                               or raw.get("TimeCreated")),
            "ingest_time_raw": None,
            "channel": raw.get("Channel") or raw.get("channel"),
            "event_id": str(raw.get("EventID") or raw.get("event_id")),
            "computer_name": raw.get("Hostname") or raw.get("host"),
            "outcome": None,
            "keywords": [],
            "event_data": {k: v for k, v in raw.items()
                            if k not in {"EventTime", "Channel", "EventID",
                                          "Hostname", "SourceName"}},
        }
    return None


def normalize_event(raw: dict, keep_raw: bool = True) -> Optional[NormalizedEvent]:
    """Top-level entry point. Returns None only if the record has no
    recognizable envelope at all (caller should count/log this as a
    quarantined record, never silently discard).

    keep_raw=False drops the original event_data dict from the returned
    NormalizedEvent. No feature extractor reads raw_event_data, so this is safe
    for the batch training/scoring path and roughly halves per-event memory.
    Default True preserves audit/debug behavior and all existing callers.
    """
    env = _extract_envelope(raw)
    if env is None:
        return None

    channel = env["channel"] or ""
    event_id = str(env["event_id"] or "")
    event_data = env["event_data"] or {}
    warnings: list = []

    event_time = _parse_iso(env["event_time_raw"])
    if event_time is None:
        warnings.append("missing_or_unparseable_event_time")

    type_key = _event_type_key(channel, event_id)
    field_map = _FIELD_MAPS.get(type_key)

    # A feature group is claimed only for events we can actually extract fields
    # from. An event registered in EVENT_GROUP but lacking a field map (e.g. a
    # logoff 4634 under "auth", or DNS response 257) would otherwise be counted
    # toward its group's capability-manifest volume while contributing no
    # features -- the exact "group reports available, extractor emits all zeros"
    # phantom the capability manifest exists to prevent. Unmapped events still
    # produce a NormalizedEvent (event_type="unknown", raw preserved) so nothing
    # is silently dropped and the bootstrap scan still sees the true event mix.
    group = EVENT_GROUP.get((channel, event_id)) if field_map else None

    fields: Dict[str, Any] = {}
    if field_map:
        for canonical, raw_key in field_map.items():
            fields[canonical] = event_data.get(raw_key)
        _apply_type_casts(fields)
        _apply_derived_flags(type_key, fields)
        event_type = type_key
    else:
        event_type = "unknown"

    return NormalizedEvent(
        event_time=event_time,
        ingest_time=env["ingest_time_raw"],
        channel=channel,
        event_id=event_id,
        event_type=event_type,
        group=group,
        computer_name=env["computer_name"],
        outcome=env["outcome"],
        keywords=env["keywords"] or [],
        fields=fields,
        raw_event_data=event_data if keep_raw else {},
        parse_warnings=warnings,
    )


def _apply_type_casts(fields: Dict[str, Any]) -> None:
    for key in ("src_ip", "dst_ip", "target_server"):
        if key in fields:
            fields[key] = normalize_ip(fields[key])
    for key in ("target_user_name", "subject_user_name", "user",
                "source_user", "target_user", "account_name"):
        if key in fields and fields[key] is not None:
            fields[f"{key}_norm"] = normalize_username(fields[key])
    if "logon_type" in fields:
        fields["logon_type"] = hex_to_int(fields["logon_type"])
    if "process_id" in fields:
        fields["process_id"] = hex_to_int(fields["process_id"])
    if "src_port" in fields:
        fields["src_port"] = hex_to_int(fields["src_port"])
    if "signed" in fields:
        fields["signed"] = str(fields.get("signed")).lower() == "true"
    if "initiated" in fields:
        fields["initiated"] = str(fields.get("initiated")).lower() == "true"
    if "tcp" in fields:
        fields["tcp"] = str(fields.get("tcp")) == "1"


def _apply_derived_flags(type_key: str, fields: Dict[str, Any]) -> None:
    """Behavioral flags derived once at parse time,
    computed once at parse time so every downstream feature/model doesn't
    recompute the same string comparisons."""
    if type_key == "4625":
        fields["is_valid_user_wrong_pw"] = fields.get("sub_status") == "0xc000006a"
        fields["is_user_not_found"] = fields.get("sub_status") == "0xc0000064"
        fields["is_locked_out"] = fields.get("sub_status") == "0xc0000234"
    elif type_key == "4768":
        fields["is_rc4_ticket"] = fields.get("ticket_enc_type") == "0x17"
        fields["is_preauth_disabled"] = fields.get("pre_auth_type") == "0"
        fields["asrep_roast_flag"] = (
            fields.get("pre_auth_type") == "0"
            and fields.get("status") == "0x0"
            and fields.get("ticket_enc_type") == "0x17"
        )
    elif type_key == "4769":
        svc = fields.get("service_name") or ""
        fields["is_rc4_ticket"] = fields.get("ticket_enc_type") == "0x17"
        fields["is_machine_spn"] = svc.endswith("$")
        fields["kerberoast_flag"] = (
            fields.get("ticket_enc_type") == "0x17"
            and not svc.endswith("$")
            and fields.get("status") == "0x0"
        )
        fields["delegation_flag"] = (
            fields.get("transited_services") not in NULL_VALUES
        )
    elif type_key == "4771":
        fields["is_wrong_pw"] = fields.get("status") == "0x18"
        fields["is_bad_user"] = fields.get("status") == "0x6"
    elif type_key == "4776":
        fields["is_ntlm_success"] = fields.get("status") == "0x0"
    elif type_key == "sysmon_1":
        image = (fields.get("image") or "").split("\\")[-1].lower()
        image = image[:-4] if image.endswith(".exe") else image
        orig = (fields.get("original_file_name") or "").lower()
        orig = orig[:-4] if orig.endswith(".exe") else orig
        fields["is_masquerade"] = bool(orig) and orig not in ("-", "") and orig != image
    elif type_key == "sysmon_7":
        fields["is_unsigned"] = fields.get("signed") is False
    elif type_key == "sysmon_10":
        dump_masks = {"0x1fffff", "0x1f1fff", "0x1010", "0x143a", "0x1438", "0x0820"}
        ga = (fields.get("granted_access") or "").lower()
        fields["is_credential_dump_access"] = ga in dump_masks
        fields["is_lsass_target"] = "lsass.exe" in (fields.get("target_image") or "").lower()
    elif type_key == "dns_256":
        fields["is_txt_query"] = fields.get("qtype") == "16"
        fields["is_any_query"] = fields.get("qtype") == "255"
        fields["is_nxdomain"] = fields.get("rcode") == "3"
    elif type_key == "4104":
        text = (fields.get("script_block_text") or "").lower()
        fields["is_in_memory_exec"] = not (fields.get("path") or "").strip()
        fields["has_encoded_cmd"] = "-enc" in text or "-encodedcommand" in text
        fields["has_download_cradle"] = any(
            k in text for k in ("downloadstring", "invoke-webrequest", "net.webclient")
        )
        fields["has_credential_dump_kw"] = any(
            k in text for k in ("invoke-mimikatz", "sekurlsa", "procdump",
                                  "minidumpwritedump")
        )
    elif type_key == "4662":
        # DCSync detection: a
        # non-DC-machine-account subject touching AD replication rights.
        props = (fields.get("properties") or "").lower()
        replication_guids = (
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # Replicating Directory Changes All
            "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2",  # Replicating Directory Changes
            "9923a32a-3607-11d2-b9be-0000f87a36b2",  # DS-Replication-Synchronize
        )
        subject = fields.get("subject_user_name") or ""
        fields["dcsync_flag"] = (
            any(g in props for g in replication_guids)
            and not subject.endswith("$")
        )
    elif type_key == "5136":
        # RBCD delegation abuse / Kerberoasting setup
        # (RBCD / SPN manipulation).
        attr = (fields.get("attribute_name") or "")
        op = fields.get("operation_type") or ""
        fields["rbcd_modify_flag"] = attr == "msDS-AllowedToActOnBehalfOfOtherIdentity"
        fields["spn_add_flag"] = (
            attr == "servicePrincipalName" and op == "Value Added"
        )
