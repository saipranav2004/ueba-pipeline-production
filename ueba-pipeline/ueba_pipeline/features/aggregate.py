"""
features/aggregate.py — per-(entity, hour) behavioural feature vectors.

Feature groups are computed from the event families the parser extracts canonical
fields for. Coverage is explicitly partial (it is a fraction of a mature SIEM's
analytics surface); the capability manifest gates each group on what a deployment
actually ships, so a missing source degrades the feature set honestly rather than
producing silent zeros.

Every feature belongs to exactly one feature group, and a group is computed only
if the CapabilityManifest reports it available — see docs/architecture.md.
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np

from ueba_pipeline.features.manifest import CapabilityManifest
from ueba_pipeline.parsing.normalize import NormalizedEvent

# Machine / system identities excluded from the behavioural model.
_EXCLUDE_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}


# Event types where TargetUserName names the OBJECT acted on (a group, an AD
# object, an SPN) rather than a user account. The behavioural vector must carry
# these on the principal who performed the action (SubjectUserName), not on the
# object's name -- otherwise a group add creates a pseudo-identity keyed on the
# group string and the actor's own vector shows nothing.
_SUBJECT_ATTRIBUTED_EVENT_TYPES = frozenset({
    "4728", "4729", "4732", "4733", "4738",  # group membership / account attr change
    "4741", "4742", "4743",                   # computer account lifecycle
    "5136",                                    # AD attribute modify (RBCD/SPN)
})

# Sysmon events whose actor is the SourceUser, not the target. For
# CreateRemoteThread (EID 8) and ProcessAccess (EID 10) the behavioural owner is
# the accessing/injecting process's user; the target is the victim process owner
# (frequently SYSTEM), which is the wrong entity to attribute the behaviour to.
_SOURCE_USER_ATTRIBUTED_EVENT_TYPES = frozenset({"sysmon_8", "sysmon_10"})

# Failed-authentication event types that carry (src_ip, victim) and feed the
# cross-entity password-spray fan-out aggregation. 4625 = interactive/network
# logon failure; 4771 = Kerberos pre-authentication failure. A real spray
# produces both -- typically far more 4771 than 4625 -- so both are counted.
_FAILED_AUTH_EVENT_TYPES = frozenset({"4625", "4771"})


def _user_key(ne: NormalizedEvent) -> Optional[str]:
    """Resolve the behavioural-model user key for one event, excluding machine
    and SYSTEM identities.

    `source_user_norm` is in every branch's fallback chain so no event family is
    dropped for lack of a candidate field; the per-family ordering picks the
    correct actor first (subject for directory ops, source for Sysmon
    access/injection, target otherwise)."""
    if ne.event_type in _SUBJECT_ATTRIBUTED_EVENT_TYPES:
        candidates = ("subject_user_name_norm", "user_norm",
                      "source_user_norm", "target_user_name_norm",
                      "account_name_norm")
    elif ne.event_type in _SOURCE_USER_ATTRIBUTED_EVENT_TYPES:
        candidates = ("source_user_norm", "user_norm",
                      "subject_user_name_norm", "target_user_name_norm",
                      "account_name_norm")
    else:
        candidates = ("target_user_name_norm", "user_norm",
                      "source_user_norm", "subject_user_name_norm",
                      "account_name_norm")
    for candidate in candidates:
        val = ne.fields.get(candidate)
        if val:
            return val
    return None


def _issuance_ips_before(
    history: Sequence[Tuple[datetime, str]], when: datetime
) -> Set[str]:
    """Source addresses an account was issued a Kerberos ticket from before ``when``.

    ``history`` must be ordered by timestamp. Tuple ordering makes ``(when,)`` sort
    ahead of every ``(when, ip)``, so the bisect returns the count of entries
    strictly earlier than ``when`` — the information a live detector would hold at
    that instant, and nothing later.
    """
    cutoff = bisect.bisect_left(history, (when,))
    return {ip for _, ip in history[:cutoff]}


# Each extractor receives the list of NormalizedEvent belonging to one user
# in one window, restricted to event types relevant to its group, and
# returns a flat feature dict. Kept as plain functions (not classes) —
# there's no state beyond the window's event list.

def _auth_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    e4624 = [e for e in events if e.event_type == "4624"]
    e4625 = [e for e in events if e.event_type == "4625"]
    e4672 = [e for e in events if e.event_type == "4672"]
    total_logons = len(e4624) or 1
    total_failures = len(e4625)

    def pct(logon_type: int) -> float:
        return sum(1 for e in e4624 if e.fields.get("logon_type") == logon_type) / total_logons

    # Aggregate IP features for password spray detection (T1110.003).
    fail_by_ip: Dict[str, set] = defaultdict(set)
    for e in e4625:
        ip = e.fields.get("src_ip")
        target = e.fields.get("target_user_name_norm") or e.fields.get("target_user_name")
        if ip and target:
            fail_by_ip[ip].add(target)
    max_targets_per_ip = max((len(v) for v in fail_by_ip.values()), default=0)

    return {
        "f_logon_count": float(len(e4624)),
        "f_failed_logon_count": float(total_failures),
        "f_fail_success_ratio": total_failures / total_logons,
        "f_pct_type2_interactive": pct(2),
        "f_pct_type3_network": pct(3),
        "f_pct_type8_cleartext": pct(8),
        "f_pct_type9_newcred": pct(9),
        "f_pct_type10_rdp": pct(10),
        "f_pct_ntlm_auth": sum(
            1 for e in e4624 if e.fields.get("auth_package") == "NTLM"
        ) / total_logons,
        "f_privileged_logon_count": float(len(e4672)),
        "f_distinct_src_ips": float(len({
            e.fields.get("src_ip") for e in e4624 if e.fields.get("src_ip")
        })),
        "f_distinct_workstations": float(len({
            e.fields.get("workstation") for e in e4624
            if e.fields.get("workstation") and e.fields.get("workstation") != "-"
        })),
        # Spray-specific: max distinct accounts targeted by any single IP
        "f_spray_max_targets_per_ip": float(max_targets_per_ip),
        "f_spray_distinct_fail_ips": float(len(fail_by_ip)),
        "f_spray_has_cross_user_failure": float(max_targets_per_ip > 1),
        # Golden/Silver Ticket: placeholder defaults (0.0) so
        # feature_order_for_manifest discovers these names. The real values
        # are computed in build_user_windows cross-group post-processing
        # (which has access to both auth and kerberos events) and overwrite
        # these in FeatureVector.values.
        "f_golden_ticket_flag": 0.0,
        "f_silver_ticket_flag": 0.0,
    }


def _kerberos_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    e4768 = [e for e in events if e.event_type == "4768"]
    e4769 = [e for e in events if e.event_type == "4769"]
    e4771 = [e for e in events if e.event_type == "4771"]
    tgs_count = len(e4769) or 1

    return {
        "f_tgt_request_count": float(len(e4768)),
        "f_tgt_rc4_count": float(sum(1 for e in e4768 if e.fields.get("is_rc4_ticket"))),
        "f_asrep_roast_flag": float(any(e.fields.get("asrep_roast_flag") for e in e4768)),
        "f_tgs_request_count": float(len(e4769)),
        "f_tgs_rc4_count": float(sum(1 for e in e4769 if e.fields.get("is_rc4_ticket"))),
        "f_tgs_rc4_pct": sum(1 for e in e4769 if e.fields.get("is_rc4_ticket")) / tgs_count,
        "f_distinct_spns": float(len({
            e.fields.get("service_name") for e in e4769 if e.fields.get("service_name")
        })),
        "f_nonmachine_spn_count": float(sum(
            1 for e in e4769 if not e.fields.get("is_machine_spn")
        )),
        "f_kerberoast_flag": float(any(e.fields.get("kerberoast_flag") for e in e4769)),
        "f_delegation_flag": float(any(e.fields.get("delegation_flag") for e in e4769)),
        "f_preauth_fail_count": float(len(e4771)),
        "f_preauth_wrong_pw_count": float(sum(
            1 for e in e4771 if e.fields.get("is_wrong_pw")
        )),
    }


def _process_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    """Sysmon-sourced process / network / injection behaviour. Covers process
    create (EID 1), network connect (3), image load (7), CreateRemoteThread
    (8, code injection), ProcessAccess (10), file create (11), and per-process
    DNS (22)."""
    p1 = [e for e in events if e.event_type == "sysmon_1"]
    p3 = [e for e in events if e.event_type == "sysmon_3"]
    p7 = [e for e in events if e.event_type == "sysmon_7"]
    p8 = [e for e in events if e.event_type == "sysmon_8"]
    p10 = [e for e in events if e.event_type == "sysmon_10"]
    p11 = [e for e in events if e.event_type == "sysmon_11"]
    p22 = [e for e in events if e.event_type == "sysmon_22"]

    return {
        "f_process_create_count": float(len(p1)),
        "f_distinct_processes": float(len({
            e.fields.get("image") for e in p1 if e.fields.get("image")
        })),
        "f_masquerade_flag": float(any(e.fields.get("is_masquerade") for e in p1)),
        "f_outbound_conn_count": float(sum(
            1 for e in p3 if e.fields.get("initiated")
        )),
        "f_distinct_dest_ips": float(len({
            e.fields.get("dst_ip") for e in p3 if e.fields.get("dst_ip")
        })),
        "f_unsigned_dll_load_count": float(sum(
            1 for e in p7 if e.fields.get("is_unsigned")
        )),
        "f_remote_thread_count": float(len(p8)),
        "f_reflective_inject_flag": float(any(
            not (e.fields.get("start_module") or "").strip() for e in p8
        )),
        "f_lsass_access_flag": float(any(e.fields.get("is_lsass_target") for e in p10)),
        "f_credential_dump_access_flag": float(any(
            e.fields.get("is_credential_dump_access") for e in p10
        )),
        "f_temp_file_drop_count": float(sum(
            1 for e in p11
            if any(seg in (e.fields.get("target_filename") or "").lower()
                   for seg in ("\\temp\\", "\\appdata\\"))
        )),
        "f_per_process_dns_query_count": float(len(p22)),
        "f_per_process_dns_diversity": float(len({
            e.fields.get("query_name") for e in p22 if e.fields.get("query_name")
        })),
        # NTDS.dit dump indicator (T1003.003): Sysmon EID 1 where the image is
        # vssadmin/ntdsutil/diskshadow (Atomic Red Team T1003.003). Informational
        # only -- excluded from the ML vector like all indicator flags.
        "f_ntds_dump_tool_flag": float(any(
            any(kw in (e.fields.get("command_line") or "").lower() for kw in
                 ("vssadmin", "ntdsutil", "diskshadow"))
            for e in p1
        )),
    }


def _task_scheduler_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    """Scheduled-task persistence / execution behaviour (T1053.005), from Task
    Scheduler events 106 (registered), 200 (action run), 201 (action completed)."""
    t106 = [e for e in events if e.event_type == "task_106"]
    t200 = [e for e in events if e.event_type == "task_200"]
    t201 = [e for e in events if e.event_type == "task_201"]
    lolbins = ("powershell", "cmd.exe", "wscript", "cscript", "mshta",
               "regsvr32", "rundll32", "certutil", "bitsadmin")

    return {
        "f_task_registered_count": float(len(t106)),
        "f_task_action_count": float(len(t200)),
        "f_task_action_lolbin_flag": float(any(
            any(b in (e.fields.get("action_name") or "").lower() for b in lolbins)
            for e in t200
        )),
        "f_task_failed_count": float(sum(
            1 for e in t201
            if (e.fields.get("result_code") or "0") not in ("0", "0x0")
        )),
    }


def _wmi_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    """WMI activity: T1047 execution (5857) and T1546.003 event-subscription
    persistence (5861)."""
    w5857 = [e for e in events if e.event_type == "wmi_5857"]
    w5861 = [e for e in events if e.event_type == "wmi_5861"]

    return {
        "f_wmi_operation_count": float(len(w5857)),
        "f_wmi_event_subscription_count": float(len(w5861)),
        "f_wmi_distinct_consumers": float(len({
            e.fields.get("consumer") for e in w5861 if e.fields.get("consumer")
        })),
    }


def _defender_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    """Windows Defender AV/EDR verdicts (1116 detected, 1117 action taken).
    `f_malware_detected_flag` is a first-party AV verdict, not an inferred
    behavioural signal -- among the highest-value binary features available."""
    d1116 = [e for e in events if e.event_type == "defender_1116"]
    d1117 = [e for e in events if e.event_type == "defender_1117"]

    return {
        "f_malware_detected_flag": float(bool(d1116)),
        "f_malware_detection_count": float(len(d1116)),
        "f_malware_action_taken_count": float(len(d1117)),
    }


def _privilege_ad_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    """AD object-access / attribute-modification behaviour: DCSync (T1003.006,
    event 4662) and RBCD / SPN manipulation (T1134.001 / T1558.003 setup,
    event 5136)."""
    e4662 = [e for e in events if e.event_type == "4662"]
    e5136 = [e for e in events if e.event_type == "5136"]

    return {
        "f_dcsync_flag": float(any(e.fields.get("dcsync_flag") for e in e4662)),
        "f_ad_object_access_count": float(len(e4662)),
        "f_rbcd_modify_flag": float(any(e.fields.get("rbcd_modify_flag") for e in e5136)),
        "f_spn_add_flag": float(any(e.fields.get("spn_add_flag") for e in e5136)),
        "f_ad_attr_modify_count": float(len(e5136)),
    }


def _dns_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    d256 = [e for e in events if e.event_type == "dns_256"]
    total = len(d256) or 1
    qnames = [e.fields.get("qname") for e in d256 if e.fields.get("qname")]

    def entropy(s: str) -> float:
        if not s:
            return 0.0
        from math import log2
        probs = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * log2(p) for p in probs if p > 0)

    return {
        "f_dns_query_count": float(len(d256)),
        "f_unique_domains": float(len(set(qnames))),
        "f_nxdomain_rate": sum(1 for e in d256 if e.fields.get("is_nxdomain")) / total,
        "f_txt_query_count": float(sum(1 for e in d256 if e.fields.get("is_txt_query"))),
        "f_any_query_count": float(sum(1 for e in d256 if e.fields.get("is_any_query"))),
        "f_avg_qname_entropy": (
            float(np.mean([entropy(q.rstrip(".")) for q in qnames])) if qnames else 0.0
        ),
        "f_max_qname_len": float(max((len(q) for q in qnames), default=0)),
    }


def _powershell_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    p4104 = [e for e in events if e.event_type == "4104"]

    return {
        "f_ps_script_count": float(len({
            e.fields.get("script_block_id") for e in p4104
            if e.fields.get("script_block_id")
        })),
        "f_in_memory_exec_flag": float(any(e.fields.get("is_in_memory_exec") for e in p4104)),
        "f_encoded_cmd_flag": float(any(e.fields.get("has_encoded_cmd") for e in p4104)),
        "f_download_cradle_flag": float(any(e.fields.get("has_download_cradle") for e in p4104)),
        "f_credential_dump_kw_flag": float(any(
            e.fields.get("has_credential_dump_kw") for e in p4104
        )),
    }


def _account_lifecycle_features(events: List[NormalizedEvent]) -> Dict[str, float]:
    """Account lifecycle events (4720/4726/4722/4725/4728/4729/4732/4733/4738/
    4741/4742/4743): onboarding, offboarding, group membership changes,
    password resets, computer account management. These capture identity
    lifecycle signals that pure behavioral models miss — a sudden spike in
    account creation or privileged group membership changes is a distinct
    anomaly class from unusual login patterns.
    """
    e4720 = [e for e in events if e.event_type == "4720"]
    e4726 = [e for e in events if e.event_type == "4726"]
    e4722 = [e for e in events if e.event_type == "4722"]
    e4725 = [e for e in events if e.event_type == "4725"]
    e4728 = [e for e in events if e.event_type == "4728"]
    e4729 = [e for e in events if e.event_type == "4729"]
    e4732 = [e for e in events if e.event_type == "4732"]
    e4738 = [e for e in events if e.event_type == "4738"]
    e4741 = [e for e in events if e.event_type == "4741"]
    e4742 = [e for e in events if e.event_type == "4742"]
    e4743 = [e for e in events if e.event_type == "4743"]
    e4724 = [e for e in events if e.event_type == "4724"]

    return {
        "f_account_created_count": float(len(e4720)),
        "f_account_deleted_count": float(len(e4726)),
        "f_account_enabled_count": float(len(e4722)),
        "f_account_disabled_count": float(len(e4725)),
        "f_group_member_added_count": float(len(e4728) + len(e4732)),
        "f_group_member_removed_count": float(len(e4729)),
        "f_account_changed_count": float(len(e4738)),
        "f_computer_account_created": float(len(e4741)),
        "f_computer_account_changed": float(len(e4742)),
        "f_computer_account_deleted": float(len(e4743)),
        "f_password_reset_count": float(len(e4724)),
        # Privileged group membership change indicator (T1098): additions to
        # Domain Admins, Enterprise Admins, or Schema Admins. Informational only;
        # the model detects this behaviourally via the graph dir_change view.
        "f_privileged_group_add_flag": float(any(
            (e.fields.get("target_user_name") or "").lower() in
             ("domain admins", "enterprise admins", "schema admins")
            for e in e4728 + e4732
        )),
        "f_total_lifecycle_events": float(
            len(e4720) + len(e4726) + len(e4722) + len(e4725) +
            len(e4728) + len(e4729) + len(e4732) + len(e4738) +
            len(e4741) + len(e4742) + len(e4743) + len(e4724)
        ),
    }


_GROUP_EXTRACTORS: Dict[str, Callable[[List[NormalizedEvent]], Dict[str, float]]] = {
    "auth": _auth_features,
    "kerberos": _kerberos_features,
    "sysmon_process": _process_features,
    "dns": _dns_features,
    "powershell": _powershell_features,
    "task_scheduler": _task_scheduler_features,
    "wmi": _wmi_features,
    "defender": _defender_features,
    "privilege_ad": _privilege_ad_features,
    "account_lifecycle": _account_lifecycle_features,
}

# Which event_types feed which extractor — used to pre-filter the per-user
# event list once instead of each extractor re-scanning everything. Must stay
# 1:1 with _GROUP_EXTRACTORS: every group with an extractor lists the event
# types it consumes here, and each of those event types must have a field map
# in normalize.py (otherwise the events arrive as event_type="unknown" and the
# extractor sees an empty list. The capability manifest guards against that
# phantom coverage: a group is claimed only for events that actually mapped).
_GROUP_EVENT_TYPES: Dict[str, set] = {
    "auth": {"4624", "4625", "4672"},
    "kerberos": {"4768", "4769", "4771"},
    "sysmon_process": {"sysmon_1", "sysmon_3", "sysmon_7", "sysmon_8",
                        "sysmon_10", "sysmon_11", "sysmon_22"},
    "dns": {"dns_256"},
    "powershell": {"4104"},
    "task_scheduler": {"task_106", "task_200", "task_201"},
    "wmi": {"wmi_5857", "wmi_5861"},
    "defender": {"defender_1116", "defender_1117"},
    "privilege_ad": {"4662", "5136"},
    "account_lifecycle": {"4720", "4722", "4724", "4725", "4726", "4728", "4729", "4732", "4738", "4741", "4742", "4743"},
}


@dataclass
class FeatureVector:
    user: str
    window_start: datetime
    window_end: datetime
    values: Dict[str, float] = field(default_factory=dict)
    group_provenance: Dict[str, str] = field(default_factory=dict)  # feature -> group
    # Relational edge endpoints observed for this entity in this window
    # (workstation, src_ip). Retained for provenance/inspection; live edge
    # anomalies are computed per-event by the graph track (auth_graph_anomaly),
    # not from this per-window summary.
    edges: Dict[str, List[str]] = field(default_factory=dict)

    def as_array(self, feature_order: List[str]) -> np.ndarray:
        return np.array([self.values.get(f, 0.0) for f in feature_order], dtype=np.float64)


def feature_order_for_manifest(manifest: CapabilityManifest) -> List[str]:
    """Deterministic, sorted feature ordering for a given manifest — this is
    what gets persisted alongside a trained model (persistence/store.py) so
    scoring always maps columns consistently."""
    names: List[str] = []
    for group in sorted(_GROUP_EXTRACTORS):
        if not manifest.is_group_available(group):
            continue
        # Compute against an empty list to discover the group's feature
        # names without needing real data — cheap and avoids a second
        # hardcoded name list drifting out of sync with the extractors.
        names.extend(sorted(_GROUP_EXTRACTORS[group]([]).keys()))
    return names


def observed_entity_windows(
    events: List[NormalizedEvent],
    window_hours: float,
) -> Set[Tuple[str, datetime]]:
    """The ``(entity, window_start)`` pairs an entity was observed in.

    This is the number of tests an entity received, which the Šidák correction in
    the rollup needs: taking a minimum over n windows is itself a test over n
    windows. Only the keys matter there, never a feature value, so this uses the
    same entity resolution and bucket arithmetic as :func:`build_user_windows`
    but runs none of the extractors. Keeping the keying in one place is what makes
    the two interchangeable for that purpose; changing attribution here without
    changing it there would silently alter every correction.
    """
    window_seconds = window_hours * 3600.0
    observed: Set[Tuple[str, datetime]] = set()
    for ne in events:
        if ne.event_time is None:
            continue
        user = _user_key(ne)
        if not user:
            continue
        bucket = int(ne.event_time.timestamp() // window_seconds)
        observed.add((user, datetime.fromtimestamp(bucket * window_seconds,
                                                    tz=ne.event_time.tzinfo)))
    return observed


def build_user_windows(
    events: List[NormalizedEvent],
    manifest: CapabilityManifest,
    window_hours: float,
) -> List[FeatureVector]:
    """
    Buckets events by user and fixed-size UTC time window, then computes
    every available feature group per (user, window). Events with no
    resolvable user key or no event_time are excluded up front (they can't
    be attributed to a behavioral baseline) and counted by the caller via
    IngestStats, not silently absorbed here.
    """
    by_user_window: Dict[tuple, List[NormalizedEvent]] = defaultdict(list)
    window_seconds = window_hours * 3600.0

    # Cross-entity aggregation. Password spray (T1110.003) is a CROSS-user
    # pattern -- one source IP failing against many accounts -- so its defining
    # signal (distinct accounts targeted per source IP) cannot be computed inside
    # a single user's window: that window contains only one victim, so a per-user
    # count is structurally <= 1. Failed-logon fan-out is aggregated per
    # (source_ip, window bucket) across ALL users, then each attacking IP's true
    # fan-out is attributed back onto every victim window it touched.
    ip_bucket_targets: Dict[tuple, set] = defaultdict(set)

    # Per-user TGT/TGS issuance history, for the golden/silver ticket indicators
    # below. A forged ticket never contacts the DC, so it presents from a host the
    # victim's account never legitimately requested a ticket from. The
    # discriminator is "no TGT/TGS for this account from this IP BEFORE NOW", not
    # "none in this hour" (a TGT issued each morning is reused all day).
    #
    # Stored as time-ordered (timestamp, ip) pairs rather than a flat set so each
    # window can be evaluated against the history available AT THAT WINDOW. A flat
    # set accumulated over the whole batch would let a window at hour t see ticket
    # issuance from hours > t: the account's later-in-the-batch legitimate use of
    # an address would retroactively mark the attacker's use of it as familiar.
    # That is a look-ahead dependence, and it is not reproducible at inference
    # where only the past exists.
    user_tgt_history: Dict[str, List[tuple]] = defaultdict(list)
    user_tgs_history: Dict[str, List[tuple]] = defaultdict(list)

    for ne in events:
        if ne.event_time is None:
            continue
        user = _user_key(ne)
        if not user:
            continue
        epoch = ne.event_time.timestamp()
        bucket = int(epoch // window_seconds)
        by_user_window[(user, bucket)].append(ne)
        if ne.event_type == "4768":
            ip = ne.fields.get("src_ip")
            if ip:
                user_tgt_history[user].append((ne.event_time, ip))
        elif ne.event_type == "4769":
            ip = ne.fields.get("src_ip")
            if ip:
                user_tgs_history[user].append((ne.event_time, ip))
        if ne.event_type in _FAILED_AUTH_EVENT_TYPES:
            ip = ne.fields.get("src_ip")
            if ip:
                # `user` here is the victim (both 4625 and 4771 attribute to the
                # target account); count distinct victims per IP/bucket. Both
                # failure types are included because a real spray produces both.
                ip_bucket_targets[(ip, bucket)].add(user)

    # Order each account's issuance history once, so the causal prefix lookup
    # below is a binary search rather than a rescan.
    for history in (user_tgt_history, user_tgs_history):
        for entries in history.values():
            entries.sort(key=lambda entry: entry[0])

    active_groups = [g for g in _GROUP_EXTRACTORS if manifest.is_group_available(g)]

    vectors: List[FeatureVector] = []
    for (user, bucket), user_events in by_user_window.items():
        window_start = datetime.fromtimestamp(bucket * window_seconds,
                                                tz=user_events[0].event_time.tzinfo)
        window_end = datetime.fromtimestamp((bucket + 1) * window_seconds,
                                              tz=user_events[0].event_time.tzinfo)
        fv = FeatureVector(user=user, window_start=window_start, window_end=window_end)
        for group in active_groups:
            relevant = [e for e in user_events if e.event_type in _GROUP_EVENT_TYPES[group]]
            group_features = _GROUP_EXTRACTORS[group](relevant)
            for k, v in group_features.items():
                fv.values[k] = v
                fv.group_provenance[k] = group

        # Cross-entity override: replace the per-user spray fan-out features
        # (structurally <= 1) with the true cross-user distinct-target count of
        # each source IP that failed against this user in this window, so a spray
        # victim carries the attacking IP's full fan-out.
        if "auth" in active_groups:
            victim_ips = {
                e.fields.get("src_ip") for e in user_events
                if e.event_type in _FAILED_AUTH_EVENT_TYPES and e.fields.get("src_ip")
            }
            max_fanout = max(
                (len(ip_bucket_targets[(ip, bucket)]) for ip in victim_ips),
                default=0,
            )
            fv.values["f_spray_max_targets_per_ip"] = float(max_fanout)
            fv.values["f_spray_has_cross_user_failure"] = float(max_fanout > 1)
            fv.group_provenance["f_spray_max_targets_per_ip"] = "cross_entity_auth"
            fv.group_provenance["f_spray_has_cross_user_failure"] = "cross_entity_auth"

        # Cross-group indicator: Golden/Silver Ticket (T1558.001/T1558.002).
        # These need events from both the auth (4624) and kerberos (4768/4769)
        # groups, so they cannot live in a single-group extractor. Each Type-3
        # Kerberos logon's src_ip is tested against the account's ENTIRE observed
        # TGT/TGS issuance history: a forged ticket presents from an IP the
        # account never legitimately requested a ticket from. (These flags are
        # informational only -- like all indicator flags they are excluded from
        # the ML vector; forged-ticket detection in the model is the graph track's
        # novel user_src edge.)
        if "auth" in active_groups and "kerberos" in active_groups:
            tgt_history = user_tgt_history.get(user, ())
            tgs_history = user_tgs_history.get(user, ())

            # Count Type-3 Kerberos logons presenting from an address this account
            # had not been issued a ticket from at the moment of the logon. Each
            # logon is tested against the history available strictly before it, so
            # the count is reproducible at inference time.
            golden_count = 0
            silver_count = 0
            for e in user_events:
                if (e.event_type == "4624"
                        and e.fields.get("logon_type") == 3
                        and e.fields.get("auth_package") == "Kerberos"):
                    lip = e.fields.get("src_ip")
                    if not lip:
                        continue
                    if lip not in _issuance_ips_before(tgt_history, e.event_time):
                        golden_count += 1
                    if lip not in _issuance_ips_before(tgs_history, e.event_time):
                        silver_count += 1

            fv.values["f_golden_ticket_flag"] = float(golden_count)
            fv.values["f_silver_ticket_flag"] = float(silver_count)
            fv.group_provenance["f_golden_ticket_flag"] = "cross_group_auth_kerberos"
            fv.group_provenance["f_silver_ticket_flag"] = "cross_group_auth_kerberos"

        # Relational edge endpoints (workstations / source IPs this entity
        # authenticated from this window), retained for provenance. Live
        # edge-novelty is scored per-event by the graph track (confirmed on data:
        # the PtH victim's baseline is one workstation, and the attack window
        # introduces a novel workstation AND a novel src_ip simultaneously).
        fv.edges = {
            "workstation": sorted({
                e.fields.get("workstation") for e in user_events
                if e.event_type in ("4624", "4625")
                and e.fields.get("workstation") and e.fields.get("workstation") != "-"
            }),
            "src_ip": sorted({
                e.fields.get("src_ip") for e in user_events
                if e.event_type in ("4624", "4625", "4768") and e.fields.get("src_ip")
            }),
        }

        vectors.append(fv)

    return vectors
