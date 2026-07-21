"""
run_simulation.py — Main entry point for the Nexovate Solutions enterprise log simulator.

Produces correlated Windows telemetry across 7 log sources for 253 employees
over 58 business days (12 weeks, Jan–Mar 2025).

Output structure:
  output/security_logs/        JSONL — Windows Security channel events
  output/sysmon_logs/          JSONL — Sysmon Operational events
  output/dns_logs/             JSONL — DNS Server Analytical events
  output/powershell_logs/      JSONL — PowerShell Operational events
  output/task_scheduler_logs/  JSONL — Task Scheduler Operational events
  output/wmi_logs/             JSONL — WMI Activity Operational events
  output/defender_logs/        JSONL — Windows Defender Operational events
  output/kafka_json/           JSONL — All sources combined, chronological
  output/csv_exports/          CSV  — Flat exports per source per week

Usage:
    python run_simulation.py              # full 58 business days
    python run_simulation.py --days 3     # quick test (3 days)
    python run_simulation.py --seed 42    # fixed seed for reproducibility
    python run_simulation.py --quiet      # suppress per-day progress
"""

from __future__ import annotations
import argparse
import csv
import json
import os
import random
import shutil
import sys
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, date
from typing import List, Dict, Any

sys.path.insert(0, os.path.dirname(__file__))

# The banner and progress output contain box-drawing and dash glyphs. On a stock
# Windows console (cp1252) these raise UnicodeEncodeError mid-run, which --quiet
# does not suppress. Force UTF-8 with a lossy fallback so the simulator runs on
# any platform without corrupting the (ASCII-only) JSONL it writes to disk.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from config.company import RANDOM_SEED, SIM_START_DATE, DEPARTMENTS, ADMIN_ACCOUNTS
from core.employees import (build_employee_roster, build_service_accounts,
                             stable_seed, roster_to_peer_group_map)
from core.event_bus import EventBus
from attacks import ATTACK_REGISTRY, AttackLabel
from core.time_engine import (
    all_sim_dates, is_business_day, parse_date, AbsenceCalendar,
)
from core.daily_simulation import (
    simulate_employee_day,
    simulate_service_account_day,
    simulate_it_admin_day,
    simulate_lifecycle_events,
    simulate_routine_group_management,
    simulate_defender_event,
    DayResult,
)

# SimulatorConfig integration: department behavioral overrides can be
# loaded from ueba_pipeline/config/schema.py's SimulatorConfig and
# applied to the DEPARTMENTS dict at runtime. This is not yet wired
# automatically — it's a structural hook for the ueba_pipeline CLI
# to call when it has a validated config that includes simulator
# department overrides.

# ── Output directories ────────────────────────────────────────────────────────
BASE_OUTPUT = os.path.join(os.path.dirname(__file__), "output")

SOURCE_DIRS: Dict[str, str] = {
    "security":       os.path.join(BASE_OUTPUT, "security_logs"),
    "sysmon":         os.path.join(BASE_OUTPUT, "sysmon_logs"),
    "dns":            os.path.join(BASE_OUTPUT, "dns_logs"),
    "powershell":     os.path.join(BASE_OUTPUT, "powershell_logs"),
    "task_scheduler": os.path.join(BASE_OUTPUT, "task_scheduler_logs"),
    "wmi":            os.path.join(BASE_OUTPUT, "wmi_logs"),
    "defender":       os.path.join(BASE_OUTPUT, "defender_logs"),
    "kafka":          os.path.join(BASE_OUTPUT, "kafka_json"),
    "csv":            os.path.join(BASE_OUTPUT, "csv_exports"),
}

# ── CSV field schemas — flattened view per source ─────────────────────────────
CSV_FIELDS: Dict[str, List[str]] = {
    "security": [
        "timestamp", "event_id", "computer", "channel", "outcome", "task",
        "target_user_name", "subject_user_name", "target_domain",
        "logon_type", "auth_package", "lm_package", "src_ip", "workstation",
        "status", "sub_status", "target_logon_id", "elevated_token",
        "logon_process", "service_name", "share_name", "object_name",
    ],
    "sysmon": [
        "timestamp", "event_id", "computer", "process_guid", "process_id",
        "image", "command_line", "user", "integrity_level", "parent_image",
        "target_object", "details", "event_type",
        "dest_ip", "dest_port", "dest_hostname",
        "query_name", "query_results",
        "target_filename", "granted_access", "target_image",
        "pipe_name", "image_loaded", "signed", "driver_image",
    ],
    "dns": [
        "timestamp", "event_id", "dns_server", "source_ip",
        "qname", "qtype", "rcode", "tcp", "zone", "xid",
    ],
    "powershell": [
        "timestamp", "event_id", "computer", "user",
        "script_block_id", "script_block_text_preview",
        "path", "level", "command_name", "host_name",
        "host_application", "runspace_id",
    ],
    "task_scheduler": [
        "timestamp", "event_id", "computer",
        "task_name", "action_name", "user_context",
        "task_instance_id", "result_code",
    ],
    "wmi": [
        "timestamp", "event_id", "computer",
        "provider_name", "host_process", "process_id", "provider_path",
        "operation", "user", "client_machine", "result_code",
        "namespace", "filter_name", "consumer_name", "query",
    ],
    "defender": [
        "timestamp", "event_id", "computer",
        "threat_name", "severity", "category", "path",
        "detection_user", "action", "error_code",
        "setting_old_value", "setting_new_value",
    ],
}


def _ensure_dirs() -> None:
    """
    Wipe and recreate BASE_OUTPUT before every run, so that orphaned per-day log
    files from a longer prior run cannot be ingested alongside fresh data when a
    later run regenerates fewer days (per-day files are opened in truncate mode,
    but dates the new run never touches would otherwise be left behind).
    """
    if os.path.isdir(BASE_OUTPUT):
        shutil.rmtree(BASE_OUTPUT)
    for d in SOURCE_DIRS.values():
        os.makedirs(d, exist_ok=True)


def _jsonl_path(source: str, sim_date: date) -> str:
    date_str = sim_date.strftime("%Y-%m-%d")
    return os.path.join(SOURCE_DIRS.get(source, SOURCE_DIRS["security"]),
                        f"{date_str}.jsonl")


def _kafka_path(sim_date: date) -> str:
    return os.path.join(SOURCE_DIRS["kafka"],
                        f"{sim_date.strftime('%Y-%m-%d')}.jsonl")


def _csv_path(source: str, week_num: int) -> str:
    return os.path.join(SOURCE_DIRS["csv"], f"{source}_week{week_num:02d}.csv")


def _flatten_event(source: str, ev: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a nested Winlogbeat JSON event to a CSV-ready dict."""
    winlog = ev.get("winlog", {})
    ed     = winlog.get("event_data", {})
    emeta  = ev.get("event", {})

    row: Dict[str, Any] = {
        "timestamp":  ev.get("@timestamp", ""),
        "event_id":   winlog.get("event_id", ""),
        "computer":   winlog.get("computer_name", ""),
        "channel":    winlog.get("channel", ""),
        "outcome":    emeta.get("outcome", ""),
        "task":       winlog.get("task", ""),
    }

    if source == "security":
        row.update({
            "target_user_name": ed.get("TargetUserName", ""),
            "subject_user_name":ed.get("SubjectUserName", ""),
            "target_domain":    ed.get("TargetDomainName", ""),
            "logon_type":       ed.get("LogonType", ""),
            "auth_package":     ed.get("AuthenticationPackageName", ""),
            "lm_package":       ed.get("LmPackageName", ""),
            "src_ip":           ed.get("IpAddress", ""),
            "workstation":      ed.get("WorkstationName", ""),
            "status":           ed.get("Status", ""),
            "sub_status":       ed.get("SubStatus", ""),
            "target_logon_id":  ed.get("TargetLogonId", ""),
            "elevated_token":   ed.get("ElevatedToken", ""),
            "logon_process":    ed.get("LogonProcessName", ""),
            "service_name":     ed.get("ServiceName", ""),
            "share_name":       ed.get("ShareName", ""),
            "object_name":      ed.get("ObjectName", ""),
        })
    elif source == "sysmon":
        row.update({
            "process_guid":  ed.get("ProcessGuid", ""),
            "process_id":    ed.get("ProcessId", ""),
            "image":         ed.get("Image", ""),
            "command_line":  ed.get("CommandLine", ""),
            "user":          ed.get("User", ""),
            "integrity_level":ed.get("IntegrityLevel", ""),
            "parent_image":  ed.get("ParentImage", ""),
            "target_object": ed.get("TargetObject", ""),
            "details":       ed.get("Details", ""),
            "event_type":    ed.get("EventType", ""),
            "dest_ip":       ed.get("DestinationIp", ""),
            "dest_port":     ed.get("DestinationPort", ""),
            "dest_hostname": ed.get("DestinationHostname", ""),
            "query_name":    ed.get("QueryName", ""),
            "query_results": ed.get("QueryResults", ""),
            "target_filename":ed.get("TargetFilename", ""),
            "granted_access":ed.get("GrantedAccess", ""),
            "target_image":  ed.get("TargetImage", ""),
            "pipe_name":     ed.get("PipeName", ""),
            "image_loaded":  ed.get("ImageLoaded", ""),
            "signed":        ed.get("Signed", ""),
            "driver_image":  ed.get("ImageLoaded", ""),   # EID 6 uses ImageLoaded
        })
    elif source == "dns":
        row.update({
            "dns_server": winlog.get("computer_name", ""),
            "source_ip":  ed.get("Source", ""),
            "qname":      ed.get("QNAME", ""),
            "qtype":      ed.get("QTYPE", ""),
            "rcode":      ed.get("RCODE", ""),
            "tcp":        ed.get("TCP", ""),
            "zone":       ed.get("Zone", ""),
            "xid":        ed.get("XID", ""),
        })
    elif source == "powershell":
        row.update({
            "user":                      winlog.get("user", {}).get("identifier", ""),
            "script_block_id":           ed.get("ScriptBlockId", ""),
            "script_block_text_preview": ed.get("ScriptBlockText", "")[:200],
            "path":                      ed.get("Path", ""),
            "level":                     ev.get("log", {}).get("level", ""),
            "command_name":              ed.get("ContextInfo_Command Name", ""),
            "host_name":                 ed.get("ContextInfo_Host Name", ""),
            "host_application":          ed.get("ContextInfo_Host Application", ""),
            "runspace_id":               ed.get("ContextInfo_Runspace ID", ""),
        })
    elif source == "task_scheduler":
        row.update({
            "task_name":        ed.get("TaskName", ""),
            "action_name":      ed.get("ActionName", ""),
            "user_context":     ed.get("UserContext", ""),
            "task_instance_id": ed.get("TaskInstanceId", ""),
            "result_code":      ed.get("ResultCode", ""),
        })
    elif source == "wmi":
        row.update({
            "provider_name":  ed.get("ProviderName", ""),
            "host_process":   ed.get("HostProcess", ""),
            "process_id":     ed.get("ProcessID", ""),
            "provider_path":  ed.get("ProviderPath", ""),
            "operation":      ed.get("Operation", ""),
            "user":           ed.get("User", ""),
            "client_machine": ed.get("ClientMachine", ""),
            "result_code":    ed.get("ResultCode", "") or ed.get("Code", ""),
            "namespace":      ed.get("Namespace", ""),
            "filter_name":    ed.get("FilterName", ""),
            "consumer_name":  ed.get("ConsumerName", ""),
            "query":          ed.get("Query", ""),
        })
    elif source == "defender":
        row.update({
            "threat_name":      ed.get("Threat Name", ""),
            "severity":         ed.get("Severity Name", ""),
            "category":         ed.get("Category Name", ""),
            "path":             ed.get("Path", ""),
            "detection_user":   ed.get("Detection User", ""),
            "action":           ed.get("Action Name", ""),
            "error_code":       ed.get("Error Code", ""),
            "setting_old_value":ed.get("Old Value", ""),
            "setting_new_value":ed.get("New Value", ""),
        })

    return row


class WeeklyCSVWriter:
    """Accumulates events per source per week, writes CSV at week boundary."""

    def __init__(self):
        self._rows: Dict[str, List[Dict]] = defaultdict(list)

    def add(self, source: str, ev_data: Dict[str, Any]) -> None:
        if source == "kafka":
            return
        self._rows[source].append(_flatten_event(source, ev_data))

    def flush(self, week_num: int) -> None:
        for source, rows in self._rows.items():
            if not rows:
                continue
            path   = _csv_path(source, week_num)
            fields = CSV_FIELDS.get(source, list(rows[0].keys()))
            write_header = not os.path.exists(path)
            with open(path, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                if write_header:
                    writer.writeheader()
                writer.writerows(rows)
        self._rows.clear()


class JSONLWriter:
    """Buffers and writes JSONL files; reuses file handles across calls."""

    def __init__(self, buffer_size: int = 500):
        self._handles: Dict[str, Any] = {}
        self._buf:     Dict[str, List[str]] = defaultdict(list)
        self._buf_size = buffer_size

    def write(self, path: str, event: Dict[str, Any]) -> None:
        self._buf[path].append(json.dumps(event, default=str))
        if len(self._buf[path]) >= self._buf_size:
            self._flush_path(path)

    def _flush_path(self, path: str) -> None:
        if not self._buf[path]:
            return
        if path not in self._handles:
            self._handles[path] = open(path, "w", encoding="utf-8")
        self._handles[path].write("\n".join(self._buf[path]) + "\n")
        self._handles[path].flush()
        self._buf[path].clear()

    def flush_all(self) -> None:
        for path in list(self._buf.keys()):
            self._flush_path(path)

    def close_all(self) -> None:
        self.flush_all()
        for fh in self._handles.values():
            try:
                fh.close()
            except Exception:
                pass
        self._handles.clear()


# ── Main simulation loop ──────────────────────────────────────────────────────
def apply_simulator_config_overrides(config_overrides: dict) -> None:
    """Apply SimulatorConfig department overrides to the DEPARTMENTS dict.

    This bridges the ueba_pipeline config system with the enterprise
    simulator, allowing department behavioral parameters (remote_fraction,
    login_start_mean, work_duration_mean, ps_scripts_per_week) to be
    externally configured rather than hardcoded.

    Args:
        config_overrides: dict mapping department name -> behavioral params,
            e.g. {"Engineering": {"remote_fraction": 0.6, ...}}
    """
    for dept_name, overrides in config_overrides.items():
        if dept_name not in DEPARTMENTS:
            continue
        dept = DEPARTMENTS[dept_name]
        if "remote_fraction" in overrides:
            dept.remote_fraction = float(overrides["remote_fraction"])
        if "login_start_mean_ist" in overrides:
            dept.login_start_mean = float(overrides["login_start_mean_ist"])
        if "login_start_std" in overrides:
            dept.login_start_std = float(overrides["login_start_std"])
        if "work_duration_mean_hours" in overrides:
            dept.work_duration_mean = float(overrides["work_duration_mean_hours"])
        if "work_duration_std" in overrides:
            dept.work_duration_std = float(overrides["work_duration_std"])
        if "ps_scripts_per_week" in overrides:
            dept.ps_scripts_per_week = float(overrides["ps_scripts_per_week"])


def run(max_days: int = 9999, seed: int = RANDOM_SEED, quiet: bool = False,
        inject_attacks: str = "", attack_count: int = 5,
        attack_placement: str = "uniform",
        dump_roster: str | None = None,
        config_overrides: dict | None = None) -> int:
    _ensure_dirs()

    print("=" * 62)
    print("  Nexovate Solutions Pvt. Ltd. — Enterprise Log Simulator")
    print("  Bangalore, India  ·  Timezone: IST (UTC+5:30)")
    print("=" * 62)

    # Apply SimulatorConfig overrides if provided
    if config_overrides:
        apply_simulator_config_overrides(config_overrides)

    roster = build_employee_roster()
    sas    = build_service_accounts()
    it_admins = [e for e in roster if e.department == "IT"]

    print(f"  Employees:         {len(roster)}")
    print(f"  Service accounts:  {len(sas)}")
    print(f"  IT staff:          {len(it_admins)}")

    # Peer-group roster export -- ueba_pipeline.cli.main's documented `train`
    # command takes --roster and does a bare `open()` on it; nothing in this
    # module produced that file, which made the project's own verified
    # Quickstart command fail with FileNotFoundError. Shape is deliberately
    # a flat {samaccountname.lower(): department} map, matching exactly what
    # ueba_pipeline.parsing.normalize.normalize_username produces as a user
    # key -- a richer Employee-record export would silently disagree with
    # that normalization and break peer-group joins in a way that's much
    # harder to notice than a missing file.
    roster_path = dump_roster if dump_roster else os.path.join(BASE_OUTPUT, "roster.json")
    with open(roster_path, "w") as f:
        json.dump(roster_to_peer_group_map(roster), f, indent=2)
    print(f"  Peer-group roster: {roster_path}")

    # Estate topology export for `ueba_pipeline.cli.main graph-viz --directory`.
    #
    # The roster alone carries no Tier-0 designation, so graph-viz built from it
    # reported n_tier0_assets = 0 -- which silently zeroes the largest-weighted
    # term of the composite risk score (tier0_risk_weight = 0.40), reducing it to
    # a centrality blend that no longer sums to 1. The simulator already knows
    # which hosts are DCs and which accounts are privileged; not emitting that
    # was the gap. See graph/identity_graph.py.
    from config.company import ADMIN_ACCOUNTS, DOMAIN_CONTROLLERS, SERVERS
    directory_path = os.path.join(BASE_OUTPUT, "directory.json")
    with open(directory_path, "w") as f:
        # Shape must match what build_identity_graph_from_roster consumes:
        # lists of dicts keyed hostname/role/fqdn for hosts, and
        # samaccountname/real_user/tier for admin accounts.
        json.dump({
            "domain_controllers": [
                {"hostname": d["hostname"], "fqdn": d["fqdn"], "role": d["role"]}
                for d in DOMAIN_CONTROLLERS
            ],
            "servers": [
                {"hostname": s["hostname"], "fqdn": s["fqdn"], "role": s["role"]}
                for s in SERVERS
            ],
            "admin_accounts": [
                {"samaccountname": a["samaccountname"], "real_user": a["real_user"],
                 "tier": a["tier"]}
                for a in ADMIN_ACCOUNTS
            ],
            "service_accounts": [
                {"samaccountname": sa.samaccountname, "server_hostname": sa.server_hostname}
                for sa in build_service_accounts()
            ],
        }, f, indent=2)
    print(f"  Estate directory:  {directory_path}")

    sim_start  = parse_date(SIM_START_DATE)
    all_dates  = all_sim_dates()
    # We iterate ALL calendar days so that:
    #   - Service accounts run on weekends (backup, SQL jobs don't stop)
    #   - IT/Engineering employees can log in on weekends (5% chance per their logic)
    # simulate_employee_day() handles the weekend skip for non-IT/Eng internally.
    biz_days   = [d for d in all_dates if is_business_day(d)]
    all_sim    = all_dates[:max_days]  # full calendar including weekends
    biz_days   = biz_days[:max_days]   # for progress reporting / week numbering
    print(f"  Business days:     {len(biz_days)}  ({biz_days[0]} → {biz_days[-1]})")
    print(f"  Calendar days:     {len(all_sim)}  (incl. weekends/holidays)")
    print()

    # Per-entity seeded RNGs — isolated so entity A's events don't affect B
    emp_rngs:  Dict[str, random.Random] = {}
    emp_cals:  Dict[str, AbsenceCalendar] = {}
    for emp in roster:
        er = random.Random(stable_seed(seed, emp.samaccountname))
        emp_rngs[emp.samaccountname] = er
        emp_cals[emp.samaccountname] = AbsenceCalendar(er, emp.samaccountname)

    svc_rngs: Dict[str, random.Random] = {
        svc.samaccountname: random.Random(stable_seed(seed, svc.samaccountname))
        for svc in sas
    }

    lifecycle_rng = random.Random(seed ^ 0xDEADBEEF)
    group_mgmt_rng = random.Random(seed ^ 0x9E3779B9)
    bus = EventBus(random.Random(seed), sim_seed=seed)

    # ── Attack injection scheduling ─────────────────────────────────────────
    # Off by default (inject_attacks=""). Uses its own RNG stream, seeded
    # separately from every other stream in this run, so enabling/disabling
    # attack injection never changes the reproducible output of the normal
    # (non-attack) traffic -- turning this flag on adds events, it does not
    # perturb anything else.
    attack_rng = random.Random(seed ^ 0xA77ACC)
    attack_schedule: Dict[date, List[str]] = defaultdict(list)
    attack_labels: List[AttackLabel] = []
    if inject_attacks:
        requested_types = (
            list(ATTACK_REGISTRY.keys()) if inject_attacks == "all"
            else [t.strip() for t in inject_attacks.split(",") if t.strip()]
        )
        unknown = set(requested_types) - set(ATTACK_REGISTRY.keys())
        if unknown:
            raise ValueError(
                f"unknown attack type(s) {unknown}; available: "
                f"{sorted(ATTACK_REGISTRY.keys())}"
            )
        # Only schedule on days the day loop will actually visit. biz_days
        # is computed by filtering business days from the full multi-week
        # date range and THEN slicing to max_days, while all_sim is sliced
        # to max_days FIRST -- for a short run (e.g. --days 7) this makes
        # biz_days include dates beyond what all_sim actually contains
        # (verified directly: a --days 7 run's biz_days included Jan 13
        # and Jan 15, which the day loop never reaches when it only
        # iterates the first 7 calendar days). Scheduling an attack on a
        # day the loop never visits means it silently never fires -- no
        # error, no warning, just missing from the output. Intersecting
        # with all_sim here is the minimal fix; biz_days' own computation
        # is left alone since other callers (week numbering, progress
        # display) tolerate the mismatch harmlessly.
        eligible_days = sorted(d for d in biz_days if d in set(all_sim))

        # Placement controls WHERE in the timeline attacks land. Random-uniform
        # placement scatters them anywhere, which routinely drops most attacks
        # into the training slice of a walk-forward split (they are then
        # correctly excluded from training and simply never scored, depressing
        # measurable recall for a reason that has nothing to do with detector
        # quality). For a defensible evaluation the attacks must fall in the
        # held-out tail. Modes:
        #   uniform : sample distinct days uniformly (default; realistic-ish,
        #             but weak for evaluation on short runs).
        #   tail    : restrict candidate days to the last test_fraction of the
        #             timeline, so every injected attack is scoreable by
        #             walk-forward. Use this for evaluation runs.
        #   spread  : one attack on every eligible day, cycling through the
        #             requested types, to maximize per-technique instance
        #             counts across the whole period.
        # Multiple attacks per day are allowed (a day maps to a list), so a
        # long run can reach statistically meaningful per-technique counts
        # rather than being capped at one-per-day.
        placement = (attack_placement or "uniform").lower()
        if placement == "tail":
            # Reserve the last ~40% of eligible days as the injection zone.
            # This comfortably covers a 0.2 test_fraction plus the inter-fold
            # gap, so injected attacks land in a held-out slice of at least
            # one fold.
            cut = max(1, int(len(eligible_days) * 0.6))
            candidate_days = eligible_days[cut:] or eligible_days[-1:]
        else:
            candidate_days = eligible_days

        # Balanced, seed-varied technique coverage. A balanced multiset of the
        # requested types (each appearing ~attack_count / n_types times) is
        # shuffled with the per-run attack RNG, then distributed round-robin
        # across the placement's candidate days (multiple attacks per day are
        # allowed). This gives a walk-forward evaluation two properties it needs:
        #   (1) COMPLETE coverage -- every requested technique is injected, so the
        #       held-out tail of a time split contains a sample of ALL techniques
        #       rather than a fixed subset.
        #   (2) SEED VARIANCE -- the shuffle is seeded per run, so which technique
        #       lands in the test window varies across seeds, making multi-seed
        #       confidence intervals count independent draws.
        # `spread` distributes over all eligible days (attacks throughout the
        # timeline, realistic); `tail`/`uniform` distribute over their candidate
        # window (last 40% for tail) so every injected attack is scoreable.
        days_for_placement = eligible_days if placement == "spread" else candidate_days
        n_attacks = attack_count or len(days_for_placement)
        n_types = len(requested_types)
        reps = (n_attacks + n_types - 1) // n_types
        type_pool = (list(requested_types) * reps)[:n_attacks]
        attack_rng.shuffle(type_pool)

        attack_schedule = defaultdict(list)
        for i, attack_type in enumerate(type_pool):
            attack_schedule[days_for_placement[i % len(days_for_placement)]].append(attack_type)

    jsonl   = JSONLWriter(buffer_size=500)
    csv_w   = WeeklyCSVWriter()
    skipped_days: List[str] = []   # employee-days lost to a generator fault

    total_events = 0
    week_of: Dict[date, int] = {d: (i // 5 + 1) for i, d in enumerate(biz_days)}
    t0 = time.time()

    for day_idx, sim_date in enumerate(all_sim):
        day_events: List[tuple] = []
        week_num   = week_of.get(sim_date, 0)  # 0 for weekends/holidays

        # ── Employee workdays ──────────────────────────────────────────────
        for emp in roster:
            rng  = emp_rngs[emp.samaccountname]
            acal = emp_cals[emp.samaccountname]
            try:
                result = simulate_employee_day(emp, sim_date, bus, acal, rng, sim_start)
            except Exception as exc:
                # Counted and surfaced at the end even under --quiet: a fault here
                # drops an entire employee-day, and a silent partial dataset is far
                # more dangerous than a loud failure -- it trains and benchmarks
                # against data nobody knows is missing.
                skipped_days.append(f"{emp.samaccountname} {sim_date}: {exc}")
                if not quiet:
                    print(f"  [WARN] {emp.samaccountname} {sim_date}: {exc}")
                continue

            # IT staff run admin sessions — 25% daily chance per IT employee.
            # The session uses a rotating named ADMIN_ACCOUNTS SAM (not the
            # employee's daily-use SAM), correctly modeling tiered admin usage.
            if emp.department == "IT" and rng.random() < 0.25:
                try:
                    emp_idx = it_admins.index(emp) if emp in it_admins else 0
                    adm_entry = ADMIN_ACCOUNTS[emp_idx % len(ADMIN_ACCOUNTS)]
                    emp.admin_sam = emp.admin_sam or adm_entry["samaccountname"]
                    adm = simulate_it_admin_day(emp, sim_date, bus, rng, sim_start, roster=roster)
                    result.events.extend(adm.events)
                except Exception as exc:
                    if not quiet:
                        print(f"  [WARN] IT admin {emp.samaccountname} {sim_date}: {exc}")

            # Rare Defender event (~0.1% of user-days)
            if rng.random() < 0.001:
                try:
                    def_result = simulate_defender_event(emp, sim_date, bus, rng)
                    result.events.extend(def_result.events)
                except Exception as exc:
                    if not quiet:
                        print(f"  [WARN] defender {emp.samaccountname} {sim_date}: {exc}")

            for ev in result.sorted_events():
                day_events.append((ev.source, ev.ts, ev.data))

        # ── Service account activity ───────────────────────────────────────
        for svc in sas:
            rng = svc_rngs[svc.samaccountname]
            try:
                result = simulate_service_account_day(svc, sim_date, bus, rng)
            except Exception as exc:
                if not quiet:
                    print(f"  [WARN] {svc.samaccountname} {sim_date}: {exc}")
                continue
            for ev in result.sorted_events():
                day_events.append((ev.source, ev.ts, ev.data))

        # ── Weekly lifecycle events (onboarding, offboarding, transfers) ───
        # Run on first business day of each week (Monday equivalent)
        is_first_of_week = (is_business_day(sim_date) and
                         (day_idx == 0 or week_of.get(all_sim[day_idx - 1], 0) != week_num))
        if is_first_of_week:
            try:
                lc = simulate_lifecycle_events(it_admins, roster, sim_date, bus, lifecycle_rng)
                for ev in lc.sorted_events():
                    day_events.append((ev.source, ev.ts, ev.data))
            except Exception as exc:
                if not quiet:
                    print(f"  [WARN] lifecycle {sim_date}: {exc}")

        # ── Routine daily group/access management (benign directory churn) ──
        # Every business day helpdesk admins process access requests against
        # ordinary department/file-share groups. This is the baseline the graph
        # track's directory view learns from, so a privileged-group escalation
        # stands out as novel rather than being the first group change ever seen.
        try:
            gm = simulate_routine_group_management(it_admins, roster, sim_date, bus, group_mgmt_rng)
            for ev in gm.sorted_events():
                day_events.append((ev.source, ev.ts, ev.data))
        except Exception as exc:
            if not quiet:
                print(f"  [WARN] group-mgmt {sim_date}: {exc}")

        # ── Injected attack(s) (if scheduled for this day) ──────────────────
        # attack_schedule maps a day to a LIST of attack types, so more than
        # one attack can be injected on the same day (needed to reach
        # statistically meaningful per-technique counts on longer runs).
        for attack_type in attack_schedule.get(sim_date, []):
            try:
                inject_fn = ATTACK_REGISTRY[attack_type]
                attack_events, label = inject_fn(roster, bus, sim_date, attack_rng)
                for source, ts, ev_data in attack_events:
                    day_events.append((source, ts, ev_data))
                attack_labels.append(label)
                if not quiet:
                    print(f"  [ATTACK] injected {attack_type} on {sim_date} "
                          f"({len(attack_events)} events)")
            except Exception as exc:
                if not quiet:
                    print(f"  [WARN] attack injection {attack_type} {sim_date}: {exc}")

        # ── Sort all day's events by timestamp ─────────────────────────────
        day_events.sort(key=lambda x: x[1])

        # ── Write events ───────────────────────────────────────────────────
        kafka_path = _kafka_path(sim_date)
        for source, ts, ev_data in day_events:
            # Per-source JSONL
            jsonl.write(_jsonl_path(source, sim_date), ev_data)
            # Kafka combined JSONL (all sources, timestamped, source-tagged)
            kafka_event = dict(ev_data)
            kafka_event["_log_source"] = source
            jsonl.write(kafka_path, kafka_event)
            # CSV accumulator
            csv_w.add(source, ev_data)

        total_events += len(day_events)

        # ── Flush CSV at week boundary ─────────────────────────────────────
        next_week = week_of.get(all_sim[day_idx + 1], -1) if day_idx + 1 < len(all_sim) else -1
        if next_week != week_num:
            csv_w.flush(week_num)

        if not quiet:
            elapsed = time.time() - t0
            rate    = total_events / max(elapsed, 0.01)
            print(f"  Day {day_idx+1:2d}/{len(biz_days)} [{sim_date}]  "
                  f"IST business hours 09:00–18:30  "
                  f"events={len(day_events):5d}  "
                  f"total={total_events:7,d}  "
                  f"elapsed={elapsed:.1f}s  "
                  f"rate={rate:.0f}/s")

    jsonl.close_all()

    if attack_labels:
        labels_path = os.path.join(BASE_OUTPUT, "attack_labels.jsonl")
        with open(labels_path, "w") as f:
            for label in attack_labels:
                f.write(json.dumps(asdict(label)) + "\n")
        print(f"  Injected attacks:        {len(attack_labels)}  (labels: {labels_path})")

    print()
    print("=" * 62)
    print(f"  Simulation complete.")
    print(f"  Total events generated:  {total_events:,}")
    if skipped_days:
        # Always reported, including under --quiet: a partial dataset must never
        # look like a healthy one.
        print(f"  !! SKIPPED employee-days:  {len(skipped_days)} "
              f"(dataset is INCOMPLETE -- first: {skipped_days[0]})")
    print(f"  Total time:              {time.time() - t0:.1f}s")
    print(f"  Output:                  {BASE_OUTPUT}/")
    print("=" * 62)
    return total_events


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Nexovate Solutions — Enterprise Log Simulator"
    )
    parser.add_argument("--days",  type=int, default=9999,
                        help="Simulate only first N business days (default: all 59)")
    parser.add_argument("--seed",  type=int, default=RANDOM_SEED,
                        help="Random seed (default: 20250106)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress per-day progress output")
    parser.add_argument("--inject-attacks", type=str, default="",
                        help="Comma-separated attack types to inject "
                             "(pass_the_hash,kerberoasting,password_spray), "
                             "or 'all'. Off by default -- see attacks.py.")
    parser.add_argument("--dump-roster", type=str, default=None,
                         help="Path to write the peer-group roster JSON "
                              "({samaccountname.lower(): department}) that "
                              "graph-viz --directory consumes. "
                              "Defaults to <output-dir>/roster.json, "
                              "written unconditionally on every run since "
                              "training/scoring always need it.")
    parser.add_argument("--attack-count", type=int, default=5,
                        help="Number of attack instances to inject across "
                             "the simulated period (default: 5)")
    parser.add_argument("--attack-placement", type=str, default="uniform",
                        choices=["uniform", "tail", "spread"],
                        help="Where attacks land in time. 'uniform': scattered "
                             "(realistic, weak for eval). 'tail': in the last "
                             "~40%% of days so walk-forward can score them "
                             "(use for evaluation). 'spread': one per day, "
                             "cycling types, for max per-technique counts.")
    parser.add_argument("--config", type=str, default=None,
                        help="Path to YAML config file with simulator "
                             "department overrides (UEBA__SIMULATOR__DEPARTMENTS__*)")
    parser.add_argument("--headcount-scale", type=float, default=1.0,
                        help="Multiply every department's headcount by this "
                             "factor. Generates a larger or smaller estate from "
                             "the same profiles, which is how identity-scaling "
                             "behaviour is measured (scripts/"
                             "benchmark_performance.py).")
    args = parser.parse_args()

    if args.headcount_scale != 1.0:
        for dept in DEPARTMENTS.values():
            dept.headcount = max(1, int(round(dept.headcount * args.headcount_scale)))
        total = sum(d.headcount for d in DEPARTMENTS.values())
        if not args.quiet:
            print(f"  headcount scaled by {args.headcount_scale}x -> {total} employees")

    # Load config overrides if a config file is provided
    config_overrides_dict: dict | None = None
    if args.config:
        try:
            from ueba_pipeline.config.schema import load_config
            cfg = load_config(args.config)
            if cfg.simulator.departments:
                config_overrides_dict = {
                    name: dept.model_dump()
                    for name, dept in cfg.simulator.departments.items()
                }
        except Exception as exc:
            print(f"  [WARN] Could not load config overrides: {exc}", file=sys.stderr)

    run(max_days=args.days, seed=args.seed, quiet=args.quiet,
        inject_attacks=args.inject_attacks, attack_count=args.attack_count,
        attack_placement=args.attack_placement,
        dump_roster=args.dump_roster,
        config_overrides=config_overrides_dict)
