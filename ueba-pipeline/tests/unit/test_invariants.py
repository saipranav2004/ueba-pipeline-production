"""Pipeline invariants that are easy to break silently.

Each test states a property the pipeline must hold and why holding it matters.
The failures these guard against are quiet ones -- a mis-keyed lookup that simply
misses, a double-counted event stream, an edge keyed on a value that churns --
which produce plausible-looking numbers rather than an error.
"""

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.features.manifest import CapabilityManifest
from ueba_pipeline.parsing.normalize import normalize_username


def test_normalize_username_strips_netbios_prefix():
    """Sysmon's NetBIOS User field must resolve to the same identity as the SAM
    name that Security-log events carry.

    Two spellings of one account would otherwise fragment a single real user's
    behaviour across two model buckets, halving the evidence behind each.
    """
    assert normalize_username("NEXOVATE\\gsundaram") == "gsundaram"
    assert normalize_username("nexovate\\gsundaram") == "gsundaram"


def test_normalize_username_strips_upn_suffix():
    """Existing UPN-handling behavior must not regress while fixing the
    NetBIOS case above."""
    assert normalize_username("jsmith@CORP.LOCAL") == "jsmith"


def test_normalize_username_excludes_machine_accounts():
    assert normalize_username("WORKSTATION01$") is None
    assert normalize_username("NEXOVATE\\WORKSTATION01$") is None


def test_file_event_source_excludes_merged_representation_dirs(tmp_path):
    """
    enterprise_simulator writes every event to BOTH a per-channel
    directory (e.g. security_logs/) AND a merged kafka_json/ directory
    containing the same events combined into one stream. from_directory()'s
    recursive glob must not read both and double-count every event.
    This test builds a minimal directory with one real event in a
    per-channel dir and a duplicate of it in kafka_json/, and asserts only
    one copy is ingested.
    """
    from ueba_pipeline.ingestion.source import FileEventSource

    event = {
        "@timestamp": "2026-01-06T08:00:00.000Z",
        "winlog": {
            "event_id": "4624", "channel": "Security",
            "computer_name": "DC01.test.local", "record_id": 1,
            "keywords": ["Audit Success"],
            "event_data": {"TargetUserName": "jsmith", "LogonType": "3"},
        },
        "event": {"outcome": "success"},
        "host": {"name": "DC01.test.local"},
    }

    security_dir = tmp_path / "security_logs"
    security_dir.mkdir()
    (security_dir / "2026-01-06.jsonl").write_text(json.dumps(event) + "\n")

    kafka_dir = tmp_path / "kafka_json"
    kafka_dir.mkdir()
    (kafka_dir / "2026-01-06.jsonl").write_text(json.dumps(event) + "\n")

    source = FileEventSource.from_directory(tmp_path)
    events = list(source.read())
    assert len(events) == 1, (
        f"expected 1 event after excluding kafka_json/, got {len(events)} -- "
        f"the merged-representation directory is being double-counted again"
    )


def test_drift_no_false_positive_on_noise():
    """
    Invariant: detect_concept_drift() fed np.histogram(...,
    density=True) output directly into a discrete KL-divergence formula.
    density=True returns mass/bin_width, which does not sum to 1 -- for a
    50-bin histogram over [0,1) that inflated every KL value by ~49x,
    causing 20/20 false positives on pure resampling noise (independently
    reproduced against this exact code before the fix). Regression: over
    200 genuinely-no-drift trials (one distribution split in half), the
    fixed detector must not flag drift at the current default threshold.
    """
    from ueba_pipeline.monitoring.drift import detect_concept_drift

    rng = np.random.default_rng(11)
    false_positives = 0
    for _ in range(200):
        sample = rng.beta(2, 8, 4000)
        half = len(sample) // 2
        old, new = list(sample[:half]), list(sample[half:])
        if detect_concept_drift(old, new):
            false_positives += 1

    assert false_positives == 0, (
        f"{false_positives}/200 false positives on pure noise -- KL "
        f"divergence is still operating on unnormalized density, not "
        f"probability mass"
    )


def test_drift_still_detects_genuine_shift():
    """Companion to the false-positive test above: the C1 fix must not
    overcorrect into never firing. Two visibly different distributions
    (different Beta shape parameters) must still be flagged."""
    from ueba_pipeline.monitoring.drift import detect_concept_drift

    rng = np.random.default_rng(11)
    true_positives = 0
    for _ in range(50):
        old = list(rng.beta(2, 8, 2000))
        new = list(rng.beta(4, 6, 2000))
        if detect_concept_drift(old, new):
            true_positives += 1

    assert true_positives == 50, (
        f"only {true_positives}/50 genuine-shift trials detected -- "
        f"threshold may be miscalibrated in the other direction now"
    )


def test_kl_divergence_requires_normalized_mass():
    """Direct unit test of the primitive: passing two arrays that each sum
    to 1 must reproduce the textbook KL divergence, not the density-scaled
    version. Guards the contract _kl_divergence's docstring now states
    explicitly, independent of the higher-level drift-detection behavior."""
    from ueba_pipeline.monitoring.drift import _kl_divergence

    p = np.array([0.5, 0.5])
    q = np.array([0.5, 0.5])
    assert _kl_divergence(p, q) == pytest.approx(0.0, abs=1e-9)

    p = np.array([0.9, 0.1])
    q = np.array([0.5, 0.5])
    expected = 0.9 * np.log(0.9 / 0.5) + 0.1 * np.log(0.1 / 0.5)
    assert _kl_divergence(p, q) == pytest.approx(expected, abs=1e-9)


def test_roster_projection_matches_normalize_username_key_shape():
    """
    The roster must be written in the shape the pipeline consumes AND keyed the
    way ``parsing.normalize.normalize_username`` keys accounts. A roster keyed
    differently does not raise -- peer-group lookups simply miss -- so the
    mismatch would be invisible at runtime and silently degrade every lookup.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "enterprise_simulator"))
    from core.employees import build_employee_roster, roster_to_peer_group_map

    from ueba_pipeline.parsing.normalize import normalize_username

    roster = build_employee_roster()
    mapping = roster_to_peer_group_map(roster)

    # The map contains every human employee plus the non-human identities
    # (service accounts) under dedicated nhi_* peer groups, so it is at least
    # as large as the human roster, and every human is present.
    assert len(mapping) >= len(roster)
    for emp in roster:
        assert emp.samaccountname.lower() in mapping
    # Service accounts are grouped under nhi_* (never a human department).
    nhi_groups = [g for g in mapping.values() if g.startswith("nhi_")]
    assert nhi_groups, "service accounts should be mapped to nhi_* peer groups"
    sample = roster[0]
    assert mapping[sample.samaccountname.lower()] == sample.department
    # Cross-subsystem contract: every key must be exactly what the pipeline's
    # own normalizer would produce for that same account, or the join is
    # silently broken rather than erroring.
    for emp in roster[:20]:
        assert normalize_username(emp.samaccountname) in mapping


def test_sysmon_source_user_events_are_attributed_not_dropped():
    """
    Invariant: _user_key() only
    consulted target_user_name_norm / user_norm / subject_user_name_norm /
    account_name_norm. Sysmon ProcessAccess (EID 10) and CreateRemoteThread
    (EID 8) carry the acting user under `source_user` -> `source_user_norm`,
    which no branch looked at, so those events resolved to None and were
    dropped from every user window. The single LSASS-dump EID 10 event on the
    injected-attack day (source_user_norm=stiwari2) was silently discarded,
    leaving f_lsass_access_flag / f_credential_dump_access_flag structurally 0
    and blinding both the behavioral and indicator tracks to T1003.001/T1055.
    Fixed by attributing EID 8/10 to source_user_norm (and adding it as a
    universal fallback). This test constructs the exact event shape and
    asserts the actor is recovered, and that a normal EID 10 whose source is a
    machine/SYSTEM account is still correctly excluded (returns None).
    """
    from ueba_pipeline.features.aggregate import _user_key
    from ueba_pipeline.parsing.normalize import NormalizedEvent

    def eid10(source_user_norm, target_user_norm=None):
        return NormalizedEvent(
            event_time=datetime.now(UTC), ingest_time=None,
            channel="Microsoft-Windows-Sysmon/Operational", event_id="10",
            event_type="sysmon_10", group="sysmon_process",
            computer_name="WKS01", outcome=None, keywords=[],
            fields={"source_user_norm": source_user_norm,
                    "target_user_norm": target_user_norm,
                    "is_lsass_target": True},
            raw_event_data={}, parse_warnings=[],
        )

    # Attacker running the dump tool -> attribute to the SOURCE user, not the
    # victim process owner (TargetUser, here None/SYSTEM).
    assert _user_key(eid10("stiwari2", target_user_norm=None)) == "stiwari2"
    # Even if a target user is present, the acting (source) user wins for EID 10.
    assert _user_key(eid10("attacker", target_user_norm="victim")) == "attacker"
    # A normal EID 10 whose source normalized away (machine/SYSTEM) stays dropped.
    assert _user_key(eid10(None, target_user_norm=None)) is None


def test_password_spray_fanout_is_cross_user_not_per_window():
    """
    Invariant: f_spray_max_targets_
    per_ip aggregated distinct target accounts per source IP INSIDE a single
    user's window. Windows are bucketed per-user, so that set only ever held
    one victim -> the feature was structurally <=1 and the defining spray
    signature (one IP -> many accounts) was invisible. Measured max was 0.0
    across 254 users on the 32-account spray day, and both spray labels were
    missed. Also confirmed: 25 of the 32 real spray failures were 4771
    (Kerberos pre-auth), not 4625, so a 4625-only pass saw almost nothing.
    Fixed by a cross-entity pass that fans failed-auth (4625+4771) out per
    (source_ip, window) across ALL users, then attributes each IP's true
    fan-out back onto every victim window.
    """
    from ueba_pipeline.features.aggregate import build_user_windows
    from ueba_pipeline.parsing.normalize import normalize_event

    t0 = "2025-02-05T20:35:%02d.0000000Z"
    victims = [f"victim{i}" for i in range(20)]
    events = []
    # One external IP fails a Kerberos pre-auth (4771) against 20 distinct
    # accounts within the same hour -- a textbook spray, all from 10.9.9.9.
    for i, v in enumerate(victims):
        events.append(normalize_event({
            "@timestamp": t0 % (i % 60),
            "winlog": {"event_id": "4771", "channel": "Security",
                       "computer_name": "DC01",
                       "event_data": {"TargetUserName": v, "Status": "0x18",
                                      "IpAddress": "10.9.9.9"}},
            "event": {}, "host": {"name": "DC01"},
        }))
    manifest = CapabilityManifest(available_groups={"auth", "kerberos"})
    manifest.compute_hash()
    vectors = build_user_windows(events, manifest, window_hours=1.0)

    fanouts = [v.values.get("f_spray_max_targets_per_ip", 0.0) for v in vectors]
    assert max(fanouts) == 20.0, (
        f"expected the attacking IP's cross-user fan-out (20) to surface on "
        f"victim windows, got max {max(fanouts)} -- the spray feature is still "
        f"being computed per-user-window and cannot see cross-account fan-out"
    )
    # Every scored victim window in the attack hour should carry the full
    # fan-out, not just one of them.
    assert sum(1 for f in fanouts if f == 20.0) == len(victims)


def test_config_rejects_unknown_keys():
    """
    Invariant: config/schema.py's docstring claims to "fail
    fast" on invalid config, but no BaseModel set extra="forbid", so
    Pydantic v2's default (extra="ignore") silently dropped typo'd keys
    and used the field default instead -- an operator changing
    threshold.percentile via YAML would see no error and no effect.
    """
    from pydantic import ValidationError

    from ueba_pipeline.config.schema import WindowConfig

    with pytest.raises(ValidationError):
        WindowConfig(collinearity_threshld=0.9)  # typo for "collinearity_threshold"

    with pytest.raises(ValidationError):
        WindowConfig(feature_window_hors=2.0)  # typo for "feature_window_hours"

    # Correctly-spelled keys must still work with extra="forbid".
    cfg = WindowConfig(feature_window_hours=2.0)
    assert cfg.feature_window_hours == 2.0


def test_capability_manifest_groups_match_feature_extractors():
    """
    Invariant: normalize.py registered WMI, Task Scheduler,
    and Windows Defender events into the same 'process' capability group
    as Sysmon, but aggregate.py's _GROUP_EVENT_TYPES["process"] only
    listed Sysmon event types -- so a deployment with WMI/Task/Defender
    logging but no Sysmon would have the manifest report "process"
    available (crossing the volume bar on non-Sysmon traffic) while
    silently emitting all-zero feature vectors for every user, forever,
    with no error. Regression: every group name normalize.py's EVENT_GROUP can
    produce must have a matching entry in both aggregate.py dispatch tables, and
    neither table may reference a group the other doesn't know about. (The
    formerly-excluded "security_object_access" group was phantom -- none of its
    event IDs had field maps -- and has been removed entirely; normalize.py now
    only claims a group for events it can actually extract fields from, so there
    are no tracked-gap exclusions left.)
    """
    from ueba_pipeline.features.aggregate import _GROUP_EVENT_TYPES, _GROUP_EXTRACTORS
    from ueba_pipeline.parsing.normalize import EVENT_GROUP

    implemented_groups = set(EVENT_GROUP.values())

    assert implemented_groups <= set(_GROUP_EVENT_TYPES.keys()), (
        f"groups registered in normalize.py but missing from "
        f"_GROUP_EVENT_TYPES (invisible to feature extraction despite "
        f"counting toward manifest availability): "
        f"{implemented_groups - set(_GROUP_EVENT_TYPES.keys())}"
    )
    assert set(_GROUP_EVENT_TYPES.keys()) == set(_GROUP_EXTRACTORS.keys()), (
        "‌_GROUP_EVENT_TYPES and _GROUP_EXTRACTORS have drifted apart"
    )


def test_defender_malware_flag_is_computed_when_available():
    """The specific highest-value case C3 was silently dropping: an actual
    Defender malware-detected event (EID 1116) must produce a nonzero
    f_malware_detected_flag once routed through the real dispatch path,
    not just exist in isolation as a unit-testable function."""
    from datetime import datetime

    from ueba_pipeline.features.aggregate import _GROUP_EVENT_TYPES, _GROUP_EXTRACTORS
    from ueba_pipeline.parsing.normalize import NormalizedEvent

    ne = NormalizedEvent(
        event_time=datetime.now(UTC), ingest_time=None,
        channel="Microsoft-Windows-Windows Defender/Operational", event_id="1116",
        event_type="defender_1116", group="defender", computer_name="WKS01",
        outcome=None, keywords=[],
        fields={"threat_name": "Trojan:Win32/Test", "severity": "Severe", "path": "C:\\x"},
        raw_event_data={}, parse_warnings=[],
    )
    relevant = [e for e in [ne] if e.event_type in _GROUP_EVENT_TYPES["defender"]]
    result = _GROUP_EXTRACTORS["defender"](relevant)
    assert result["f_malware_detected_flag"] == 1.0


def test_rare_signal_groups_bypass_volume_fraction_gate():
    """
    Groups whose signal is rare BY DESIGN must be admitted on their first
    occurrence, not gated on volume. Measured on a 5-day, 253-employee estate,
    Defender produced 2 events out of 55,996: since it only fires on an actual
    malware verdict, any shared volume floor is unreachable for a healthy
    deployment, which would leave the feature permanently inert despite being
    wired correctly.
    """
    from ueba_pipeline.config.schema import CapabilityConfig
    from ueba_pipeline.features.manifest import build_capability_manifest
    from ueba_pipeline.parsing.normalize import NormalizedEvent

    config = CapabilityConfig(bootstrap_min_events=100)

    events = []
    # Bulk of volume: routine auth events, far more than 1 defender event.
    for _ in range(500):
        events.append(NormalizedEvent(
            event_time=datetime.now(UTC), ingest_time=None,
            channel="Security", event_id="4624", event_type="4624",
            group="auth", computer_name="DC01", outcome="success",
            keywords=[], fields={}, raw_event_data={}, parse_warnings=[],
        ))
    # Exactly one real Defender detection -- 1/501 = 0.2%, and realistic
    # deployments will often see even less than this.
    events.append(NormalizedEvent(
        event_time=datetime.now(UTC), ingest_time=None,
        channel="Microsoft-Windows-Windows Defender/Operational",
        event_id="1116", event_type="defender_1116", group="defender",
        computer_name="WKS01", outcome=None, keywords=[],
        fields={"threat_name": "Trojan:Win32/Test"}, raw_event_data={},
        parse_warnings=[],
    ))

    manifest = build_capability_manifest(events, config)
    assert "defender" in manifest.available_groups, (
        "a single real malware-detection event must be enough to turn on "
        "the defender capability -- it should never need to hit a volume "
        "floor calibrated for routine behavioral telemetry"
    )
    assert "auth" in manifest.available_groups


def _bulk_events(group, channel, event_id, event_type, n, host="H1"):
    from ueba_pipeline.parsing.normalize import NormalizedEvent
    return [
        NormalizedEvent(
            event_time=datetime.now(UTC), ingest_time=None,
            channel=channel, event_id=event_id, event_type=event_type,
            group=group, computer_name=host, outcome=None, keywords=[],
            fields={}, raw_event_data={}, parse_warnings=[],
        )
        for _ in range(n)
    ]


def test_capability_gate_is_an_absolute_floor_not_a_fraction():
    """A present source must not be gated out just because another, unrelated,
    higher-volume source shares the bootstrap window.

    A fraction-of-total gate would let a flood of Sysmon events raise the bar
    every other source has to clear, so a legitimately-present but lower-volume
    Kerberos source could fall below it. An absolute floor decides each source on
    its own event count, so two independent log sources never gate each other.
    """
    from ueba_pipeline.config.schema import CapabilityConfig
    from ueba_pipeline.features.manifest import build_capability_manifest

    config = CapabilityConfig(bootstrap_min_events=100, min_events_for_capability=5)
    events = (
        _bulk_events("sysmon_process", "Microsoft-Windows-Sysmon/Operational",
                     "1", "sysmon_1", 5000, host="WKS01")
        + _bulk_events("kerberos", "Security", "4768", "4768", 20, host="DC01")
    )
    manifest = build_capability_manifest(events, config)
    assert "kerberos" in manifest.available_groups, (
        "a source with 20 events was gated out by an unrelated 5000-event "
        "source sharing the window — the gate is still coupling sources"
    )
    assert "sysmon_process" in manifest.available_groups


def test_capability_gate_rejects_a_single_stray_event():
    """A lone leftover event from a decommissioned pilot install must not enable
    an entire feature group."""
    from ueba_pipeline.config.schema import CapabilityConfig
    from ueba_pipeline.features.manifest import build_capability_manifest

    config = CapabilityConfig(bootstrap_min_events=100, min_events_for_capability=5)
    events = (
        _bulk_events("auth", "Security", "4624", "4624", 500, host="DC01")
        + _bulk_events("sysmon_process", "Microsoft-Windows-Sysmon/Operational",
                       "1", "sysmon_1", 1, host="GHOST-PILOT")
    )
    manifest = build_capability_manifest(events, config)
    assert "auth" in manifest.available_groups
    assert "sysmon_process" not in manifest.available_groups, (
        "a single stray Sysmon event enabled the whole process group"
    )


def test_capability_gate_is_stable_across_window_sizes():
    """The same source at the same rate must produce the same decision whether
    the bootstrap window is small or large."""
    from ueba_pipeline.config.schema import CapabilityConfig
    from ueba_pipeline.features.manifest import build_capability_manifest

    config = CapabilityConfig(bootstrap_min_events=50, min_events_for_capability=5)
    small = build_capability_manifest(
        _bulk_events("auth", "Security", "4624", "4624", 60), config)
    large = build_capability_manifest(
        _bulk_events("auth", "Security", "4624", "4624", 60000), config)
    assert ("auth" in small.available_groups) == ("auth" in large.available_groups) is True


def test_golden_silver_ticket_uses_full_history_not_window_local_tgt():
    """Golden/Silver ticket flags must correlate a Type-3 Kerberos logon's
    src_ip against the account's FULL-HISTORY TGT/TGS issuance, not just
    tickets issued inside the same hourly window.

    A TGT is issued once (e.g. 02:00) and reused for ~10h, so most hourly logon
    windows contain a Type-3 Kerberos 4624 with no 4768 of their own. Correlating
    only within the window would therefore fire on entirely benign cross-window
    logons. The discriminator is "no ticket for this account from this address
    before now", not "none in this hour".

    This test encodes both halves of the property on one synthetic account:
      - a benign logon from the account's normal IP (whose TGT was requested
        in an EARLIER window) must NOT fire, and
      - a forged-ticket logon from an IP the account never requested a ticket
        from MUST still fire (recall preserved).
    """
    from ueba_pipeline.features.aggregate import build_user_windows
    from ueba_pipeline.parsing.normalize import normalize_event

    def ev(eid, ts, **ed):
        return normalize_event({
            "@timestamp": ts,
            "winlog": {"event_id": eid, "channel": "Security",
                       "computer_name": "DC01", "event_data": ed},
            "event": {}, "host": {"name": "DC01"},
        })

    NORMAL_IP = "10.0.0.5"
    FORGED_IP = "10.66.66.66"   # attacker host; account never got a ticket here
    events = [
        # Legitimate morning TGT + service-ticket from the normal workstation
        # (window 02:00). A real Kerberos session produces both a 4768 (TGT)
        # and 4769 (TGS); silver-ticket correlation keys on the 4769 history.
        ev("4768", "2025-02-05T02:00:00.0000000Z",
           TargetUserName="alice", IpAddress=NORMAL_IP),
        ev("4769", "2025-02-05T02:00:05.0000000Z",
           TargetUserName="alice", IpAddress=NORMAL_IP),
        # Benign Type-3 Kerberos logon later the same day (window 09:00) from
        # the SAME normal IP -- TGT was issued hours earlier, so this window
        # has no 4768 of its own. Must NOT be treated as forged.
        ev("4624", "2025-02-05T09:15:00.0000000Z",
           TargetUserName="alice", LogonType="3",
           AuthenticationPackageName="Kerberos", IpAddress=NORMAL_IP,
           WorkstationName="WS-ALICE"),
        # Forged-ticket logon (window 14:00) from an IP alice never requested
        # a ticket from. Must fire.
        ev("4624", "2025-02-05T14:30:00.0000000Z",
           TargetUserName="alice", LogonType="3",
           AuthenticationPackageName="Kerberos", IpAddress=FORGED_IP,
           WorkstationName="WS-ATTACKER"),
    ]

    manifest = CapabilityManifest(available_groups={"auth", "kerberos"})
    manifest.compute_hash()
    vectors = build_user_windows(events, manifest, window_hours=1.0)
    by_start = {v.window_start.hour: v for v in vectors if v.user == "alice"}

    benign = by_start[9]
    forged = by_start[14]

    assert benign.values.get("f_golden_ticket_flag", 0.0) == 0.0, (
        "benign cross-window Kerberos logon (TGT issued in an earlier window) "
        "false-fired the golden-ticket flag -- window-local TGT correlation "
        "regressed"
    )
    assert benign.values.get("f_silver_ticket_flag", 0.0) == 0.0
    assert forged.values.get("f_golden_ticket_flag", 0.0) >= 1.0, (
        "forged-ticket logon from an IP with no full-history TGT issuance "
        "failed to fire -- golden-ticket recall regressed"
    )
    assert forged.values.get("f_silver_ticket_flag", 0.0) >= 1.0


def test_source_edge_keys_on_device_not_address():
    """An authentication's source must be identified by the DEVICE, not the IP
    address. Addresses churn constantly in a real estate (DHCP leases,
    VPN pool assignment, wired vs Wi-Fi), so keying the (account -> source) edge
    on an address turns ordinary churn into a stream of novel edges -- measured on
    a realistically churning estate, 91.8% of benign edges look novel when keyed on
    the address versus 4.4% when keyed on the device. That is the difference
    between a detector that works on a real network and one that floods.
    """
    from datetime import datetime
    from types import SimpleNamespace

    from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector, AuthGraphConfig

    det = AuthGraphAnomalyDetector(config=AuthGraphConfig())

    def logon(ip, ws="WSENG01"):
        return SimpleNamespace(
            event_type="4624",
            event_time=datetime(2025, 1, 1, 9, tzinfo=UTC),
            computer_name="fs01",
            fields={"target_user_name": "alice", "src_ip": ip,
                    "workstation": ws, "logon_type": 3},
        )

    # Same device, three different DHCP leases -> one stable edge.
    edges = {tuple(e) for _, e in
             [x for ip in ("10.10.2.5", "10.10.2.77", "10.10.4.31")
              for x in det.edges_for(logon(ip))] if _ == "user_src"}
    assert edges == {("alice", "wseng01")}, (
        f"address churn must not create novel source edges, got {edges}")

    # No device name (external / spray traffic) -> fall back to the address,
    # which is then the only identity available and is itself worth learning.
    fallback = [e for v, e in det.edges_for(logon("185.220.101.9", ws="-")) if v == "user_src"]
    assert fallback == [("alice", "185.220.101.9")]
