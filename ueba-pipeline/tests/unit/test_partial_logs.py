"""
tests/unit/test_partial_logs.py -- partial-log adaptivity (redesign doc §8.2):
the engine must learn and detect from ANY subset of log sources, with a feature
space that adapts to what is present (never a hardcoded width, never a required
source), and enrich as more sources appear. Validated end-to-end against the
real 35-day dataset (Security-only -> 4 groups/width 49, Sysmon-only -> 1
group/width 14, combined -> 63, all -> 81); this test locks the property in
with synthetic events so it can't silently regress.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.config.schema import CapabilityConfig
from ueba_pipeline.features.aggregate import feature_order_for_manifest
from ueba_pipeline.features.manifest import build_capability_manifest
from ueba_pipeline.parsing.normalize import normalize_event


def _security_4624(i):
    return {
        "@timestamp": f"2025-01-06T08:{i % 60:02d}:00.000Z",
        "winlog": {"event_id": "4624", "channel": "Security",
                   "computer_name": "DC01",
                   "event_data": {"TargetUserName": f"user{i % 7}", "LogonType": "3",
                                  "IpAddress": "10.0.0.5"}},
        "event": {"outcome": "success"}, "host": {"name": "DC01"},
    }


def _sysmon_1(i):
    return {
        "@timestamp": f"2025-01-06T08:{i % 60:02d}:00.000Z",
        "winlog": {"event_id": "1", "channel": "Microsoft-Windows-Sysmon/Operational",
                   "computer_name": "WKS01",
                   "event_data": {"Image": f"C:\\p{i % 3}.exe", "User": f"NEXOVATE\\user{i % 7}",
                                  "CommandLine": "x", "ProcessGuid": f"{{g{i}}}"}},
        "event": {}, "host": {"name": "WKS01"},
    }


def _manifest_and_width(raws):
    cfg = CapabilityConfig(bootstrap_min_events=50)
    events = [ne for ne in (normalize_event(r) for r in raws) if ne is not None]
    manifest = build_capability_manifest(events, cfg)
    return manifest, feature_order_for_manifest(manifest)


def test_engine_adapts_feature_space_to_available_log_sources():
    sec_raw = [_security_4624(i) for i in range(200)]
    sys_raw = [_sysmon_1(i) for i in range(200)]

    sec_manifest, sec_order = _manifest_and_width(sec_raw)
    sys_manifest, sys_order = _manifest_and_width(sys_raw)
    both_manifest, both_order = _manifest_and_width(sec_raw + sys_raw)

    # Security-only: auth present, sysmon absent -> its columns simply do not
    # exist (not zero-filled), and vice versa.
    assert "auth" in sec_manifest.available_groups
    assert "sysmon_process" not in sec_manifest.available_groups
    assert "sysmon_process" in sys_manifest.available_groups
    assert "auth" not in sys_manifest.available_groups

    # Each subset yields a valid, non-empty, DIFFERENT-width feature space.
    assert len(sec_order) > 0 and len(sys_order) > 0
    assert len(sec_order) != len(sys_order)

    # Adding a source enriches the space: the union is strictly wider than
    # either alone and is exactly the union of their feature sets.
    assert len(both_order) > len(sec_order)
    assert len(both_order) > len(sys_order)
    assert set(both_order) == set(sec_order) | set(sys_order)
    assert {"auth", "sysmon_process"} <= both_manifest.available_groups


def test_manifest_hash_changes_when_sources_change():
    """Capability-drift detection depends on the manifest hash reflecting which
    sources are present, so a newly-available source is noticed and can trigger
    a baseline enrich/retrain (redesign §8.2)."""
    sec_manifest, _ = _manifest_and_width([_security_4624(i) for i in range(200)])
    both_manifest, _ = _manifest_and_width(
        [_security_4624(i) for i in range(200)] + [_sysmon_1(i) for i in range(200)]
    )
    assert sec_manifest.manifest_hash != both_manifest.manifest_hash
