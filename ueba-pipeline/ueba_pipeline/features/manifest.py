"""
features/manifest.py — CapabilityManifest: the mechanism that keeps the pipeline
correct when log sources are missing (see docs/architecture.md). Built from a
bootstrap scan of ingested data, not assumed from a static list of expected
sources.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field

from ueba_pipeline.config.schema import CapabilityConfig
from ueba_pipeline.parsing.normalize import NormalizedEvent


@dataclass
class CapabilityManifest:
    available_groups: set[str] = field(default_factory=set)
    event_type_counts: dict[str, int] = field(default_factory=dict)
    total_events_scanned: int = 0
    dropped_constant_fields: dict[str, list[str]] = field(default_factory=dict)
    manifest_hash: str = ""

    def is_group_available(self, group: str) -> bool:
        return group in self.available_groups

    def to_dict(self) -> dict:
        d = asdict(self)
        d["available_groups"] = sorted(self.available_groups)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> CapabilityManifest:
        d = dict(d)
        d["available_groups"] = set(d.get("available_groups", []))
        return cls(**d)

    def compute_hash(self) -> str:
        payload = json.dumps(
            {"groups": sorted(self.available_groups),
             "dropped": {k: sorted(v) for k, v in self.dropped_constant_fields.items()}},
            sort_keys=True,
        )
        self.manifest_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        return self.manifest_hash


def build_capability_manifest(
    events: Iterable[NormalizedEvent],
    config: CapabilityConfig,
) -> CapabilityManifest:
    """
    Scans a bootstrap window of already-normalized events and decides which
    feature groups are trustworthy to compute. A group's events must number at
    least `min_events_for_capability` (an absolute floor, not a fraction of
    total events) before the group is turned on — this guards against a single
    stray Sysmon event (e.g. left over from a decommissioned pilot install)
    falsely flipping on an entire feature group for a deployment that doesn't
    actually run Sysmon, without coupling the decision to unrelated sources'
    volume or destabilising it on a small/rolling window (see
    CapabilityConfig.min_events_for_capability). Rare-by-design groups
    (Defender verdicts, DCSync, privileged-group changes) bypass the floor via
    `presence_gated_groups` and are admitted on the first occurrence.

    Also detects per-field zero-variance within event types that ARE
    present (e.g. DNS QTYPE always "1") and
    records them for exclusion, rather than leaving that decision to the
    aggregator to silently rediscover per-window.
    """
    manifest = CapabilityManifest()
    group_event_counts: dict[str, int] = {}
    field_value_sets: dict[str, dict[str, set[str]]] = {}  # event_type -> field -> values
    total = 0

    events = list(events)  # bootstrap window is bounded; materializing is fine
    for ne in events:
        total += 1
        manifest.event_type_counts[ne.event_type] = (
            manifest.event_type_counts.get(ne.event_type, 0) + 1
        )
        if ne.group:
            group_event_counts[ne.group] = group_event_counts.get(ne.group, 0) + 1

        if config.zero_variance_check_enabled and ne.event_type != "unknown":
            fv = field_value_sets.setdefault(ne.event_type, {})
            for k, v in ne.fields.items():
                vs = fv.setdefault(k, set())
                if len(vs) < 5:  # cap — we only need to know >1 distinct value exists
                    vs.add(str(v))

    manifest.total_events_scanned = total

    if total < config.bootstrap_min_events:
        # Not enough data to trust any capability decision yet. Return an
        # empty manifest rather than guessing — callers must treat this as
        # "insufficient bootstrap data," not "no capabilities available."
        manifest.compute_hash()
        return manifest

    min_count = config.min_events_for_capability
    presence_gated = set(config.presence_gated_groups)
    for group, count in group_event_counts.items():
        # An absolute floor per group; presence-gated groups admit on the first
        # occurrence because for them the event's presence is itself the signal.
        threshold = 1 if group in presence_gated else min_count
        if count >= threshold:
            manifest.available_groups.add(group)

    for event_type, fv in field_value_sets.items():
        constants = [f for f, vals in fv.items() if len(vals) <= 1]
        if constants:
            manifest.dropped_constant_fields[event_type] = constants

    manifest.compute_hash()
    return manifest
