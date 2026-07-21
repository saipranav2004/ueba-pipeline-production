"""The feature contract: which features exist, what they mean, and which of them
a model is permitted to learn from.

Raw Windows Security and Sysmon records have a variable schema — fields appear
and disappear with audit policy, Sysmon configuration, and OS version. Classical
models need the opposite: a stable, ordered, typed input vector. This module is
the boundary between the two. It declares every feature the extractors emit,
assigns each a kind, and decides eligibility for model input.

WHY ELIGIBILITY IS ENFORCED IN CODE
-----------------------------------
The detector is a behavioural model, not a rule engine. That distinction is only
real if it is mechanical. Two families of feature would quietly turn it back into
one, and both are excluded here rather than by convention:

  * **Hypothesis flags** (``*_flag``). These encode an analyst's belief about a
    named technique — "this looks like Kerberoasting", "this command line matches
    a download cradle". Training on them measures how well the flag was written,
    not whether behaviour generalises, and it inflates any benchmark whose attacks
    were generated from the same technique list the flags were written against.
    They remain computed and exposed to analysts as provenance; they are simply
    not model input.

  * **Upstream detector verdicts** (the ``defender`` group). A Defender detection
    is another detector's output. A model trained on it learns to agree with
    Defender, scores well wherever Defender already fired, and contributes nothing
    where it did not — the case that matters. It is label-adjacent, so it is
    excluded from model input for the same reason a label is.

Everything else — counts, rates, distinct-value cardinalities, entropies, ratios
— is a statistical description of behaviour and is eligible.

Eligibility is expressed as a rule plus an explicit exception table, not as
seventy hand-maintained rows, so a newly added extractor feature is classified on
the day it appears instead of silently defaulting to eligible. ``validate()``
fails loudly if a feature the extractors emit is not covered.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Mapping

from ueba_pipeline.features.aggregate import (
    _GROUP_EXTRACTORS,
    feature_order_for_manifest,
)
from ueba_pipeline.features.manifest import CapabilityManifest

# Bump the MINOR component when a feature is added, the MAJOR component when one
# is removed or its meaning changes. A model bundle records the version it was fit
# against; a mismatch means the stored column order no longer describes the data.
FEATURE_CONTRACT_VERSION = "1.0.0"


class FeatureKind(str, Enum):
    """What a feature's value represents. Drives interpretation, not arithmetic."""

    COUNT = "count"                # unbounded non-negative event tally
    RATE = "rate"                  # bounded ratio or percentage in [0, 1]
    CARDINALITY = "cardinality"    # number of distinct values observed
    STATISTIC = "statistic"        # derived quantity (entropy, max length)
    INDICATOR = "indicator"        # boolean hypothesis about a named technique


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    group: str
    kind: FeatureKind
    model_eligible: bool
    rationale: str


# Feature groups excluded from model input in their entirety, with the reason.
INELIGIBLE_GROUPS: Mapping[str, str] = {
    "defender": (
        "Windows Defender verdicts are another detector's output. Training on "
        "them teaches the model to reproduce Defender rather than to describe "
        "behaviour, and inflates any benchmark where Defender already fired."
    ),
}

# Features whose classification does not follow from the naming rule. Each entry
# needs a reason; an override without one is a silent policy change.
ELIGIBILITY_OVERRIDES: Mapping[str, tuple] = {
    # Cross-entity failed-authentication fan-out: the number of distinct accounts
    # a single source address failed against in the window. Despite the name this
    # is a plain aggregate statistic over observed failures, not a threshold on a
    # technique hypothesis, so it is eligible.
    "f_spray_max_targets_per_ip": (
        True,
        "Distinct-victim count per source address — an aggregate statistic, not a "
        "hypothesis about a named technique.",
    ),
    "f_spray_distinct_fail_ips": (
        True,
        "Distinct failing source addresses — an aggregate statistic.",
    ),
    "f_spray_has_cross_user_failure": (
        False,
        "Thresholds f_spray_max_targets_per_ip at >1. The cut point is arbitrary "
        "and the continuous form is already eligible, so this adds a hand-chosen "
        "decision boundary without adding information.",
    ),
    # Counts sitting inside an ineligible group inherit that group's exclusion,
    # stated explicitly so the reason survives a reading of this table alone.
    "f_malware_detection_count": (
        False,
        "Upstream Defender verdict count; label-adjacent (see INELIGIBLE_GROUPS).",
    ),
    "f_malware_action_taken_count": (
        False,
        "Upstream Defender remediation count; label-adjacent.",
    ),
}

# Suffix that marks a boolean technique hypothesis.
_INDICATOR_SUFFIX = "_flag"

# Substrings that classify an eligible feature's kind. Order matters: the first
# match wins, so the more specific prefixes precede the generic count/rate ones.
_KIND_RULES = (
    ("_distinct_", FeatureKind.CARDINALITY),
    ("f_distinct", FeatureKind.CARDINALITY),
    ("_unique_", FeatureKind.CARDINALITY),
    ("_diversity", FeatureKind.CARDINALITY),
    ("_entropy", FeatureKind.STATISTIC),
    ("_len", FeatureKind.STATISTIC),
    ("_pct_", FeatureKind.RATE),
    ("_rate", FeatureKind.RATE),
    ("_ratio", FeatureKind.RATE),
    ("_count", FeatureKind.COUNT),
)


def _group_of(name: str) -> str:
    """The extractor group that emits ``name``.

    Resolved by asking each extractor what it produces rather than by consulting a
    second hardcoded map, which would drift from the extractors it describes.
    """
    for group, extractor in _GROUP_EXTRACTORS.items():
        if name in extractor([]):
            return group
    # Cross-entity and cross-group features are written directly into the vector
    # by build_user_windows after the per-group extractors have run.
    return "cross_entity"


def _kind_of(name: str) -> FeatureKind:
    if name.endswith(_INDICATOR_SUFFIX):
        return FeatureKind.INDICATOR
    for token, kind in _KIND_RULES:
        if token in name:
            return kind
    return FeatureKind.COUNT


def spec_for(name: str) -> FeatureSpec:
    """Classify one feature. Deterministic and independent of any dataset."""
    group = _group_of(name)
    kind = _kind_of(name)

    if name in ELIGIBILITY_OVERRIDES:
        eligible, rationale = ELIGIBILITY_OVERRIDES[name]
    elif group in INELIGIBLE_GROUPS:
        eligible, rationale = False, INELIGIBLE_GROUPS[group]
    elif kind is FeatureKind.INDICATOR:
        eligible = False
        rationale = (
            "Boolean hypothesis about a named technique; retained for analyst "
            "provenance but excluded from model input."
        )
    else:
        eligible = True
        rationale = "Statistical description of observed behaviour."

    return FeatureSpec(
        name=name, group=group, kind=kind,
        model_eligible=eligible, rationale=rationale,
    )


def build_contract(manifest: CapabilityManifest) -> List[FeatureSpec]:
    """Every feature available under ``manifest``, in the vector's column order.

    The order is the extractors' own deterministic ordering, so a contract and a
    feature matrix built from the same manifest always agree column for column.
    """
    return [spec_for(name) for name in feature_order_for_manifest(manifest)]


def model_feature_names(manifest: CapabilityManifest) -> List[str]:
    """The ordered columns a model may consume. This is the ONLY supported way to
    select model input; selecting columns by hand bypasses the exclusions above."""
    return [s.name for s in build_contract(manifest) if s.model_eligible]


def quarantined_feature_names(manifest: CapabilityManifest) -> List[str]:
    """Features computed and shown to analysts but withheld from every model."""
    return [s.name for s in build_contract(manifest) if not s.model_eligible]


def contract_hash(manifest: CapabilityManifest) -> str:
    """Stable digest of the contract, for pinning a trained bundle to its inputs.

    Covers name, kind and eligibility — the properties that change how a vector is
    interpreted. Rationale text is excluded so that clarifying a comment does not
    invalidate a model.
    """
    payload = json.dumps(
        [
            {"name": s.name, "kind": s.kind.value, "eligible": s.model_eligible}
            for s in build_contract(manifest)
        ],
        sort_keys=True,
    )
    digest = hashlib.sha256(payload.encode()).hexdigest()[:16]
    return f"{FEATURE_CONTRACT_VERSION}+{digest}"


def validate(manifest: CapabilityManifest) -> Dict[str, List[str]]:
    """Check the contract still describes what the extractors emit.

    Returns a summary for logging. Raises ``ValueError`` if a feature cannot be
    attributed to a group, which means an extractor emits something no group
    claims — the failure mode that would otherwise let an unclassified feature
    default into model input.
    """
    contract = build_contract(manifest)
    orphans = [s.name for s in contract if s.group == "cross_entity"
               and s.name not in ELIGIBILITY_OVERRIDES
               and s.kind is not FeatureKind.INDICATOR]
    if orphans:
        raise ValueError(
            "features are not attributable to an extractor group and have no "
            f"explicit override, so their eligibility is undefined: {sorted(orphans)}. "
            "Add them to ELIGIBILITY_OVERRIDES with a rationale."
        )
    return {
        "eligible": [s.name for s in contract if s.model_eligible],
        "quarantined": [s.name for s in contract if not s.model_eligible],
    }
