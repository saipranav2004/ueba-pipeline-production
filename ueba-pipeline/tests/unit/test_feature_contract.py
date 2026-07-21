"""The feature contract must stay enforceable, not merely documented.

These tests fail when a new extractor feature would reach a model without anyone
deciding that it should — the failure mode that turns a behavioural detector back
into a rule engine one convenient flag at a time.
"""
from __future__ import annotations

import pytest

from ueba_pipeline.config.schema import CapabilityConfig
from ueba_pipeline.features import contract as C
from ueba_pipeline.features.aggregate import _GROUP_EXTRACTORS, feature_order_for_manifest
from ueba_pipeline.features.manifest import CapabilityManifest


@pytest.fixture
def full_manifest() -> CapabilityManifest:
    """A manifest claiming every group, so the contract is exercised in full."""
    return CapabilityManifest(available_groups=set(_GROUP_EXTRACTORS))


def test_every_emitted_feature_is_classified(full_manifest):
    declared = {s.name for s in C.build_contract(full_manifest)}
    emitted = set(feature_order_for_manifest(full_manifest))
    assert emitted == declared, (
        "the contract and the extractors disagree about which features exist; "
        f"only in extractors: {sorted(emitted - declared)}; "
        f"only in contract: {sorted(declared - emitted)}"
    )


def test_no_technique_hypothesis_flag_is_model_eligible(full_manifest):
    """Any `*_flag` feature encodes a belief about a named technique."""
    leaked = [
        s.name for s in C.build_contract(full_manifest)
        if s.name.endswith("_flag") and s.model_eligible
    ]
    assert not leaked, f"technique hypothesis flags reached model input: {leaked}"


def test_upstream_detector_verdicts_are_never_model_eligible(full_manifest):
    """Defender output is label-adjacent: a model must not learn to echo it."""
    leaked = [
        s.name for s in C.build_contract(full_manifest)
        if s.group in C.INELIGIBLE_GROUPS and s.model_eligible
    ]
    assert not leaked, f"upstream detector verdicts reached model input: {leaked}"


def test_eligible_and_quarantined_partition_the_contract(full_manifest):
    """Every feature is exactly one of eligible or quarantined — no third state."""
    eligible = set(C.model_feature_names(full_manifest))
    quarantined = set(C.quarantined_feature_names(full_manifest))
    everything = {s.name for s in C.build_contract(full_manifest)}
    assert eligible.isdisjoint(quarantined)
    assert eligible | quarantined == everything


def test_every_override_carries_a_rationale():
    """An override without a stated reason is an undocumented policy change."""
    for name, (_, rationale) in C.ELIGIBILITY_OVERRIDES.items():
        assert rationale.strip(), f"override for {name} has no rationale"


def test_contract_hash_is_stable_and_manifest_sensitive(full_manifest):
    assert C.contract_hash(full_manifest) == C.contract_hash(full_manifest)

    narrower = CapabilityManifest(available_groups={"auth"})
    assert C.contract_hash(narrower) != C.contract_hash(full_manifest), (
        "a manifest offering fewer log sources must produce a different contract "
        "hash, or a bundle could be loaded against a feature vector it was not fit on"
    )


def test_contract_hash_carries_the_version(full_manifest):
    assert C.contract_hash(full_manifest).startswith(C.FEATURE_CONTRACT_VERSION + "+")


def test_model_columns_follow_the_vector_column_order(full_manifest):
    """Eligible names must appear in the same relative order as the full vector,
    so a matrix built from either ordering lines up column for column."""
    full_order = feature_order_for_manifest(full_manifest)
    eligible = C.model_feature_names(full_manifest)
    assert eligible == [n for n in full_order if n in set(eligible)]


def test_validate_rejects_an_unclassifiable_feature(full_manifest, monkeypatch):
    """A feature belonging to no extractor group and holding no override has
    undefined eligibility, and must fail loudly rather than default to eligible."""
    monkeypatch.setattr(
        C, "feature_order_for_manifest",
        lambda m: list(feature_order_for_manifest(m)) + ["f_unowned_statistic"],
    )
    with pytest.raises(ValueError, match="not attributable to an extractor group"):
        C.validate(full_manifest)


def test_observed_windows_match_full_feature_vector_keys():
    """The cheap window enumeration must key exactly like the full extractor.

    `score()` needs only the (entity, hour) pairs, to count the tests each entity
    received for the Šidák correction. It therefore uses `observed_entity_windows`
    rather than building feature vectors it would discard. The two must agree on
    every key: if attribution drifted between them, every correction would shift
    silently.
    """
    from datetime import datetime, timedelta, timezone

    from ueba_pipeline.features.aggregate import build_user_windows, observed_entity_windows
    from ueba_pipeline.parsing.normalize import NormalizedEvent

    base = datetime(2025, 5, 1, 8, 0, tzinfo=timezone.utc)

    def event(event_type, minute, group, **fields):
        return NormalizedEvent(
            event_time=base + timedelta(minutes=minute), ingest_time=None,
            channel="Security", event_id=event_type, event_type=event_type,
            group=group, computer_name="WS-01", outcome=None, keywords=[],
            fields=fields,
        )

    events = []
    for hour in range(4):
        for user in ("alice", "bob"):
            events.append(event("4624", hour * 60, "auth",
                                target_user_name=user, target_user_name_norm=user,
                                logon_type=3, auth_package="Kerberos", src_ip="10.0.0.5"))
        # A directory operation, which attributes to the SUBJECT rather than the
        # target -- the case most likely to diverge between the two paths.
        events.append(event("4728", hour * 60 + 5, "account_lifecycle",
                            subject_user_name_norm="admin",
                            target_user_name_norm="domain admins"))

    manifest = CapabilityManifest(available_groups=set(_GROUP_EXTRACTORS))
    full = {(w.user, w.window_start) for w in build_user_windows(events, manifest, 1.0)}
    cheap = observed_entity_windows(events, 1.0)
    assert cheap == full, (
        f"window keys diverged; only in full: {sorted(full - cheap)}; "
        f"only in cheap: {sorted(cheap - full)}"
    )
