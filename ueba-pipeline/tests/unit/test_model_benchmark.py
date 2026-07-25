"""The model-comparison harness must enforce the split invariants it claims.

These tests assert the leakage-resistance properties structurally, on tiny
synthetic matrices, so a regression in a split protocol fails here rather than in
a long benchmark run whose numbers nobody re-derives. They deliberately do not
fit any sklearn model — the estimator loop is exercised by the full benchmark;
here we test the protocol boundaries that make its numbers trustworthy.
"""
from __future__ import annotations

import numpy as np
import pytest

from ueba_pipeline.evaluation.model_benchmark import (
    WindowDataset,
    attack_family_folds,
    entity_and_time_disjoint_folds,
    entity_disjoint_folds,
    temporal_folds,
)


def _dataset(n_entities=10, n_hours=20, seed=0) -> WindowDataset:
    """A grid of (entity, hour) rows with a handful of positives spread in time."""
    rng = np.random.default_rng(seed)
    entities, hours, families, y, rows = [], [], [], [], []
    t0 = np.datetime64("2025-01-01T00:00:00", "s")
    for e in range(n_entities):
        for h in range(n_hours):
            entities.append(f"user{e}")
            hours.append(t0 + np.timedelta64(h, "h"))
            # Two techniques, each appearing in the second half of the timeline.
            fam = ""
            if e == 2 and h in (12, 13):
                fam = "kerberoasting"
            elif e == 5 and h in (15, 16):
                fam = "dcsync"
            families.append(fam)
            y.append(1 if fam else 0)
            rows.append(rng.normal(size=4))
    return WindowDataset(
        X=np.asarray(rows), y=np.asarray(y, dtype=np.int8),
        entities=np.asarray(entities), hours=np.asarray(hours),
        families=np.asarray(families), feature_names=["a", "b", "c", "d"],
        contract="test", source="synthetic",
    )


def test_temporal_split_never_puts_a_later_hour_in_train():
    data = _dataset()
    (train, test), = temporal_folds(data, train_fraction=0.6)
    assert data.hours[train].max() < data.hours[test].min(), (
        "a training window is at or after a test window — the temporal split leaks"
    )


def test_entity_disjoint_shares_no_account_between_sides():
    data = _dataset()
    for train, test in entity_disjoint_folds(data, n_folds=5):
        assert set(data.entities[train]).isdisjoint(set(data.entities[test])), (
            "an account appears in both train and test — the split is not "
            "entity-disjoint"
        )


def test_entity_and_time_disjoint_shares_neither_account_nor_hour():
    data = _dataset()
    folds = entity_and_time_disjoint_folds(data, n_folds=5, train_fraction=0.6)
    assert folds, "expected at least one fold with positives on the held-out side"
    for train, test in folds:
        assert set(data.entities[train]).isdisjoint(set(data.entities[test]))
        assert data.hours[train].max() < data.hours[test].min(), (
            "train and test overlap in time despite the strict protocol"
        )


def test_attack_family_fold_excludes_the_held_out_technique_from_training():
    data = _dataset()
    folds = dict(attack_family_folds(data))
    assert set(folds) == {"kerberoasting", "dcsync"}
    for family, (train, test) in folds.items():
        assert not (data.families[train] == family).any(), (
            f"{family} windows leaked into training for its own leave-one-out fold"
        )
        assert (data.families[test] == family).any(), (
            f"{family} has no positives on the test side"
        )


def test_family_fold_keeps_other_families_as_training_positives():
    """Leaving one technique out must not blind the model to the others."""
    data = _dataset()
    folds = dict(attack_family_folds(data))
    train, _ = folds["kerberoasting"]
    assert (data.families[train] == "dcsync").any(), (
        "holding out kerberoasting also removed dcsync positives from training"
    )


def test_prevalence_matches_label_mean():
    data = _dataset()
    assert data.prevalence == pytest.approx(data.y.mean())
