"""
monitoring/drift.py — concept-drift and data-quality monitoring (capability
loss, volume drop-outs). Log sources get disabled by unrelated IT changes after
go-live, not just absent at day one; this layer detects that so the engine does
not silently score against a changed schema.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ueba_pipeline.features.manifest import CapabilityManifest


def _kl_divergence(p: np.ndarray, q: np.ndarray) -> float:
    """
    Kullback-Leibler divergence D(p || q) = sum(p * log(p / q)).

    CONTRACT: `p` and `q` must be normalized probability MASSES (`p.sum() == 1`),
    not densities. `np.histogram(..., density=True)` returns mass / bin_width,
    which does not sum to 1 and is not a valid input here — use
    `_to_probability_mass`.
    """
    p = np.asarray(p, dtype=np.float64)
    q = np.asarray(q, dtype=np.float64)
    return float(np.sum(p * np.log(p / q)))


def _to_probability_mass(samples: list[float], bins: np.ndarray) -> np.ndarray:
    """Histogram `samples` into `bins` as counts (not density), then
    normalize to a probability mass vector that sums to 1, with additive
    smoothing so empty bins don't produce log(0)/div-by-zero in KL."""
    counts, _ = np.histogram(samples, bins=bins)
    mass = counts.astype(np.float64) + 1e-10
    return mass / mass.sum()


def detect_concept_drift(old_scores: list[float], new_scores: list[float],
                          kl_threshold: float = 0.2, n_bins: int = 50) -> bool:
    """KL divergence between old and new score-distribution histograms, computed
    on true probability mass (see `_to_probability_mass`).

    `kl_threshold = 0.2` is an interim default: over 200 zero-drift resampling
    trials the observed KL ceiling was ~0.18, while genuinely shifted
    distributions produced KL ≥ 1.1. It is not tuned against real score
    distributions or labelled drift scenarios; re-tune once enough real
    training/scoring runs exist to characterise this pipeline's no-drift KL.
    """
    if not old_scores or not new_scores:
        return False
    bins = np.linspace(0, 1, n_bins)
    old_mass = _to_probability_mass(old_scores, bins)
    new_mass = _to_probability_mass(new_scores, bins)
    return _kl_divergence(old_mass, new_mass) > kl_threshold


@dataclass
class CapabilityDriftReport:
    groups_lost: set
    groups_gained: set
    requires_retrain: bool


def detect_capability_drift(
    trained_manifest: CapabilityManifest, live_manifest: CapabilityManifest
) -> CapabilityDriftReport:
    """
    Detects when a deployment's actual log-source availability has changed
    since the model was trained — e.g. an unrelated GPO change silently
    disabled PowerShell script block logging, or Sysmon got rolled out
    fleet-wide six weeks after initial training. Either direction requires
    a retrain per persistence/store.py's strict manifest check; this
    function is what a scheduled monitoring job calls to decide whether to
    trigger one automatically rather than waiting for a hard load-time
    error.
    """
    lost = trained_manifest.available_groups - live_manifest.available_groups
    gained = live_manifest.available_groups - trained_manifest.available_groups
    return CapabilityDriftReport(
        groups_lost=lost, groups_gained=gained,
        requires_retrain=bool(lost or gained),
    )


@dataclass
class VolumeAnomalyReport:
    is_anomalous_dropout: bool
    current_volume: int
    baseline_mean: float
    baseline_std: float
    z_score: float | None


def detect_volume_dropout(
    current_window_event_count: int, baseline_hourly_counts: list[int],
    z_threshold: float = 3.0,
) -> VolumeAnomalyReport:
    """A sudden drop in total ingested event volume for a channel most
    often means a forwarder died or a GPO regressed, not that the
    environment went quiet — distinguishing those is a monitoring-layer
    job, not something the anomaly scorer should try to infer from a
    behavioral feature vector."""
    if len(baseline_hourly_counts) < 2:
        return VolumeAnomalyReport(False, current_window_event_count, 0.0, 0.0, None)
    arr = np.array(baseline_hourly_counts, dtype=np.float64)
    mean, std = float(arr.mean()), float(arr.std())
    if std < 1e-9:
        return VolumeAnomalyReport(False, current_window_event_count, mean, std, None)
    z = (current_window_event_count - mean) / std
    return VolumeAnomalyReport(
        is_anomalous_dropout=z < -z_threshold,
        current_volume=current_window_event_count,
        baseline_mean=mean, baseline_std=std, z_score=z,
    )
