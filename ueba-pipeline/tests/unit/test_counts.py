"""Gamma-Poisson count anomaly model (models/counts.py).

The predictive tail must be exact (it is checked against scipy's Negative
Binomial), and the properties the track relies on -- safe cold start, ranking
preserved deep in the tail, no degeneracy on sparse counts -- must hold.
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.models.counts import GammaPoissonCounts, negbinom_upper_tail


@pytest.mark.parametrize("r,p,y", [(5, 0.5, 10), (2.5, 0.9, 3), (50, 0.95, 60),
                                   (1, 0.5, 1), (100, 0.99, 120)])
def test_tail_matches_scipy_negative_binomial(r, p, y):
    """P(Y >= y) must equal scipy's nbinom survival, including far into the tail."""
    scipy_stats = pytest.importorskip("scipy.stats")
    ref = float(scipy_stats.nbinom(n=r, p=p).sf(y - 1))
    assert negbinom_upper_tail(y, r, p) == pytest.approx(ref, rel=1e-6, abs=1e-300)


def test_cold_start_is_never_anomalous():
    """With no history, any count must score 1.0.

    A proper Gamma prior is still a claim about the rate, so an unseen entity's
    busy period would otherwise be judged against the prior and flagged. Refusing
    to score without evidence is the same stance the relational detector takes.
    """
    g = GammaPoissonCounts()
    assert g.tail("newcomer", 50) == 1.0
    assert not g.is_covered("newcomer")


def test_entity_becomes_covered_once_it_has_history():
    g = GammaPoissonCounts()
    for c in (3, 2, 4, 3, 3):
        g.observe("svc", c)
    assert g.is_covered("svc")
    assert g.tail("svc", 20) < 1e-6          # far above its learned rate
    assert g.tail("svc", 3) > 0.1            # its ordinary rate is unremarkable


def test_tail_is_monotone_and_ranks_deep_extremes():
    """Two very different extremes must stay rankable, not both clamp to a floor."""
    g = GammaPoissonCounts()
    rng = np.random.default_rng(0)
    for c in rng.poisson(3, 100):
        g.observe("svc", c)
    tails = [g.tail("svc", y) for y in (5, 10, 20, 60, 140)]
    assert all(a > b for a, b in zip(tails, tails[1:]))


def test_no_degeneracy_on_sparse_counts():
    """Where a median/MAD z-score divides by zero, a count model stays finite.

    Most identity-hours hold zero or one event, so MAD is frequently exactly 0 --
    the failure that made the earlier robust-z volume attempt unusable.
    """
    g = GammaPoissonCounts()
    for c in [0] * 80 + [1] * 20:
        g.observe("rare", c)
    assert 0.0 < g.tail("rare", 1) <= 1.0
    assert g.tail("rare", 5) < g.tail("rare", 2) < g.tail("rare", 1)
    assert np.isfinite(g.surprise("rare", 15))


def test_observe_is_o1_sufficient_statistics_only():
    """State must be two numbers per entity, so the model streams."""
    g = GammaPoissonCounts()
    for c in range(100):
        g.observe("e", c)
    assert g.periods("e") == 100
    assert set(g._total) == {"e"} and set(g._periods) == {"e"}


def test_posterior_mean_tracks_the_true_rate():
    g = GammaPoissonCounts()
    rng = np.random.default_rng(1)
    for c in rng.poisson(7, 300):
        g.observe("svc", c)
    assert g.mean_rate("svc") == pytest.approx(7.0, rel=0.15)
