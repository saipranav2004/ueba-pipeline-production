"""Fisher's exact g-test for periodicity (models/periodicity.py).

The g-test is the statistical core of NHI typing, so its p-value must be exactly
Fisher's (1929) — verified here against hand-computed values — and its qualitative
behaviour (a period gives tiny p, noise does not) must hold.
"""
import math
import sys
from itertools import pairwise
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ueba_pipeline.models.periodicity import fisher_g_pvalue, fisher_g_test


def test_gpvalue_matches_hand_computed_small_m():
    """p = sum_{k=1}^{floor(1/g)} (-1)^(k-1) C(m,k) (1-k*g)^(m-1)."""
    # m=2, g=0.6: b=1 -> C(2,1)*(0.4)^1 = 0.8
    assert fisher_g_pvalue(0.6, 2) == 0.8
    # m=3, g=0.5: b=2 -> C(3,1)(0.5)^2 - C(3,2)(0)^2 = 0.75 - 0 = 0.75
    assert abs(fisher_g_pvalue(0.5, 3) - 0.75) < 1e-12


def test_gpvalue_is_monotone_decreasing_in_g():
    """A more dominant ordinate is more significant (smaller p)."""
    ps = [fisher_g_pvalue(g, 100) for g in (0.05, 0.1, 0.2, 0.4, 0.8)]
    assert all(a > b for a, b in pairwise(ps))


def test_gpvalue_bounds():
    assert fisher_g_pvalue(0.0, 50) == 1.0          # no power anywhere
    assert fisher_g_pvalue(1.0, 50) < 1e-10         # all power in one ordinate
    assert fisher_g_pvalue(0.5, 0) == 1.0           # no ordinates -> undefined -> 1


def test_pure_periodic_signal_is_significant():
    """A clean sinusoid concentrates all power in one ordinate: g~1, p~0."""
    t = np.arange(480)
    r = fisher_g_test(np.sin(2 * math.pi * t / 24))
    assert r.g > 0.99
    assert r.p_value < 1e-6
    assert abs(r.dominant_period_bins - 24.0) < 1e-6


def test_daily_spike_train_is_significant():
    """A once-a-day event (a scheduled job) is strongly periodic."""
    x = np.zeros(480)
    x[np.arange(20) * 24 + 21] = 1.0
    r = fisher_g_test(x)
    assert r.p_value < 1e-3


def test_constant_and_tiny_series_are_non_periodic():
    """Degenerate inputs are reported non-periodic, never raised on."""
    flat = fisher_g_test(np.ones(100))              # no variation -> no power
    assert flat.g == 0.0 and flat.p_value == 1.0
    tiny = fisher_g_test(np.array([0.0, 1.0, 0.0]))  # too few ordinates
    assert tiny.p_value == 1.0


def test_white_noise_is_usually_not_flagged():
    """Across many white-noise draws, the g-test rejects at roughly its nominal
    rate — not on almost everything (which a mis-scaled statistic would)."""
    rng = np.random.default_rng(0)
    flagged = sum(fisher_g_test(rng.standard_normal(240)).p_value < 0.01
                  for _ in range(200))
    assert flagged < 20   # ~1% nominal, generously bounded for sampling noise
