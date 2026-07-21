"""p-value combination toolbox.

Combiner selection follows Heard & Rubin-Delanchy, "Choosing between methods of
combining p-values" (Biometrika 105(1):239-246, 2018), which shows via Birnbaum
(1954) that every reasonable combiner is optimal against *some* alternative, so
the choice is made per level against the alternative that level faces.

TIPPETT (min-p + Šidák)
-----------------------
The engine's combiner, both within a track (many homogeneous tests, expect one
bad) and across the two tracks (an intrusion typically trips one detector). An
entity is as suspicious as its single most anomalous test, corrected for how many
tests it received:

    p_combined = 1 - (1 - min_i p_i)^k

This is optimal against the one-small-among-k alternative and, unlike a decayed
noisy-OR, cannot let a busy-but-benign entity accumulate its way to significance:
more observation only raises the correction. `sidak` implements it.

FISHER
------
    X = -2 * sum_i log(p_i)   ~   chi2(2k),   p = upper tail

Optimal against the *few-small-among-many* alternative. Provided as a utility and
for comparison; it is not on the engine's fusion path, where it would reward
several moderate p-values and, under a fixed alert budget, let ordinary variation
in a chatty entity manufacture significance.

STOUFFER
--------
Preferable when the alternative shifts *all* p-values; provided for comparison.

BENJAMINI-HOCHBERG
------------------
FDR control across the entities tested in a run — the error rate a triage queue
cares about (what fraction of the queue is junk), an alternative to the analyst
budget for entity-level alerting.
"""
from __future__ import annotations

from typing import Sequence, Tuple

import numpy as np
from scipy.stats import chi2

_EPS = 1e-300


def fisher_combine(pvalues: Sequence[float]) -> Tuple[float, float, int]:
    """Combine independent p-values. Returns (combined_p, X, df).

    Empty input is not significant (p = 1.0) rather than an error: an entity
    with no tests has produced no evidence.
    """
    p = np.asarray([q for q in pvalues if q is not None], dtype=np.float64)
    p = np.clip(p[np.isfinite(p)], _EPS, 1.0)
    k = p.size
    if k == 0:
        return 1.0, 0.0, 0
    x = float(-2.0 * np.log(p).sum())
    return float(chi2.sf(x, 2 * k)), x, k


def stouffer_combine(pvalues: Sequence[float], weights: Sequence[float] | None = None) -> float:
    """Stouffer's Z, retained for comparison only.

    Heard & Rubin-Delanchy (2018) show Stouffer is preferable when the
    alternative shifts *all* p-values, and inferior to Fisher when only a few
    are small. Intrusion detection is the latter.
    """
    from scipy.stats import norm

    p = np.clip(np.asarray(list(pvalues), dtype=np.float64), 1e-12, 1 - 1e-12)
    if p.size == 0:
        return 1.0
    w = np.ones_like(p) if weights is None else np.asarray(weights, dtype=np.float64)
    z = float((w * norm.isf(p)).sum() / np.sqrt((w ** 2).sum()))
    return float(norm.sf(z))


def benjamini_hochberg(pvalues: Sequence[float], fdr: float = 0.01) -> np.ndarray:
    """Return a boolean mask of rejections controlling FDR at ``fdr``.

    Benjamini & Hochberg (1995). Chosen over Bonferroni because the operational
    question is "what fraction of my alert queue is noise", not "is any alert
    ever wrong". Bonferroni at these entity counts would suppress essentially
    everything.
    """
    p = np.asarray(list(pvalues), dtype=np.float64)
    n = p.size
    if n == 0:
        return np.zeros(0, dtype=bool)
    order = np.argsort(p)
    thresh = fdr * (np.arange(1, n + 1) / n)
    passed = p[order] <= thresh
    mask = np.zeros(n, dtype=bool)
    if passed.any():
        cutoff = np.max(np.nonzero(passed)[0])
        mask[order[: cutoff + 1]] = True
    return mask


def sidak(p_min: float, n_tests: int) -> float:
    """Šidák correction for taking the minimum of ``n_tests`` independent tests.

    An entity's risk is the most significant window it produced; that minimum is
    itself a test statistic over n_tests windows and must be corrected, or every
    entity with enough windows eventually looks significant -- the same
    frequency bias, reintroduced one level up.
    """
    if n_tests <= 1:
        return float(min(max(p_min, 0.0), 1.0))
    return float(1.0 - (1.0 - min(max(p_min, 0.0), 1.0)) ** n_tests)
