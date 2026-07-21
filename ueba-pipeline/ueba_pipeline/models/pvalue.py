"""Calibrated p-values from a frozen empirical null.

RESEARCH BASIS
--------------
Rubin-Delanchy, Lawson & Heard, "Anomaly detection for cyber security
applications" (Dynamic Networks and Cyber-Security, World Scientific, 2016) set
out the modus operandi this module implements: a monitoring tool learns 'normal'
behaviour from large stores of benign data; intrusion is then framed as a
hypothesis test where, under H0 (no intrusion), observations follow the learnt
model. The output of every detector should therefore be a **p-value** -- the
upper-tail probability of the observed statistic under the benign null -- not an
uncalibrated score.

Turcotte, Moore, Heard & McPhall, "Poisson factorization for peer-based anomaly
detection" (IEEE ISI 2016) score LANL authentication and process activity by
exactly this quantity: "an anomaly score equal to the upper tail probability of
y_ui given the posterior expected [rate]".

WHY THIS MATTERS HERE
---------------------
The engine runs several detectors on incommensurable scales. p-values are
commensurable by construction: a p of 1e-4 means the same thing whichever
detector produced it, which is the precondition for principled fusion (see
fisher.py). Uncalibrated scores can only be combined by rescaling each with a
hand-picked constant, which does not survive contact with a second detector.

CALIBRATION IS NOT A PROMISE OF UNIFORMITY
------------------------------------------
p-values are uniform under the null only if train and live data are
exchangeable. They are not: estates drift. So the realised false-positive rate
will exceed the nominal alpha, and the *size of that gap is a direct measurement
of train/test distribution shift* -- which the benchmark now reports rather than
hides.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import numpy as np

DEFAULT_GRID = 4096


@dataclass
class EmpiricalPValue:
    """Upper-tail p-value against a frozen empirical null distribution.

    The null is stored as a bounded quantile grid (not the raw sample), so the
    fitted object is O(grid) regardless of how much benign data it saw, holds no
    copy of the training telemetry, and scores in O(log grid) by binary search.
    """

    grid_size: int = DEFAULT_GRID
    _grid: Optional[np.ndarray] = None
    _n: int = 0

    def fit(self, benign_scores: np.ndarray) -> "EmpiricalPValue":
        x = np.asarray(benign_scores, dtype=np.float64).ravel()
        x = x[np.isfinite(x)]
        if x.size == 0:
            x = np.zeros(1)
        self._n = int(x.size)
        s = np.sort(x)
        if s.size > self.grid_size:
            idx = np.linspace(0, s.size - 1, self.grid_size).round().astype(np.int64)
            s = s[idx]
        self._grid = s
        return self

    def pvalue(self, scores) -> np.ndarray:
        """P(S >= s) under the benign null, floored at 1/(n+1).

        The floor is the standard finite-sample bound: with n benign
        observations you cannot assert a tail probability smaller than
        1/(n+1) without extrapolating beyond your evidence. Reporting an
        unfloored 0 would let a single observation dominate any Fisher
        combination with infinite weight.
        """
        if self._grid is None:
            raise RuntimeError("EmpiricalPValue.fit must be called first")
        s = np.atleast_1d(np.asarray(scores, dtype=np.float64))
        g = self._grid.size
        n_ge = g - np.searchsorted(self._grid, s, side="left")
        p = (n_ge + 1.0) / (g + 1.0)
        return np.clip(p, 1.0 / (self._n + 1.0), 1.0)

    @property
    def state_bytes(self) -> int:
        return 0 if self._grid is None else self._grid.nbytes
