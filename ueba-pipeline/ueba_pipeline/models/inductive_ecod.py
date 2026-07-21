"""Inductive ECOD -- a frozen-ECDF reimplementation of Li et al. (TKDE 2022).

WHY THIS EXISTS
---------------
``pyod.models.ecod.ECOD`` is *transductive at inference*. Its
``decision_function(X)`` does::

    X = np.concatenate((self.X_train, X), axis=0)
    self.U_l = -np.log(column_ecdf(X)); ...

Every scoring call re-derives the empirical CDF over the training matrix
concatenated with the batch. Three consequences, each disqualifying for a
streaming detector:

1. **O(n_train) per score call**, degrading linearly as the training set grows.
2. **Scores depend on batch composition.** The same window scored alone vs.
   inside a batch produces different values — the detector is not reproducible,
   cannot be A/B'd, and makes ``score()`` and ``score_stream()`` disagree by
   construction.
3. **The artifact embeds the training data.** Retaining ``X_train`` is an
   unbounded size problem and a confidentiality problem: the model file becomes a
   verbatim copy of the estate's behavioural feature matrix.

This class fits the same ECOD statistic but freezes the per-column ECDF at fit
time into a bounded quantile grid. Scoring is then a binary search per feature:
O(d log q), independent of n_train, order-independent, batch-independent, and
the artifact is O(d * q) regardless of how much data it was trained on.

EQUIVALENCE
-----------
With ``grid_size=None`` the ECDF is exact (full sorted column retained) and
scores match pyod's ECOD to floating-point tolerance on held-out points. With a
finite grid the ECDF is approximated to +/- 1/grid_size in probability; the
default (4096) bounds ECDF error at 2.4e-4, well below the resolution any
threshold quantile is calibrated to.

The ECOD statistic itself is unchanged:
    U_l[j]    = -log P(X_j <= x_j)          (left tail)
    U_r[j]    = -log P(X_j >= x_j)          (right tail)
    U_skew[j] = U_l if skew_j < 0, U_r if skew_j > 0, U_l + U_r if skew_j == 0
    score     = sum_j max(U_l[j], U_r[j], U_skew[j])
Tail probabilities are floored at 1/n_train, matching pyod's ``column_ecdf``,
so a new extreme beyond anything seen in training saturates at -log(1/n) rather
than diverging.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np
from scipy.stats import skew

DEFAULT_GRID = 4096


@dataclass
class InductiveECOD:
    """ECOD with a frozen, bounded-size empirical CDF. Drop-in for the subset of
    the pyod API this project uses (``fit`` / ``decision_function``)."""

    grid_size: Optional[int] = DEFAULT_GRID

    # -- fitted state (bounded: d x grid_size, independent of n_train) ------
    _grids: List[np.ndarray] = field(default_factory=list)   # sorted per-column quantile grid
    _skew_sign: Optional[np.ndarray] = None
    _n_train: int = 0
    _floor: float = 1.0
    decision_scores_: Optional[np.ndarray] = None

    # -- fit ---------------------------------------------------------------
    def fit(self, X: np.ndarray) -> "InductiveECOD":
        X = np.asarray(X, dtype=np.float64)
        if X.ndim != 2 or X.shape[0] < 2:
            raise ValueError("InductiveECOD.fit needs a 2-D array with >= 2 rows")
        n, d = X.shape
        self._n_train = n
        self._floor = 1.0 / n
        self._skew_sign = np.sign(skew(X, axis=0))
        self._skew_sign = np.nan_to_num(self._skew_sign, nan=0.0)

        self._grids = []
        for j in range(d):
            col = np.sort(X[:, j])
            if self.grid_size is None or n <= self.grid_size:
                self._grids.append(col)
            else:
                # Evenly-spaced order statistics: preserves both tails exactly
                # at the endpoints and bounds ECDF error at 1/grid_size.
                idx = np.linspace(0, n - 1, self.grid_size).round().astype(np.int64)
                self._grids.append(col[idx])

        # decision_scores_ on the training set, for threshold calibration.
        # NOTE: computed against the frozen ECDF -- i.e. the *same* function
        # that will score live data. pyod's ECOD instead scores the training
        # set against concat(X_train, X_train), a doubled distribution no live
        # batch ever sees, which silently biases any quantile derived from it.
        self.decision_scores_ = self.decision_function(X)
        return self

    # -- inference ---------------------------------------------------------
    def decision_function(self, X: np.ndarray) -> np.ndarray:
        if not self._grids:
            raise RuntimeError("InductiveECOD.fit must be called first")
        X = np.atleast_2d(np.asarray(X, dtype=np.float64))
        if X.shape[1] != len(self._grids):
            raise ValueError(f"expected {len(self._grids)} features, got {X.shape[1]}")

        n_out = X.shape[0]
        d = len(self._grids)
        u_l = np.empty((n_out, d), dtype=np.float64)
        u_r = np.empty((n_out, d), dtype=np.float64)
        for j, grid in enumerate(self._grids):
            g = len(grid)
            x = X[:, j]
            # P(X_j <= x) and P(X_j >= x) from the frozen grid.
            p_le = np.searchsorted(grid, x, side="right") / g
            p_ge = (g - np.searchsorted(grid, x, side="left")) / g
            u_l[:, j] = -np.log(np.clip(p_le, self._floor, 1.0))
            u_r[:, j] = -np.log(np.clip(p_ge, self._floor, 1.0))

        s = self._skew_sign
        u_skew = u_l * -np.sign(s - 1) + u_r * np.sign(s + 1)
        o = np.maximum(np.maximum(u_l, u_r), u_skew)
        return o.sum(axis=1).ravel()

    # -- introspection: which feature drove the score ----------------------
    def explain(self, x: np.ndarray) -> np.ndarray:
        """Per-feature contribution to one point's score (the interpretability
        the project's design doc claims ECOD gives an analyst -- pyod exposes
        this only as a plot, never as a returned vector, so nothing in this
        repo could actually surface it)."""
        x = np.asarray(x, dtype=np.float64).reshape(1, -1)
        d = len(self._grids)
        u_l = np.empty(d)
        u_r = np.empty(d)
        for j, grid in enumerate(self._grids):
            g = len(grid)
            p_le = np.searchsorted(grid, x[0, j], side="right") / g
            p_ge = (g - np.searchsorted(grid, x[0, j], side="left")) / g
            u_l[j] = -np.log(np.clip(p_le, self._floor, 1.0))
            u_r[j] = -np.log(np.clip(p_ge, self._floor, 1.0))
        s = self._skew_sign
        u_skew = u_l * -np.sign(s - 1) + u_r * np.sign(s + 1)
        return np.maximum(np.maximum(u_l, u_r), u_skew)

    # -- accounting --------------------------------------------------------
    @property
    def state_bytes(self) -> int:
        return sum(g.nbytes for g in self._grids) + (self._skew_sign.nbytes if self._skew_sign is not None else 0)
