"""Volumetric behavioral detector.

Detection for the *volumetric* attack class -- credential-abuse and mass-request
behaviour whose signal is a sudden change in an entity's activity counts
(e.g. a service account whose distinct source IPs jump 8 -> 65, or an account
issuing an abnormal burst of service-ticket requests during kerberoasting).

Design decisions, each measured rather than assumed:

* Detector = ECOD (Li et al., "ECOD: Unsupervised Outlier Detection Using
  Empirical Cumulative Distribution Functions", TKDE 2022).

  ECOD's selection over COPOD/HBOS/LODA rests on the literature, not on a
  measurement made here: ADBench (Han et al., NeurIPS 2022) finds no
  unsupervised detector dominates, with ECOD/COPOD consistently strong. The
  deciding factor is interpretability -- ECOD yields a per-feature
  tail-probability breakdown, so an analyst sees which dimension drove the
  score, which a forest does not give. A head-to-head on this estate has not
  been run; see BENCHMARK.md.

  ECOD is parameter-free and deterministic.

* Representation = per-entity z-normalised counts. The signal is a deviation
  from the *entity's own* baseline ("high for this account"), which a globally
  fitted model cannot see. Entities without enough history fall back to global
  statistics (cold start). This is the peer/self-relative baseline that
  production UEBA (Securonix, Exabeam) centres on.

* Training excludes threat-signature features (they belong to the rule/label
  layer, not the behavioral model) and known-attack windows (contamination
  guard). Batch fit + stream score: the model is frozen and applied per window;
  online adaptation happens at the next retrain, the production-standard pattern
  for this detector family (ECOD has no incremental update).
"""
from __future__ import annotations

import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

MIN_ENTITY_WINDOWS = 5  # baseline windows before an entity gets its own stats


def _is_signature_feature(key: str) -> bool:
    tokens = (
        "flag", "dcsync", "golden", "silver", "kerberoast", "asrep", "spray",
        "_ticket", "lsass", "ntds", "_susp",
    )
    return any(t in key for t in tokens)


@dataclass
class VolumetricDetector:
    """Per-entity-normalised ECOD over behavioral count features."""

    feature_order: List[str] = field(default_factory=list)
    _model: object = None
    _global_mean: Optional[np.ndarray] = None
    _global_std: Optional[np.ndarray] = None
    _entity_mean: Dict[str, np.ndarray] = field(default_factory=dict)
    _entity_std: Dict[str, np.ndarray] = field(default_factory=dict)

    def _row(self, values: Dict[str, float]) -> np.ndarray:
        return np.array([float(values.get(k, 0.0)) for k in self.feature_order], dtype=np.float64)

    def _encode(self, entity: str, values: Dict[str, float]) -> np.ndarray:
        r = self._row(values)
        if entity in self._entity_mean:
            return (r - self._entity_mean[entity]) / self._entity_std[entity]
        return (r - self._global_mean) / self._global_std

    def fit(self, windows: List) -> "VolumetricDetector":
        """Fit on benign training windows. Each window needs ``.user`` and
        ``.values`` (dict). Signature features are dropped automatically."""
        from ueba_pipeline.models.inductive_ecod import InductiveECOD

        if not self.feature_order:
            keys = sorted({k for w in windows for k in w.values})
            self.feature_order = [k for k in keys if not _is_signature_feature(k)]

        raw = np.array([self._row(w.values) for w in windows])
        self._global_mean = raw.mean(axis=0)
        self._global_std = raw.std(axis=0) + 1e-6

        by_entity: Dict[str, list] = defaultdict(list)
        for w in windows:
            by_entity[_norm(w.user)].append(self._row(w.values))
        for ent, rows in by_entity.items():
            if len(rows) >= MIN_ENTITY_WINDOWS:
                arr = np.asarray(rows)
                self._entity_mean[ent] = arr.mean(axis=0)
                self._entity_std[ent] = arr.std(axis=0) + 1e-6

        X = np.array([self._encode(_norm(w.user), w.values) for w in windows])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self._model = InductiveECOD()
            self._model.fit(X)
        return self

    def score(self, window) -> float:
        """Anomaly score for one window (higher = more anomalous)."""
        if self._model is None:
            raise RuntimeError("VolumetricDetector.fit must be called first")
        X = self._encode(_norm(window.user), window.values).reshape(1, -1)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return float(self._model.decision_function(X)[0])

    def score_many(self, windows: List) -> np.ndarray:
        X = np.array([self._encode(_norm(w.user), w.values) for w in windows])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return self._model.decision_function(X)


def _norm(v) -> str:
    if v is None:
        return ""
    return str(v).strip().lower().split("@")[0]
