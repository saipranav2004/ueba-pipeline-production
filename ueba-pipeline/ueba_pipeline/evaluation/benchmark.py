"""Per-authentication ROC evaluation on a labelled auth stream (LANL / OpTC).

Reports the metric the lateral-movement literature uses so results are directly
comparable: an ROC over the anomaly score, i.e. true-positive rate at a fixed
false-positive rate, plus AUC. The unit under test is the production graph
detector's calibrated per-view edge surprise -- the same scoring the engine uses,
not a bare raw-surprise threshold.

Reference (LANL, Bowman et al. RAID 2020): ~0.85 TPR at 0.9% FPR for unsupervised
graph learning, vs ~0.72 TPR / 4.4% FPR for the best non-graph ML. King & Huang
("Euler", TOPS 2023) report temporal-GNN link prediction on LANL/OpTC.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np

from ueba_pipeline.graph.auth_graph_anomaly import AuthGraphAnomalyDetector, AuthGraphConfig
from ueba_pipeline.models.fisher import sidak
from ueba_pipeline.models.pvalue import EmpiricalPValue


@dataclass
class RocResult:
    n_train: int
    n_test: int
    n_malicious: int
    contamination: str
    tpr_at_target_fpr: float
    target_fpr: float
    achieved_fpr: float
    auc: float
    throughput_events_per_s: float

    def render(self) -> str:
        return (
            f"per-auth ROC  [contamination={self.contamination}]\n"
            f"  train {self.n_train:,}  test {self.n_test:,}  malicious {self.n_malicious:,}\n"
            f"  TPR @ {self.target_fpr:.1%} FPR = {self.tpr_at_target_fpr:.3f} "
            f"(achieved FPR {self.achieved_fpr:.4f})   AUC {self.auc:.3f}\n"
            f"  throughput {self.throughput_events_per_s:,.0f} events/s\n"
            "  reference (LANL, Bowman RAID 2020): ~0.85 TPR @ 0.009 FPR"
        )


def _fit_view_nulls(det: AuthGraphAnomalyDetector, train) -> dict:
    by_view: dict = {}
    for e in train:
        for view, s in det.score_event_views(e, absorb=False):
            by_view.setdefault(view, []).append(s)
    return {v: EmpiricalPValue().fit(np.asarray(s)) for v, s in by_view.items()}


def _event_pvalue(det: AuthGraphAnomalyDetector, nulls: dict, e, absorb: bool) -> float:
    """Production graph p-value for one event: most-significant view against its
    own frozen null, Sidak-corrected for the number of views that fired."""
    ps = []
    for view, s in det.score_event_views(e, absorb=absorb):
        null = nulls.get(view)
        if null is not None:
            ps.append(float(null.pvalue(s)[0]))
    return sidak(min(ps), len(ps)) if ps else 1.0


def _roc_auc(scores: np.ndarray, labels: np.ndarray, target_fpr: float):
    """ROC over an anomaly score where LOWER p = more anomalous. Returns
    (tpr_at_target_fpr, achieved_fpr, auc)."""
    anomaly = -scores                       # higher = more anomalous
    order = np.argsort(-anomaly)            # most anomalous first
    y = labels[order]
    P, N = int(y.sum()), int((~y.astype(bool)).sum())
    if P == 0 or N == 0:
        return 0.0, 0.0, 0.5
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    tpr = tp / P
    fpr = fp / N
    _trap = getattr(np, "trapezoid", None) or np.trapz  # numpy>=2 renamed trapz
    auc = float(_trap(np.concatenate(([0], tpr)), np.concatenate(([0], fpr))))
    idx = np.searchsorted(fpr, target_fpr, side="right") - 1
    if idx < 0:
        return 0.0, 0.0, auc
    return float(tpr[idx]), float(fpr[idx]), auc


def lanl_roc_eval(
    events: list,
    is_malicious: Callable[[object], bool],
    train_fraction: float = 0.5,
    contamination: str = "oracle",
    target_fpr: float = 0.009,
    config: AuthGraphConfig | None = None,
) -> RocResult:
    """Causal, per-authentication ROC of the production graph detector.

    contamination: 'oracle' excludes red-team events from the training baseline
    (upper bound); 'none' trains on everything (unlabelled cold start). Test-set
    scoring adapts online (absorb=True), the streaming path; MIDAS-F stops a
    flagged edge from being absorbed.
    """
    events = sorted(events, key=lambda e: e.event_time)
    split_time = events[int(len(events) * train_fraction)].event_time
    train = [e for e in events if e.event_time < split_time]
    test = [e for e in events if e.event_time >= split_time]

    det = AuthGraphAnomalyDetector(config=config or AuthGraphConfig())
    for e in train:
        if contamination == "oracle" and is_malicious(e):
            continue
        det.observe_baseline(e)
    nulls = _fit_view_nulls(
        det, [e for e in train if not (contamination == "oracle" and is_malicious(e))])

    scores, labels = [], []
    t0 = time.perf_counter()
    for e in test:
        scores.append(_event_pvalue(det, nulls, e, absorb=True))
        labels.append(bool(is_malicious(e)))
    elapsed = time.perf_counter() - t0

    scores = np.asarray(scores)
    labels = np.asarray(labels, dtype=bool)
    tpr, achieved, auc = _roc_auc(scores, labels, target_fpr)
    return RocResult(
        n_train=len(train), n_test=len(test), n_malicious=int(labels.sum()),
        contamination=contamination, tpr_at_target_fpr=tpr, target_fpr=target_fpr,
        achieved_fpr=achieved, auc=auc,
        throughput_events_per_s=len(test) / elapsed if elapsed else 0.0,
    )
