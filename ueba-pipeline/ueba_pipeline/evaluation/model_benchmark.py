"""Leakage-resistant comparison of classical models on the behavioural feature matrix.

WHAT THIS ANSWERS
-----------------
The engine's detection path is a statistical graph model. That is one hypothesis
about how to separate malicious from benign behaviour, and it has never been
compared against the obvious alternatives on the same data under the same rules.
This module runs that comparison: several supervised and unsupervised classical
models over the per-(entity, hour) feature vectors, plus the engine's own graph
score as a reference column, all scored by one protocol.

Deep-learning methods are out of scope by design. Every model here is a classical
estimator whose fit is deterministic given a seed.

WHY THE PROTOCOL LOOKS LIKE THIS
--------------------------------
Three properties of the problem drive every choice below.

*Extreme imbalance.* Malicious windows are a tiny fraction of all windows, so
accuracy is meaningless and ROC-AUC is close to insensitive — a detector can move
from useless to usable while ROC-AUC barely moves. Average precision (PR-AUC) is
the primary metric, and prevalence is reported next to it so the numbers can be
read against the right baseline: a random ranker scores PR-AUC equal to
prevalence, not 0.5.

*Very few positives.* An estate-day produces few attack windows. Point estimates
from a single run are therefore noisy, and the harness aggregates across
independent seeds reporting mean and spread rather than one flattering figure.
Where a fold contains too few positives to estimate anything, it is skipped and
counted, not silently averaged in.

*Thresholds must not see test labels.* The operating point is fixed by policy —
the same per-day alert budget the engine deploys with — and never chosen by
sweeping the test set for the best F1. Choosing a threshold on the test set and
reporting the metrics it produces is the most common way an anomaly-detection
benchmark overstates itself.

THE THREE SPLIT PROTOCOLS
-------------------------
Each answers a different generalisation question, and a model can pass one while
failing another:

``temporal``
    Train on the earlier part of the estate's timeline, test on the later part.
    Answers: does yesterday's baseline hold tomorrow? This is the deployment
    condition, and the only protocol whose numbers describe live operation.

``entity_disjoint``
    No account appears in both train and test. Answers: does the model work on an
    account it has never seen — a new hire, a newly onboarded service account,
    the cold-start case? A per-entity self-baseline is expected to do poorly here
    and that is informative, not a defect: it quantifies how much of the model's
    power comes from having history on the specific account.

``attack_family_disjoint``
    One technique is withheld from training entirely and appears only in test.
    Answers: does the model detect a technique it was never trained on? This is
    the closest available proxy for unknown-threat detection, and it is the
    protocol under which signature-like features collapse — which is exactly why
    the feature contract keeps them out of model input.
"""
from __future__ import annotations

import json
import statistics
import time
import tracemalloc
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

import numpy as np

from ueba_pipeline.config.schema import load_config
from ueba_pipeline.features import build_capability_manifest, build_user_windows
from ueba_pipeline.features.contract import contract_hash, model_feature_names
from ueba_pipeline.ingestion.source import FileEventSource
from ueba_pipeline.parsing.normalize import entity_key as _norm

# Tolerance around a labelled attack span, matching the engine's own evaluation
# harness so both report against the same notion of "during the attack".
ATTACK_TOLERANCE = timedelta(hours=1)

# Alert budget defining the reported operating point. Policy, not a tuned value:
# it is the analyst capacity the product is designed around, and it is applied
# identically to every model so the precision/recall column is comparable.
DEFAULT_ALERT_BUDGET_PER_DAY = 5.0

RANDOM_SEED = 20250106

# Negative/positive ratio at the estate's ~0.7% prevalence, used as XGBoost's
# scale_pos_weight. Held as a constant rather than fitted per fold so every fold
# sees the same learner; the folds' prevalences differ by well under an order of
# magnitude, so a per-fold value would change the model without changing the
# comparison it is part of.
_IMBALANCE_RATIO = 140.0


# ── dataset ────────────────────────────────────────────────────────────────
@dataclass
class WindowDataset:
    """A labelled (entity, hour) design matrix and everything needed to split it."""

    X: np.ndarray
    y: np.ndarray
    entities: np.ndarray          # account per row, for entity-disjoint splits
    hours: np.ndarray             # window start per row, for temporal splits
    families: np.ndarray          # attack technique per positive row, "" if benign
    feature_names: list[str]
    contract: str                 # feature-contract version+hash the matrix was built under
    source: str

    def __len__(self) -> int:
        return int(self.X.shape[0])

    @property
    def prevalence(self) -> float:
        return float(self.y.mean()) if len(self) else 0.0

    @property
    def observed_days(self) -> float:
        if not len(self):
            return 1.0
        span = (self.hours.max() - self.hours.min()) / np.timedelta64(1, "D")
        return max(float(span), 1.0)


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _attack_principals(attack: dict) -> set:
    """Accounts an alert may legitimately name for this attack.

    Mirrors ``honest_eval.attack_principals`` so the supervised labels here and
    the engine's detection credit describe the same event.
    """
    principals = {_norm(u) for u in attack.get("target_users", [])}
    details = attack.get("details") or {}
    for key in ("attacker", "target"):
        if details.get(key):
            principals.add(_norm(details[key]))
    return {p for p in principals if p}


def graph_reference_scores(data_dir: str, data: WindowDataset,
                           train_fraction: float = 0.60,
                           ) -> dict[tuple[str, np.datetime64], float] | None:
    """Score the shipped graph track per window under the same temporal split.

    The graph detector reads relational edges, not the feature matrix, so it
    cannot be a row in the estimator loop. It is scored here on its own substrate
    and mapped to (entity, floored-hour) so its per-window separation can be
    reported in the same PR-AUC column as the classical models. This is the one
    fair comparison between the two representations; forcing the graph track to
    consume the feature vectors, or the classical models to consume edges, would
    compare neither faithfully.

    Returns a map of (entity, hour) -> anomaly score (1 - graph p-value), or
    None if the engine is unavailable. The split boundary matches
    ``temporal_folds`` so the reference and the classical temporal rows describe
    the same train/test division.
    """
    try:
        from ueba_pipeline.engine import BehavioralEngine, EngineConfig, _floor_hour
    except Exception:
        return None

    events = [e for e in FileEventSource.from_directory(data_dir).read() if e.event_time]
    events.sort(key=lambda e: e.event_time)
    if not events:
        return None
    t0, t1 = events[0].event_time, events[-1].event_time
    split = t0 + (t1 - t0) * train_fraction
    train = [e for e in events if e.event_time < split]
    test = [e for e in events if e.event_time >= split]
    if not train or not test:
        return None

    config = load_config()
    engine = BehavioralEngine(config=EngineConfig(
        window_hours=config.window.feature_window_hours))
    engine.fit(train, config_capability=config.capability)
    detections, _ = engine.score(test)

    scores: dict[tuple[str, np.datetime64], float] = {}
    for d in detections:
        if d.graph_p >= 1.0:
            continue
        key = (_norm(d.entity), np.datetime64(_floor_hour(d.hour).replace(tzinfo=None), "s"))
        scores[key] = max(scores.get(key, 0.0), 1.0 - d.graph_p)
    return scores


def build_window_dataset(data_dir: str, window_hours: float = 1.0) -> WindowDataset:
    """Ingest one estate and produce the labelled matrix.

    A window is positive when its account is a principal of a labelled attack and
    the window overlaps that attack's span. Labelling by time alone would mark
    every account active during the attack hour, which measures activity rather
    than compromise.

    Only contract-eligible columns are materialised, so a quarantined indicator
    cannot reach a model even by accident downstream.
    """
    config = load_config()
    events = [e for e in FileEventSource.from_directory(data_dir).read() if e.event_time]
    events.sort(key=lambda e: e.event_time)

    manifest = build_capability_manifest(events, config.capability)
    windows = build_user_windows(events, manifest, window_hours)
    windows.sort(key=lambda w: (w.window_start, w.user))

    names = model_feature_names(manifest)

    with open(f"{data_dir}/attack_labels.jsonl", encoding="utf-8") as handle:
        attacks = [json.loads(line) for line in handle if line.strip()]
    for attack in attacks:
        attack["_start"] = _parse_time(attack["start_time"]) - ATTACK_TOLERANCE
        attack["_end"] = _parse_time(attack["end_time"]) + ATTACK_TOLERANCE
        attack["_principals"] = _attack_principals(attack)

    rows, labels, entities, hours, families = [], [], [], [], []
    for window in windows:
        entity = _norm(window.user)
        start, end = window.window_start, window.window_end
        family = ""
        for attack in attacks:
            if (entity in attack["_principals"]
                    and start <= attack["_end"] and end >= attack["_start"]):
                family = attack["attack_type"]
                break
        rows.append([float(window.values.get(n, 0.0)) for n in names])
        labels.append(1 if family else 0)
        entities.append(entity)
        hours.append(np.datetime64(start.replace(tzinfo=None), "s"))
        families.append(family)

    return WindowDataset(
        X=np.asarray(rows, dtype=np.float64),
        y=np.asarray(labels, dtype=np.int8),
        entities=np.asarray(entities),
        hours=np.asarray(hours),
        families=np.asarray(families),
        feature_names=names,
        contract=contract_hash(manifest),
        source=data_dir,
    )


# ── split protocols ────────────────────────────────────────────────────────
Fold = tuple[np.ndarray, np.ndarray]


def temporal_folds(data: WindowDataset, train_fraction: float = 0.60) -> list[Fold]:
    """One causal split: everything before the cut trains, everything after tests."""
    order = np.argsort(data.hours, kind="stable")
    cut = int(len(order) * train_fraction)
    if cut == 0 or cut == len(order):
        return []
    boundary = data.hours[order[cut]]
    # Move the boundary to a window edge so a single hour never straddles the
    # split, which would place the same hour's behaviour on both sides.
    train = np.flatnonzero(data.hours < boundary)
    test = np.flatnonzero(data.hours >= boundary)
    return [(train, test)] if len(train) and len(test) else []


def entity_disjoint_folds(data: WindowDataset, n_folds: int = 5,
                          seed: int = RANDOM_SEED) -> list[Fold]:
    """K folds in which no account appears on both sides.

    Accounts are partitioned, then rows follow their account. Splitting rows
    directly would put the same account's Monday in train and its Tuesday in
    test, which measures recall of a memorised baseline rather than transfer to
    an unseen identity.
    """
    unique = np.unique(data.entities)
    rng = np.random.default_rng(seed)
    rng.shuffle(unique)
    buckets = np.array_split(unique, n_folds)

    folds: list[Fold] = []
    for held_out in buckets:
        if not len(held_out):
            continue
        mask = np.isin(data.entities, held_out)
        train, test = np.flatnonzero(~mask), np.flatnonzero(mask)
        if len(train) and len(test):
            folds.append((train, test))
    return folds


def entity_and_time_disjoint_folds(data: WindowDataset, n_folds: int = 5,
                                    train_fraction: float = 0.60,
                                    seed: int = RANDOM_SEED) -> list[Fold]:
    """The strict protocol: train and test share neither an account nor an hour.

    Entity-disjoint folds alone are not sufficient, and measurably so. Their folds
    still overlap in time, so a model can learn a campaign from the accounts held
    in training and recognise the same campaign, in the same hours, on the
    accounts held out — scoring well without generalising to anything. On this
    estate that shortcut roughly doubles apparent PR-AUC relative to the temporal
    protocol, which is the opposite of the expected ordering and is the signature
    of the leak rather than of a genuinely easier task.

    Removing both shortcuts at once costs positives, because the test side keeps
    only the held-out accounts in the later period. Folds left without positives
    are skipped and reported, not padded.
    """
    unique = np.unique(data.entities)
    rng = np.random.default_rng(seed)
    rng.shuffle(unique)
    buckets = np.array_split(unique, n_folds)

    order = np.argsort(data.hours, kind="stable")
    cut = int(len(order) * train_fraction)
    if cut == 0 or cut == len(order):
        return []
    boundary = data.hours[order[cut]]

    folds: list[Fold] = []
    for held_out in buckets:
        if not len(held_out):
            continue
        is_held = np.isin(data.entities, held_out)
        train = np.flatnonzero(~is_held & (data.hours < boundary))
        test = np.flatnonzero(is_held & (data.hours >= boundary))
        if len(train) and len(test):
            folds.append((train, test))
    return folds


def attack_family_folds(data: WindowDataset) -> list[tuple[str, Fold]]:
    """Leave-one-technique-out: the held-out family's positives never train.

    Windows of the held-out family are removed from training rather than
    relabelled benign. Relabelling them would actively teach the model that the
    technique's behaviour is normal, which understates transfer for a reason that
    has nothing to do with the model.
    """
    present = sorted({f for f in np.unique(data.families) if f})
    folds: list[tuple[str, Fold]] = []
    for family in present:
        is_family = data.families == family
        train = np.flatnonzero(~is_family)
        # Test on the held-out family's positives against the full benign field,
        # so precision is measured against a realistic amount of benign traffic.
        test = np.flatnonzero(is_family | (data.y == 0))
        if is_family.sum() and len(train):
            folds.append((family, (train, test)))
    return folds


# ── model zoo ──────────────────────────────────────────────────────────────
@dataclass
class ModelSpec:
    name: str
    build: Callable[[], object]
    supervised: bool
    # Methods whose fit cost grows worse than linearly get a training cap; the
    # cap is recorded in the results so a truncated fit is never read as a full one.
    max_train_rows: int | None = None
    note: str = ""


def _supervised_zoo() -> list[ModelSpec]:
    from sklearn.ensemble import (
        ExtraTreesClassifier,
        HistGradientBoostingClassifier,
        RandomForestClassifier,
    )
    from sklearn.impute import SimpleImputer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    def linear() -> object:
        return Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000, class_weight="balanced", random_state=RANDOM_SEED)),
        ])

    def forest(cls) -> Callable[[], object]:
        return lambda: Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("clf", cls(n_estimators=300, class_weight="balanced_subsample",
                        n_jobs=-1, random_state=RANDOM_SEED)),
        ])

    def boosting() -> object:
        # class_weight="balanced" rather than unweighted: the other supervised
        # models are class-weighted, and comparing a weighted model against an
        # unweighted one measures the weighting, not the learner. At ~0.7%
        # prevalence an unweighted boosting model predicts the majority class
        # almost everywhere.
        return Pipeline([
            ("clf", HistGradientBoostingClassifier(
                class_weight="balanced", random_state=RANDOM_SEED)),
        ])

    def xgboost_model() -> object:
        from xgboost import XGBClassifier
        return Pipeline([
            ("clf", XGBClassifier(
                n_estimators=300, max_depth=6, learning_rate=0.1,
                # The documented remedy for imbalance in XGBoost: weight the
                # positive class by the negative/positive ratio, which is what
                # class_weight="balanced" does for the other learners.
                scale_pos_weight=_IMBALANCE_RATIO,
                eval_metric="aucpr", n_jobs=-1, random_state=RANDOM_SEED,
                tree_method="hist")),
        ])

    return [
        ModelSpec("logistic_regression", linear, True,
                  note="L2 linear baseline; class-weighted for imbalance."),
        ModelSpec("random_forest", forest(RandomForestClassifier), True),
        ModelSpec("extra_trees", forest(ExtraTreesClassifier), True),
        ModelSpec("hist_gradient_boosting", boosting, True,
                  note="Handles NaN natively, so no imputation step."),
        ModelSpec("xgboost", xgboost_model, True,
                  note="scale_pos_weight set to the negative/positive ratio."),
    ]


def _unsupervised_zoo() -> list[ModelSpec]:
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM

    def scaled(estimator) -> object:
        return Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("clf", estimator),
        ])

    return [
        ModelSpec("isolation_forest",
                  lambda: scaled(IsolationForest(n_estimators=300,
                                                  random_state=RANDOM_SEED, n_jobs=-1)),
                  False),
        ModelSpec("local_outlier_factor",
                  lambda: scaled(LocalOutlierFactor(novelty=True, n_jobs=-1)),
                  False, max_train_rows=20000,
                  note="Neighbour search is superlinear in training rows; capped."),
        ModelSpec("one_class_svm",
                  lambda: scaled(OneClassSVM(kernel="rbf", nu=0.05, gamma="scale")),
                  False, max_train_rows=8000,
                  note="RBF kernel fit is ~O(n^2); capped to stay tractable."),
    ]


def model_zoo() -> list[ModelSpec]:
    return _supervised_zoo() + _unsupervised_zoo()


# ── metrics ────────────────────────────────────────────────────────────────
@dataclass
class ModelResult:
    model: str
    protocol: str
    fold: str
    n_train: int
    n_test: int
    n_positives: int
    prevalence: float
    pr_auc: float
    roc_auc: float
    recall_at_1pct_fpr: float
    precision_at_budget: float
    recall_at_budget: float
    f1_at_budget: float
    mcc_at_budget: float
    brier: float | None
    fit_seconds: float
    score_seconds: float
    peak_mib: float
    truncated_train: bool = False
    note: str = ""


def _recall_at_fpr(y_true: np.ndarray, scores: np.ndarray, max_fpr: float) -> float:
    from sklearn.metrics import roc_curve

    fpr, tpr, _ = roc_curve(y_true, scores)
    allowed = fpr <= max_fpr
    return float(tpr[allowed].max()) if allowed.any() else 0.0


def _budget_metrics(y_true: np.ndarray, scores: np.ndarray,
                    k: int) -> tuple[float, float, float, float]:
    """Precision/recall/F1/MCC when the top ``k`` scored windows are alerted.

    ``k`` comes from the alert budget and the length of the test period, so no
    test label participates in choosing the operating point.
    """
    from sklearn.metrics import matthews_corrcoef, precision_recall_fscore_support

    k = max(1, min(k, len(scores)))
    predicted = np.zeros_like(y_true)
    predicted[np.argsort(scores, kind="stable")[::-1][:k]] = 1
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predicted, average="binary", zero_division=0)
    mcc = matthews_corrcoef(y_true, predicted) if predicted.any() and y_true.any() else 0.0
    return float(precision), float(recall), float(f1), float(mcc)


def _score_model(
    spec: ModelSpec, X_train, y_train, X_test,
) -> tuple[np.ndarray, float, float, float, bool, np.ndarray | None]:
    """Fit and score one model, returning anomaly scores where higher = more suspicious."""
    rng = np.random.default_rng(RANDOM_SEED)
    truncated = False

    if spec.supervised:
        fit_X, fit_y = X_train, y_train
    else:
        # Unsupervised detectors model normality, so they are fitted on the
        # benign training rows only. Including known attack rows would teach the
        # model that the attack is part of the normal region it must not flag.
        benign = np.flatnonzero(y_train == 0)
        fit_X, fit_y = X_train[benign], None

    if spec.max_train_rows and len(fit_X) > spec.max_train_rows:
        keep = rng.choice(len(fit_X), spec.max_train_rows, replace=False)
        fit_X = fit_X[keep]
        if fit_y is not None:
            fit_y = fit_y[keep]
        truncated = True

    model = spec.build()
    tracemalloc.start()
    started = time.perf_counter()
    model.fit(fit_X, fit_y) if spec.supervised else model.fit(fit_X)
    fit_seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    started = time.perf_counter()
    probabilities: np.ndarray | None = None
    if spec.supervised:
        probabilities = model.predict_proba(X_test)[:, 1]
        scores = probabilities
    else:
        # sklearn's convention is higher = more normal; invert so that in every
        # column of the report a larger score means more suspicious.
        scores = -model.score_samples(X_test)
    score_seconds = time.perf_counter() - started

    return scores, fit_seconds, score_seconds, peak / (1024 * 1024), truncated, probabilities


def evaluate_fold(spec: ModelSpec, data: WindowDataset, train_idx: np.ndarray,
                  test_idx: np.ndarray, protocol: str, fold: str,
                  alert_budget_per_day: float) -> ModelResult | None:
    from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score

    y_train, y_test = data.y[train_idx], data.y[test_idx]
    positives = int(y_test.sum())
    # A fold with no positives, or with no negatives, cannot rank anything; it is
    # reported as skipped rather than averaged in as a zero.
    if positives == 0 or positives == len(y_test):
        return None
    if spec.supervised and y_train.sum() == 0:
        return None

    X_train, X_test = data.X[train_idx], data.X[test_idx]
    scores, fit_s, score_s, peak_mib, truncated, probabilities = _score_model(
        spec, X_train, y_train, X_test)

    days = max(
        (data.hours[test_idx].max() - data.hours[test_idx].min())
        / np.timedelta64(1, "D"), 1.0)
    k = round(alert_budget_per_day * float(days))
    precision, recall, f1, mcc = _budget_metrics(y_test, scores, k)

    return ModelResult(
        model=spec.name,
        protocol=protocol,
        fold=fold,
        n_train=len(train_idx),
        n_test=len(test_idx),
        n_positives=positives,
        prevalence=float(y_test.mean()),
        pr_auc=float(average_precision_score(y_test, scores)),
        roc_auc=float(roc_auc_score(y_test, scores)),
        recall_at_1pct_fpr=_recall_at_fpr(y_test, scores, 0.01),
        precision_at_budget=precision,
        recall_at_budget=recall,
        f1_at_budget=f1,
        mcc_at_budget=mcc,
        brier=float(brier_score_loss(y_test, probabilities)) if probabilities is not None else None,
        fit_seconds=fit_s,
        score_seconds=score_s,
        peak_mib=peak_mib,
        truncated_train=truncated,
        note=spec.note,
    )


# ── benchmark driver ───────────────────────────────────────────────────────
def evaluate_graph_reference(data: WindowDataset,
                             scores_by_cell: dict[tuple[str, np.datetime64], float],
                             train_fraction: float = 0.60,
                             alert_budget_per_day: float = DEFAULT_ALERT_BUDGET_PER_DAY,
                             ) -> ModelResult | None:
    """Turn the graph track's per-window scores into a temporal-protocol row.

    Rows in the temporal test fold are looked up in the graph score map; a window
    the graph track never scored (no edge projected) gets 0, which is correct —
    the detector expressed no suspicion about it.
    """
    from sklearn.metrics import average_precision_score, roc_auc_score

    folds = temporal_folds(data, train_fraction)
    if not folds:
        return None
    _, test_idx = folds[0]
    y_test = data.y[test_idx]
    positives = int(y_test.sum())
    if positives == 0 or positives == len(y_test):
        return None

    scores = np.array([
        scores_by_cell.get((data.entities[i], data.hours[i]), 0.0) for i in test_idx
    ])
    days = max((data.hours[test_idx].max() - data.hours[test_idx].min())
               / np.timedelta64(1, "D"), 1.0)
    k = round(alert_budget_per_day * float(days))
    precision, recall, f1, mcc = _budget_metrics(y_test, scores, k)

    return ModelResult(
        model="graph_track (reference)",
        protocol="temporal",
        fold="t0",
        n_train=len(folds[0][0]),
        n_test=len(test_idx),
        n_positives=positives,
        prevalence=float(y_test.mean()),
        pr_auc=float(average_precision_score(y_test, scores)),
        roc_auc=float(roc_auc_score(y_test, scores)),
        recall_at_1pct_fpr=_recall_at_fpr(y_test, scores, 0.01),
        precision_at_budget=precision,
        recall_at_budget=recall,
        f1_at_budget=f1,
        mcc_at_budget=mcc,
        brier=None,
        fit_seconds=0.0,
        score_seconds=0.0,
        peak_mib=0.0,
        note="shipped relational detector, scored on its own substrate",
    )


def run_protocol(data: WindowDataset, protocol: str,
                 alert_budget_per_day: float = DEFAULT_ALERT_BUDGET_PER_DAY,
                 specs: Sequence[ModelSpec] | None = None) -> list[ModelResult]:
    specs = list(specs or model_zoo())

    if protocol == "temporal":
        folds = [("t0", f) for f in temporal_folds(data)]
    elif protocol == "entity_disjoint":
        folds = [(f"fold{i}", f) for i, f in enumerate(entity_disjoint_folds(data))]
    elif protocol == "entity_and_time_disjoint":
        folds = [(f"fold{i}", f) for i, f in enumerate(entity_and_time_disjoint_folds(data))]
    elif protocol == "attack_family_disjoint":
        folds = attack_family_folds(data)
    else:
        raise ValueError(f"unknown protocol {protocol!r}")

    results: list[ModelResult] = []
    for fold_name, (train_idx, test_idx) in folds:
        for spec in specs:
            outcome = evaluate_fold(spec, data, train_idx, test_idx,
                                     protocol, fold_name, alert_budget_per_day)
            if outcome is not None:
                results.append(outcome)
    return results


@dataclass
class Aggregate:
    model: str
    protocol: str
    n_folds: int
    total_positives: int
    mean_prevalence: float
    pr_auc_mean: float
    pr_auc_sd: float
    roc_auc_mean: float
    recall_at_1pct_fpr_mean: float
    precision_at_budget_mean: float
    recall_at_budget_mean: float
    mcc_at_budget_mean: float
    fit_seconds_mean: float
    peak_mib_max: float
    truncated: bool


def aggregate(results: Sequence[ModelResult]) -> list[Aggregate]:
    """Collapse folds and seeds to mean and spread per (model, protocol)."""
    grouped: dict[tuple[str, str], list[ModelResult]] = {}
    for r in results:
        grouped.setdefault((r.model, r.protocol), []).append(r)

    def mean(values: list[float]) -> float:
        return float(statistics.fmean(values)) if values else 0.0

    def sd(values: list[float]) -> float:
        return float(statistics.stdev(values)) if len(values) > 1 else 0.0

    out: list[Aggregate] = []
    for (model, protocol), rows in sorted(grouped.items()):
        out.append(Aggregate(
            model=model,
            protocol=protocol,
            n_folds=len(rows),
            total_positives=sum(r.n_positives for r in rows),
            mean_prevalence=mean([r.prevalence for r in rows]),
            pr_auc_mean=mean([r.pr_auc for r in rows]),
            pr_auc_sd=sd([r.pr_auc for r in rows]),
            roc_auc_mean=mean([r.roc_auc for r in rows]),
            recall_at_1pct_fpr_mean=mean([r.recall_at_1pct_fpr for r in rows]),
            precision_at_budget_mean=mean([r.precision_at_budget for r in rows]),
            recall_at_budget_mean=mean([r.recall_at_budget for r in rows]),
            mcc_at_budget_mean=mean([r.mcc_at_budget for r in rows]),
            fit_seconds_mean=mean([r.fit_seconds for r in rows]),
            peak_mib_max=max([r.peak_mib for r in rows], default=0.0),
            truncated=any(r.truncated_train for r in rows),
        ))
    return out


def render(aggregates: Sequence[Aggregate], datasets: Sequence[WindowDataset]) -> str:
    """A report that states the conditions the numbers were produced under."""
    lines: list[str] = []
    prevalences = [d.prevalence for d in datasets]
    lines.append(
        f"datasets={len(datasets)}  windows={sum(len(d) for d in datasets)}  "
        f"positives={sum(int(d.y.sum()) for d in datasets)}  "
        f"prevalence={statistics.fmean(prevalences):.5f}"
    )
    lines.append(f"feature contract: {datasets[0].contract}  "
                 f"({len(datasets[0].feature_names)} eligible columns)")
    lines.append("")
    lines.append("PR-AUC is the primary metric; a random ranker scores ~prevalence.")
    lines.append("")

    header = (f"{'protocol':<24}{'model':<24}{'folds':>6}{'pos':>6}"
              f"{'PR-AUC':>10}{'±sd':>8}{'ROC':>7}{'R@1%FP':>9}"
              f"{'P@bud':>8}{'R@bud':>8}{'MCC':>7}{'fit s':>8}")
    for protocol in ("temporal", "entity_disjoint", "entity_and_time_disjoint",
                     "attack_family_disjoint"):
        rows = [a for a in aggregates if a.protocol == protocol]
        if not rows:
            continue
        lines.append(header)
        for a in sorted(rows, key=lambda r: -r.pr_auc_mean):
            flag = " *" if a.truncated else ""
            lines.append(
                f"{a.protocol:<24}{a.model:<24}{a.n_folds:>6}{a.total_positives:>6}"
                f"{a.pr_auc_mean:>10.4f}{a.pr_auc_sd:>8.4f}{a.roc_auc_mean:>7.3f}"
                f"{a.recall_at_1pct_fpr_mean:>9.3f}{a.precision_at_budget_mean:>8.3f}"
                f"{a.recall_at_budget_mean:>8.3f}{a.mcc_at_budget_mean:>7.3f}"
                f"{a.fit_seconds_mean:>8.2f}{flag}"
            )
        lines.append("")
    if any(a.truncated for a in aggregates):
        lines.append("* training set was capped for tractability; see ModelSpec.max_train_rows")
    return "\n".join(lines)


def run_benchmark(data_dirs: Sequence[str], protocols: Sequence[str],
                  window_hours: float = 1.0,
                  alert_budget_per_day: float = DEFAULT_ALERT_BUDGET_PER_DAY,
                  ) -> tuple[list[ModelResult], list[WindowDataset]]:
    """Run every protocol over every dataset, pooling folds across datasets.

    Datasets are kept separate rather than concatenated: each is an independent
    estate with its own timeline, and concatenating them would create a temporal
    split that cuts across unrelated clocks.
    """
    datasets = [build_window_dataset(d, window_hours) for d in data_dirs]
    results: list[ModelResult] = []
    for data in datasets:
        for protocol in protocols:
            results.extend(run_protocol(data, protocol, alert_budget_per_day))
    return results, datasets
