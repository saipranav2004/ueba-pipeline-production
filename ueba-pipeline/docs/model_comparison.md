# Model comparison

How several classical models compare against each other, and against the shipped
graph track, on the behavioural feature matrix — under four split protocols chosen
so a model cannot look good for the wrong reason. Implemented in
`ueba_pipeline/evaluation/model_benchmark.py`; run with the `model-benchmark` CLI
or `scripts/run_model_benchmark.py`.

Deep-learning methods are out of scope by design. Every model here is a classical
estimator with a deterministic fit given a seed.

## What is being compared

Supervised, on contract-eligible behavioural features only (indicator flags are
excluded by the feature contract, so none of these models can learn an attack name):

- Logistic regression (L2, class-weighted)
- Random forest, Extra Trees (class-weighted)
- Histogram gradient boosting (class-weighted)
- XGBoost (`scale_pos_weight` = negative/positive ratio)

Every supervised model is class-weighted. Comparing a weighted model against an
unweighted one measures the weighting rather than the learner, and at 0.7%
prevalence an unweighted model predicts the majority class almost everywhere.

Unsupervised, fitted on benign training windows only:

- Isolation Forest
- Local Outlier Factor (novelty mode; training capped for tractability)
- One-Class SVM (RBF; training capped — kernel fit is ~O(n²))

Reference column:

- **graph_track** — the shipped relational detector, scored on its own substrate
  (edges, not the feature matrix) and mapped onto the same windows so its
  per-window separation is directly comparable. It is not one of the feature-matrix
  models; it reads a different representation entirely.

## Metrics, and why these

Malicious windows are ~0.6–0.9% of all windows. At that imbalance:

- **PR-AUC (average precision)** is the primary metric. A random ranker scores
  PR-AUC ≈ prevalence, so prevalence is printed beside it.
- **ROC-AUC** is reported but is near-insensitive at this imbalance — a detector can
  go from useless to usable while ROC-AUC barely moves.
- **Recall at 1% FPR** — a fixed, policy-set operating point.
- **Precision / recall / F1 / MCC at the alert budget** — the top *k* windows where
  *k* = budget × test-days. The operating point is set by policy, never by sweeping
  the test set for the best F1 (which would leak test labels into the threshold).
- **Fit seconds, peak MiB** — operational cost.

Reported as mean ± spread across six seeded estates. Folds with no positives (or no
negatives) are skipped and counted, never averaged in as zero.

## The four protocols

| protocol | train and test share… | generalisation question |
|---|---|---|
| `temporal` | past trains, future tests | does yesterday's baseline hold tomorrow? (the deployment condition) |
| `entity_disjoint` | no account in common | does it work on an account never seen? (cold start) |
| `entity_and_time_disjoint` | neither an account nor an hour | the strict combination |
| `attack_family_disjoint` | one technique withheld from training | can it detect a technique it never trained on? |

**Why `entity_and_time_disjoint` exists.** Entity-disjoint folds alone leak. Their
folds still overlap in time, so a supervised model can learn an attack campaign from
the accounts kept in training and recognise the same campaign, in the same hours, on
the accounts held out — without generalising to anything. Measured on this estate,
that shortcut roughly *doubles* apparent PR-AUC relative to the temporal protocol,
which is the opposite of the expected ordering and is the fingerprint of the leak.
Removing both shortcuts is the honest cold-start number. This is enforced by
`tests/unit/test_model_benchmark.py`.

## Results

Six seeded estates, 123,436 windows, 882 positive windows, prevalence 0.70%,
alert budget 5/day. PR-AUC is the mean across folds, ±sd the spread. Regenerate
with `python scripts/run_model_benchmark.py`; full rows in
`artifacts/bench/model_comparison_folds.csv`.

**Temporal** — the deployment condition (6 folds, 320 positives):

| model | PR-AUC | ±sd | ROC | R@1%FP | R@budget | fit s |
|---|---|---|---|---|---|---|
| logistic_regression | **0.702** | 0.158 | 0.867 | 0.700 | 0.580 | 0.27 |
| random_forest | 0.652 | 0.218 | 0.855 | 0.675 | 0.544 | 5.38 |
| extra_trees | 0.624 | 0.211 | 0.852 | 0.696 | 0.558 | 3.80 |
| hist_gradient_boosting | 0.617 | 0.271 | 0.851 | 0.659 | 0.536 | 2.18 |
| **xgboost** | **0.496** | 0.189 | 0.722 | 0.508 | 0.491 | 0.45 |
| one_class_svm * | 0.472 | 0.343 | 0.832 | 0.540 | 0.388 | 0.65 |
| _graph_track (reference)_ | _0.146_ | _0.090_ | _0.569_ | _0.240_ | _0.194_ | — |
| local_outlier_factor | 0.090 | 0.048 | 0.826 | 0.083 | 0.083 | 1.04 |
| isolation_forest | 0.016 | 0.011 | 0.699 | 0.000 | 0.000 | 3.85 |

**Entity-and-time-disjoint** — the strict cold start (30 folds, 320 positives):

| model | PR-AUC | ±sd | R@budget |
|---|---|---|---|
| logistic_regression | **0.705** | 0.175 | 0.702 |
| random_forest | 0.652 | 0.228 | 0.687 |
| hist_gradient_boosting | 0.642 | 0.252 | 0.694 |
| extra_trees | 0.607 | 0.254 | 0.708 |
| **xgboost** | 0.506 | 0.219 | 0.512 |
| one_class_svm * | 0.483 | 0.315 | 0.648 |

**Attack-family-disjoint** — an unseen technique (60 folds, 882 positives):

| model | PR-AUC | ±sd | R@budget |
|---|---|---|---|
| logistic_regression | **0.318** | **0.332** | 0.390 |
| **xgboost** | 0.308 | 0.341 | 0.355 |
| hist_gradient_boosting | 0.228 | 0.315 | 0.316 |
| random_forest | 0.222 | 0.324 | 0.330 |
| extra_trees | 0.155 | 0.296 | 0.316 |

(`entity_disjoint` is omitted here; it leaks through shared time and is retained
in the harness only to demonstrate that leak. XGBoost places 2nd there at 0.778
against logistic regression's 0.793.)

`*` training set capped for tractability (see `ModelSpec.max_train_rows`).

## Does XGBoost help? No.

It was tested because gradient boosting is the standard answer for tabular data —
Grinsztajn et al. (arXiv:2207.08815) find tree ensembles still beat deep learning
on medium-sized tabular problems — and because prior security work reports XGBoost
giving the best accuracy/latency balance for Sysmon-derived ransomware detection.

**It loses to plain logistic regression on all four protocols**, and on the two
that matter most it is beaten by every other tree ensemble as well: 0.496 against
0.617–0.652 on temporal, 0.506 against 0.607–0.652 on the strict split. It is only
competitive where the task is easiest (entity-disjoint, 2nd) or where every
supervised model has already collapsed (attack-family-disjoint, 2nd at 0.308 with
a ±0.341 spread as large as the mean).

Two reasons fit the evidence. The positives are extremely scarce — roughly 0.7%
prevalence, and as few as ~50 positive windows in a temporal fold — so 300 boosted
trees at depth 6 have far more capacity than the signal supports and spend it on
variance; the ±0.189–0.219 spreads say as much. And the signal appears close to
linearly separable in these features, which is why the *simplest* model wins
outright. Grinsztajn's result is about medium-sized, roughly balanced tabular
data; this is neither.

**Caveat stated plainly:** XGBoost was run with reasonable defaults plus
`scale_pos_weight` at the negative/positive ratio, not tuned. A tuned
configuration might close the gap. It was not tuned because tuning it against the
estates the comparison is reported on would be selection on the test set — the
same error avoided for `null_calibration_fraction` in
[evaluation.md](evaluation.md). The honest claim is therefore narrow: *untuned
XGBoost with documented imbalance handling does not beat untuned logistic
regression here*, and nothing about the result suggests the extra capacity is
what this problem needs.

**It changes nothing about the shipped detector**, which is unsupervised. Every
model in this table needs labelled attack windows that a live deployment does not
have, and all of them collapse when the technique is unseen — which is the case
the engine exists to handle.

## Caveats

- Per-window PR-AUC here is a different, stricter lens than the graph track's
  product-level per-attack recall (71.7%, see [evaluation.md](evaluation.md)); the
  two are not interchangeable.
- One-Class SVM and LOF training sets are capped for tractability; capped rows are
  flagged in the report and the cap is recorded in `ModelSpec.max_train_rows`.
- All of this is on the simulator. The same harness runs on any estate directory,
  including a preprocessed LANL export, which is where these numbers should next be
  taken.
