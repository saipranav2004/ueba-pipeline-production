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
- Histogram gradient boosting

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

Six seeded estates (`20250106`–`20250111`), 123,436 windows, 858 positive
windows, prevalence 0.70%, 1-hour windows, alert budget 5/day. PR-AUC is the mean
across folds; ±sd is the standard deviation across folds (a stability measure).
Full per-fold rows: `artifacts/bench/model_comparison_folds.csv`. Regenerate with
`python scripts/run_model_benchmark.py`.

**Temporal** — the deployment condition (6 folds, 310 positive windows):

| model | PR-AUC | ±sd | ROC | R@1%FP | P@budget | R@budget | MCC |
|---|---|---|---|---|---|---|---|
| logistic_regression | **0.720** | 0.175 | 0.872 | 0.721 | 0.710 | 0.592 | 0.627 |
| random_forest | 0.691 | 0.195 | 0.848 | 0.693 | 0.694 | 0.570 | 0.608 |
| extra_trees | 0.673 | 0.177 | 0.848 | 0.705 | 0.667 | 0.550 | 0.584 |
| hist_gradient_boosting | 0.657 | 0.244 | 0.830 | 0.683 | 0.683 | 0.553 | 0.595 |
| one_class_svm * | 0.491 | 0.352 | 0.846 | 0.500 | 0.560 | 0.386 | 0.455 |
| local_outlier_factor | 0.197 | 0.215 | 0.844 | 0.294 | 0.183 | 0.230 | 0.196 |
| isolation_forest | 0.017 | 0.012 | 0.734 | 0.002 | 0.004 | 0.002 | -0.003 |
| _graph_track (reference)_ | _0.160_ | _0.044_ | _0.579_ | _0.286_ | _0.250_ | _0.245_ | _0.232_ |

**Entity-disjoint** — *leaks through shared time; shown to contrast with the strict
protocol below* (30 folds, 858 positive windows):

| model | PR-AUC | ±sd | ROC | R@budget |
|---|---|---|---|---|
| logistic_regression | 0.809 | 0.073 | 0.904 | 0.812 |
| hist_gradient_boosting | 0.786 | 0.074 | 0.891 | 0.804 |
| random_forest | 0.784 | 0.085 | 0.893 | 0.795 |
| extra_trees | 0.782 | 0.086 | 0.893 | 0.797 |
| one_class_svm * | 0.650 | 0.117 | 0.903 | 0.760 |
| local_outlier_factor | 0.652 | 0.192 | 0.900 | 0.735 |
| isolation_forest | 0.017 | 0.004 | 0.724 | 0.006 |

**Entity-and-time-disjoint** — the strict cold-start number (30 folds, 310 positive
windows):

| model | PR-AUC | ±sd | ROC | R@budget |
|---|---|---|---|---|
| logistic_regression | 0.723 | 0.218 | 0.871 | 0.730 |
| random_forest | 0.676 | 0.254 | 0.845 | 0.701 |
| extra_trees | 0.663 | 0.243 | 0.850 | 0.715 |
| hist_gradient_boosting | 0.632 | 0.285 | 0.816 | 0.667 |
| one_class_svm * | 0.499 | 0.330 | 0.838 | 0.643 |
| local_outlier_factor | 0.145 | 0.145 | 0.840 | 0.184 |
| isolation_forest | 0.018 | 0.012 | 0.727 | 0.007 |

**Attack-family-disjoint** — one technique withheld from training (60 folds, 858
positive windows):

| model | PR-AUC | ±sd | ROC | R@budget |
|---|---|---|---|---|
| logistic_regression | 0.328 | **0.336** | 0.608 | 0.421 |
| hist_gradient_boosting | 0.281 | 0.288 | 0.711 | 0.359 |
| random_forest | 0.270 | 0.331 | 0.590 | 0.292 |
| extra_trees | 0.177 | 0.300 | 0.571 | 0.300 |
| one_class_svm * | 0.122 | 0.290 | 0.824 | 0.201 |
| local_outlier_factor * | 0.082 | 0.211 | 0.830 | 0.444 |
| isolation_forest | 0.003 | 0.004 | 0.734 | 0.004 |

`*` training set capped for tractability (see `ModelSpec.max_train_rows`).

## Reading the results

- **Temporal:** a class-weighted **logistic regression on the behavioural features
  is the strongest per-window ranker** (PR-AUC 0.72), ahead of the tree ensembles
  (0.66–0.69) and well ahead of the unsupervised detectors (Isolation Forest is
  essentially useless at this imbalance, 0.02) and the graph track's per-window
  score (0.16). Where labelled attack windows exist, a cheap linear model on good
  behavioural features is a strong supervised baseline — a genuinely useful result.

- **Entity-disjoint alone inflates, and the strict protocol proves it.**
  Entity-disjoint gives LR PR-AUC 0.81 — *higher* than the temporal 0.72, which
  should be impossible for a genuinely harder task and is the fingerprint of the
  time-overlap leak. The strict entity-and-time-disjoint protocol brings it back to
  0.72, essentially equal to temporal: on this estate the temporal boundary is the
  binding constraint, and once time is respected, holding entities out as well costs
  almost nothing. That is the honest cold-start number.

- **Attack-family-disjoint: the supervised models collapse and turn
  high-variance.** LR falls from 0.72 to **0.33, with a standard deviation of 0.34**
  — as large as the mean, i.e. on some held-out techniques it detects nothing.
  Holding a technique out of training drops detection sharply and inconsistently
  depending on which technique is withheld. This is a supervised model learning the
  *known* techniques' fingerprints rather than a general notion of abnormal — and it
  is the case a real unknown threat resembles. It is the circularity the research
  findings warn about, quantified: strong supervised numbers on a self-authored
  simulator largely measure memorisation of that simulator's attacks.

- **The graph track is unsupervised** and therefore has no attack-family-disjoint
  collapse mode — its behaviour does not depend on which techniques were "in
  training". Its per-window PR-AUC (0.16) is lower than the supervised models on the
  simulator, but that per-window lens understates it: its product-level per-attack
  recall is 71.7% (an attack spans several windows and needs only one to rank the
  entity into the day's alert budget). It trades peak per-window separation for
  label-independence and unknown-technique robustness.

**Synthesis.** On this simulator a supervised classifier wins the per-window ranking
by a wide margin *when the test technique was seen in training* (0.72 vs the graph
track's 0.16), and loses most of that advantage when it was not (collapsing to 0.33
± 0.34). The unsupervised graph track is steadier across the unknown-technique case
and needs no labels at all. Which matters more is a deployment decision about label
availability and threat model — and it cannot be settled on synthetic data, where
the supervised advantage is inflated by memorisation. The comparison's real value is
the *shape*: it measures exactly how much of the supervised advantage is
memorisation, using splits designed to expose it, and it is why the shipped detector
is the label-free graph track rather than a supervised classifier tuned on known
techniques.

## Caveats

- Per-window PR-AUC here is a different, stricter lens than the graph track's
  product-level per-attack recall (71.7%, see [BENCHMARK.md](../BENCHMARK.md)); the
  two are not interchangeable.
- One-Class SVM and LOF training sets are capped for tractability; capped rows are
  flagged in the report and the cap is recorded in `ModelSpec.max_train_rows`.
- All of this is on the simulator. The same harness runs on any estate directory,
  including a preprocessed LANL export, which is where these numbers should next be
  taken.
