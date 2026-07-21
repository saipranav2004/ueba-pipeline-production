# Behavioral ITDR Engine

A behavioral and graph anomaly-detection engine for Active Directory and Entra ID
identity threat detection. It learns each entity's normal behaviour from
authentication and endpoint telemetry and detects attacks that leave a
behavioural or relational trace — golden/silver ticket, Pass-the-Hash, DCSync,
Kerberoasting, AS-REP roasting, password spray, and LSASS credential dumping.

No attack signatures are used for detection. The engine detects behaviourally and
relationally; the few expert-defined indicator features that exist are excluded
from the model.

## Documentation map

Read in this order depending on what you need:

| you want to… | read |
|---|---|
| understand and run the system | this README |
| a complete narrative: what changed, evidence, limitations, next steps | [FINAL_REPORT.md](FINAL_REPORT.md) |
| the pipeline, data flow, and components | [docs/architecture.md](docs/architecture.md) |
| the feature layer, contract, and causality guarantees | [docs/features.md](docs/features.md) |
| how the authentication graph is built and scored | [docs/graph.md](docs/graph.md) |
| the statistical design (p-values, calibration, fusion) | [MODEL_EXPLAINED.md](MODEL_EXPLAINED.md) |
| a step-by-step walkthrough of how each attack is caught | [DETECTION_EXPLAINED.md](DETECTION_EXPLAINED.md) |
| the graph-track product benchmark and its methodology | [BENCHMARK.md](BENCHMARK.md) |
| the classical-model comparison and split protocols | [docs/model_comparison.md](docs/model_comparison.md) |
| public datasets researched and real-data (OTRF) validation | [docs/datasets.md](docs/datasets.md) |
| the line-level evaluation/leakage audit | [EVALUATION_AUDIT.md](EVALUATION_AUDIT.md) |
| the full change record for this project | [CHANGES.md](CHANGES.md) |

## How it works

The engine is a **calibrated authentication-graph anomaly detector**. Every event
is projected onto directed edges across several relationship views —
account↔source, host↔host, ticket-encryption context, process-access,
rare-process, directory-change — and each edge is scored for surprise under the
estate's learned access distribution:

```
surprise = max( −log P(dst | src), −log P(src | dst) )
P(b | a) = (c_ab + α·π_b) / (n_a + α)
```

Each raw surprise becomes a **calibrated p-value** against a benign null **frozen
per view** at fit time, so every relationship type is judged against its own
baseline. Per entity the most significant hour is Šidák-corrected for the number
of hours tested; alerts are the N most significant entities per day.

There is **one** alerting knob — `alert_budget_per_day`.

A supplementary **volumetric ECOD** track (per-entity behavioural counts) is
included but **off by default**: on the benchmark it catches no technique the
graph misses and lowers overall recall. Enable it for estates with volume-based
threats a relational view cannot see, after validating on that estate's data.

See [docs/architecture.md](docs/architecture.md) for the pipeline,
[MODEL_EXPLAINED.md](MODEL_EXPLAINED.md) for the statistical design, and
[DETECTION_EXPLAINED.md](DETECTION_EXPLAINED.md) for a step-by-step walkthrough of
how each attack is caught.

## Measured performance

6 seeds × 20 days × 253 employees, 60 held-out test attacks across all ten
techniques, 60/40 out-of-time split, strict attribution, alert budget 5/day:

| | recall | FP entities/day |
|---|---|---|
| **engine (graph track)** | **43/60 = 71.7%** | **3.44** |

Per-technique: AS-REP `10/10`, Pass-the-Hash `8/9`, DCSync `5/7`, LSASS dump `5/5`,
silver ticket `4/6`, Kerberoasting `4/4`, password spray `4/4`, golden ticket `3/3`,
account manipulation `0/7`, NTDS dump `0/5`.

**Read [BENCHMARK.md](BENCHMARK.md) before quoting these.** Two things matter:

- The null is calibrated on a **held-out slice** of training scored against a
  frozen baseline. Calibrating it in-sample (absorbing all training data, then
  scoring it) inflates this headline to 83% by leaving the null with no
  benign-novelty mass — see [EVALUATION_AUDIT.md](EVALUATION_AUDIT.md).
- These are measured on a simulator this project ships. It now churns addresses
  realistically (DHCP leases, VPN pool assignment, Wi-Fi — ~10 source addresses per
  user), and detection is unchanged by that churn because source edges are keyed on
  the **device**, not the address. A simulator still cannot reproduce a real
  network's full messiness, and nothing here is validated against real
  authentication data; `lanl-eval` is the harness for when it is.

## Quickstart

```bash
pip install -r requirements.txt
export UEBA__SECURITY__MODEL_SIGNING_KEY=<32+ random bytes>

# 1. Generate an estate with injected attacks
python enterprise_simulator/run_simulation.py --days 20 --seed 20250106 \
    --inject-attacks all --attack-count 30 --attack-placement spread

# 2. Fit the engine -> HMAC-signed bundle
python -m ueba_pipeline.cli.main train \
    --data-dir enterprise_simulator/output --model-dir artifacts/models/engine

# 3. Score -> ranked entity alerts (lower p = worse)
python -m ueba_pipeline.cli.main score \
    --data-dir enterprise_simulator/output --model-dir artifacts/models/engine \
    --alert-budget-per-day 5

# 4. Causal out-of-time evaluation
python -m ueba_pipeline.cli.main walk-forward-eval \
    --data-dir enterprise_simulator/output --contamination none

# 5. Identity graph -> HTML (analyst tooling; not part of detection)
python -m ueba_pipeline.cli.main graph-viz \
    --roster enterprise_simulator/output/roster.json \
    --directory enterprise_simulator/output/directory.json
```

## Commands

| command | purpose |
|---|---|
| `train` | ingest → fit baseline → calibrate per-view nulls → signed bundle |
| `score` | load bundle → score → ranked entity alerts at an analyst budget |
| `score-stream` | score online, adapting the baseline as events arrive |
| `drift-check` | compare a live window's log-source capabilities against the trained bundle |
| `walk-forward-eval` | causal out-of-time evaluation: per-technique recall, FP/day |
| `model-benchmark` | compare classical models on the feature matrix under four leakage-resistant split protocols |
| `lanl-eval` | per-authentication ROC (TPR@FPR, AUC) on LANL 2015 |
| `graph-viz` | render the structural identity graph to standalone HTML |

Model persistence is a non-executable, HMAC-signed bundle (versioned JSON plus
`allow_pickle=False` NumPy arrays), not a pickle — loading populates known fields
and never executes bundle content. See
[models/serialization.py](ueba_pipeline/models/serialization.py).

## Is this a rule engine? No — and it is enforced, not asserted

Every feature the extractors emit is classified by a versioned **feature
contract** ([features/contract.py](ueba_pipeline/features/contract.py)) as either
a behavioural statistic (count, rate, cardinality, entropy — eligible for model
input) or a technique-hypothesis indicator / upstream-detector verdict
(quarantined). Indicator flags such as `f_kerberoast_flag` are computed for
analyst provenance but a test fails if any of them reaches model input. The
graph detector likewise scores relational surprise, never attack names.

## How classical models compare on the same features

`model-benchmark` runs LogisticRegression, RandomForest, ExtraTrees,
HistGradientBoosting, IsolationForest, LOF and OneClassSVM over the behavioural
feature matrix, with the shipped graph track as a reference column, under four
protocols that answer different generalisation questions:

- **temporal** — train on the past, test on the future (the deployment condition);
- **entity-disjoint** — test on accounts never seen in training (cold start);
- **entity-and-time-disjoint** — share neither an account nor an hour (the strict
  protocol; entity-disjoint alone leaks through shared time);
- **attack-family-disjoint** — hold one technique out of training entirely
  (unknown-technique generalisation).

See [docs/model_comparison.md](docs/model_comparison.md) for results and what they
mean — including why a supervised classifier that looks strong under the temporal
protocol collapses under attack-family-disjoint, which is the case a real unknown
threat resembles.

## Layout

```
ueba_pipeline/
  engine.py                     the engine: per-view calibrated p-values, alerting
  models/pvalue.py              frozen empirical null -> calibrated p-value
  models/fisher.py              Tippett / Šidák / Benjamini-Hochberg
  models/inductive_ecod.py      frozen-ECDF ECOD (inductive, bounded artifact)
  models/volumetric_detector.py per-entity normalised counts -> ECOD
  models/serialization.py       non-executable, signed JSON+npy model bundle
  graph/auth_graph_anomaly.py   Dirichlet-smoothed bidirectional edge surprise
  graph/sessions.py             4624 logons -> causal host->account resolution
  graph/identity_graph.py       structural graph (Tier-0, blast radius) — analyst tooling
  features/aggregate.py         per (entity, hour) behavioural feature vectors
  features/contract.py          versioned feature contract; indicator quarantine
  features/manifest.py          capability manifest (log-source gating)
  parsing/normalize.py          channel+EventID -> exact event_type
  evaluation/honest_eval.py     product evaluation harness; drives the real engine
  evaluation/model_benchmark.py classical-model comparison + split protocols
  monitoring/drift.py           capability / concept-drift detection
  ingestion/, connectors/, config/, cli/
enterprise_simulator/           253-employee estate + attack injection
tests/unit/                     116 tests
```

## Status

**Working.** Per-view calibrated graph detection, held-out null calibration,
signed bundles, file and Kafka ingestion, online scoring, capability-drift
detection, the identity graph, the simulator, a causal evaluation harness, and a
LANL ROC harness.

**Gaps**, with evidence in [BENCHMARK.md](BENCHMARK.md):

- **No real-world validation.** The blocker. `lanl-eval` is ready; LANL 2015 sits
  behind a data-use agreement that must be accepted manually.
- **Account manipulation and NTDS dump** sit at the boundary of behavioural
  detection (they need directory-context or command-line signals, not novel
  relationships). Extension paths are documented.
- **Learned temporal graph models** (Euler, TOPS 2023; and later temporal-graph
  work) report materially higher AUC on LANL than an unsupervised statistical
  baseline. That is the documented upgrade path, contingent on real labelled data
  to train and validate against — see [docs/architecture.md](docs/architecture.md).
- **No multi-tenancy, RBAC, or API.** The product is a CLI.
