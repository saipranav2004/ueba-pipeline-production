# Behavioural ITDR Engine

A behavioural and graph anomaly-detection engine for Active Directory identity
threat detection. It learns each entity's normal behaviour from Windows Security
and Sysmon telemetry and surfaces the entities whose behaviour becomes improbable
under that learned baseline.

Detection is statistical and relational. There are no attack signatures on the
detection path: technique-hypothesis indicators are computed for analyst
provenance but are **structurally excluded from model input** by a versioned
feature contract, and a test fails if any of them reaches a model.

## How it works

Every event is projected onto directed edges across several relationship views —
account↔source, ticket-encryption context, Kerberos context, process-access,
directory-operation — and each edge is scored for surprise under the estate's
learned access distribution:

```
surprise = max( −log P(dst | src), −log P(src | dst) )
P(b | a) = (c_ab + α·π_b) / (n_a + α)
```

Each raw surprise becomes a **calibrated p-value** against a benign null **frozen
per view** at fit time, so every relationship type is judged against its own
baseline. Per entity the most significant hour is Šidák-corrected for the number
of hours tested; alerts are the *N* most significant entities per day.

There is **one** alerting knob — `alert_budget_per_day`.

## Measured performance

Six seeded estates × 20 days × 253 employees, 60 held-out test attacks across ten
techniques, 60/40 out-of-time split, strict attribution, alert budget 5/day:

| | recall | FP entities/day |
|---|---|---|
| **engine** | **54/60 = 90.0%** | **3.19** |

Per-technique: Pass-the-Hash `9/9`, DCSync `8/8`, Kerberoasting `7/8`, silver
ticket `7/8`, password spray `6/6`, AS-REP roasting `5/6`, golden ticket `4/4`,
LSASS dump `4/4`, account manipulation `4/5`, NTDS dump `0/2`
(NTDS is covered by the execution queue below, not by the relational path).

Three **separately budgeted** queues cover the threat classes the relational
queue is blind to. Each was measured *inside* that queue first and displaced its
evidence, so each was given its own budget instead of being dropped:

| queue | threat class | relational engine | this track |
|---|---|---|---|
| execution | NTDS extraction / novel program use | 0/2 | **2/2** @ 0.90 FP/day |
| NHI schedule | compromised service account | 0/18 | **81.8%** @ 0.31 FP/day |
| insider rate | insider / credential abuse | 1/9 | **88.9%** @ 0.17 FP/day |

See [docs/identities.md](docs/identities.md).

**These are simulator numbers.** Read [docs/evaluation.md](docs/evaluation.md)
before quoting them: the estate is self-generated, and no detection-performance
figure here is validated against real labelled telemetry. Real-data *ingestion*
is validated separately — see [docs/datasets.md](docs/datasets.md).

## Quickstart

```bash
pip install -e ".[dev]"   # runtime deps + pytest + ruff
export UEBA__SECURITY__MODEL_SIGNING_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")

# 1. Generate an estate with injected attacks. `headline` = the ten
#    credential/lateral-movement techniques the recall figure is measured over;
#    `all` also injects the separately-measured insider and NHI corpora
#    (see docs/evaluation.md).
python enterprise_simulator/run_simulation.py --days 20 --seed 20250106 \
    --inject-attacks headline --attack-count 30 --attack-placement spread

# 2. Fit the engine -> signed, non-executable bundle
ueba train --data-dir enterprise_simulator/output --model-dir artifacts/models/engine

# 3. Score -> the relational ranking, then each separately budgeted queue
ueba score --data-dir enterprise_simulator/output --model-dir artifacts/models/engine \
    --alert-budget-per-day 5

# 4. Causal out-of-time evaluation
ueba walk-forward-eval --data-dir enterprise_simulator/output --contamination none
```

## Commands

| command | purpose |
|---|---|
| `train` | ingest → fit baseline → calibrate per-view nulls → signed bundle |
| `score` | load bundle → score → ranked entity alerts at an analyst budget |
| `score-stream` | score online, adapting the baseline as events arrive |
| `drift-check` | compare a live window's log-source capabilities against the bundle |
| `classify-identities` | type each identity as automated (NHI) or human from activity timing |
| `deviation-scan` | NHI schedule + insider rate queues, each with its own budget |
| `walk-forward-eval` | causal out-of-time evaluation: per-technique recall, FP/day |
| `comiset-eval` | real-data eval on a COMISET archive: per-view benign novelty + per-auth ROC |
| `model-benchmark` | compare classical models under four leakage-resistant protocols |
| `lanl-eval` | per-authentication ROC (TPR@FPR, AUC) on LANL 2015 |
| `graph-viz` | render the structural identity graph to standalone HTML |

## Documentation

| you want to… | read |
|---|---|
| the pipeline, data flow, and components | [docs/architecture.md](docs/architecture.md) |
| the statistical design and how each attack is caught | [docs/detection.md](docs/detection.md) |
| the feature contract and causality guarantees | [docs/features.md](docs/features.md) |
| how the authentication graph is built and scored | [docs/graph.md](docs/graph.md) |
| NHI: typing identities, and the schedule-deviation track | [docs/identities.md](docs/identities.md) |
| evaluation methodology, results, and limitations | [docs/evaluation.md](docs/evaluation.md) |
| classical models compared under disjoint splits | [docs/model_comparison.md](docs/model_comparison.md) |
| public datasets and real-data validation | [docs/datasets.md](docs/datasets.md) |
| running it, containers, scaling, operations | [docs/deployment.md](docs/deployment.md) |

## Layout

```
pyproject.toml                  packaging, dependency extras, pytest + ruff config
ueba_pipeline/
  engine.py                     per-view calibrated p-values, rollup, alerting
  parsing/normalize.py          channel + EventID -> canonical typed event
  features/manifest.py          capability manifest (log-source gating)
  features/aggregate.py         per (entity, hour) behavioural vectors
  features/contract.py          versioned feature contract; indicator quarantine
  graph/auth_graph_anomaly.py   Dirichlet-smoothed bidirectional edge surprise
  graph/sessions.py             4624 logons -> causal host->account resolution
  graph/identity_graph.py       structural graph (Tier-0, blast radius) — analyst tooling
  identity/typing.py            type an identity automated (NHI) vs human by activity timing
  identity/deviation.py         NHI schedule + insider rate queues (own budgets)
  models/counts.py              Gamma-Poisson count anomaly (Negative-Binomial tail)
  models/periodicity.py         Fisher's exact g-test for periodic activity
  models/pvalue.py              frozen empirical null -> calibrated p-value
  models/fisher.py              Tippett / Šidák / Benjamini-Hochberg
  models/serialization.py       non-executable, signed JSON + NumPy bundle
  evaluation/honest_eval.py     product evaluation harness; drives the real engine
  evaluation/model_benchmark.py classical-model comparison + split protocols
  evaluation/otrf_adapter.py    real Windows/Sysmon telemetry ingestion (OTRF/Mordor)
  evaluation/comiset_adapter.py real HELK/Winlogbeat telemetry ingestion (COMISET)
  monitoring/drift.py           capability-drift detection
  ingestion/, config/, cli/
enterprise_simulator/           253-employee AD estate + labelled attack injection
tests/unit/                     166 tests
.github/workflows/ci.yml        lint, tests (3.12/3.13), quickstart, wheel, image
```

## Model persistence

A trained bundle is a directory of versioned JSON plus `allow_pickle=False` NumPy
arrays, HMAC-SHA256-signed over the whole bundle and verified before any file is
parsed. Loading populates known fields and never executes bundle content. The
signing key is required — an empty key is refused rather than defaulted.

## Status

**Working.** Per-view calibrated detection, held-out null calibration, signed
bundles, file and Kafka ingestion, online scoring, capability-drift detection, the
identity graph, the simulator, a causal evaluation harness, a classical-model
comparison harness, and real-telemetry ingestion validation.

**Known limits**, with evidence in [docs/evaluation.md](docs/evaluation.md):

- **No real-world detection-performance validation.** Every recall and
  false-positive figure is measured on a self-generated estate. LANL 2015 is the
  target and `lanl-eval` is ready; the data sits behind a data-use agreement.
- **Round-the-clock non-human identities** (a poller active every hour) are
  covered by no queue: they have no schedule to deviate from. A burst-based
  inter-arrival (`cadence`) instrument was built for exactly this cohort,
  measured, and left unshipped — the attack it would need to see does not disturb
  cadence. Evidence in [docs/identities.md](docs/identities.md) §16.
- **Scoring is quadratic in estate size.** Measured 1.7s at 265 employees and
  72.9s at 2,036 — each doubling costs ~3.5–4× the time. Memory and edge count
  are linear as designed; the cost is the predictive p-value's sum over
  principals. Partly fixed (1.3–1.5×, verified exact to 2 ULP), with the residual
  cause and the remaining fix specified in
  [docs/evaluation.md](docs/evaluation.md#scalability).
- **Recall falls under a fixed alert budget as the estate grows** — 10/10 at 265
  employees, 4/10 at 2,036 on five alerts/day. Scaling the budget with the estate
  restores it. This is a capacity trade-off the engine surfaces, not hides.
- **No multi-tenancy, RBAC, or API.** The product is a CLI.
