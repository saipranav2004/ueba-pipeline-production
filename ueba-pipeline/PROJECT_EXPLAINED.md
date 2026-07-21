# Project, explained

*What each part of the repository is, what it does, and which decisions are
load-bearing.*

## The bet

A small number of well-calibrated behavioural models generalise further than a
large catalogue of rules. Every design choice follows from that, and the
falsification test is simple: **if detecting a new technique requires new
attack-specific code, the bet has failed.** That is why there are no per-view
scoring gates, no attack-specific branches in the detectors, and no rule engine —
and why the indicator-flag features that do exist are excluded from the model.

## Data flow

```
enterprise_simulator/  OR  real logs  OR  Kafka
        |
   ingestion/source.py
        |
   parsing/normalize.py        channel + EventID -> exact event_type + typed fields
        |
   features/manifest.py        what can this estate support?
   features/aggregate.py       per (entity, hour) count vectors
   graph/sessions.py           4624 -> host->account resolution
        |
   engine.py  ── fit ──> two nulls frozen ──> HMAC-signed bundle
        |
   engine.py  ── score ──> p-values -> Tippett -> Šidák -> budget/BH
        |
   ranked entity alerts
```

## Module by module

### `engine.py`
The product. Owns fit, score, streaming, rollup, alerting, persistence. Two tracks
in — graph and volumetric — ranked entities out.

Load-bearing decisions:
- **`score()` is pure.** Non-idempotent scoring means a re-run after a crash
  under-reports the very attack it was re-run to catch. `observe()` is the explicit
  online path; `score_stream()` opts in.
- **Non-executable, signed model bundle.** The bundle is versioned JSON plus
  `allow_pickle=False` NumPy arrays, not a pickle, so loading it cannot execute
  code. An HMAC-SHA256 over the whole bundle is verified before any file is parsed;
  empty key → refuse, don't degrade. See `models/serialization.py`.
- **Tippett fusion across tracks.** An entity is as suspicious as its single most
  anomalous track, so the volumetric track adds coverage without displacing graph
  detections under the alert budget.
- **One alerting knob.** `alert_budget_per_day`. Everything else is derived.

### `models/pvalue.py`
Frozen empirical null → calibrated p-value. Bounded quantile grid, so the artifact
is O(grid) and holds no telemetry. Floored at `1/(n+1)`.

### `models/fisher.py`
Tippett, Šidák, Benjamini-Hochberg. The module comment explains why each combiner
sits where it does; read it before changing any of them.

### `models/inductive_ecod.py`
ECOD with a frozen ECDF: inductive at inference (scores are pure functions of the
point scored), bounded at O(features × grid), and holds no copy of the training
matrix. Rank-correlates with the reference ECOD on held-out data.

### `models/volumetric_detector.py`
Per-entity z-normalisation → InductiveECOD over behavioural counts. Indicator-flag
features are dropped at fit, keeping the model behavioural.

### `graph/auth_graph_anomaly.py`
Dirichlet-smoothed bidirectional edge surprise across seven views, MIDAS burst, and
MIDAS-F non-absorption. Counters only; O(1) update per event.

### `graph/sessions.py`
Host → account resolution from 4624, so all scoring lives in one entity space.
Built fresh per batch so scoring stays pure.

### `graph/identity_graph.py`
Structural risk — Tier-0 proximity, blast radius. **Analyst tooling, not
detection.** Consumed only by `graph-viz`.

### `features/manifest.py`, `features/aggregate.py`
The capability manifest makes the engine adapt to available log sources rather than
assuming a fixed schema: a group is claimed only for events the parser can extract,
pinned at fit and reused at score, so a missing channel degrades honestly.

### `monitoring/drift.py`
Capability-drift and concept-drift detection. `drift-check` compares a live
window's log-source availability against the trained bundle and flags a required
retrain.

### `evaluation/honest_eval.py`
The evaluation. Drives the real engine — one implementation, one set of bugs. Its
docstring enumerates the guarantees; each exists because it is a way an ITDR
benchmark is commonly wrong.

### `enterprise_simulator/`
253-employee estate with per-department behaviour, routine directory activity, and
labelled attack injection across ten techniques. Everything the engine consumes, it
emits, including `roster.json` and `directory.json`.

## What to check first

1. **The evaluation, before anything else.** If the harness is wrong, every
   architectural conclusion downstream is noise. Specifically: does anything select
   a threshold using test labels? Does attribution require the alert's peak hour?
   Does the attack placement give the held-out tail a sample of *all* techniques?
2. **Whether each component earns its place.** Every one has an ablation in
   BENCHMARK.md.
3. **Whether the simulator is doing the work.** It cannot produce DHCP churn, VDI
   pools, or roaming laptops. The FP numbers are a floor.

## Known-honest gaps

- **No real-world validation.** LANL 2015 / OpTC. The blocker.
- **Account manipulation and NTDS dump** need directory-context or command-line
  signals, not novel relationships. Extension paths in docs/architecture.md.
- **FDR alerting alerts on nothing** — a real statistical limit (BENCHMARK.md).
- **No multi-tenancy, RBAC, or API.**
