# Deployment and operations

What ships, how to run it, what has been validated by execution, and what has
not.

## What is validated, and what is not

| asset | state |
|---|---|
| the CLI (`train`, `score`, `score-stream`, `drift-check`, evaluation commands) | run end to end |
| file ingestion | run end to end |
| Kafka consumer (`ingestion/source.py`) | implemented; exercised against a mock in the unit suite |
| `docker/Dockerfile`, both compose files, `deploy/k8s/` | schema-valid, **never executed** — no Docker daemon in the authoring environment |

Nothing in the container or Kubernetes path should be treated as regression
tested. Treat first use as a bring-up.

## Running locally

The engine is a CLI. It needs a signing key and a directory of JSONL telemetry:

```bash
export UEBA__SECURITY__MODEL_SIGNING_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")

python -m ueba_pipeline.cli.main train --data-dir /path/to/logs \
    --model-dir artifacts/models/engine
python -m ueba_pipeline.cli.main score --data-dir /path/to/logs \
    --model-dir artifacts/models/engine --alert-budget-per-day 5
```

## The signing key

The key is mandatory. The engine refuses to sign or load a bundle without it
rather than falling back to a default, because a default key would let anyone
substitute the baseline the detector trusts.

- Generate 32+ random bytes; never commit it.
- Inject it as an environment variable from a secret store. `deploy/k8s/
  secret-signing-key.example.yaml` shows the External Secrets Operator shape.
- Rotating the key invalidates existing bundles: retrain after rotation.

## Ingestion

Two sources sit behind one interface (`ingestion/source.py`), so switching does
not touch parsing, features, or detection:

- **File** — newline-delimited JSON, one record per line. The default, and what
  the evaluation harnesses use.
- **Kafka** — `confluent-kafka`, manual-commit at-least-once. Offsets are
  committed only after an event is consumed downstream, so a crash re-delivers
  the in-flight event rather than dropping it. At-least-once is the correct
  choice here because feature aggregation is idempotent to a duplicate; it does
  not replay a state machine, so exactly-once buys nothing for the overhead.
  Back-pressure is natural: `read()` is a pull-based generator, so a slow
  consumer simply polls less often.

`scripts/validate_streaming.py` is the broker-dependent harness. It produces the
estate onto a topic and then verifies offset accounting on the consume side —
every produced offset seen exactly once, which is the observable half of
at-least-once. Run it against a real broker; a mock cannot establish it.

## Containers

`docker/Dockerfile` is a two-stage build: build tooling stays out of the runtime
image, which runs as a non-root user because this service handles identity and
security telemetry. Model artifacts and ingested data are mounted, never baked
into the image.

- `docker/docker-compose.yml` — local loop: the CLI image plus a single-node
  KRaft Kafka broker. Listeners are **PLAINTEXT**; this file is for a trusted
  local network only.
- `docker/docker-compose.prod.yml` — the hardening overlay: SASL_SSL and mTLS.
  Use this for any shared or production broker.

## Scheduled retraining

`deploy/k8s/cronjob-retrain.yaml` runs `train` on a schedule against a mounted
data volume, with the signing key injected from a secret. Retraining cadence is
a deployment decision, but two things force it:

- **Capability drift.** If a log source appears or disappears, the frozen
  feature order no longer describes the data. `drift-check` compares a live
  window against the trained bundle and exits non-zero when a retrain is
  required, so it can gate the pipeline.
- **Baseline staleness.** The baseline is what "normal" means. An estate that
  has changed materially since the last fit will produce novelty that is
  organisational, not adversarial.

## Performance and scaling

Measured with `scripts/benchmark_performance.py` over estates generated at 1×
through 8× headcount. Full table in [evaluation.md](evaluation.md).

| identities | fit ev/s | score ev/s | detector state | p50 / p99 latency | bundle |
|---|---|---|---|---|---|
| 265 | 30,990 | 60,771 | 0.9 MiB | 4.0 / 71.7 µs | 202 KiB |
| 1,024 | 32,280 | 104,601 | 3.5 MiB | 3.4 / 99.2 µs | 764 KiB |
| 2,036 | 31,206 | 91,735 | 7.5 MiB | 4.9 / 102.7 µs | 1,526 KiB |

**Capacity planning.** State grows linearly with identities, not quadratically:
7.7× the identities produced 7.7× the distinct edges, because each identity has a
bounded working set. Extrapolating the measured fit, 10,000 identities implies
roughly 37 MiB of detector state and 100,000 implies ~370 MiB. Throughput and
per-event latency are flat across the whole measured range — nothing in the
scoring path depends on how many identities exist. If exact counters ever become
the constraint, count-min sketching (MIDAS's mechanism) swaps in behind the same
interface at the cost of collision noise.

**The alert budget must be sized against the estate.** At a fixed five alerts a
day, recall fell from 10/10 to 8/10 as the estate grew from 265 to 1,024
identities: the same queue has to cover four times as many entities. Scaling the
budget with the estate restored full recall, and the false-positive rate per
identity stayed near 0.015/day throughout, so the ranking itself is
size-invariant. Budget is therefore a capacity decision — holding recall as an
estate grows costs analyst time proportionally.

The identity graph is recomputed on a rolling snapshot rather than per event, so
it only has to finish inside the retrain window.

## Tuning

Two of the three free parameters do not move batch detection (`alpha` is flat below
its default; `absorb_surprise` governs only the streaming baseline, since batch
`score()` never absorbs). `null_calibration_fraction` does matter — 0.15 costs
seven detections against the default 0.30 — and should be selected on a
validation estate held apart from whatever estate performance is reported on.
See [evaluation.md](evaluation.md).

## Operating the alert queue

There is one knob: `alert_budget_per_day`, the number of most-significant
entities surfaced per day. It is an analyst-capacity decision, not a detection
threshold — the p-values provide the ranking, and the budget decides how deep
into that ranking the queue goes.

`alert_mode="fdr"` (Benjamini-Hochberg) is implemented but alerts on nothing at
realistic evidence volumes; [detection.md](detection.md) explains why this is a
property of the evidence rather than a tuning failure.
