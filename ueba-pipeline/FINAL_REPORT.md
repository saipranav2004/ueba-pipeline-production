# Final report — behavioural ITDR engine

This report explains what the system is, what was audited and changed in this
round of work, what the evidence says, and what remains unresolved. It is written
to be read by an engineer who has not seen the project before. It documents only
what is implemented and measured; proposed extensions are labelled as such.

---

## 1. What the system is

A behavioural and graph anomaly-detection engine for Active Directory / Entra ID
identity-threat detection. It learns each entity's normal authentication and
endpoint behaviour from Windows Security and Sysmon telemetry and flags entities
whose behaviour becomes improbable under that learned baseline. It is **not** a
rule engine: detection is driven by statistical, temporal, entity and
graph-derived evidence, and attack-name-derived indicator features are structurally
excluded from every model (Section 4).

The production detection path is a single **calibrated authentication-graph
detector**. Every event is projected onto directed edges across several
relationship views (account↔source, host↔host, ticket-encryption context,
process-access, rare-process, directory-operation) and scored as Dirichlet-smoothed
edge surprise. Each raw surprise becomes a p-value against a benign null frozen
per view at fit time; per entity the most significant hour is Šidák-corrected and
the analyst sees the *N* most significant entities per day. A supplementary
volumetric (ECOD) track exists but is off by default.

Design scope constraint honoured throughout: **no deep learning.** Every model is
a classical estimator or a closed-form statistic.

---

## 2. Method — how detection works, end to end

```
raw logs (JSONL, per channel)
  → normalize.py        channel + EventID → exact event_type, typed canonical fields
  → manifest.py         which feature groups the deployment actually supports
  → aggregate.py        per (entity, hour) behavioural feature vectors
  → contract.py         classify features: behavioural (model input) vs indicator (quarantined)
  → engine.py
       graph track:  auth_graph_anomaly.py  edge surprise → per-view p-value
       volumetric:   volumetric_detector.py per-entity ECOD → p-value  (off by default)
       fusion:       Tippett (min-p, Šidák-corrected) across views and tracks
       alerting:     top-N entities/day, or Benjamini-Hochberg at a target FDR
  → signed non-executable bundle (serialization.py)
```

Two properties make the numbers trustworthy and are enforced by tests:

- **Causal / frozen at fit.** The baseline and every per-view null are frozen
  during `fit` on training events only; `score` is a pure function that never
  recalibrates. Online adaptation is a separate, explicit `observe`/`score_stream`
  path.
- **Per-view null calibration on a held-out slice.** The null for each view is
  measured on a later held-out slice of training scored against the frozen earlier
  baseline — exactly the situation a live benign event meets. Calibrating it
  in-sample (the pre-existing bug found in the prior audit) leaves the null with no
  benign-novelty mass and over-flags every first contact.

---

## 3. Leakage found and fixed this round

**Look-ahead in the golden/silver-ticket indicators.** `build_user_windows`
accumulated each account's TGT/TGS issuance addresses over the *entire* event batch
before windowing, then tested each Kerberos logon against that whole-batch set. A
window at hour *t* could therefore see ticket issuance from hours after *t*: the
account's later legitimate use of an address would retroactively mark the
attacker's earlier use of it as familiar. `EVALUATION_AUDIT.md` §3's claim of "no
forward dependence" was false for these two features.

Fixed by storing issuance as a time-ordered history and consulting only the prefix
strictly before each logon (`_issuance_ips_before`, binary search).
`tests/unit/test_feature_causality.py` now recomputes every window against
truncated event streams and asserts no feature value changes when later events are
withheld — a general causality guard that also covers features not yet written.
These are informational flags excluded from the model, so measured scores are
unaffected; the value of the fix is removing a latent trap and making the audit
claim true. Demonstrated: on a logon-then-later-issuance sequence the golden-ticket
flag correctly stays 1 (caught) under the causal history, where the batch-wide set
scored 0 (missed).

---

## 4. Feature contract — "not a rule engine", enforced mechanically

Before this round, the only separation of rule-like indicator flags from
behavioural features was a substring check inside the volumetric detector, which is
off by default — so on the shipped path nothing prevented an attack-name feature
from reaching a model. `features/contract.py` makes the separation explicit,
versioned and tested:

- Every emitted feature is classified as one of `count`, `rate`, `cardinality`,
  `statistic` (behavioural, **model-eligible**) or `indicator` (a boolean
  hypothesis about a named technique, **quarantined**). Upstream detector verdicts
  (the Windows Defender group) are also quarantined as label-adjacent.
- On the full manifest this is **58 model-eligible behavioural features** and **21
  quarantined** (e.g. `f_kerberoast_flag`, `f_dcsync_flag`, `f_golden_ticket_flag`,
  `f_malware_detected_flag`). Quarantined features are still computed and shown to
  analysts as provenance; they are simply never model input.
- `model_feature_names(manifest)` is the only supported way to select model input.
  `contract_hash(manifest)` pins a trained bundle to the exact columns it was fit
  on. `tests/unit/test_feature_contract.py` fails if any `*_flag` or Defender
  verdict is model-eligible, or if an emitted feature is unclassified.

This is what lets the "behavioural, not signatures" claim be verified rather than
trusted.

---

## 5. Model comparison — classical baselines under leakage-resistant protocols

`evaluation/model_benchmark.py` (CLI: `model-benchmark`) compares
LogisticRegression, RandomForest, ExtraTrees, HistGradientBoosting,
IsolationForest, LocalOutlierFactor and OneClassSVM over the behavioural feature
matrix, with the shipped graph track as a reference column. Metrics: PR-AUC
(primary, because malicious windows are ~0.6–0.9% of all windows and accuracy /
ROC-AUC are near-blind at that imbalance), ROC-AUC, recall at 1% FPR,
precision/recall/F1/MCC at the deployment alert budget, plus fit time and peak
memory. Reported as mean ± spread across six seeded estates.

**Four split protocols, each a different generalisation question:**

| protocol | train/test share | question it answers |
|---|---|---|
| temporal | past vs future | does yesterday's baseline hold tomorrow? (deployment) |
| entity-disjoint | no shared account | does it work on an unseen account? (cold start) |
| entity-and-time-disjoint | neither account nor hour | the strict combination |
| attack-family-disjoint | one technique held out of training | unknown-technique detection |

**Why the strict protocol was necessary.** Entity-disjoint folds *alone* were
measured to leak: their folds still overlap in time, so a supervised model learns
a campaign from the training accounts and recognises the same campaign, in the same
hours, on the held-out accounts — roughly *doubling* apparent PR-AUC versus the
temporal protocol, the opposite of the expected ordering. The
entity-and-time-disjoint protocol removes both shortcuts and is the honest cold-start
number.

Six seeded estates, 123,436 windows, 858 positive windows (prevalence 0.70%),
alert budget 5/day. Primary metric PR-AUC (mean across folds; ±sd across folds).
Full table and interpretation: [docs/model_comparison.md](docs/model_comparison.md).

| protocol | best supervised (PR-AUC) | graph track (PR-AUC) | reading |
|---|---|---|---|
| temporal | logistic_regression **0.72** | 0.16 | supervised wins per-window when labels exist |
| entity-disjoint (leaky) | 0.81 | — | *higher than temporal → the time-overlap leak* |
| entity-and-time-disjoint (strict) | 0.72 | — | honest cold start; ≈ temporal, so entity overlap added little once time is respected |
| attack-family-disjoint | 0.33 **± 0.34** | — | supervised **collapse** on an unseen technique |

**What the comparison shows.**

- Under the **temporal** protocol a class-weighted **logistic regression on the
  behavioural features is the strongest per-window ranker** (0.72) — ahead of the
  tree ensembles (0.66–0.69) and far ahead of the unsupervised detectors and the
  graph track's per-window score (0.16). Where labelled attack windows exist, a
  cheap linear model on well-chosen behavioural features is a strong supervised
  baseline.
- **Entity-disjoint alone inflates** (0.81 > temporal 0.72), which is impossible for
  a genuinely harder task and is the time-overlap leak; the strict
  entity-and-time-disjoint protocol restores 0.72. This is why the strict protocol
  was added.
- Under **attack-family-disjoint**, the supervised models **collapse and become
  high-variance** — LR falls to 0.33 with a standard deviation of 0.34, as large as
  the mean. A technique held out of training is detected far less reliably and
  inconsistently across which technique is held out: the signature of a supervised
  model learning the *known* techniques' fingerprints rather than a general notion
  of abnormal, and exactly the case a real unknown threat resembles. It is precisely
  the circularity the research findings warn about, quantified.
- The **graph track is unsupervised**: it needs no labels and its behaviour does not
  depend on which techniques were "in training", so it has no collapse mode. Its
  per-window PR-AUC (0.16) is lower than supervised LR on the simulator, but its
  *product-level* per-attack recall is 71.7% (Section 6) — an attack spans several
  windows and needs only one to rank the entity into the day's budget — and it
  generalises to unknown techniques by construction.

**The honest synthesis:** on this simulator a supervised classifier wins the
per-window ranking *when the test technique was seen in training* and loses most of
that advantage otherwise. The unsupervised graph track trades peak per-window
separation for label-independence and unknown-technique robustness. Which matters
more is a deployment decision about label availability and threat model, and it
cannot be settled on synthetic data where the supervised advantage is inflated by
memorisation — which is why the shipped detector is the label-free graph track.

Reproduce: `python scripts/run_model_benchmark.py` (writes
`artifacts/bench/model_comparison.{txt,csv,json}`).

---

## 6. Graph-track product performance (reproduced)

Six seeded estates (`20250106`–`20250111`), 20 days, 253 employees, 60 held-out
test attacks across all ten techniques, 60/40 temporal walk-forward,
contamination=none, alert budget 5 entities/day:

| | recall | FP entities/day |
|---|---|---|
| engine (graph track) | **43/60 = 71.7%** | **3.46** |

Per-technique (this seed set; the split across techniques varies with attack
placement, the 43/60 total is stable and also reproduces on BENCHMARK.md's
independent seed set): asrep_roasting 6/6, password_spray 6/6, golden_ticket 4/4,
lsass_dump 4/4, pass_the_hash 7/9, dcsync 5/8, kerberoasting 6/8, silver_ticket
5/8, **account_manipulation 0/5**, **ntds_dump 0/2**.

Saved with its exact command to `artifacts/bench/graph_track_benchmark.json`.

This reproduction reconciled three contradictory documented numbers: the engine
docstring's "47/60" (stale → 43/60) and `EVALUATION_AUDIT.md`'s
account-manipulation "2/7" (stale → 0 detected).

The two structural misses are honest evidence limits, not tuning failures.
`account_manipulation`'s signal lives in the sparse `dir_op` view (~27 benign
observations), whose null floors near 1/(n+1) ≈ 0.036 — too coarse to reach the top
of a 250-entity queue. `ntds_dump`'s tools (`vssadmin`, `ntdsutil`) run
legitimately on domain controllers, leaving no novel relational trace. The
research-backed remedies (empirical-Bayes pooling across sparse views, EVT
peaks-over-threshold to break the 1/(n+1) floor) are documented extension paths,
not implemented claims.

---

## 7. Security hardening — model persistence

The engine previously persisted with `pickle` behind an HMAC. The signature
guarantees integrity but does not change that `pickle.loads` is a code-execution
surface — the accepted position in the literature (PickleBall, ACM CCS 2025), and a
category error in a security product whose model file is exactly what an attacker
would target. Persistence is now a schema-explicit, non-executable bundle
(`models/serialization.py`): versioned JSON for all scalars/strings/nested dicts,
`numpy.save(..., allow_pickle=False)` for arrays, HMAC-SHA256 over the whole bundle
verified before any file is parsed. Loading walks a closed hand-written schema and
never constructs an object named by the file.

Verified: save→load round-trips **bit-for-bit identical** scores (both tracks), and
the loader rejects a tampered JSON field, a corrupted array byte, a wrong signing
key, an object-bearing `.npy` (the numpy RCE vector), and a version mismatch —
`tests/unit/test_serialization.py`.

---

## 8. Infrastructure assessment (Kafka / Docker)

Assessed, not removed. `KafkaEventSource` is fully implemented (confluent-kafka,
manual-commit at-least-once, pull-based backpressure, EOF-aware replay), lazily
imported so the core has no hard dependency on it, exercised by tests, and sits
behind the same `EventSource` interface as the file reader with a file fallback.
The docker-compose files are honestly headed as unvalidated (no broker reachable in
this environment) and separate a plaintext local-dev broker from a SASL_SSL/mTLS
production one. This is a legitimate real-time-ingestion seam, not dead or
misleading infrastructure, so it is retained. What remains genuinely
infra-blocked — throughput/latency/back-pressure under load against a live broker —
is stated as unmeasured rather than claimed.

---

## 9. Datasets and real-data validation (status)

Real-data validation splits into two distinct claims that need two different kinds
of data (full survey in [docs/datasets.md](docs/datasets.md)):

**Ingestion correctness on real data — DONE.** Rather than wait on LANL's
data-use agreement, the project now validates against **OTRF Security-Datasets**
(Mordor): real Windows Security + Sysmon logs from ATT&CK-mapped attacks,
MIT-licensed and downloadable over plain HTTP. `evaluation/otrf_adapter.py` reads
them through the production `normalize_event` path, and `scripts/validate_on_otrf.py`
confirms that a curated set of five credential-access captures (DCSync, NTDS dump,
LSASS dump, Pass-the-Hash, Pass-the-Ticket) **all ingest at 100% and project the
behavioural graph view the engine relies on** — most sharply, the real DCSync 4662
projects the same signature-free `dir_op` edge (`pgustavo → adobjaccess`) the
engine uses on the simulator. This proves the parser, field maps, feature contract
and graph projection exercise real Windows event structure, not a simulator
artefact. Running on real data also **surfaced two parser bugs the simulator never
could** — a timestamp format (`.927Z`) that silently dropped events, and an
unhandled `TimeCreated` field — both fixed, taking parse coverage on the curated
set from ~50% to 100%, and both now regression-tested.

**Detection performance on real data — still open.** Recall and false-positive
rate need a labelled real corpus with a realistic benign background; OTRF's
captures clear their logs per run and have none. LANL 2015 is the target and the
`lanl-eval` harness is ready (exercised end-to-end on a synthetic LANL-format
fixture); the real files sit behind a data-use agreement that must be accepted
manually. This is the single largest remaining open risk and the report does not
hide it.

---

## 10. Limitations and unresolved risks

1. **No real-world *detection-performance* validation.** Ingestion correctness is
   now validated on real data (OTRF, Section 9), but every recall / false-positive
   *metric* is still on a self-authored simulator. Supervised model results on such
   data are especially suspect (Section 5), and the research findings are explicit
   that headline scores on real data (LANL) collapse under honest evaluation. Only
   a labelled real corpus with a benign background (LANL 2015 / OpTC) can retire
   this.
2. **Account manipulation (0) and NTDS dump (0)** are evidence limits on this
   simulator, with documented — not implemented — statistical remedies.
3. **Per-window vs product metrics measure different things.** The model-comparison
   PR-AUC is per (entity, hour) window; the graph track's 71.7% is per attack at an
   entity-day budget. Neither should be quoted as the other.
4. **Simulator realism.** The estate now churns source addresses realistically
   (the historic false-positive driver), but cannot reproduce shared/kiosk hosts,
   service-account sprawl, M&A estates, or cloud identity.
5. **Scale is unmeasured above 253 entities.** O(1) counter updates and
   linear-in-events fit predict it holds; that is a prediction, not a measurement.
6. **`alpha = 1.0`** (Dirichlet concentration) is an uninformative default, not a
   tuned value — deliberately, to avoid tuning on the benchmark.

---

## 11. Recommended next improvements (in priority order)

1. **Run `lanl-eval` and `model-benchmark` on real LANL 2015 / 2017.** Nothing else
   settles the detection-performance circularity. Re-measure the graph track's real
   recall and the supervised models' real attack-family-disjoint transfer. (Real-
   data *ingestion* is already validated on OTRF; this is the *performance* half.)
   The OTRF adapter also generalises: OpTC or LMDG/LMTrace can be wired behind the
   same `read_otrf_events`-style seam to broaden real-data coverage.
2. **Sparse-view resolution** for account manipulation: empirical-Bayes pooling and
   EVT peaks-over-threshold to break the 1/(n+1) floor (research findings Recs 03,
   05). Success criterion: account-manipulation recall > 0 on real labelled data
   *without* any attack-specific rule.
3. **Periodicity / non-human-identity model class** (Heard/Rubin-Delanchy Fourier
   g-test) for service accounts, whose behaviour is statistically distinct from
   humans.
4. **Scale test** on LANL 2017's 27k hosts; adopt count-min sketching if the exact
   per-edge counters break memory or latency.
5. **Calibrated supervised head, if labels become available operationally** — but
   only gated behind the attack-family-disjoint protocol, so it is admitted on
   unknown-technique transfer, not on memorising known ones.

---

## 12. Reproducibility

```bash
pip install -r requirements-dev.txt
export UEBA__SECURITY__MODEL_SIGNING_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")

# test suite (116 tests)
python -m pytest tests/ -q

# generate six seeded estates
for s in 20250106 20250107 20250108 20250109 20250110 20250111; do
  python enterprise_simulator/run_simulation.py --days 20 --seed $s --quiet \
     --inject-attacks all --attack-count 30 --attack-placement spread
  cp -r enterprise_simulator/output artifacts/bench/seed_$s
done

# graph-track product benchmark (per-technique recall, FP/day)
python -m ueba_pipeline.cli.main walk-forward-eval \
    --data-dir artifacts/bench/seed_20250106 --contamination none

# classical-model comparison under all four protocols
python scripts/run_model_benchmark.py            # writes artifacts/bench/model_comparison.*

# ingestion correctness on real Windows/Sysmon telemetry (OTRF; needs network)
python scripts/validate_on_otrf.py --cache-dir artifacts/otrf
```

Environment used for this report: numpy 2.5.1, scipy 1.18.0, scikit-learn 1.9.0,
pandas 3.0.3, Python 3.14, Windows 11.
