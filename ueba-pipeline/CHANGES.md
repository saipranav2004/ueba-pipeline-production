# Change summary — production audit and redesign

This document records the audit findings and every change made in response. It is
a change record, not product documentation; the team-facing docs (README,
`docs/`, `MODEL_EXPLAINED.md`, `PROJECT_EXPLAINED.md`, `BENCHMARK.md`,
`DETECTION_EXPLAINED.md`) describe only the current system.

---

## Session 2 — feature contract, model comparison, causality, safe persistence

Reproduced independently (venv: numpy 2.5.1, scipy 1.18, scikit-learn 1.9.0,
pandas 3.0.3; 116 tests pass, was 88). The full rationale and results are in
[FINAL_REPORT.md](FINAL_REPORT.md).

1. **Look-ahead leakage fixed in the golden/silver-ticket indicators.** The
   per-account TGT/TGS issuance history was accumulated over the whole event
   batch before windowing, so a window at hour *t* could see ticket issuance from
   hours after *t* — `EVALUATION_AUDIT.md` §3's "no forward dependence" was false
   for these two features. The history is now consulted causally (issuance strictly
   before each logon). New `tests/unit/test_feature_causality.py` recomputes every
   window against truncated event streams and asserts nothing reads ahead, so a
   future extractor that reaches forward fails a test rather than a silent
   benchmark. These are informational flags (excluded from the model), so scores
   are unaffected; the fix removes a latent trap and makes the audit claim true.

2. **Versioned feature contract with enforced indicator quarantine**
   (`features/contract.py`). Previously the only separation of rule-like indicator
   flags from behavioural features was a substring check inside the volumetric
   detector, which is off by default. The contract now classifies every emitted
   feature (58 model-eligible behavioural features vs 21 quarantined indicators /
   upstream-detector verdicts) and is the single supported way to select model
   input. `tests/unit/test_feature_contract.py` fails if any `*_flag` or Defender
   verdict reaches model input, so "not a rule engine" is enforced mechanically.

3. **Classical model comparison + leakage-resistant split protocols**
   (`evaluation/model_benchmark.py`, `model-benchmark` CLI). New: LogisticRegression,
   RandomForest, ExtraTrees, HistGradientBoosting, IsolationForest, LOF,
   OneClassSVM, and the shipped graph track as a reference column — under four
   protocols (temporal, entity-disjoint, **entity-and-time-disjoint**,
   attack-family-disjoint), scored by PR-AUC / ROC-AUC / recall@fixed-FPR /
   precision-recall-F1-MCC at a fixed alert budget across six seeds. The
   entity-and-time-disjoint protocol was added after entity-disjoint-alone was
   measured to leak (folds overlapping in time roughly double apparent PR-AUC).

4. **Pickle persistence replaced with a non-executable, schema-explicit bundle**
   (`models/serialization.py`). `pickle.loads` is a code-execution surface even
   behind an HMAC (PickleBall, ACM CCS 2025); the engine now persists as versioned
   JSON + `allow_pickle=False` `.npy` arrays, HMAC-signed over the whole bundle.
   Save/load round-trips bit-for-bit identical scores (verified) and rejects
   tampered files, wrong keys, object-bearing arrays, and version mismatches.

5. **Contradictory documented metrics reconciled.** The engine docstring claimed
   the graph track carries 47/60; the README and a fresh six-seed reproduction both
   give 43/60. `EVALUATION_AUDIT.md` claimed account-manipulation 2/7; the
   reproduction gives 0. Stale numbers corrected; the canonical measurement is
   saved to `artifacts/bench/graph_track_benchmark.json` with the exact command.

6. **Real-data ingestion validated on OTRF Security-Datasets (Mordor).** Rather
   than wait on LANL's data-use agreement, added `evaluation/otrf_adapter.py` and
   `scripts/validate_on_otrf.py` to run the production parser over real,
   MIT-licensed, HTTP-downloadable Windows Security + Sysmon attack telemetry. A
   curated set of five credential-access captures (DCSync, NTDS dump, LSASS dump,
   Pass-the-Hash, Pass-the-Ticket) ingests at 100% and projects the expected
   behavioural graph views — the real DCSync 4662 projects the same signature-free
   `dir_op` edge the engine uses on the simulator. Running on real data surfaced
   **two parser bugs the simulator never could**, both fixed and regression-tested:
   `_parse_iso` mangled a short fractional second before `Z` (`.927Z` →
   `.927+00+00:00`, silently dropping every such event), and the flat-envelope
   reader ignored the `TimeCreated` timestamp field. Parse coverage on the curated
   set went from ~50% to 100%. This validates ingestion correctness on real data;
   detection recall/FP on real data still needs a labelled corpus with a benign
   background (LANL 2015). See [docs/datasets.md](docs/datasets.md).

7. **Capability gate changed from a fraction of total events to an absolute
   floor** (`CapabilityConfig.min_events_for_capability`, default 5). The manifest
   itself is kept — source-presence gating is correct and load-bearing (the
   feature contract's column order and `drift-check` derive from it). The
   *fraction-of-total* gate was the fragile part: it coupled unrelated sources (a
   high-volume source raised the bar every other source had to clear) and was
   unstable on a small or rolling training window (a group flips on/off between
   retrains from sampling noise, invalidating the model each time). An absolute
   floor is independent per source and stable across window sizes, still rejects a
   lone stray event from a decommissioned pilot, and keeps the `presence_gated_groups`
   bypass for rare-by-design signals. A distinct-host floor was considered and
   rejected — auth/Kerberos/directory events legitimately concentrate on one or two
   DCs. New tests in `test_regressions.py` lock in source-independence, stray-event
   rejection, and window-size stability.

Everything below was reproduced independently before and after the change
(venv: numpy 2.4.4, scipy 1.18, pydantic 2.13.4, networkx 3.6.1; the test suite
and the six-seed benchmark drive the shipped engine, not a reimplementation).

---

## Headline result

| | before | after |
|---|---|---|
| benchmark scope | 5 of 10 techniques ever scored | **all 10 techniques**, 6 seeds, n=60 |
| null calibration | in-sample (leaked) | **held-out slice vs frozen baseline** |
| recall @ budget 5 | 12/15 on the 5 easy techniques (reported as 80%) | **43/60 = 71.7%** across all ten, honestly calibrated |
| FP entities/day | 4.14 | **3.46** |
| detection tracks | 3 (graph + volumetric + peer) | **1 (graph)**; volumetric opt-in, peer removed |
| signed bundle | 3.45 MB, contains a dense O(users×dests) matrix | **~2.6 MB**, no dense per-pair matrix |

**The headline went down, and that is the point.** The old 80% was measured on the
five easiest techniques with a leaked null. The new 71.7% is measured on all ten
with a null that matches deployment. Every intermediate number produced during
this work (48/60, 50/60) was inflated by the same calibration leak and has been
retracted.

---

## 1. Evaluation methodology (fixed first, before any architecture change)

**Finding — technique-coverage bias.** The `spread` attack placement assigned
techniques positionally (`requested_types[i % 10]`), independent of seed, so a
60/40 time split always left the same five techniques (`account_manipulation,
pass_the_hash, kerberoasting, password_spray, dcsync`) in the held-out tail and
the other five (`golden/silver ticket, asrep, lsass_dump, ntds_dump`) always in
the training window, never scored. The README's marquee claims had no benchmark
support, and the six "seeds" added no technique coverage.

**Finding — the published per-technique table did not reconcile with the
headline** (it summed to 10/15 against a 12/15 headline).

**Fix.** `run_simulation.py` now injects a balanced, seed-shuffled multiset of all
techniques across the timeline, so the held-out tail samples every technique and
the seeds vary which instance lands where. The benchmark now runs six seeds
(n=60) with every technique measured, and reports per-technique recall with n.

**Verified clean (kept as regression tests):** causal time-ordered split; both
nulls frozen at fit; inductive (non-transductive) scoring; strict peak-hour
attribution; both contamination bounds; `score()` purity.

## 1b. Null calibration — the most consequential defect (found late, fixed)

The null must describe what a benign event scores against the **deployed, frozen**
baseline. The original calibration folded every training event into the baseline
and then scored those same events against it, so every training edge was already
"seen", scored ≈0, and **the null contained no benign-novelty mass**. Measured p99
benign surprise: `user_src` 3.26 in-sample vs **8.49** correctly calibrated;
`rare_proc` 1.08 vs **15.57**.

The detector therefore treated any first contact as extreme. The simulator's static
IPs made benign novelty artificially rare, so the over-flagging landed almost
entirely on injected attacks — the fixture *hid* the defect, and a real estate
(DHCP, VDI, roaming) would have exposed it as a flood of false positives.

Fixed in `TwoTrackEngine._fit_graph`: the baseline is learnt from the earlier
training period and each view's null is measured on a **held-out later slice**
scored against that frozen baseline, then the slice is folded in. The same
discipline was applied to the volumetric null. Three calibrations were measured on
the same six seeds: in-sample 50/60 (wrong), fully prequential 41/60
(over-conservative — cold-start first contacts inflate the tail), held-out
**43/60 (shipped)**.

## 1c. Per-view null calibration

One null per relationship view instead of a single pooled null. Views differ by an
order of magnitude in their benign baseline (`proc_access` ≈5.5 nats for ordinary
traffic; `user_src` ≈0.3), so a pooled null lets high-volume, high-baseline views
set the significance bar for everything else. The engine also now reports each
view's **benign novelty rate** at fit — the measurable property that decides
whether a relationship type carries signal at all.

## 2. Architecture — from three tracks to one, and Fisher to Tippett

An honest all-technique benchmark showed the three-track engine (graph +
volumetric + peer, Fisher fusion) scoring **39/60**, *below* the graph track
alone (**47/60**) at higher FP. Two root causes:

- **Fisher across tracks manufactured significance.** Fisher rewards several
  moderate p-values; under a fixed alert budget this let a busy-but-benign
  entity's ordinary variation combine into false significance and displace real
  single-track detections (e.g. AS-REP roasting: graph 10/10 but Fisher-fused
  0/10).
- **The peer track was net-negative.** Poisson matrix factorization added no
  technique the graph track did not already catch, is correlated with the
  volumetric track (both are functions of the same access counts), and
  materialised a dense `O(users × dests)` rate matrix (~2 GB projected at 50k
  users × 5k dests). It underperformed even though the simulator's deterministic
  per-department access is biased in its favour.

**Fixes.**
- Combination is now **Tippett** at every level — an entity is as suspicious as
  its single most anomalous view/track, never more.
- The **peer track was removed** entirely.
- The **volumetric track is disabled by default**. Re-measured under the corrected
  calibration it is clearly harmful: graph-only **43/60 at FP 3.46** versus
  graph+volumetric **30/60 at FP 3.86**, and it catches no technique the graph
  misses. It is retained behind `enable_volumetric` for estates with volume-based
  threats a relational view cannot see, to be validated on that estate's data.
- Result: the engine is a single, honestly-calibrated graph track.

## 3. Graph track — generalized coverage (no attack-specific logic)

- **`tgs_enc` view** projects 4769 service-ticket requests onto `(account →
  ticket-encryption-type)` edges. Keyed on the low-cardinality cipher (not the
  SPN, which floods the model with benign service diversity), it is the
  generalized ticket-downgrade signal and moved Kerberoasting into the graph
  track (0/4 → 3/4).
- **`dir_change` view** projects directory operations (4728/4732/4756 group adds,
  4662 AD object access, 5136 attribute modify) onto `(actor → object)` edges,
  attributed to the acting principal — the generalized representation of directory
  change, with no group allow/deny list. It produces real signal (~5 nats) but does
  not clear the alert budget for account manipulation (0/7); see limitations.
- Both directions of the conditional and MIDAS burst are retained.

## 4. Simulator alignment

- **Routine directory management** was added: help-desk admins process access
  requests against ordinary department/file-share groups every business day. This
  is a faithful baseline (real estates have constant group churn) and the baseline
  the `dir_change` view needs so a privileged-group escalation stands out rather
  than being the first group change ever seen.
- **Balanced attack placement** (above) keeps the simulator aligned with a
  technique-complete evaluation.
- **Windows portability:** the simulator forces UTF-8 on stdout/stderr so its
  banner and progress output do not raise `UnicodeEncodeError` on a stock Windows
  console.

## 5. Feature layer and parser

- **Phantom coverage removed.** The parser assigned a feature group to events it
  had no field mapping for, so groups (notably `security_object_access`) reported
  "available" and fed all-zero vectors into the model. A group is now claimed only
  for events the parser can actually extract, and the fully-unmapped
  `security_object_access` group was removed. Feature count dropped from 64 to 57
  (the removed features were structurally zero).
- The orphaned `threat_signatures.py` module (no readers in the engine, eval, or
  CLI) was removed; the real signature-flag exclusion lives in the volumetric
  detector.

## 6. Scalability and correctness

- **Peer scalability** was moot after the track's removal, but the general
  principle now holds throughout the detection path: nothing materialises a dense
  per-entity-pair matrix. The bundle is the frozen ECDF grids (O(features × grid),
  estate-independent) plus per-entity statistics (O(entities × features), inherent
  to a self-baseline) plus graph counters.
- **Dead configuration** (`TrainEvalConfig`, read by nothing) was removed.
- **New CLI commands** close documented gaps: `score-stream` (online scoring that
  adapts the baseline) and `drift-check` (compares a live window's log-source
  capabilities against the trained bundle, exits non-zero on a required retrain).

## 7. Documentation and comments

- All team-facing documentation was rewritten to describe the current two-track
  Tippett architecture, with honest all-technique benchmark numbers.
- Code comments and docstrings were scrubbed of fix-history, audit narrative, and
  references to internal documents that are not part of the repository.
- `DETECTION_EXPLAINED.md` (new) walks through, per technique, which fields are
  checked, which detector/view fires, and how the anomaly surfaces.

---

## Honest limitations (unchanged by this work, and why)

- **No real-world validation.** All data is self-generated; employees hold static
  IPs, so the simulator cannot produce the DHCP/VDI churn that dominates
  real-world false positives. The FP figures are a floor. This is the largest open
  risk and requires LANL 2015 / OpTC — external data that cannot be reproduced in
  code.
- **Account manipulation (1/7) and NTDS dump (0/5)** sit at the boundary of
  behavioural detection. Research into production detection (SIEM/EDR) confirms
  these are reliably caught only with a Tier-0 group watchlist (directory context)
  or command-line/execution-sequence rules — signals outside pure behavioural
  novelty. The generalized representations (`dir_change`, `rare_proc`) produce real
  signal; the remaining gap is context, and the extension paths are documented in
  `docs/architecture.md` rather than closed with simulator-gaming heuristics.
- **Rigorous FDR-controlled alerting alerts on nothing** — a genuine statistical
  limit of the null-sample size, not a tuning failure. The analyst budget is the
  operational path.


## 8. LANL 2015 validation harness

The adapter and benchmark were audited and rebuilt:

- `lanl_adapter.py` emitted `event_type="4624_logon"`, which the engine's exact
  `is_graph_event` match rejects — the full engine would have scored **zero**
  events. Now emits the exact code, and red-team matching accepts the compromised
  credential as either the source or destination user.
- `benchmark.py` tested a bare raw-surprise threshold hand-set to 5.0 at a single
  operating point. It now computes a proper **ROC** (TPR at a fixed reference FPR,
  plus AUC) over the **production per-view calibrated p-values**, and reports both
  contamination bounds.
- New `lanl-eval` CLI, a synthetic LANL-format fixture generator
  (`scripts/make_lanl_fixture.py`) and tests (`tests/unit/test_lanl_eval.py`) that
  exercise adapter → matching → causal split → ROC end to end.

**Real LANL numbers are not included.** The files sit behind a data-use agreement
at `csr.lanl.gov/data/cyber1/` (auth.txt.gz is 7.2 GB); direct programmatic
download returns 404 and the gate must be accepted by a human. Circumventing a
dataset's access control is not acceptable, so the harness is shipped ready and the
run is yours to make. Fixture results validate the plumbing only — its lateral
movement is detectable by construction and must never be quoted as performance.

## 9. Considered and rejected: learned temporal graph models

The strongest published LANL results come from temporal link prediction over
snapshots of the authentication graph — Euler (King & Huang, ACM TOPS 2023) reports
AUC 0.91–0.98, later temporal-graph work higher — against ~0.85 TPR @ 0.9% FPR for
unsupervised graph learning of the kind implemented here. This was researched and
deliberately not adopted **now**:

- it needs a deep-learning runtime, against a codebase whose whole detection path
  is counters and quantile grids;
- it needs real labelled data. Fitting a temporal GNN to a synthetic 253-employee
  estate would measure the simulator, not the method;
- it trades away the per-edge explainability an analyst triages on ("this account
  reached a host it never has, 8.5 nats") for an embedding distance.

Adopting it on the strength of published numbers, without data to validate it here,
would be exactly the unevidenced decision this work exists to remove. It is
documented as the upgrade path in `docs/architecture.md`, to be taken and
benchmarked as its own track once real data exists.
