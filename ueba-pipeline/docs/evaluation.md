# Evaluation: methodology, results, limitations

What is measured, how the measurement is protected against the ways an ITDR
benchmark is commonly wrong, and what the numbers do and do not support.

## Reproduce

```bash
export UEBA__SECURITY__MODEL_SIGNING_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")

for s in 20250106 20250107 20250108 20250109 20250110 20250111; do
  python enterprise_simulator/run_simulation.py --days 20 --seed $s --quiet \
      --inject-attacks all --attack-count 30 --attack-placement spread
  python -m ueba_pipeline.cli.main walk-forward-eval \
      --data-dir enterprise_simulator/output --contamination none
done
```

## Results

Six seeds × 20 days × 253 employees. 60 held-out test attacks across all ten
techniques. Alert budget 5 entities/day, strict attribution.

| | recall | FP entities/day |
|---|---|---|
| **engine** | **51/60 = 85.0%** | **3.33** |

| technique | recall | | technique | recall |
|---|---|---|---|---|
| AS-REP roasting | 6/6 | | DCSync | 8/8 |
| password spray | 6/6 | | silver ticket | 8/8 |
| golden ticket | 4/4 | | Pass-the-Hash | 8/9 |
| LSASS dump | 4/4 | | Kerberoasting | 6/8 |
| account manipulation | 1/5 | | NTDS dump | 0/2 |

The per-technique split varies with attack placement across seeds; the 51/60 total
is stable and reproduces on an independent six-seed set. The contamination guard
makes no measurable difference (`oracle` ≡ `none`).

## Methodology guarantees

Each of these is a way an ITDR benchmark is commonly wrong, and each is enforced
by a test rather than a convention.

**Causal split.** Time-ordered 60/40. The engine is fit on train events only. The
capability manifest and every per-view null are built inside `fit(train)` and
reused unchanged for scoring.

**No threshold leakage.** No threshold is selected from the test set's benign
scores. All nulls are frozen at fit; `score()` never recalibrates, asserted by
inspecting the source of `fit`/`_fit_graph` against `score`. The only operating
knob, `alert_budget_per_day`, is a configuration value, not a fitted one.

**No look-ahead.** Features for a window depend only on events at or before that
window. Cross-window history — for example an account's prior Kerberos
ticket-issuance addresses — is consulted strictly causally. A generic guard
recomputes every window against truncated event streams and fails if any value
changes when later events are withheld, so it also covers features not yet
written.

**No transduction.** A score is a pure function of the point being scored, not of
the batch it arrives in. Per-view nulls are frozen quantile grids; `score()` does
not mutate detector state.

**Strict attribution.** An attack counts as detected only if an alerted entity is
one of its principals **and** the peak hour driving that entity's alert falls
inside the attack span. Under p-value scoring nearly every (entity, hour) cell
carries p < 1, so a looser "any detection during the window" check is satisfied by
mere activity — and the attack generates its own principal's activity. That looser
check degenerates into "is this entity in the top-k anywhere in the test period".

**No exempt regions.** Every alert is a true positive if attributable and a false
positive otherwise. Alerts inside attack windows are not excused.

**Both contamination bounds.** `oracle` cleans the training baseline using
ground-truth labels — an upper bound no deployment has. `none` is the unlabelled
cold start. Both are reported.

**Variance.** Six seeds, with n printed beside every ratio so 100% of 3 cannot
masquerade as 100%.

**Train/test entity overlap is correct here, not leakage.** The method is a
per-entity self-baseline, so an entity-disjoint split measures a different task.
That different task is measured separately and deliberately in
[model_comparison.md](model_comparison.md).

## Null calibration decides the headline

A detector's null must answer: *what surprise does a benign event produce when
scored against the deployed, frozen baseline?* How that null is measured moves the
headline further than any modelling choice, so all three candidates were measured
on the same six seeds:

| null calibration | recall | FP/day | verdict |
|---|---|---|---|
| in-sample (absorb all training, then score it) | 50/60 (83%) | 3.29 | **wrong** — every training edge is already "seen" and scores ~0, so the null holds no benign-novelty mass and any first contact looks extreme |
| prequential (score each event, then absorb) | 41/60 (68%) | 3.48 | over-conservative — every account's cold-start first contact inflates the tail |
| **held-out slice (shipped)** | **43/60 (72%)** | **3.46** | **correct** — baseline from the earlier training period, null measured on a later held-out slice scored against that frozen baseline |

These three were measured against each other on one estate revision, so the
absolute figures sit below the current headline; the ordering between them is the
result, and it is what decides the design.

The in-sample null is not a small optimism. Measured p99 benign surprise:

| view | in-sample | correctly calibrated |
|---|---|---|
| `user_src` | 3.26 | **8.49** |
| `proc_access` | 6.85 | **16.27** |

It asserts that 3.3 is the 99th percentile of benign `user_src` surprise when
benign novelty routinely reaches 8.5. An estate with static addresses hides this,
because benign novelty is artificially rare and the over-flagging lands almost
entirely on injected attacks.

## Address churn: the real-world false-positive driver

The estate churns addresses the way a real one does — VPN pools, DHCP leases,
wired vs Wi-Fi — giving ~10 distinct source addresses per user over 20 days while
the *device* identity stays stable (~1.1 per user). This is the condition that
historically makes authentication-graph detection unusable in production, and it
is decided entirely by what identifies "source":

| `(account → source)` keyed on | benign edges that are novel |
|---|---|
| IP address | **91.8%** |
| **device identity (shipped)** | **4.4%** |

Keyed on the address, 92% of ordinary logons look like first contacts and the view
is pure noise. Detection is unchanged by the churn.

## Component evidence

Every component is held to measured contribution.

| component | evidence | verdict |
|---|---|---|
| edge surprise | 51/60; carries the product | keep |
| per-view null calibration | without it, high-baseline views (`proc_access` ~5.5 nats benign) set the bar for low-baseline views (`user_src` ~0.29) | keep |
| `tgs_enc` view | Kerberoasting 6/8; 0 without it | keep |
| MIDAS burst term | surfaces fan-out / spray / rapid reuse | keep |
| host→user session attribution | one entity space for alerting | keep |
| `dir_op` view | keyed on operation class (9.1% benign novelty) not object touched (72%) | keep |
| volumetric (ECOD) track | 15/60 alone; fused 29/60 at 3.88 FP/day against 43/60 at 3.46 for the detector alone | **removed** |
| peer track (Poisson MF) | added no technique the edge model missed; dense O(users × dests) state | **removed** |

`train` reports each view's benign novelty rate, which is the measurable test of
whether a relationship type can carry signal at all:

```
  view              edges  benign novelty
  proc_access        2053           0.0%     <- stable: a novel edge is real evidence
  tgs_enc            2114           0.4%
  kerb_ctx            981           0.2%
  dir_op               21           4.8%     <- 72.0% when keyed on the group object
  user_src            351           9.1%     <- 91.8% if keyed on IP instead of device
```

A view whose benign edges are routinely novel cannot separate a first contact from
an attack, however it is calibrated. This single number drove three design
decisions: key the source edge on the device, key Kerberoasting on the cipher
rather than the SPN, and key directory operations on the operation class rather
than the object. Admitting a new view is therefore an evidence-based decision
rather than per-attack judgement.

## What each relationship view contributes

`scripts/ablate_graph_views.py` drops each view in turn and re-runs the whole
benchmark, so a view is kept on measured contribution rather than on the
plausibility of its rationale. Six seeds, same protocol as above.

Two views were removed on this evidence, taking the engine from 46/60 at 3.37
FP/day to **51/60 at 3.33** — more recall and fewer false positives:

| view dropped | recall | Δ | FP/day | standalone |
|---|---|---|---|---|
| — (all seven) | 46/60 | — | 3.37 | — |
| `user_src` | 39/60 | **−7** | 3.50 | 35/60 |
| `kerb_ctx` | 41/60 | **−5** | 3.46 | 6/60 |
| `tgs_enc` | 42/60 | **−4** | 3.44 | 7/60 |
| `dir_op` | 46/60 | 0 | 3.37 | 13/60 |
| `rare_proc` | 46/60 | 0 | 3.37 | **0/60** |
| `proc_access` | 49/60 | +3 | 3.31 | 5/60 |
| `src_dst` | 51/60 | **+5** | 3.33 | 29/60 |

**Why dropping a view can *raise* recall.** Each view that fires on an event adds
a test to that cell's Šidák correction. Šidák assumes the tests are independent;
two views derived from the same event are not, so a correlated pair is penalised
twice — once for adding no independent evidence, and again for inflating the
correction applied to the view that did. A view must therefore earn its
correction cost, not merely be plausible.

**Removed: `src_dst`.** It projects (source host → destination host) from the same
4624 events `user_src` reads, so the two are strongly correlated. It is capable
alone (29/60) but redundant in combination, and dropping it gains 5 detections
while lowering false positives. The finding reproduced across two estate
revisions, including after the estate's per-department server access was replaced
with realistic per-person working sets — the confound originally suspected of
causing it.

This is a deliberate divergence from the published baseline: Bowman et al. (RAID
2020) use source-computer → destination-computer edges as the *primary* signal on
LANL, at ~0.85 TPR / 0.9% FPR. That setting has no account-to-device view
available — a flat authentication log makes host-to-host the richest relation
obtainable. Here the account→device view exists and strictly dominates it. The
view remains selectable via `AuthGraphConfig.enabled_views` for a deployment
whose telemetry lacks a usable device identity.

**Removed: `rare_proc`.** It detected nothing, in every configuration, across
both estate revisions: 0/60 standalone and no change when dropped. A view that
has never contributed a detection cannot justify the correction it costs.

**Retained despite a positive drop-delta: `proc_access`** (+3). Unlike `src_dst`
it is not redundant — it is the only view reading Sysmon process access, so
removing it would leave credential-store access structurally undetectable. Real
telemetry exercises it far more heavily than the estate does (7,495 edges on the
OTRF NTDS capture against 2,053 here), so the estate is the weaker evidence about
its value. Its cost is false-positive displacement under a fixed budget rather
than absence of signal.

**Retained: `dir_op`** (0). Evidence-starved at ~21 baseline observations, so its
null floors near `1/(n+1) ≈ 0.045` and it can rarely assert significance — yet it
reaches 13/60 alone at only 0.71 FP/day, and it is the only view reading directory
operations. A longer baseline resolves the floor; deleting the view would make
directory attacks permanently invisible.

## Scalability

Measured on 253 employees × 20 days (~160k events): fit ~30k events/s, score ~37k
events/s, signed bundle ~440 KB, `score()` bit-for-bit reproducible across
repeated calls. Updates are O(1) per edge and the artifact is bounded by grid
size, not by how much data was seen. Nothing above ~300 entities has been
measured — linear-in-events fit and O(1) counter updates predict it holds, which
is a prediction, not a measurement.

## Validation against public data

`lanl-eval` runs a per-authentication ROC (TPR at a fixed FPR, plus AUC) against
LANL 2015 using the production per-view calibrated scoring, reporting both
contamination bounds. The LANL files sit behind a data-use agreement that cannot
be accepted programmatically; the harness is exercised end to end on a synthetic
LANL-format fixture, which validates the adapter, red-team matching, causal split
and ROC — **not** real-world performance.

Real-telemetry *ingestion* is validated separately and does run:
[datasets.md](datasets.md) covers the OTRF Security-Datasets corpus, where the
parser, feature contract and graph projections are exercised against genuine
Windows Security and Sysmon captures.

## Limitations

1. **No real-world detection-performance validation.** All detection data is
   self-generated. The estate churns addresses realistically, so FP/day is no
   longer a pure floor, but a simulator cannot reproduce shared/kiosk hosts,
   service-account sprawl, M&A estates, or cloud identity. This is the largest
   open risk; only a labelled real corpus retires it.
2. **Account manipulation (0/5).** An evidence limit, not a tuning failure. The
   `dir_op` view sees ~27 benign directory operations in the calibration slice, so
   its null floors the smallest assertable p at `1/(n+1) ~ 0.036`; after
   correcting for the hours an entity is observed, that cannot reach the top of a
   250-entity queue however anomalous the behaviour is. Rare-operation views need
   a baseline measured in months. A Tier-0 watchlist would short-circuit it with
   directory context, which is a rule, not behaviour.
3. **NTDS dump (0/2).** Its tools (`vssadmin`, `ntdsutil`) run legitimately on
   domain controllers, so it leaves no novel relational trace; the discriminating
   signal is a command line or an execution sequence.
4. **n = 60.** A development baseline, not a product claim.
5. **`alpha = 1.0`** is an uninformative default, not a tuned value.

## Where to improve next

1. **Run `lanl-eval` and `model-benchmark` on real LANL 2015 / 2017.** Nothing
   else settles the circularity of measuring on a self-authored estate.
2. **Sparse-view resolution** for account manipulation: empirical-Bayes pooling
   across related cells, and Extreme Value Theory (peaks-over-threshold) to break
   the `1/(n+1)` floor. Success criterion: recall > 0 on real labelled data
   *without* any attack-specific rule.
3. **A periodicity / non-human-identity model class** (Fourier g-test edge
   classification) for service accounts.
4. **Scale test** beyond a few hundred identities; adopt count-min sketching if
   exact per-edge counters break memory or latency.
