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
| **engine** | **46/60 = 76.7%** | **3.37** |

| technique | recall | | technique | recall |
|---|---|---|---|---|
| AS-REP roasting | 6/6 | | Pass-the-Hash | 7/9 |
| password spray | 6/6 | | DCSync | 7/8 |
| golden ticket | 4/4 | | Kerberoasting | 6/8 |
| LSASS dump | 4/4 | | silver ticket | 5/8 |
| account manipulation | 1/5 | | NTDS dump | 0/2 |

The per-technique split varies with attack placement across seeds; the 46/60 total
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
| `rare_proc` | 1.08 | **15.57** |

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
| edge surprise | 46/60; carries the product | keep |
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
  src_dst             351           8.8%
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

| view dropped | recall | Δ | FP/day | standalone recall |
|---|---|---|---|---|
| — (all views) | 43/60 | — | 3.46 | — |
| `user_src` | 33/60 | **−10** | 3.65 | 34/60 |
| `kerb_ctx` | 37/60 | **−6** | 3.56 | 6/60 |
| `tgs_enc` | 41/60 | −2 | 3.48 | 7/60 |
| `proc_access` | 43/60 | 0 | 3.46 | 4/60 |
| `rare_proc` | 43/60 | 0 | 3.46 | 0/60 |
| `dir_op` | 45/60 | +2 | 3.42 | — |
| `src_dst` | 48/60 | **+5** | 3.39 | 29/60 |

Combined: dropping `src_dst` alone reaches 48/60 at 3.39; dropping `dir_op` or
`rare_proc` on top of that changes nothing; dropping `proc_access` as well costs
2, so `proc_access` does contribute once `src_dst` is no longer masking it.

**`user_src` carries the product.** It is the only view that is both essential
(−10 when dropped) and strong alone (34/60). Everything else is supporting
evidence.

**Two mechanisms make a view net-negative, and they are different problems.**

- *Evidence starvation.* `dir_op` sees ~22 benign directory operations in the
  calibration slice, so its null floors at `1/(n+1) ≈ 0.043`. It can never assert
  significance — but it still adds a test to the Šidák correction in every cell
  where a directory event lands, diluting the views that can. This is the same
  evidence limit that leaves account manipulation at 0/5, now visible as a cost
  rather than merely an absence. A longer baseline resolves it; deleting the view
  would instead make directory attacks structurally undetectable.
- *Redundancy plus displacement.* `src_dst` is well-evidenced (~329 edges) and
  individually capable (29/60), but it derives from the same 4624 events as
  `user_src` and is strongly correlated with it. Under a fixed alert budget its
  moderate p-values displace `user_src`'s stronger ones.

**`src_dst` is nevertheless retained, and the reason matters.** The estate's
`server_access` is a fixed per-department list, so host-to-host edges are close to
deterministic by construction — precisely the dimension this view measures. That
is a known property of the fixture, not of real networks, and it is exactly the
kind of artifact that makes a simulator result untrustworthy. The published
evidence points the other way: Bowman et al. (RAID 2020) report ~0.85 TPR at 0.9%
FPR on **real** LANL data using source-computer → destination-computer edges as
the primary lateral-movement signal. Removing the canonical real-data view on the
strength of a fixture whose bias sits in that same dimension would be the
circularity this project exists to avoid.

The finding is therefore recorded, not acted on. `AuthGraphConfig.enabled_views`
lets a deployment disable any view, and this decision should be re-made on a
corpus with realistic host-to-host variety — see [datasets.md](datasets.md).

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
