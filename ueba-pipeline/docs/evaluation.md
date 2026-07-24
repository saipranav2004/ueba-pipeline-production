# Evaluation: methodology, results, limitations

What is measured, how the measurement is protected against the ways an ITDR
benchmark is commonly wrong, and what the numbers do and do not support.

## Reproduce

```bash
export UEBA__SECURITY__MODEL_SIGNING_KEY=$(python -c "import secrets;print(secrets.token_hex(32))")

for s in 20250106 20250107 20250108 20250109 20250110 20250111; do
  python enterprise_simulator/run_simulation.py --days 20 --seed $s --quiet \
      --inject-attacks headline --attack-count 30 --attack-placement spread
  python -m ueba_pipeline.cli.main walk-forward-eval \
      --data-dir enterprise_simulator/output --contamination none
done
```

**Use `--inject-attacks headline`, not `all`, to reproduce the figure below.**
The headline is measured over the **ten** credential-theft / lateral-movement
techniques. `insider_data_staging` (volume abuse over an established
relationship) is a different attack class the relational engine cannot see; it is
measured as its own corpus ("Open capability: volume abuse", below), never folded
into this total. It lives in `ATTACK_REGISTRY`, so `--inject-attacks all` injects
it too and yields a different, non-comparable number (48/60 including its 0/7).
The `headline` preset pins the ten so the figure stays reproducible as the
registry grows (`attacks.HEADLINE_ATTACKS`; guarded by
`tests/unit/test_attack_presets.py`).

## Results

Six seeds × 20 days × 253 employees. 60 held-out test attacks across all ten
techniques. Alert budget 5 entities/day, strict attribution.

| | recall | FP entities/day |
|---|---|---|
| **engine** | **52/60 = 86.7%** | **3.27** |

> **Moved from 53/60 at 3.31 by a simulator-realism fix, not a detector change.**
> Service accounts previously produced no Kerberos service tickets at all, which
> was both unrealistic (a service account requests a TGS for the resource it
> drives, exactly as a person does) and misleading: it made *any* service-ticket
> request by a service account a novel relationship, so a compromised credential
> doing ordinary work looked anomalous for the wrong reason. Adding routine 4769s
> to the service-account day changed the `tgs_enc` baseline, and
> `account_manipulation` went 1/5 → 0/5 — one detection on the weakest technique,
> already documented below as an evidence limit at n = 5. False positives improved
> slightly. The detector is byte-identical across this change.

| technique | recall | | technique | recall |
|---|---|---|---|---|
| DCSync | 8/8 | | AS-REP roasting | 6/6 |
| Kerberoasting | 8/8 | | password spray | 6/6 |
| silver ticket | 8/8 | | golden ticket | 4/4 |
| Pass-the-Hash | 8/9 | | LSASS dump | 4/4 |
| account manipulation | 0/5 | | NTDS dump | 0/2 |

The per-technique split varies with attack placement across seeds; the total is
stable to within a detection across estate revisions. The contamination guard
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
| edge surprise | 52/60; carries the product | keep |
| per-view null calibration | without it, high-baseline views (`proc_access` ~5.5 nats benign) set the bar for low-baseline views (`user_src` ~0.29) | keep |
| `tgs_enc` view | Kerberoasting 6/8; 0 without it | keep |
| MIDAS burst term | cost 10 detections and 0.7 FP/day once it could actually fire | **removed** |
| host→user session attribution | one entity space for alerting | keep |
| `dir_op` view | keyed on operation class (9.1% benign novelty) not object touched (72%) | keep |
| volumetric (ECOD) track | 15/60 alone; fused 29/60 at 3.88 FP/day against 43/60 at 3.46 for the detector alone | **removed** |
| peer track (Poisson MF) | added no technique the edge model missed; dense O(users × dests) state | **removed** |
| EVT (peaks-over-threshold) tail | 53/60 → 53/60 at 3.31 FP/day, unchanged; the `1/(n+1)` floor is not a binding constraint here | **removed** |

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

### Low benign novelty is necessary but not sufficient

The novelty rate says whether a view *can* carry signal. It does not say whether
the view earns a place in the alert queue, and the difference is not small.

A process-lineage view — `(host|parent image → child image)` from Sysmon process
creation — was added and measured. Its profile is close to ideal by the novelty
criterion: 7,973 baseline edges at **0.4% benign novelty**, high-volume and
highly stable, so a novel spawn relationship is genuine evidence. It is also well
supported externally: Hemmati, Sadeghiyan & Saeidi (2026) report that GUID-based
process correlation consistently outperformed temporal correlation across every
classifier they tested for ATT&CK technique classification, and process lineage is
the standard discriminator for office-document-spawns-shell behaviour.

It cost 17 detections: **53/60 at 3.31 FP/day became 36/60 at 4.23**, with
password spray falling 6/6 → 2/6 and silver ticket 8/8 → 2/8.

**This is the third independent confirmation of one mechanism.** `src_dst`, a
per-entity volume signal, and now process lineage all measured well in isolation
and all degraded the product. Under a minimum-combination rule with a shared alert
budget, an added signal is harmful unless it is *strictly more specific* than what
it displaces: it costs a Šidák test in every cell it touches, and its moderate
p-values compete for queue slots against another view's strong ones. A
high-volume view is penalised twice over, however clean its novelty rate.

The external evidence is not wrong; it is answering a different question.
Supervised technique classification benefits from more behavioural context because
a classifier can weigh it. Unsupervised ranking under a fixed budget cannot — it
can only take the minimum, and more context means more chances to be displaced.

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
obtainable. Here the account→device view exists and strictly dominates it, so the
`src_dst` projection was removed from `edges_for` outright. A deployment whose
telemetry lacks a usable device identity would want it back; that means
reintroducing the projection, not toggling a config flag.

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

## The multiple-testing correction counts relationships, not events

Šidák answers "how many hypotheses did I examine". The correction originally
counted *events* scored in an (entity, hour) cell, which is not the same thing:
observing one relationship a hundred times examines one hypothesis a hundred
times. Counting events made an entity progressively harder to alert on the more
it did — and that is exactly backwards when volume over an established
relationship is itself the signal.

Correcting for distinct `(view, edge)` pairs instead moved the benchmark from
51/60 at 3.33 FP/day to **53/60 at 3.31**, with Kerberoasting reaching 8/8. It is
both the more defensible statistic and the better-measuring one.

## A microcluster term was measured and removed

The detector carried a MIDAS-style burst term: a chi-squared surprise between an
edge's current-tick count and its running mean, intended to catch fan-out, spray
and rapid credential reuse.

It never fired on the shipped path. Per-tick counters advanced only when an edge was
*absorbed* into the baseline, and batch `score()` deliberately never absorbs, so
every event looked like the first of its tick. This is why sweeping the term's
`tick_seconds` resolution across a 24× range moved nothing. With the term gone, that
per-tick scaffolding — the counters and the `tick_seconds` parameter — was removed
too; the only per-edge statistic scoring now reads is the cumulative count.

Wiring it to the pure path so it could fire produced a clear verdict:

| burst term | all-technique benchmark | insider corpus |
|---|---|---|
| **removed (shipped)** | **53/60 at 3.31 FP/day** | 1/9 |
| active | 43/60 at 4.00 FP/day | 6/9 |

It buys five insider detections for ten elsewhere and 0.7 additional
false-positive entities a day, because benign repetition is ordinary and a raw
repeat count fires on it. Removed.

## An extreme-value tail was measured and removed

The strongest external recommendation for this engine (the audit in `research
findings/`, following Siffer et al., KDD 2017) was to break the `1/(n+1)`
empirical-null floor with an Extreme Value Theory tail — a peaks-over-threshold
Generalized-Pareto model — so a sparse view could resolve a genuine extreme below
its floor. The account-manipulation miss (1/5) was the named target: the `dir_op`
null holds only a few dozen benign observations, so its floor is ~0.03, and the
hope was that an unclamped tail would let a floored directory-change signal
survive the Šidák correction.

It was built (GPD by method of moments, with the shape **pooled across views** —
shared shape, per-view scale — so the sparse `dir_op` view could borrow a tail it
has too few points to fit alone) and measured off vs on on the identical six
headline estates:

| EVT tail | headline recall | FP/day | account manipulation |
|---|---|---|---|
| **off (shipped)** | **53/60** | **3.31** | 1/5 |
| on | 53/60 | 3.31 | 1/5 |

**Zero change, every technique, every seed.** The diagnosis is specific and it
refutes the premise. Two things were confirmed by instrumenting the scorer:

- **The floor is not a binding constraint here.** The high-volume views already
  floor near 1e-4 (n in the thousands), far below anything the ranking turns on,
  so a tail changes nothing for them.
- **The account-manipulation limit is attribution, not resolution.** The floored
  attacks *do* score extremely — a non-admin's privileged operation reaches a
  `dir_op` surprise of 9.2 nats, above the largest benign surprise the slice ever
  produced (8.4) — but the principals are active admin-like accounts that already
  rank inside the alert budget on ordinary activity, and the attack hour is not
  their single most anomalous hour, so strict attribution fails regardless. And an
  honest GPD fit to a few dozen points is *more* conservative than the floor at
  9.2 nats (it cannot assert the extreme is rarer than its own sparse evidence
  supports), so even unclamping does not push the attack hour past the principal's
  own noisy baseline.

The idea is sound where a sparse view carries a signal that *is* the entity's peak
— which needs a real estate with a genuine sparse-but-discriminating view, not
this simulator's active-admin directory traffic. On the evidence available it adds
no measurable value, so it was removed rather than shipped dark; the mechanism is
recorded here so it is not re-attempted without the conditions that would make it
pay.

## Closed capability: volume abuse over an established relationship

**Superseded — this section is kept because the diagnosis below is correct and the
resolution turned on understanding exactly *why* the first attempt failed.** Insider
volume abuse now measures **16/18 = 88.9% at 0.17 FP identities/day** in a separate
queue with its own budget ([identities.md](identities.md) §14), against the 1/9
recorded below.

Two things were wrong with the first attempt, and only one of them was about the
idea:

1. **The estimator.** It scored hourly counts against a **median and MAD**. Counts
   are not that kind of quantity — most identity-hours hold zero or one event, so
   the MAD is frequently exactly 0 and every non-median observation becomes
   infinitely anomalous; counts are skewed with variance tied to the mean; and
   median/MAD cannot stream. The literature's instrument for count anomalies is a
   count model: a Poisson likelihood under a conjugate Gamma prior, signalling on
   the tail of the **Negative-Binomial posterior predictive** (Heard, Weston,
   Platanioti & Hand 2010) — the same upper-tail modus operandi used everywhere
   else here, and O(1) to update.
2. **The integration**, diagnosed correctly at the time (below): fusing it into the
   shared Tippett minimum and shared budget cost 41 detections elsewhere.

Fixing both closes the gap with the relational headline untouched. The general
lesson is worth keeping: *a signal that measures badly may be a bad estimator or a
bad integration before it is a bad idea.*

### The original finding, retained

The benchmark's ten techniques are all credential theft or lateral movement —
each one creates a relationship the identity did not have. Insider abuse,
credential misuse and privilege abuse do the opposite: a legitimate account uses
its own workstation against its own file server, and only the *rate* is wrong.

`insider_data_staging` (T1005) was added to the simulator to measure this: 60–140
service-ticket requests for the account's own file server, in working hours, from
its own workstation, every one succeeding. Nothing about it is novel.

**The engine detects 1/9.** That is an honest negative result, and the diagnosis is
specific rather than vague: the relational model scores the abuse strongly — the
surprise reaches 15.27 nats at p = 0.00123 — but relational novelty is the wrong
instrument for a threat that creates no new relationship, and the burst term that
would have caught it costs more elsewhere than it returns.

### A per-entity volume view was built and rejected

The obvious remedy was tried: a per-entity volume model scoring each identity's
hourly event count against **its own** robust baseline (median and MAD), carried
as a separately calibrated signal and combined by Tippett like every other.
Per-entity rather than global is essential and was verified first — benign and
insider volumes overlap heavily in absolute terms, because service accounts
legitimately run hot, but separate cleanly per identity.

It works, and it is still not shippable:

| configuration | all-technique benchmark | insider corpus |
|---|---|---|
| **no volume signal (shipped)** | **53/60 at 3.31 FP/day** | 1/9 |
| volume, global fallback for unknown identities | 8/60 at 4.86 | 9/9 |
| volume, scored only where a baseline exists | 12/60 at 4.78 | 8/9 |

It solves the insider case outright and costs 41 detections elsewhere. Removing
the global fallback — which flags every service account against a population
median of one or two events an hour — recovers only four of them.

**The cause is architectural, not a calibration detail.** Tippett takes the
minimum across signals, and the alert budget is shared. A signal with broad
coverage and modest specificity therefore dominates the minimum for a large
number of identities and displaces a signal with narrow coverage and high
specificity, however well each is individually calibrated. Roughly half of all
benign identity-hours legitimately exceed that identity's own median, so volume is
inherently the broad, modest signal.

This is the second independent test of the same conclusion: an ECOD volumetric
track over per-entity normalised feature counts failed the same way and for the
same reason. Two different implementations, one outcome.

**The direction that remains open is separate queues, not better fusion.**
Relational and volume evidence answer different questions and have different
specificity, and forcing them through one minimum and one budget is what fails. A
volume queue with its own budget would let both operate, at the cost of changing
the product's alerting contract — a decision that should not be made on one
synthetic corpus.

## Closed capability: compromised non-human identities

The second class the relational detector cannot see, and unlike volume abuse this
one now has a working detector — in a **separate track with its own budget**,
which is the architecture this document's own evidence prescribes.

`nhi_schedule_hijack` (T1078.003) was added to measure it: a stolen service-account
credential driving *its own* server, over *its own* service, with no new
relationship of any kind, no downgrade and no failure burst — only the hour is
wrong. The shipped relational engine detects **0/3** of these per seed, exactly as
its design predicts.

The NHI temporal track (`nhi-scan`, [identities.md](identities.md) Part 2) scores
each *scheduled* identity's activity hour against its own circularly-smoothed
baseline:

| | recall | FP identities/day |
|---|---|---|
| relational engine | 0/18 | — |
| **NHI track, covered identities** | **9/11 = 81.8%** | **0.31** |
| NHI track, whole corpus | 9/18 = 50.0% | 0.31 |

Both figures are reported because 7 of the 18 instances targeted a round-the-clock
agent, which has no schedule to deviate from and is deliberately out of the
track's coverage — out of scope by construction, not missed. Benign surprise
reaches at most 1.32 while the attack's 5th percentile is 1.48, so the two
separate almost completely (100% TPR at 0.13% FPR on a raw threshold).

**Crucially, the headline is untouched by construction**: this track never enters
the relational detector's Tippett minimum or its alert budget, so it cannot
displace relational evidence the way `src_dst`, a volume signal and a
process-lineage view each did. That is the "separate queues, not better fusion"
direction, implemented and measured.

## Parameter sensitivity

`scripts/sweep_hyperparameters.py` moves each free parameter across its plausible
range and re-runs the whole benchmark. This reports sensitivity, not a tuned
optimum: selecting the value that maximises recall on the estates the headline is
quoted from would be selection on the test set, and the resulting figure would
restate the search rather than measure the model.

| parameter | range swept | spread | reading |
|---|---|---|---|
| `alpha` | 0.1 → 10 | 4 detections | flat from 0.1 to 1.0, degrading above 2.0 |
| `absorb_surprise` | 6 → ∞ (no cap) | **0** | cannot move batch detection — the batch path never absorbs; governs streaming non-absorption only |
| `null_calibration_fraction` | 0.15 → 0.40 | **9 detections** | genuinely load bearing |

**Two of the three parameters do not move batch detection, which is the useful
result.** The Dirichlet concentration is flat across an order of magnitude below its
default, so `alpha = 1.0` sits on a plateau rather than a peak and needs no defence
beyond being uninformative. `absorb_surprise` cannot affect batch scoring at all —
the batch path never absorbs — so its only role is the streaming baseline (MIDAS-F
non-absorption); it is swept here to make that structural insensitivity explicit.
(The burst term whose `tick_seconds` resolution once appeared in this table was
measured and removed; see the note below.)

**`null_calibration_fraction` is the exception and deserves care.** At 0.15 the
held-out slice is too small to give the nulls resolution and recall falls to
44/60; at 0.40 it reaches 53/60. The default of 0.30 is *not* the best value
measured here, and it is deliberately not moved to 0.40 on that basis: these are
the estates the headline is quoted from, so tuning against them would make the
headline a restatement of the sweep. Choosing this parameter properly requires a
validation estate held apart from the reported one.

## Scalability

Measured with `scripts/benchmark_performance.py`, generating estates at 1×, 2×,
4× and 8× headcount via the simulator's `--headcount-scale`.

| identities | events | fit ev/s | score ev/s | fit MiB | p50 µs | p99 µs | distinct edges | bundle KiB |
|---|---|---|---|---|---|---|---|---|
| 265 | 70,246 | 30,990 | 60,771 | 0.9 | 4.0 | 71.7 | 1,004 | 202 |
| 518 | 137,712 | 24,718 | 76,378 | 1.9 | 4.7 | 98.7 | 1,984 | 394 |
| 1,024 | 275,394 | 32,280 | 104,601 | 3.5 | 3.4 | 99.2 | 3,848 | 764 |
| 2,036 | 544,323 | 31,206 | 91,735 | 7.5 | 4.9 | 102.7 | 7,693 | 1,526 |

**Edge count grows linearly with identities, not quadratically.** 7.7× the
identities produces 7.7× the edges. The feared O(users × destinations) blow-up
does not occur, because each identity has a bounded working set rather than
reaching everything. Memory and bundle size follow the same linear curve.

**Throughput and latency are flat.** Fit holds ~25–32k events/s and scoring
60–105k events/s across the whole range; per-event streaming latency stays at
~4 µs median and ~100 µs at the 99th percentile regardless of estate size. Nothing
in the scoring path is a function of how many identities exist.

Extrapolating the measured linear fit: 10,000 identities implies roughly 38k
edges and ~37 MiB of detector state; 100,000 implies ~370 MiB and a ~75 MB
bundle. Both remain tractable, and count-min sketching (MIDAS's mechanism) is the
documented fallback if exact counters ever stop being.

### Recall under a fixed analyst budget declines as the estate grows

This is a property of budget-based alerting, not of the model, and it is the more
important operational finding:

| estate | identities | budget/day | recall | FP/day |
|---|---|---|---|---|
| 1× | 265 | 5 | 10/10 | 3.77 |
| 2× | 518 | 5 | 9/10 | 3.90 |
| 2× | 518 | 9.8 (scaled) | **10/10** | 8.55 |
| 4× | 1,024 | 5 | 8/10 | 4.02 |
| 4× | 1,024 | 19.3 (scaled) | **10/10** | 17.99 |

At a fixed five alerts a day, four times the identities compete for the same five
queue slots and two true positives fall below the cut. Scaling the budget with the
estate recovers full recall, which shows the ranking itself is size-invariant: the
false-positive *rate per identity* stays near 0.015/day across the whole range.

The operational consequence is a capacity question, not a tuning one. Holding
recall constant as an estate grows costs analyst time proportionally; holding
analyst time constant costs recall. The engine surfaces the trade-off rather than
hiding it.

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
2. **Account manipulation (1/5).** An evidence limit, not a tuning failure — and
   the mechanism is more specific than "the null floors". The `dir_op` view sees
   only a few dozen benign operations in the calibration slice, so its null floors
   the smallest assertable p at `1/(n+1) ~ 0.03`. But the deeper cause is
   **attribution**: the principals are active admin-like accounts that already sit
   inside the alert budget on their ordinary activity, and the injected operation
   is not their single most anomalous hour, so it fails strict attribution
   (peak-hour-in-span) even when the account alerts. **Breaking the floor does not
   fix this**, and that was measured: a non-admin performing a privileged
   directory change scores a `dir_op` surprise of ~9.2 nats — *above* the largest
   benign surprise the calibration slice ever produced (~8.4) — yet an honest
   Generalized-Pareto tail fit to a few dozen points assigns it a p *more*
   conservative than the empirical floor, so it still cannot beat the principal's
   own noisy baseline hours ("An extreme-value tail was measured and removed",
   below). The remedies that would work here are not behavioural: a Tier-0
   watchlist (directory context, i.e. a rule) or a baseline measured in months.
3. **NTDS dump (0/2).** Its tools (`vssadmin`, `ntdsutil`) run legitimately on
   domain controllers, so it leaves no novel relational trace; the discriminating
   signal is a command line or an execution sequence.
4. **n = 60.** A development baseline, not a product claim.
5. **`alpha = 1.0`** is an uninformative default, not a tuned value.

## Where to improve next

1. **Run `lanl-eval` and `model-benchmark` on real LANL 2015 / 2017.** Nothing
   else settles the circularity of measuring on a self-authored estate.
2. **Sparse-view resolution** for account manipulation. Extreme Value Theory
   (peaks-over-threshold) was tried and **did not help on this estate** — see "An
   extreme-value tail was measured and removed" — because the binding limit here
   is attribution, not the `1/(n+1)` floor. Empirical-Bayes pooling across related
   cells remains untried; revisit both on real labelled data, where a sparse view
   may carry a signal an active principal's own baseline does not already drown.
   Success criterion: recall > 0 on real labelled data *without* any
   attack-specific rule.
3. **NHI capability — shipped, with the next dimensions open.** Identity typing and
   the NHI temporal track now both ship ([identities.md](identities.md)): 81.8%
   recall on covered identities at 0.31 FP/day against a class the relational
   engine detects 0/18 of. What remains is **day-of-week** modelling (a weekday job
   running on a Sunday inside its usual hour is not yet flagged) and
   **volume-per-schedule** (an identity that keeps its hours but does ten times its
   usual work) — the latter being the same open problem as insider volume abuse,
   now with an obvious home in a track that has its own budget.
4. **Scale test** beyond a few hundred identities; adopt count-min sketching if
   exact per-edge counters break memory or latency.
