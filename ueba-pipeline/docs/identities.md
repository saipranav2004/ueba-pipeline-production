# Identity typing — separating non-human identities from people

An identity threat platform has to model service accounts and people differently:
they are different statistical populations, and modelling a backup job with the
same machinery as a person both mis-scores the job and pollutes the person's
baseline. The first step is deciding, from behaviour alone, which an identity is.
This document is the complete reference for that capability: what it measures, why
those signals and not others, the measured separation, and where it is (and is
**not**) used.

> **Beginner's mental model.** A person works a drifting daytime band on
> weekdays and takes weekends off. A service account does not: a backup fires at
> 02:30 every night including Saturday, a monitoring agent polls around the clock,
> a batch job runs at one exact clock time seven days a week. `classify-identities`
> reads only *when* each identity is active and types it `automated`, `human`, or
> `unknown` on that shape.

Source: `ueba_pipeline/identity/typing.py` (the classifier) and
`ueba_pipeline/models/periodicity.py` (Fisher's g-test). CLI:
`python -m ueba_pipeline.cli.main classify-identities --data-dir <dir>`.

---

## 1. Why this exists, and what it is not

Supporting non-human identities (service accounts, managed service accounts,
scheduled jobs, monitoring agents, application identities) is a stated product
requirement, and the engine's own documentation flags the gap: service accounts
are "statistically distinct (strong periodicity, low entropy, narrow baselines)
but are currently modelled with the same machinery as people"
([detection.md](detection.md) §7). Typing is the prerequisite for closing it —
you cannot give NHIs a baseline of their own until you can identify them.

It reads **only event timestamps**, so it is data-source-agnostic (any estate,
any log format that yields a time and an account) and it types by *behaviour*, not
by a `svc_*` naming convention — a real estate's service accounts are not reliably
named, and a named allow-list is a rule, not a behavioural model.

**It does not touch detection scoring.** Typing is enrichment: analyst context,
and the substrate an NHI-specific detector would build on. Folding it into
detection is the documented next step (§7) and would enter as a
separately-calibrated track benchmarked on its own — the standard every detection
component here is held to ([graph.md](graph.md) Part 2).

---

## 2. The signals, and the one finding that shapes the rule

Three timestamp-only statistics, each independently discriminating.

| signal | what it measures | human | service account |
|---|---|---|---|
| **weekend-activity ratio** | share of events on Sat/Sun | 0.00–0.13 | 0.19–0.31 |
| **time-of-day concentration** (Rayleigh R) | how tightly events cluster on the 24h clock, ∈[0,1] | 0.54–0.997 | ≤0.24 *or* ≈1.00 |
| **periodicity** (Fisher g-test p) | significance of a dominant period | down to 1e-13 | down to 1e-11 |

The load-bearing finding is in the last row. **Periodicity does not separate the
two populations here**, and this is the opposite of what the headline method
predicts. Fisher's g-test — Heard, Rubin-Delanchy & Lawson's method for detecting
automated traffic (JISIC 2014) — is the literature's tool for exactly this
problem, but at the coarse (hourly) granularity of logon telemetry a person
working a weekday office band is *itself* strongly daily-periodic: measured, human
g-test p-values reach 1e-13, **more extreme than several service accounts**. Keying
on periodicity alone types two-thirds of humans as automated. The `classify-
identities` output makes it concrete — the most periodic identities in the estate
are people:

```
svc_backup    automated  ... g-test p=7.6e-07   scheduled ...
abanerjee2    human      ... g-test p=1.7e-13   human work rhythm (weekend 0%, R=0.71)
gsundaram     human      ... g-test p=1.0e-12   human work rhythm (weekend 0%, R=0.72)
```

Periodicity is therefore **necessary but not sufficient**. It is retained for two
reasons: it *confirms* that a razor-tight time-of-day is a real schedule rather
than one busy day, and it is the signal that *would* dominate on fine-grained
polling data — sub-minute intervals a human never produces, the setting the JISIC
method was built for. The engine records the finding rather than forcing the
method: the same "measure, keep only what earns its place" stance applied to the
extreme-value tail in [evaluation.md](evaluation.md).

The signals that *do* separate are the ones where machine and human genuinely
differ: an automated identity works the whole week, and its time-of-day profile is
**never a human daytime band** — it is either round-the-clock (a monitoring agent,
R≤0.24) or razor-tight (a batch job at one clock time, R≈1.00). A person's daytime
band sits strictly between (R∈[0.54, 0.997]).

---

## 3. The decision rule

An identity is **automated** if either holds; **unknown** if too sparse to judge;
**human** otherwise.

- **round-the-clock** — weekend-active (ratio ≥ 0.15) **and** time-of-day spread
  across all hours (R ≤ 0.50). Catches monitoring agents, which are neither
  periodic nor concentrated; only the round-the-week, round-the-clock shape marks
  them.
- **razor-tight (scheduled)** — weekend-active **and** fires in one clock window
  (R ≥ 0.995) that periodicity confirms is a real schedule (g-test p ≤ 1e-4).

Pairing weekend activity with a *non-human time-of-day shape* is what leaves a
weekend-*working* person correctly typed human: they keep a daytime band (R≈0.7),
so neither clause fires. The thresholds are each placed inside the empty gap
between the two measured populations (weekend 0.15; R 0.50 and 0.995), so the rule
is conservative — a periodic-but-human account is left human. They are a small,
auditable rule rather than a fitted model because the separation is large and a
misplaced threshold should misorder a display, not silently mistype an identity —
the same stance the identity graph takes on its composite ([graph.md](graph.md)
§2.4).

**Too sparse to judge** is an explicit outcome: fewer than 12 events, or activity
in fewer than 6 distinct clock-hours, resolves no rhythm and is typed `unknown`
rather than guessed.

---

## 4. Fisher's g-test (the periodicity primitive)

`models/periodicity.py`. For a regularly-binned activity series (events per hourly
bin over the identity's active span), the Schuster periodogram is taken at the
Fourier frequencies and the g-statistic is the share of total power in its single
largest ordinate:

```
g = max_k I(f_k) / sum_k I(f_k)
```

Under the null of white noise the power spreads evenly, so g is small; one dominant
period drives g toward 1. Fisher's (1929) exact upper-tail probability gives the
p-value:

```
P(g > g0) = sum_{k=1}^{floor(1/g0)} (-1)^(k-1) C(m, k) (1 - k*g0)^(m-1)
```

with m the number of Fourier frequencies. The DC term is removed before the
transform, so the overall activity level never competes for the maximum. The null
is Gaussian white noise and event counts are not, so the p-value is a strong ranked
statistic, not a calibrated false-positive rate — the engine's stance on every
p-value it computes ([pvalue.py](../ueba_pipeline/models/pvalue.py)). Correctness
is pinned against hand-computed values in `tests/unit/test_periodicity.py`.

---

## 5. Measured separation

Six seeded estates × 20 days × 253 employees + 12 service accounts. Ground truth
is the account kind the simulator generates; typing sees only timestamps.

| | value |
|---|---|
| **service accounts typed `automated`** | **72/72 = 100.0%** |
| **humans typed `automated` (false positives)** | **0/1562 = 0.00%** |
| identities typed `unknown` | 0 (all have ≥12 events over 20 days) |

The clean 0% false-positive rate is the result that matters: mistyping a *person*
as automated is the costly error (it would suppress a human's anomaly signal),
where mistyping a service account as human merely leaves it on today's machinery.
The rule is tuned to that asymmetry. Reproduce over the estate with
`classify-identities`; the per-seed breakdown is in the commit that introduced
this document.

---

## 6. Limitations

1. **Weekday-only automated identities are missed.** Both clauses require weekend
   activity, because the tightest humans reach R≈0.997 and a weekend gate is what
   keeps a weekday-only tight-scheduled person from being mistyped. A genuine
   automated identity that runs only on business days (a weekday batch job) is
   therefore typed human. This is the accepted cost of the 0% false-positive
   operating point on this estate; a longer baseline or a directory hint would
   resolve it.
2. **Thresholds are simulator-measured.** 0.15 / 0.50 / 0.995 sit in the gaps this
   estate produces. A real estate with heavy weekend on-call, follow-the-sun
   teams, or shared service accounts will move those gaps, so the thresholds need
   re-measuring on real telemetry before the false-positive claim transfers —
   exactly the circularity [datasets.md](datasets.md) documents for detection.
3. **Machine `$` accounts and SYSTEM are excluded.** Typing reuses the feature
   layer's entity attribution (`features.aggregate._user_key`), which drops
   machine and well-known SYSTEM identities. Typing computer/machine identities is
   a natural extension on the same primitive but is out of scope here.
4. **Coarse granularity limits the g-test.** On hourly logon telemetry the g-test
   cannot separate machine from human (§2); its discriminating power would return
   on fine-grained (sub-minute) polling data, which this telemetry does not carry.

---

---

# Part 2 — The behavioural deviation track (detection)

`ueba_pipeline/identity/deviation.py`. CLI: `deviation-scan`. Two **separate
queues, each with its own budget**, neither ever merged into the relational
detector's Tippett minimum or its alert budget:

| queue | signal | threat class | relational engine | this track |
|---|---|---|---|---|
| **nhi** | schedule (hour-of-day) | compromised non-human identity | 0/18 | **9/11 = 81.8%** @ 0.31 FP/day |
| **insider** | rate (volume) | insider / credential abuse | 1/9 | **16/18 = 88.9%** @ 0.17 FP/day |

Both cover classes the relational views are blind to **by construction**: neither
creates a new relationship. The insider figure replaces a long-standing 1/9 — see
§14 for why the earlier attempt failed and what changed.

## 8. The gap, and why the shipped engine cannot close it

A stolen service-account credential used within that account's own access creates
**no new relationship**: its own server, its own service, its own ticket
encryption. Every relationship view scores it as routine, correctly. The only
thing wrong is *when* — a backup job that has only ever run at 02:30 working at
15:00.

This is measured, not asserted. On an estate carrying the `nhi_schedule_hijack`
corpus (below), the shipped relational engine detects **0/3** held-out instances.
That is the honest baseline this track is built against.

## 9. What it covers, decided by measurement

Deviation from a schedule only means something for an identity that *has* one, so
coverage is a measured property, not a name or a label. An identity is admitted
only if its busiest three hour-buckets carry **≥95%** of its baseline activity and
it has **≥50** baseline events. Measured on training slices across three seeds:

| cohort | top-3-hour share of activity |
|---|---|
| scheduled service accounts | **1.000** (all 27) |
| round-the-clock agents | ≤0.452 |
| humans (with enough history) | ≤0.920 |

Both exclusions are deliberate:

- **Round-the-clock agents** (a poller firing every hour) have no schedule to
  deviate from at this resolution. Including them was measured to be actively
  harmful: their benign activity constantly lands in hours they have not used, which
  inflated the shared null (p99 benign surprise 11.45) and buried the genuine
  deviation of a scheduled job. Excluding them leaves the cohort homogeneous, which
  is what makes a single null valid.
- **People** do not pass; a work-hour band is not a schedule. The few humans who
  look concentrated are low-activity admin accounts, which the ≥50-event floor
  removes — with thirty events you cannot establish that an identity has a schedule.

This is the same admission discipline the relationship views are held to
([evaluation.md](evaluation.md)): a signal whose benign behaviour is routinely
"novel" cannot separate an attack from ordinary variation.

## 10. The model

The same statistical machinery as the relational detector, so the system carries
one idea rather than two — a Dirichlet-smoothed conditional over the hour an
identity is active, backing off to the cohort's hour marginal:

```
surprise = −log P(hour | identity)
P(h | e) = (c~_eh + α·π~_h) / (n_e + α)
```

**The hour is a circular variable, and treating it otherwise does not work.** 23:00
is adjacent to 00:00, and a job scheduled for 02:30 that slips to 03:05 has done
nothing surprising. Scoring raw per-hour counts made that slip look exactly as
novel as activity twelve hours away, and it was the dominant error: real schedules
jitter across bucket boundaries constantly, so nearly every covered identity
produced a benign "novel hour". So counts are **circularly smoothed** before the
conditional is formed —

```
c~(h) = Σ_d exp(−|d|_circ / τ) · c(h + d mod 24),   τ = 1 hour
```

— the discrete counterpart of a circular (von Mises-style) kernel estimate, the
standard treatment of a periodic variable. An adjacent hour then borrows most of
its neighbour's mass; an hour across the clock borrows essentially nothing
(exp(−12) ≈ 6e-6).

Raw surprise becomes a **calibrated p-value against a benign null frozen on a
held-out slice** of training, exactly as in the relational track. Only one
hypothesis is examined per (identity, hour) cell — the hour itself — so there is no
within-cell multiplicity; across an identity's windows the minimum is Šidák-corrected
for the number of windows tested.

**Ties are the norm and are broken on surprise.** Every window whose surprise
exceeds the entire benign null floors at the same `1/(n+1)`, so a plain minimum
over p picks an arbitrary window — often a benign one — and reports the wrong hour
to the analyst. Since p is a monotone transform of surprise and the floor is only a
resolution limit, the tie is resolved on raw surprise.

## 11. Measured performance

Six seeded estates, `nhi_schedule_hijack` corpus, causal 60/40 split, strict
attribution (an alerted identity must be the attacked principal **and** its peak
window must fall inside the attack span), this track's own budget of 0.5/day.

| | value |
|---|---|
| **shipped relational engine (baseline)** | **0/3 per seed — structurally blind** |
| **recall on covered identities** | **9/11 = 81.8%** |
| recall overall (incl. out-of-scope targets) | 9/18 = 50.0% |
| false-positive identities/day | **0.31** |

Both recall figures are reported because they answer different questions. The
attack picks any of the twelve service accounts uniformly, including the
round-the-clock agents this track deliberately does not cover; **7 of 18 instances
targeted an identity with no schedule to deviate from**, and those are out of
scope by construction rather than missed. 81.8% is the capability where it applies;
50% is what the corpus as a whole yields.

Score separation is close to complete, which is why the operating point is
comfortable: benign surprise reaches at most 1.32 (p99 = 0.86) while the attack's
5th percentile is 1.48. At a raw threshold of 1.25 the corpus separates at **100%
TPR for 0.13% FPR**.

## 12. Limitations of this track

1. **Round-the-clock identities are out of scope**, by design and by measurement.
   Catching a compromise of those needs a different instrument (volume or
   relationship, not time).
2. **Hour granularity.** A schedule shift of an hour or two is deliberately not
   surprising (the circular kernel). An attacker who confines activity to the
   identity's own window is invisible to this track — the honest boundary of a
   temporal model.
3. **Simulator-measured, like everything else here.** The admission thresholds and
   the operating point come from the estate, and a real estate with daylight-saving
   shifts, follow-the-sun batch windows or seasonal jobs will move them. Real
   telemetry must re-measure them before these numbers transfer.
4. **It does not model the day of the week.** A weekday-only job that runs on a
   Sunday inside its usual hour is not flagged. Day-of-week is the natural next
   dimension and was left out rather than added untested.

---

## 14. The volume signal, and why the earlier attempt failed

Insider abuse sat at **1/9** for a long time, with a per-entity volume signal
recorded as *built and rejected*. Re-examined, the rejection turned out to be
about **two separable things**, and only one of them was a property of the idea:

**The estimator was wrong for the data.** The earlier attempt scored an identity's
hourly count against its own **median and MAD**. Counts are not that kind of
quantity: most identity-hours contain zero or one event, so the MAD is frequently
exactly 0 and every non-median observation becomes infinitely anomalous; counts are
also skewed with variance tied to the mean, which a symmetric spread misstates; and
median/MAD needs the sample retained, so it cannot stream.

The literature's answer for count anomalies is a **count model**: Heard, Weston,
Platanioti & Hand (2010) score activity counts per entity per period with a Poisson
likelihood under a conjugate **Gamma** prior, and signal when an observation falls
far into the tail of the **posterior predictive** — which for a Gamma-Poisson pair
is **Negative Binomial** in closed form. That is the same "upper tail probability"
modus operandi the rest of this engine already uses (Turcotte et al., IEEE ISI
2016). It also needs only two sufficient statistics per entity (total count,
periods observed), so it updates in O(1) and streams. Implemented in
[`models/counts.py`](../ueba_pipeline/models/counts.py).

**The integration was wrong.** The signal was fused into the relational detector's
shared Tippett minimum and shared budget, where it cost 41 detections elsewhere.
That is the displacement law this codebase has now measured four times.

Changing both gives **16/18 = 88.9% at 0.17 FP identities/day**, with the
relational headline untouched by construction. The lesson is recorded because it
generalises: *a signal that measures badly may be a bad estimator or a bad
integration before it is a bad idea.*

## 15. Why the queues are separate — measured, not assumed

Running all three signals in one queue is markedly **worse** than either queue
alone. On the NHI corpus at 0.5 alerts/day:

| signals | recall (covered) | FP/day |
|---|---|---|
| **hour** (shipped as the NHI queue) | **9/11 = 81.8%** | **0.31** |
| dow | 0/11 = 0% | 0.50 |
| volume | 1/18 = 5.6% | 0.48 |
| hour + dow | 8/11 = 72.7% | 0.34 |
| hour + volume | 1/18 = 5.6% | 0.48 |
| hour + dow + volume | 1/18 = 5.6% | 0.48 |

`volume` covers **every identity in the estate** while `hour` covers only the
handful with a schedule, so under a shared budget the broad signal floods the queue
and displaces the narrow one — the same law that removed `src_dst`, a volume
signal and a process-lineage view from the relational engine. Applying "separate
queues, not better fusion" *recursively* is the resolution.

**`dow` is implemented but not shipped in either queue.** It contributes nothing
here (0/18 alone; −1 detection in combination), and the reason is structural rather
than a defect: every service account in this estate runs seven days a week, so no
day is unusual for one. The corpus cannot exercise the signal. It would matter for
a weekday-only batch job triggered on a Sunday, which this estate does not contain,
so it stays available behind `enabled_signals` and is not shipped on evidence that
does not yet exist.

## 16. Cadence was built for the round-the-clock cohort, and rejected

Round-the-clock agents (a monitoring poller active in every hour) are covered by
neither queue: they have no schedule to deviate from, and the schedule-hijack
attack against them is session-sized rather than a volume burst. Seven of the
eighteen NHI corpus instances target such an identity, so this is a real gap, and
**inter-arrival modelling** is the natural instrument (Price-Williams, Heard &
Turcotte, EISIC 2017).

Building it surfaced a modelling point worth keeping: **raw event inter-arrivals
measure the wrong thing.** An identity's activity arrives in bursts — one service
logon emits a 4624, a 4672, a service-state change and several ticket requests
within seconds — so the median raw gap for *every* service account is ~0.5 minutes
while its actual polling interval is tens of minutes. The signal only exists
between **bursts**, which is exactly the "opening event of a subsequence"
structure the paper describes. So `cadence` groups events into bursts (a gap
> 5 min opens a new one) and models the between-burst gaps in log-spaced bins with
the same Dirichlet machinery as `hour`.

It does not work here, and the diagnosis is specific rather than vague:

| signals | recall (covered) | FP/day |
|---|---|---|
| **hour** (shipped) | **9/17 = 52.9%** | **0.31** |
| cadence | 0/17 = 0% | 0.50 |
| hour + cadence | 0/17 = 0% | 0.50 |

**The attack is not a cadence anomaly.** Measured per instance, the gap preceding
the attack burst lands squarely inside the identity's ordinary distribution:

```
svc_wsus         gap =  837m -> a bin holding 57.1% of its baseline -> 0.60 nats
svc_exchange     gap = 1058m -> a bin holding 31.8% of its baseline -> 1.18 nats
svc_iis_apppool  gap =   97m -> a bin holding  5.6% of its baseline -> 2.78 nats
```

An agent that fires all day long experiences a gap of that size routinely, so
there is nothing for the model to find. The implementation is correct; the threat
model simply does not disturb cadence. And because cadence covers **262
identities** (nearly all of them people), fusing it reproduces the displacement
law a fifth time — it wipes the hour signal out entirely.

It is therefore **not enabled in either queue**, and kept behind `enabled_signals`
rather than deleted, because it remains the only instrument that could cover the
round-the-clock cohort and the estate contains no attack that exercises it. What
*would* exercise it is a compromise that changes an agent's rhythm — a silenced
agent, or an implant beaconing on its own interval — which this simulator does not
yet generate.

## 17. Where this goes next

- **A weekday-only NHI corpus** to exercise `dow`, and a **cadence-disturbing
  attack** (silenced agent, beaconing implant) to exercise `cadence`. Both signals
  are implemented and both are unshipped for want of evidence, not for want of
  code.
- **Real-data recalibration**, the standing requirement for every figure here.

## References

- Heard, Rubin-Delanchy & Lawson. *Filtering automated polling traffic in computer
  network flow data.* IEEE JISIC 2014. (Fisher's g-test for automated-traffic
  detection; the method this typing builds on and qualifies.)
- Fisher. *Tests of significance in harmonic analysis.* Proc. R. Soc. A, 1929.
  (the exact g-test distribution.)
- Price-Williams, Heard & Turcotte. *Detecting periodic subsequences in cyber
  security data.* arXiv:1707.00640, 2017.
- Mardia & Jupp. *Directional Statistics.* (the Rayleigh resultant length R.)
- Companion docs: [detection.md](detection.md) (the gap this addresses),
  [evaluation.md](evaluation.md) (the separate-track discipline),
  [datasets.md](datasets.md) (the real-data recalibration this still needs).
