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

## 7. Where this goes next

Typing is the substrate; the capability it unlocks is **NHI-specific detection**.
A service account has a tight, low-entropy baseline, so a compromise that keeps it
on its established relationships — a hijacked schedule, activity at a new time, a
silent agent — leaves no *novel relationship* for the graph detector to score
(the same blind spot documented for insider volume abuse in
[evaluation.md](evaluation.md)). A periodicity-deviation detector over typed NHIs
would catch that class. The disciplined way to add it, given that any signal fused
into the shared alert budget tends to lower headline recall (proven repeatedly in
[evaluation.md](evaluation.md)), is a **separate, separately-calibrated track for
automated identities** — not a sixth view in the main budget. That is the next
iteration, and it needs a simulator attack that hijacks an NHI's schedule to be
measured against, which does not exist yet.

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
