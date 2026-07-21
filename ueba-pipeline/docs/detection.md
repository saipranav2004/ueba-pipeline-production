# Detection design

How the engine decides that an entity is behaving improbably, and why each choice
is the one it is.

## 1. Why p-values and not scores

An anomaly score means nothing on its own — it is interpretable only relative to
what the detector emits on benign data. Scores from different views sit on
different scales and cannot be combined by rescaling each with a constant: the
constants have no common meaning, cannot be validated independently, and their
composition is untestable.

So every raw statistic goes through the upper tail of a **benign null frozen at
fit time**:

```
p = P(S >= s | benign)
```

Rubin-Delanchy, Lawson & Heard (2016) set out this modus operandi: learn normality
from the large store of benign data, then frame intrusion as a test against that
null. A p-value is commensurable by construction — 1e-4 means the same thing
whichever view produced it.

`models/pvalue.py` stores the null as a bounded quantile grid rather than the raw
sample, so the fitted object is O(grid) regardless of how much benign data it saw,
holds no copy of the estate's telemetry, and scores by binary search. p is floored
at `1/(n+1)`: with n benign observations you cannot honestly assert a smaller tail
probability.

**How the null is measured matters more than the model.** It must answer: what
does a benign event score against the *deployed, frozen* baseline? So the baseline
is learnt from the earlier training period and each null is measured on a **later
held-out slice** scored against that frozen baseline. Calibrating in-sample —
absorbing all training data, then scoring that same data — marks every training
edge "already seen", leaving the null with no benign-novelty mass, so every first
contact in production looks extreme.

Each **view gets its own null**. Relationship types differ by an order of
magnitude in their benign baseline, and one pooled null lets the loudest view set
the bar for the quietest. [docs/evaluation.md](evaluation.md) quantifies the cost
of getting either of these wrong.

**A p-value is not a promise of uniformity.** p is uniform under the null only if
train and live data are exchangeable, and estates drift. The realised
false-positive rate exceeds nominal alpha, and the size of that gap measures
distribution shift.

## 2. Edge surprise — has this principal reached, or done, something it shouldn't?

```
surprise = max( -log P(dst|src), -log P(src|dst) )
P(b|a)   = (c_ab + alpha * pi_b) / (n_a + alpha)
```

Dirichlet-multinomial back-off over plain counters: O(1) update, streaming-safe,
learnt per estate.

| situation | surprise | why it is right |
|---|---|---|
| novel edge → **popular** destination | low | routine churn: everyone eventually touches the DC, the file server, the egress IP |
| novel edge → **rare** destination | high | genuine first contact |
| novel edge from a **highly active** source | higher | many opportunities, never taken — the absence is evidence |
| **cold start**, no baseline | ~0 | nothing is surprising without evidence |
| **seen** edge | decays smoothly to 0 | continuous, rankable, no cliff |

The score is graded surprise in nats, not a novelty flag. A constant "score for a
novel edge" produces two values, and no threshold separates two values. Graded
surprise spans a wide range, which is what lets one threshold separate routine
churn from a real first contact.

**Both directions.** Conditioning only on the source is blind to "was this
destination reached by someone new?" — the entire `proc_access` signal. Where only
`wininit.exe` opens `lsass.exe`, pi(lsass) ~ 1, so `rundll32.exe` opening lsass
scores 0.0 forward; the reverse conditional catches it. Taking the max keeps each
view's informative direction without hand-assigning one per view.

**No per-view gates.** Every view uses the same conditional. This is the guard
against becoming a rule catalogue: if each new technique needed its own gate, the
model would be memorising rather than generalising. See [graph.md](graph.md) for
the full set of views and how a new one is admitted on measured evidence.

A microcluster term (MIDAS, Bhatia et al. AAAI 2020) adds a Poisson surprise for a
sudden burst of the same edge within one tick, which is what fan-out, spray and
rapid credential reuse look like. A flagged edge is **not** folded into the
baseline (MIDAS-F), so an attacker cannot launder repeated abuse into normality.

## 3. Combining evidence

Different levels face different alternatives, so the combiner is chosen per level
(Heard & Rubin-Delanchy 2018, via Birnbaum 1954).

| level | alternative | combiner |
|---|---|---|
| views within one (entity, hour) | **one** view is anomalous among several | **Tippett** (min-p + Šidák) |
| events within one (entity, hour) | **one** event is bad among many | **Tippett** |
| an entity's windows | best window among many tested | **Šidák** |
| entities | control the triage queue | **budget**, or Benjamini-Hochberg |

Tippett within the hour is load-bearing: one severe event among 500 benign ones in
the same hour must not dilute below significance. Fisher would be wrong here — it
adds 2 df per test, so more benign context actively buries the signal.

Šidák over an entity's windows: a minimum over n windows *is* a test over n
windows. Without the correction the frequency bias reappears one level up, and any
entity observed long enough eventually looks significant.

## 4. Rigorous FDR alerts on nothing — and that is real

`alert_mode="fdr"` is implemented. At any sane FDR it alerts on **zero** entities,
and this is not tunable away: the null is floored at `1/(n_benign+1) ~ 2.5e-5`,
while ~250 entities × 192 hours × ~20 events ~ 10^6 tests need p ~ 1e-8 to survive
correction. Single-event evidence is three orders of magnitude short. This is why
no commercial UEBA product alerts on corrected p-values — they ship risk scores,
which are uncorrected rankings.

This engine ships the ranking too. The difference is that it is called a ranking
and operated as a budget. The p-values still do the work: a calibrated,
non-saturating ordering across otherwise incommensurable views. Absolute
significance is not attainable at this null-sample size, and claiming it would be
dishonest.

## 5. Entity space and state

All scoring lives in one entity space. `graph/sessions.py` resolves host-scoped
Sysmon telemetry to the account logged on at that time, so process telemetry and
authentication telemetry rank against each other rather than in separate
populations. An event that cannot be attributed keeps its host rather than being
dropped — a process opening lsass on a host nobody is logged into is not less
interesting, it is just not yet an identity.

`score()` is pure and does not mutate the detector, so re-scoring the same events
always gives the same answer. `observe()` is the explicit online path;
`score_stream()` opts into adaptation deliberately, because a live stream should
track drift while batch scoring must stay reproducible.

## 6. The knobs

`alert_budget_per_day` is the only alerting knob and means what it says: the N
most significant entities per day.

`alpha = 1.0` (Dirichlet concentration) is an uninformative default, deliberately
not swept against the benchmark — tuning a prior against a self-generated fixture
is curve-fitting, not calibration.

## 7. What this design does not do

- **Detect what leaves no relational trace.** Account manipulation is missed and
  NTDS extraction is missed, because the discriminating signal is directory
  context or a command line, not a novel relationship. Both are evidence limits
  on this estate rather than tuning failures; see [evaluation.md](evaluation.md).
- **Model periodicity.** Service accounts are statistically distinct from humans
  (strong periodicity, low entropy, narrow baselines) and are currently modelled
  with the same machinery as people.
- **Generalise beyond a simulator.** No detection-performance figure is validated
  against real labelled authentication data.

## References

- Rubin-Delanchy, Lawson & Heard. *Anomaly detection for cyber security applications.* 2016.
- Heard & Rubin-Delanchy. *Choosing between methods of combining p-values.* Biometrika 105(1), 2018.
- Bowman et al. *Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI.* RAID, 2020.
- Bhatia et al. *MIDAS: Microcluster-Based Detector of Anomalies in Edge Streams.* AAAI, 2020.
- Turcotte, Moore, Heard & McPhall. *Poisson factorization for peer-based anomaly detection.* IEEE ISI, 2016.
