# Model, explained

*A detailed walkthrough of the statistical design.*

## 1. Why p-values and not scores

An anomaly detector emits a number that means nothing on its own — it is only
interpretable relative to what that detector emits on benign data. Two detectors
emit numbers on two scales, and they cannot be combined by rescaling each with a
constant: the constants have no common meaning, cannot be validated
independently, and their composition is untestable.

So every raw statistic goes through the upper tail of a **benign null frozen at
fit time**:

    p = P(S ≥ s | benign)

Rubin-Delanchy, Lawson & Heard (2016) set out this modus operandi: learn normality
from the large store of benign data, then frame intrusion as a test against that
null. The output of every detector is a p-value, which is commensurable by
construction — a p of 1e-4 means the same thing whichever detector produced it.

`models/pvalue.py` stores the null as a bounded quantile grid — not the raw sample
— so the fitted object is O(grid) regardless of how much benign data it saw, holds
no copy of the estate's telemetry, and scores by binary search. p is floored at
`1/(n+1)`: with n benign observations you cannot honestly assert a smaller tail
probability.

**How the null is measured matters more than the model.** It must answer: what
does a benign event score against the *deployed, frozen* baseline? So the baseline
is learnt from the earlier training period and each null is measured on a **later
held-out slice** scored against that frozen baseline. Calibrating in-sample —
absorbing all training data, then scoring that same data — marks every training
edge "already seen", leaving the null with no benign-novelty mass, so every first
contact in production looks extreme. And each **view gets its own null**: relationship
types differ by an order of magnitude in their benign baseline, and one pooled null
lets the loudest view set the bar for the quietest. See
[EVALUATION_AUDIT.md](EVALUATION_AUDIT.md) for the measured cost of getting this
wrong.

**A p-value is not a promise of uniformity.** p is uniform under the null only if
train and live data are exchangeable, and estates drift. The realised FP rate
exceeds nominal alpha, and the size of that gap measures distribution shift.

## 2. Graph track — has this principal reached, or done, something it shouldn't?

    surprise = max( −log P(dst|src), −log P(src|dst) )
    P(b|a)   = (c_ab + α·π_b) / (n_a + α)

Dirichlet-multinomial back-off. Counters only: O(1) update, streaming, per estate.

| situation | surprise | why it's right |
|---|---|---|
| novel edge → **popular** destination | low | routine churn: everyone eventually touches the DC, the file server, the egress IP |
| novel edge → **rare** destination | high | genuine first contact |
| novel edge from a **highly active** source | higher | many opportunities, never taken — the absence is evidence |
| **cold start**, no baseline | ~0 | nothing is surprising without evidence |
| **seen** edge | decays smoothly to 0 | continuous, rankable, no cliff |

The score is graded surprise in nats, not a novelty flag. A constant "score for a
novel edge" produces two values, and no threshold separates two values. Graded
surprise spans a wide range, which is what makes one threshold able to separate
routine churn from a real first contact.

**Both directions.** Conditioning only on the source is blind to "was this
destination reached by someone new?" — the entire `proc_access` signal. With a
baseline where only `wininit.exe` opens `lsass.exe`, π(lsass) ≈ 1, so
`rundll32.exe` opening lsass scores 0.0 forward. The reverse conditional catches
it.

**No per-view gates.** Every view uses the same conditional. This is the guard
against becoming a rule catalogue: if each new technique needed a new view gate,
the model would be memorising, not generalising. See [docs/graph.md](docs/graph.md)
for the full set of views.

## 3. Volumetric track — has the activity profile shifted?

Per-entity z-normalised counts → ECOD (Li et al., TKDE 2022) → p-value. The signal
is a deviation from the *entity's own* baseline; entities without enough history
fall back to global statistics.

`models/inductive_ecod.py` freezes the per-column ECDF at fit into a bounded
quantile grid. Scoring is then a binary search per feature: inductive,
order-independent, batch-independent, and the artifact is O(features × grid)
regardless of training-set size. Signature-flag features are excluded from the
vector — the track sees behavioural counts only.

## 4. Combining evidence

Different levels face different alternatives, so the choice of combiner is made per
level (Heard & Rubin-Delanchy 2018, via Birnbaum 1954).

| level | alternative | combiner |
|---|---|---|
| events within one track, one (entity, hour) | **one** event is bad among many | **Tippett** (min-p + Šidák) |
| the two tracks | **one** track fires strongly | **Tippett** |
| an entity's windows | best window among many tested | **Šidák** |
| entities | control the triage queue | **budget**, or Benjamini-Hochberg |

Tippett at the within-track level is load-bearing: one severe event among 500
benign ones in the same hour must not dilute below significance.

Tippett at the cross-track level makes an entity exactly as suspicious as its
single most anomalous track. This is the right test because an intrusion typically
trips one detector strongly — a relational anomaly *or* a volume shift — which is
the one-among-k alternative. Fisher, which rewards several moderate p-values, is
the wrong test here: under a fixed alert budget it lets a busy-but-benign entity's
ordinary variation combine into false significance and displace a real single-track
detection.

Šidák over an entity's windows: a minimum over n windows *is* a test over n
windows. Without it the frequency bias reappears one level up — any entity observed
long enough eventually looks significant.

## 5. Rigorous FDR alerts on nothing — and that's real

`alert_mode="fdr"` is implemented. At any sane FDR it alerts on **zero** entities,
and this is not tunable away: the null is floored at `1/(n_benign+1) ≈ 2.5e-5`,
while ~250 entities × 192 hours × ~20 events ≈ 10⁶ tests need p ≈ 1e-8 to survive
correction. Single-event evidence is three orders of magnitude short. This is why
no commercial UEBA product alerts on corrected p-values — they ship risk scores,
which are uncorrected rankings.

We ship the ranking too. The difference: we call it a ranking and operate it as a
budget. The p-values still do the work — a calibrated, non-saturating ranking
across incommensurable detectors. Absolute significance is not attainable at this
null-sample size.

## 6. Entity space and state

Every track scores accounts. `graph/sessions.py` resolves host-scoped Sysmon
telemetry to the account logged on at that time, so all scoring lives in one entity
space. `score()` is pure; `observe()` is the explicit online path; `score_stream()`
opts in — a live stream should adapt, batch scoring must be reproducible.

## 7. The knobs

`alert_budget_per_day` is the only alerting knob and means what it says: the N most
significant entities per day.

`alpha = 1.0` (Dirichlet concentration) is an uninformative default, deliberately
not swept against the benchmark — tuning priors against a self-generated fixture is
curve-fitting.

## 8. What this model does not do

- **Detect what leaves no relational or volume trace.** Account manipulation is
  weak and NTDS extraction is missed, because the discriminating signal is
  directory context (a Tier-0 watchlist) or a command line, not a novel
  relationship. See [BENCHMARK.md](BENCHMARK.md).
- **Generalise beyond a simulator.** The FP numbers are a floor; nothing is
  validated against real authentication data.
