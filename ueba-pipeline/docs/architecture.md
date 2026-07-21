# Architecture

## Pipeline

```
log files / Kafka
      |
      v
  parsing/normalize.py ......... channel+EventID -> exact event_type, typed fields
  graph/sessions.py ............ 4624 logons -> causal host->account resolution
      |
      v
  features/manifest.py ......... which feature groups this estate can support
  features/aggregate.py ........ per (entity, hour) behavioural count vectors
      |
      v
  graph/auth_graph_anomaly.py .. edge surprise per view (Dirichlet, nats)
      |
      v
  models/pvalue.py ............. ONE frozen null PER VIEW -> calibrated p-value
      |
      v
  models/fisher.py
        Tippett  across the views an event fires
        Šidák    over the windows an entity was tested in
        budget / BH  across entities
      |
      v
  ranked entity alerts
```

## Everything is a p-value

Each detector emits the upper-tail probability of its raw statistic under a benign
null frozen at fit time, before anything is combined. This follows Rubin-Delanchy,
Lawson & Heard (*Anomaly detection for cyber security applications*, 2016).

The reason is structural, not aesthetic. Detectors on different scales cannot be
combined by rescaling each with a constant: the constants have no common meaning,
cannot be validated independently, and their composition is untestable. A p of
1e-4 means the same thing whichever detector produced it.

p-values are uniform under the null only if train and live data are exchangeable.
Estates drift, so the realised false-positive rate exceeds the nominal alpha — and
the size of that gap is a direct measurement of distribution shift.

## How the null is calibrated (the load-bearing detail)

The null must answer: *what surprise does a benign event produce when scored
against the deployed, frozen baseline?* Two properties are required, and both are
easy to get wrong:

**Held out.** The baseline is learnt from the earlier part of the training period;
each view's null is then measured on a **later held-out slice** scored against that
frozen baseline (`absorb=False`) — exactly the situation a live benign event meets.
Folding all training data into the baseline and then scoring that same data marks
every training edge "already seen", so it scores ≈0 and the null contains no
benign-novelty mass at all. A detector calibrated that way treats *any* first
contact as extreme. That is a calibration leak, and a fixture with static IPs hides
it while a real estate (DHCP, VDI, roaming laptops, new shares) exposes it as a
flood of false positives. The held-out slice is folded into the deployed baseline
afterwards, so the null is calibrated against a slightly smaller baseline than the
one deployed — conservative, never optimistic.

**Per view.** Each relationship type gets its own null. Views differ enormously in
their benign baseline: `proc_access` sits near 5.5 nats for ordinary traffic
(its reverse conditional is high for every common target) while `user_src` sits
near 0.3. One pooled null lets the high-baseline, high-volume views set the
significance bar for the low-baseline ones. Per-view calibration also means the
engine reports each view's **benign novelty rate** at fit — the measurable property
that decides whether a relationship type carries signal at all (a view whose benign
edges are routinely novel cannot separate a first contact from an attack, however
it is calibrated).

## Combination: which combiner, and why

| level | tests | combiner | reason |
|---|---|---|---|
| across the views one event fires | few, expect **one** to be anomalous | **Tippett** (min-p + Šidák) | each view is already calibrated against its own null; the event is as suspicious as its most anomalous relationship |
| within one (entity, hour) | many, homogeneous, expect **one** bad | **Tippett** (min-p + Šidák) | a single severe event among many benign ones in the same hour must not be diluted |
| across an entity's windows | many | **Šidák** | a minimum over n windows *is* a test over n windows; uncorrected, any entity observed long enough looks significant |
| across entities | many | **budget** or Benjamini-Hochberg | the analyst operates a fixed triage queue |

Combiner selection follows Heard & Rubin-Delanchy (Biometrika 105(1), 2018), which
shows via Birnbaum (1954) that every reasonable combiner is optimal against *some*
alternative — so the choice is made per level, against the alternative that level
faces. Both the per-view and the within-hour level face a one-anomaly-among-k
alternative, so both use Tippett. Fisher (few-small-among-many) is the wrong test
here: it rewards several moderate p-values, which under a fixed alert budget lets a
busy-but-benign entity's ordinary variation combine into false significance and
displace a real detection.

**Do not replace this with noisy-OR and decay.** Solving that recursion at a 24h
halflife, any entity with a recurring per-hour risk ≥ 0.15 crosses an 0.85
threshold within a day regardless of severity: it surfaces whichever accounts are
busiest, and it saturates so nothing ranks. The Šidák/Tippett path inverts this:
an entity's significance is its single most anomalous window, corrected for how
many windows it was tested in, so more observation cannot manufacture significance.

## The detector — has this principal reached, or done, something it shouldn't?

```
surprise = max( −log P(dst | src), −log P(src | dst) )
P(b | a) = (c_ab + α·π_b) / (n_a + α)
```

Dirichlet-multinomial back-off to the global marginal, learnt per estate from
counters: O(1) update, streaming, no retraining.

- novel edge to a **popular** destination → low surprise (routine churn)
- novel edge to a **rare** destination → high surprise
- novel edge from a **highly active** source → higher surprise: it had many
  opportunities and never took them, so the absence is evidence
- **cold start** → ~0 surprise: nothing is surprising without evidence
- a **seen** edge decays smoothly toward 0 — continuous and rankable

Both conditional directions are required. Conditioning only on the source is blind
to "was this destination reached by someone new?", the entire signal for
`proc_access`: where only `wininit.exe` opens `lsass.exe`, π(lsass) ≈ 1 and
`rundll32.exe` opening lsass scores 0.0 forward. The reverse conditional catches
it. The full set of views is documented in [graph.md](graph.md).

## Entity space

All scoring is over **accounts**. Host-scoped telemetry (Sysmon
ProcessAccess/ProcessCreate) names a host and an image but no user;
`graph/sessions.py` resolves it to the account logged on at that time, causally,
from 4624 events. This keeps all telemetry in one entity space, which the
entity-level ranking requires. Unresolved events keep the host — a process opening lsass on a
host nobody is logged into is not less interesting, it is just not yet an identity.

## State contract

`score()` is **pure**: it does not mutate the detector, so re-scoring the same
events always gives the same answer and a re-run after a crash cannot under-report.
Online adaptation is an explicit separate call, `observe()`; `score_stream()` opts
into it deliberately — a live stream should adapt while batch scoring must be
reproducible.

Persistence is a non-executable, schema-explicit bundle (versioned JSON plus
`allow_pickle=False` NumPy arrays), HMAC-SHA256-signed over the whole bundle and
integrity-verified before any file is parsed — loading never executes bundle
content. An empty signing key is refused rather than degraded. See
`models/serialization.py`.

## Identity graph (separate concern)

`graph/identity_graph.py` computes structural risk — Tier-0 proximity, attack
paths, blast radius — for visualisation and prioritisation. It is **not** fused
into detection scoring. If it ever should be, the way in is as an additional
calibrated p-value, benchmarked separately and kept only if it earns its place. This is the
natural home for the directory context (a Tier-0 watchlist) that a privileged-group
change needs to be reliably distinguished from routine group management.

Computed with NetworkX on a rolling snapshot rather than per event, so it only
has to finish inside the retrain window: at this scale (a few hundred to a few
thousand nodes) the full five-metric pass completes in well under a second.

## Extension paths (not implemented)

- **Real-world validation** against LANL 2015 or OpTC. The blocker for any external
  performance claim; `lanl-eval` is the harness.
- **Learned temporal graph models.** The strongest published results on LANL
  lateral movement come from temporal link prediction over snapshots of the
  authentication graph — Euler (King & Huang, ACM TOPS 2023) reports AUC 0.91–0.98,
  and later temporal-graph work reports higher still, against ~0.85 TPR @ 0.9% FPR
  for unsupervised graph learning of the kind this engine implements. A learned
  model captures what a memoryless per-edge conditional cannot: how an entity's
  neighbourhood *evolves*, and structural context beyond the pairwise relation.
  This is the documented upgrade, deliberately not attempted here: it needs a deep
  learning runtime, and it needs real labelled data to train and validate against —
  fitting a temporal GNN to a synthetic 253-employee estate would measure the
  simulator, not the method, and would trade away the per-edge explainability an
  analyst triages on. Take this path once real data exists, and benchmark it as its
  own track against the harness in `evaluation/`.
- **Command-line / execution-sequence features** for NTDS-style extraction, whose
  tools run legitimately on domain controllers and so leave no novel relational
  trace.
- **Structural risk as a calibrated additional track**, carrying the Tier-0 context
  that privileged-group-change detection needs.
- **Multi-tenancy, RBAC, an API.** The product is a CLI.
