# Graphs

Two distinct things in this codebase are called "graph". They serve different
purposes and must be kept apart.

## 1. Authentication graph — detection (`graph/auth_graph_anomaly.py`)

An online edge-anomaly scorer and the engine's primary detector. Each normalized
event is projected onto one or more `(view, (src, dst))` edges, and every edge is
scored for surprise under a Dirichlet-smoothed model of the estate's learned
access distribution:

```
surprise = max( −log P(dst | src), −log P(src | dst) )
P(b | a) = (c_ab + α·π_b) / (n_a + α)
```

where `π_b` is the global marginal for `b` in that view. Counters only: O(1)
update per event, streaming-safe, no retraining. State after 253 employees ×
20 days is ~0.2 MB.

The score is **graded surprise in nats**, not a novelty flag:

| situation | surprise | rationale |
|---|---|---|
| novel edge → popular destination | low | routine churn — everyone eventually reaches the DC, a file server, the egress IP |
| novel edge → rare destination | high | a genuine first contact |
| novel edge from a highly active source | higher | many opportunities, never taken — the absence is evidence |
| cold start (no baseline) | ~0 | nothing is surprising without evidence |
| a seen edge | decays smoothly to 0 | continuous and rankable, no cliff |

A single threshold can separate routine churn from a real first contact only
because the score is graded — a constant "novelty score" produces two values, and
no threshold separates two values.

### Views

Every view is scored by the identical conditional. There are **no per-view
scoring gates** — no view is special-cased as "burst-only" or "established
principals only". The model expresses natively what such gates would hand-code: a
new principal backs off to the global marginal and is unsurprising; a novel edge
to a popular destination scores low. If detecting each technique required a new
gate, the engine would be a rule catalogue wearing a model's clothes.

| view | edge `(src → dst)` | source events |
|---|---|---|
| `user_src` | account → source host/IP | 4624/4625 remote logons (type 3/10) |
| `src_dst` | source host → destination host | 4624/4625 remote logons |
| `kerb_ctx` | account → TGT encryption\|pre-auth context | 4768 |
| `tgs_enc` | account → service-ticket encryption type | 4769 |
| `proc_access` | `host\|source-image` → target-image | Sysmon 10 (ProcessAccess) |
| `rare_proc` | host → image (image on ≤ `RARE_PROC_MAX_HOSTS` baseline hosts) | Sysmon 1 |
| `dir_change` | actor → `group:`/`adobj:`/`attr:` | 4728/4732/4756, 4662, 5136 |

`tgs_enc` keys on the ticket **encryption type** (a handful of values), not the
service name: keying on the SPN floods the model with benign service diversity;
the low-cardinality cipher is the generalized ticket-downgrade signal.

`dir_change` projects directory operations onto `(actor → object)` edges — a
group-membership add, an AD object access, an attribute modification — attributed
to the acting principal (`SubjectUserName`), with machine accounts excluded. A
first-ever add to a rarely-touched group, or a non-machine account touching the
directory-replication object, is a novel edge to a rare destination.

`RARE_PROC_MAX_HOSTS` is a *projection* filter, not a scoring gate: it bounds
which process-create events become edges at all, keeping the highest-volume
stream tractable.

### Why both conditional directions

Conditioning only on the source answers "did this principal go somewhere new?" —
right for `user_src`, blind for `proc_access`. Where only `wininit.exe` opens
`lsass.exe`, π(lsass) ≈ 1, so `rundll32.exe` opening lsass scores **0.0** under
the forward conditional: the model reasons "lsass is what things open". The
reverse conditional catches it — lsass has only ever been opened by wininit.
Taking `max` of the two keeps each view's informative direction without
hand-assigning one per view.

### MIDAS burst

A microcluster term (Bhatia et al., AAAI 2020) added on top of surprise: many
occurrences of one edge within a single tick, measured against that edge's normal
active-hour rate. This is what surfaces fan-out and rapid credential reuse
(password spray, a Kerberoasting sweep) that a single novel edge would understate.

MIDAS-F non-absorption (Bhatia et al., TKDD 2022): an edge scoring above
`absorb_surprise` is not folded into the baseline, so an attacker cannot launder
repeated abuse into normality. Surprise is unbounded above, so the threshold is
reachable by construction.

## 2. Identity graph — structure (`graph/identity_graph.py`)

Tier-0 reasoning, attack paths, blast radius, visualisation. **Not fused into
detection scoring** — no code path multiplies a behavioural p-value by a
structural risk. It answers a question behaviour cannot: an account that has done
nothing unusual may still be one hop from a Tier-0 asset.

Composite risk is a weighted sum of Tier-0 proximity (0.40), betweenness (0.25),
PageRank (0.20), and degree (0.15), validated to sum to 1.0. Greedy modularity
assigns a community id for visual grouping; it does not feed the composite. These
weights are asserted, not fitted — defensible here because nothing downstream
consumes them but a visualisation, so a wrong weight misorders a display rather
than silently killing an alert path.

**Pass `--directory`, or the score is not what it claims.** Without it the roster
carries no Tier-0 designation, `n_tier0_assets = 0`, and the largest-weighted
term is constant zero for every entity — the composite degrades to a centrality
blend that no longer sums to 1 while still reading as a blast-radius ranking. The
simulator emits `directory.json` for exactly this; supply the equivalent for a
real estate.

If structural risk is ever fused into detection, the way in is as a fourth
calibrated p-value, benchmarked as its own track and kept only if it earns its
place — the standard every detection component is held to.

Backend: NetworkX in-memory by default (a few thousand nodes, snapshot recompute
under a second). Memgraph via Bolt for scale-out. Betweenness falls back to pivot
sampling (Brandes & Pich, 2007) above `betweenness_exact_max_nodes`, since exact
Brandes is O(V·E) and unusable past ~10k nodes.
