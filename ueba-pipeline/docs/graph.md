# Graphs

Two different things in this codebase are called a "graph". They serve opposite
purposes, run on different data, and must never be confused. This document explains
both from first principles, then in full detail.

| | **authentication graph** | **identity graph** |
|---|---|---|
| file | `graph/auth_graph_anomaly.py` | `graph/identity_graph.py` |
| purpose | **detection** — the shipped detector | **analyst tooling** — visualisation & prioritisation |
| built from | the live *event stream* | directory *state* (a roster + AD/LDAP/IDP metadata) |
| updated | per event, online (O(1)) | on a rolling snapshot, per retrain |
| answers | "did this principal reach or do something improbable?" | "if this account were compromised, how much would fall?" |
| feeds an alert? | **yes** — it is the alert | **no** — it multiplies no score |

> **Beginner's mental model.** The *authentication* graph watches who-talks-to-what
> as events stream in and flags a relationship the estate has never (or rarely)
> seen. The *identity* graph is a static map of who-can-reach-what in the directory,
> used to tell an analyst which accounts are dangerous to lose — independent of
> whether they have done anything yet.

---

# Part 1 — Authentication graph (detection)

`graph/auth_graph_anomaly.py`. This is the engine's **primary and only** detector.
The signal is a *relationship*, not a per-entity feature histogram: lateral movement,
credential-forgery reuse, credential-store access, ticket downgrade and directory
change all show up as an edge the estate's learned access distribution finds
improbable.

## 1.1 The idea: graded edge surprise

Each normalized event is projected onto one or more directed edges `(src → dst)`
within a named **view** (§1.3). Every edge is scored for *surprise* — how improbable
that relationship is under what the estate has learned — in **nats** (natural-log
units), not as a yes/no novelty flag:

```
surprise = max( −log P(dst | src), −log P(src | dst) )
P(b | a) = (c_ab + α·π_b) / (n_a + α)
```

Read `P(dst | src)` as "given traffic from `src`, how expected is `dst`". It is a
**Dirichlet-multinomial** estimate — plain event counts with a smoothing term that
backs off to the global popularity `π_b` of the destination:

- `c_ab` = times this exact edge was seen; `n_a` = times `src` appeared at all.
- `π_b` = how popular `dst` is estate-wide (its global marginal, Laplace-smoothed).
- `α` = 1.0, the Dirichlet concentration — an uninformative default (§1.6).

Why this specific form produces the right behaviour, with no per-technique tuning:

| situation | surprise | why it is right |
|---|---|---|
| novel edge → **popular** destination | low | routine churn — everyone eventually reaches the DC, a file server, the egress IP |
| novel edge → **rare** destination | high | a genuine first contact |
| novel edge from a **highly active** source | higher | many opportunities, never taken — the *absence* is evidence |
| **cold start** (no baseline) | ~0 | with no history `π=1`, surprise=0 — nothing is surprising without evidence, so a brand-new account's first edge does not alert |
| a **seen** edge | decays smoothly toward 0 | continuous and rankable, no cliff |

That the score is *graded* (a wide range of nats) rather than a constant "novelty
score" (two values) is what lets a single threshold separate routine churn from a
real first contact.

## 1.2 Why both conditional directions

The `max` of two conditionals is load-bearing. Conditioning only on the source
answers "did this principal go somewhere new?" — right for a user→host logon, but
**blind** to "was this destination reached by someone new?", which is the entire
`proc_access` signal. Where only `wininit.exe` normally opens `lsass.exe`,
`π(lsass) ≈ 1`, so `rundll32.exe` opening lsass scores **0.0** under the forward
conditional ("lsass is what things open"). The *reverse* conditional catches it:
lsass has only ever been opened by wininit, so a new opener is extreme. Taking the
max keeps each view's informative direction without hand-assigning one per view.

## 1.3 The relationship views

A **view** is one way of projecting events onto edges. Every view is scored by the
**identical** conditional above — there are **no per-view scoring gates** (no view is
special-cased as "burst-only" or "established-principals-only"). If detecting each
technique needed its own gate, the engine would be a rule catalogue wearing a model's
clothes.

| view | edge `(src → dst)` | source events | catches |
|---|---|---|---|
| `user_src` | account → source host/IP | 4624/4625 remote logons (type 3/10) | PtH / forged-ticket reuse from an attacker foothold |
| `kerb_ctx` | account → TGT encryption\|pre-auth context | 4768 | AS-REP roasting, RC4 downgrade on the TGT |
| `tgs_enc` | account → service-ticket encryption type | 4769 | Kerberoasting / RC4 service-ticket downgrade |
| `proc_access` | `host\|source-image` → target-image | Sysmon 10 (ProcessAccess) | credential-store (lsass/ntds) dumping |
| `dir_op` | actor → operation class | 4728/4732/4756, 4720/4726, 4662, 5136 | DCSync, privileged-group and account-lifecycle abuse |
| `share` | actor → file share | 5140/5145 (network share access) | insider scope abuse: reading a share the account has never touched |

Three design decisions inside the views are worth understanding, because each is the
difference between signal and noise, and each was made on measured *benign novelty
rate* — the fraction of benign edges that are novel, which decides whether novelty
can mean anything at all in that view:

- **`user_src` keys on the device, not the IP.** Keyed on IP, ~92% of benign logons
  look like first contacts (DHCP, VPN pools, Wi-Fi vs wired), and the view is pure
  noise. Keyed on the workstation/device identity, benign novelty drops to ~4%.
- **`share` keys on the share, not the file.** Routine share access is
  department-keyed, so an account touches a mean of **1.00** distinct shares across
  a 20-day estate and a second one is maximally surprising. Keyed on the individual
  file (`RelativeTargetName`) the destination space would be near-unique per event
  and novelty would mean nothing — the same failure `dir_op` avoids by keying on
  the operation rather than the object.
- **`tgs_enc` keys on the encryption type, not the SPN.** Users legitimately reach
  many services, so `(user, SPN)` novelty fires on benign churn (it collapsed graph
  recall from 43/60 to 1/60 when measured). The low-cardinality cipher is the
  generalized ticket-downgrade signal; a machine SPN is excluded.
- **`dir_op` keys on the operation class, not the object.** Keyed on the object
  touched, ~72% of an admin's benign access-request work is novel; keyed on the
  coarse operation class (`groupadd`, `adobjaccess`, …), ~5–9%. The signal is then
  carried by the reverse conditional — a directory operation only a few admins ever
  perform gives a regular account a tiny `P(actor | operation)` and high surprise —
  with no allow/deny list, Tier-0 label, or attack-specific branch. Extending
  directory coverage is a row in `DIR_OP_CLASS`, not new logic.

`AuthGraphConfig.enabled_views` can **restrict** scoring to a subset of the five
implemented views (this is how `scripts/ablate_graph_views.py` measures each view's
contribution, dropping one at a time). It can only select among views the projector
actually emits; a view that was removed from `edges_for` (§1.7) is gone from the
projection, not merely deselected.

## 1.4 From host-scoped events to identities (session resolution)

`proc_access` edges come from Sysmon, which names a host and an image but **no user**.
This is an *identity* product — an analyst triages an account — so `graph/sessions.py`
resolves each host-scoped event to the account logged on at that time.

`SessionResolver.fit` indexes every session-*binding* logon (4624 of type 2 console,
7 unlock, 10 RDP, 11 cached — **not** type 3 network or 5 service, which do not make
you the owner of a host's processes). `resolve(host, when)` binary-searches for the
most recent binding logon at or before `when`, within a `session_ttl_hours` window
(default 12 h). It is built **fresh from each batch** and holds no cross-call state,
so scoring stays a pure function of its input; a stale session map carried from
training would silently misattribute months later. Unresolved events keep the host as
the entity — a process opening lsass on a host nobody is logged into is not less
interesting, it is just not yet an identity. *Stated limit:* multi-user hosts
(RDS/Citrix) bind to the most recent logon (a coin flip); resolving that needs
4634/4647 logoff correlation the simulator cannot yet validate against.

## 1.5 MIDAS-F non-absorption (what remains of a removed burst term)

A MIDAS-style burst term (extra surprise for repeated occurrences of one edge within
a window; Bhatia et al., AAAI 2020) was measured against this model and **removed** —
it cost ten detections and 0.7 false-positive entities a day, because benign
repetition is ordinary and a raw repeat count fires on it ([evaluation.md](evaluation.md)).
Its per-tick counters and time-resolution scaffolding were removed with it.

What remains is the **non-absorption rule** (MIDAS-F, Bhatia et al., TKDD 2022): on
the streaming `absorb=True` path an edge scoring above `absorb_surprise` (12.0 nats)
is *not* folded into the baseline, so an attacker cannot launder repeated abuse into
normality by simply repeating it. Surprise is unbounded above, so the threshold is
reachable by construction. Batch `score()` never absorbs, so this rule governs the
streaming path only.

## 1.6 State, calibration, and cost

- **State.** Per view: plain integer-ish counters — per-edge counts (`_edges`),
  per-source and per-destination totals, and a per-view total. All O(1) to update,
  streaming-safe, no retraining. After 253 employees × 20 days the whole detector is
  ~0.2 MB.
- **Calibration to a p-value.** Raw surprise in nats is not comparable across views
  (`proc_access` sits near 5.5 nats for ordinary traffic, `user_src` near 0.3), so
  each view's surprise is turned into a **calibrated p-value against that view's own
  benign null, frozen on a held-out slice at fit time**. This is the load-bearing
  step; it lives in the engine and `models/pvalue.py` and is documented in
  [detection.md](detection.md). Per-view calibration is why the engine can report
  each view's *benign novelty rate* at train time — the number that decides whether a
  relationship type carries signal at all.
- **`α = 1.0`** is the one modelling constant, and it is an uninformative Dirichlet
  default, deliberately not swept against the benchmark (tuning a prior against a
  self-generated fixture is curve-fitting, not calibration; the sweep in
  [evaluation.md](evaluation.md) confirms it sits on a flat plateau).
- **Scale.** Distinct edges grow *linearly* with identities (each identity has a
  bounded working set, not access to everything), so state and latency are flat in
  the estate size; [evaluation.md](evaluation.md) measures it to ~2,000 identities and
  extrapolates count-min sketching (MIDAS's mechanism) as the fallback if exact
  counters ever break memory.

## 1.7 Views that were removed, and why adding views usually hurts

Two views were dropped after `scripts/ablate_graph_views.py` measured their
contribution across six seeds; both removals **raised** recall and **lowered** false
positives:

- **`src_dst`** (source host → destination host) read the same 4624 events as
  `user_src` and was strongly correlated with it — capable alone (29/60) but redundant
  in combination; dropping it gained 5 detections. Its projection was **removed** from
  `edges_for`. It would be the richest relation for a deployment with no usable device
  identity (a flat auth log, e.g. LANL, where host-to-host is all there is — the
  setting Bowman et al. (RAID 2020) operate in); serving that estate means
  reintroducing the projection, not flipping a config flag.
- **`rare_proc`** (host → rarely-seen image) detected nothing in any configuration
  across two estate revisions (0/60 standalone). A view that never contributes a
  detection cannot justify the correction it costs.

Two further views were **built and left disabled**, and the distinction matters:
they were rejected on *this estate*, not on the idea.

- **`reg`** (account → registry location class, Sysmon 12/13) is the worst view ever
  measured here: it takes the headline from 54/60 to **40/60**, destroying
  Kerberoasting (−7) and AS-REP roasting (−5). The mechanism is not mysterious. An
  account touches a mean of **3.98 of the 4** registry classes this estate produces,
  so the view is a near-constant that can never fire — while carrying the highest
  event volume of any candidate (39.7 events per account), inflating every Šidák
  correction and every Tippett minimum it appears in.
- **`pipe`** (account → named pipe, Sysmon 17/18). Once the simulator gained
  per-identity software profiles — dropping its benign novelty from 11.0% to
  4.9% — this went from detecting nothing to **5/6 standalone** on a PsExec
  corpus. The view was never the problem; the estate was. It still cannot join
  the relational queue (six headline detections lost to recover two) and cannot
  share the execution queue with `proc_exec` (which displaces it 3/6 → 0/6), so
  it has a queue of its own — `PIPE_VIEWS`, its own budget and its own calibrated
  null. It is the fifth queue, and the seventh time this engine has resolved a
  displacement the same way.

**Both destination counts are simulator artifacts, and that is the finding.** A real
Windows estate produces hundreds of registry locations and pipe names; a Cobalt
Strike or PsExec pipe is novel by construction, which is exactly what `pipe` is built
to see and exactly what published named-pipe detection uses a hard-coded name list to
approximate. This corpus cannot exercise either view, so both stay in `edges_for`
behind `enabled_views` awaiting a simulator with realistic registry and pipe
diversity and a pipe-based lateral-movement attack — not deleted on a measurement
their input could not have passed.

This points at the single most important constraint on the whole detector, and it is
counter-intuitive: **adding a view usually lowers product recall, even when the view
measures well alone.** Detection combines by *Tippett* (the minimum p-value) under a
*shared alert budget*, and every view that fires on an event adds a Šidák test to that
cell. Šidák assumes independence, so two views derived from the same event are
penalised twice — once for adding no independent evidence, and again for inflating the
correction on the view that did. A view is therefore net-positive only if it is
*strictly more specific* than what it displaces. This has been confirmed three times
(`src_dst`, a per-entity volume signal, and a process-lineage view all measured well
alone and degraded the product). The corollary: a low benign-novelty rate is
*necessary but not sufficient* to admit a view. See [evaluation.md](evaluation.md) for
the full per-view ablation table.

---

# Part 2 — Identity graph (structure)

`graph/identity_graph.py`. This is **analyst tooling, not detection.** It answers a
question behaviour cannot: an account that has done nothing unusual may still be one
hop from a Tier-0 asset. Its only consumer is the `graph-viz` CLI, which renders the
graph and its scores to a single self-contained HTML file.

"Self-contained" is enforced, not asserted: the force-directed layout is a
vendored script (`graph/assets/minigraph.js`) inlined into the output, and a test
fails on any `src`, `href`, `@import`, or `fetch` pointing at a URL. It previously
loaded D3 from a CDN, which meant the file rendered blank on an air-gapped host
and a security product pulled an unpinned third-party script every time an analyst
opened its own output. The replacement implements only the four forces that were
configured, following the published d3-force 3.0.0 algorithm; measured against
real D3 on the same 200-node graph it reproduces the layout to a
pairwise-distance correlation of 0.9999 and a median-distance ratio of 0.998.

**It is not part of any alert.** No code path multiplies a behavioural p-value by a
structural risk. If structural risk is ever fused into scoring, the honest way in is
as a *fourth calibrated p-value* through `models/pvalue.py`, benchmarked as its own
track and kept only if it earns its place — the standard every detection component is
held to. This is the natural home for the Tier-0 directory context that
privileged-group-change detection would need.

## 2.1 What it is built from

Directory **state**, via `load_from_roster`: a roster (`user → department`) plus
optional admin accounts, service accounts, servers and domain controllers. Real
deployments load the same shape from AD/LDAP/IDP directory APIs; the simulator emits
it as `directory.json` / `roster.json`. It is deliberately **not** built from the live
event stream — structural risk is a property of the directory, recomputed on a rolling
snapshot, not per event.

## 2.2 Node and edge schema

| node type | examples |
|---|---|
| `user` | human accounts, admin accounts (tiered) |
| `group` | department groups, tiered admin groups |
| `computer` | workstations, servers, domain controllers |
| `service_account` | non-human identities bound to the servers they run on |
| `application` | application identities |

| edge type | meaning |
|---|---|
| `member_of` | user → group |
| `manages` | admin account → the real user it belongs to (credential-exposure path) |
| `can_access` | group → share, service account → server, Tier-0 admin group → DC |
| `owns`, `delegated_to` | ownership / delegation relationships |

The shape follows Microsoft's **AD Administrative Tier Model**: department groups for
horizontal structure, tiered admin groups (T0/T1/T2) for privilege, service accounts
bound to servers, and DCs / Tier-0 servers as the crown-jewel targets that
shortest-path-to-Tier-0 measures blast radius against. The admin→real-user
`manages` edge is what makes the credential-theft lateral-movement path visible:
compromising a user's session can expose the admin credential that user holds.

## 2.3 Tier-0: the anchor of blast radius

Control of any **Tier-0** asset is equivalent to control of the domain, so Tier-0
nodes anchor the attack-path analysis. Following Microsoft's tier model and the
SpecterOps Tier Zero Table, Tier-0 is **not only** the privileged directory groups
(Domain/Enterprise/Schema Admins, Administrators, Account/Backup/Server/Print
Operators, Group Policy Creator Owners) **but also** assets that grant *indirect*
control of the directory: domain controllers, backup infrastructure (a DC backup
contains every password hash), systems-management servers that can push code to DCs
(SCCM), and PKI/ADCS/ADFS. Classifying these as Tier-0 is what lets
shortest-path-to-Tier-0 reflect real domain-takeover paths rather than only group
membership.

> **Pass `--directory`, or the score is not what it claims.** With `graph-viz --roster
> X` alone, the roster carries no Tier-0 designation, so `n_tier0_assets = 0`, the
> largest-weighted term (Tier-0 proximity, 0.40) is a constant zero for every entity,
> and the composite silently degrades to a centrality blend that no longer sums to 1
> while still reading as a blast-radius ranking. The simulator emits `directory.json`
> for exactly this; supply the equivalent for a real estate.

## 2.4 The five structural metrics and the composite

For every node the graph computes five metrics (on an undirected projection for the
centralities — a group "connects" its members bidirectionally):

1. **Hops to nearest Tier-0** — blast radius. Found with a **single multi-source BFS**
   seeded from *all* Tier-0 nodes at once, so every node's distance to its nearest
   Tier-0 asset is computed in one O(V+E) pass rather than a per-node search.
2. **Betweenness centrality** — choke points that bridge otherwise separate groups
   (lateral-movement enablers).
3. **PageRank** — influence disproportionate to raw group membership.
4. **Degree centrality** — breadth of direct access.
5. **Community id** (Louvain, falling back to greedy modularity) — for **visual
   grouping only**; it does not feed the composite.

The **composite risk** (∈[0,1]) is a weighted sum, weights from
`IdentityGraphConfig`, validated to sum to 1.0:

```
composite = 0.40·tier0_proximity + 0.25·betweenness + 0.20·pagerank + 0.15·degree
```

where `tier0_proximity` is an exponential decay of the hop count (1 hop → 1.0, 2 → 0.5,
3 → 0.25, …), so being adjacent to a crown jewel dominates. **These weights are
asserted, not fitted** — defensible precisely because nothing downstream consumes them
but a visualisation, so a wrong weight misorders a display rather than silently killing
an alert. Do not promote them into scoring without calibrating them first.

## 2.5 Backend and scale

NetworkX, in-memory, recomputed on a snapshot (so it only has to finish inside the
retrain window; at a few hundred to a few thousand nodes the full five-metric pass is
well under a second). Two metrics are the scale bottlenecks, and both have measured
fallbacks:

- **Betweenness** is exact Brandes (O(V·E)) below `betweenness_exact_max_nodes`
  (1,500), and switches to **pivot-sampled** betweenness (Brandes & Pich 2007, `k`=300
  pivots) above it — measured ~50× faster at 10k nodes (4.6 s vs 227 s) with the
  high-centrality rank order preserved. The seed is fixed for reproducibility.
- **Community detection** uses **Louvain** where available (~9× faster than greedy
  modularity at 10k nodes), falling back to greedy modularity, then to "no
  communities".

Analysis patterns follow **BloodHound Enterprise** (shortest path to Tier-0, exposure
scoring) and **Cartography** (declarative node/edge schema), implemented over NetworkX
rather than Neo4j.

---

## References

- Bowman et al. *Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI.* RAID 2020. (edge-novelty of lateral movement; the `user_src`/`src_dst` lineage.)
- Turcotte, Moore, Heard & McPhall. *Poisson factorization for peer-based anomaly detection.* IEEE ISI 2016. (the Bayesian family the Dirichlet conditional belongs to.)
- Bhatia et al. *MIDAS: Microcluster-Based Detector of Anomalies in Edge Streams.* AAAI 2020; *Real-Time Anomaly Detection in Edge Streams (MIDAS-F).* TKDD 2022. (the burst term measured and removed; the non-absorption rule retained.)
- Brandes & Pich. *Centrality Estimation in Large Networks.* 2007. (pivot-sampled betweenness.)
- Blondel et al. *Fast unfolding of communities in large networks (Louvain).* 2008.
- Microsoft. *Securing privileged access — AD Administrative Tier Model.* · SpecterOps *Tier Zero Table.* · *BloodHound Enterprise* · *Cartography.* (the identity-graph schema and Tier-0 definition.)
- Companion docs: [architecture.md](architecture.md) (pipeline), [detection.md](detection.md) (p-value calibration and combination), [evaluation.md](evaluation.md) (per-view ablation, benign novelty, scale), [features.md](features.md) (the non-relational feature layer).
