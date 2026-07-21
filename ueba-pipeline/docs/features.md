# Feature layer

## Capability manifest (`features/manifest.py`)

The manifest records which feature groups an estate can actually support. It is
built by scanning ingested data, not assumed from a static list: a
`(channel, EventID)` pair must both have a canonical field mapping **and** its
group must reach `min_events_for_capability` events in the bootstrap window
before the group is enabled. Groups whose signal is rare by design (Defender
verdicts, DCSync, privileged group changes) are admitted on any non-zero count
via `presence_gated_groups`.

**The gate is an absolute event-count floor, deliberately not a fraction of total
events.** A fraction-of-total gate fails in two ways that matter here. First, it
*couples unrelated sources*: a high-volume source (Sysmon process creation, DNS)
inflates the denominator, so a legitimately-present but lower-volume source
(Kerberos, failed logons) can fall below the bar purely because something else is
noisy — two independent log sources should not gate each other. Second, it is
*unstable on a small or rolling training window*: the fraction of any event type
varies run to run, so a group flips on and off between retrains from sampling
noise alone, and every flip changes the feature order and needlessly invalidates
the model. An absolute floor decides each source on its own count, is stable
across window sizes, and still rejects a single stray event left over from a
decommissioned pilot install. (A distinct-host floor was considered and rejected:
authentication, Kerberos and directory events legitimately concentrate on one or
two domain controllers, so requiring multiple hosts would wrongly exclude them.)

A group is only claimed for events the parser can actually extract fields from,
so an unmapped event stream cannot mark a group "available" and then feed all-zero
vectors into the model. The manifest is pinned at fit time and reused for scoring,
so a live batch missing a log source cannot silently zero-fill against the trained
feature order — it degrades honestly, and `drift-check` reports the change.

This is what makes partial telemetry correct rather than quietly wrong, and how
the engine adapts to whatever a given estate ships.

## Behavioural features (`features/aggregate.py`)

Per `(entity, hour)` count vectors, with cross-entity aggregation where the signal
requires it. Password spray is a *cross-user* pattern — one source IP failing
against many accounts — so a per-user `f_spray_max_targets_per_ip` is structurally
≤ 1. Fan-out is aggregated per `(source_ip, window)` across all users, then
attributed back onto every victim window.

Events are attributed to the principal whose behaviour they represent: directory
operations (group changes, AD object access) to the acting `SubjectUserName`, not
the object acted upon; process-access and injection telemetry to the accessing
process's user; everything else to the target account.

## Feature contract and indicator quarantine (`features/contract.py`)

The separation of expert-defined attack indicators from behavioural features is
made explicit, versioned and enforced by the **feature contract**. Every feature
the extractors emit is classified as either:

- a **behavioural statistic** — count, rate, cardinality, entropy — eligible for
  model input; or
- a **quarantined** feature — a technique-hypothesis indicator (`f_dcsync_flag`,
  `f_golden_ticket_flag`, and similar) or an upstream-detector verdict (the
  Windows Defender group, which is label-adjacent).

On the full manifest this is 58 model-eligible behavioural features and 21
quarantined. Quarantined features are still computed and shown to analysts as
provenance; they are simply never model input. `model_feature_names(manifest)` is
the only supported way to select model input, and `contract_hash(manifest)` pins a
trained bundle to the exact columns it was fit on.

This matters because it makes "there is no rule engine here" a checked property,
not a promise: `tests/unit/test_feature_contract.py` fails if any `*_flag` or
Defender verdict becomes model-eligible, or if an emitted feature is left
unclassified. Blending a deterministic field-match into a statistical model's own
anomaly decision would conflate "you deviated from your baseline" with "a known
pattern matched"; the contract prevents it structurally.

## Causal features

Every feature value for a window depends only on events at or before that window.
Cross-window history (for example, the account's prior Kerberos ticket-issuance
addresses used by the golden/silver-ticket indicators) is consulted strictly
causally, so a feature is reproducible at inference time where only the past
exists. `tests/unit/test_feature_causality.py` recomputes every window against
truncated event streams and fails if any value changes when later events are
withheld — a guard that also covers features not written yet.

## Coverage

Explicitly partial. The engine maps the event families it extracts canonical
fields from; other event IDs are ingested and counted but not turned into
features, and the capability manifest gates on what is present, so missing or
unmapped channels degrade the feature set honestly rather than producing silent
zeros.

Breadth is the honest gap against a mature SIEM's analytics catalogue: this engine
covers a fraction of that surface. It is not a rule catalogue and is not trying to
be — the design bet is that a small number of well-calibrated behavioural and
relational models generalise further than a large number of rules.
