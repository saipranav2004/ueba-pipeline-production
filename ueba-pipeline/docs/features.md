# Features

This document is the complete reference for the feature layer: every engineered
feature, how it is extracted, why it exists, how it is classified, and where it is
(and is **not**) used. It is written to be read start-to-finish by someone new to
the system, while staying precise enough to be the specification the code is held
to.

If you read nothing else, read the next two boxes.

> **What a "feature" is here.** A feature is one number summarising one aspect of an
> identity's behaviour over one hour — for example, "how many times did `alice` log
> on between 09:00 and 10:00", or "what fraction of her logons used NTLM". The
> feature layer turns a raw stream of Windows events into a table of these numbers,
> one row per `(account, hour)`.

> **The one fact that surprises everyone.** The **shipped detector does not score
> these feature vectors.** The production detection path is *relational* — it scores
> the surprise of who-talked-to-what edges (see [graph.md](graph.md) and
> [detection.md](detection.md)), and it never builds a behavioural feature vector.
> So why does this layer exist? Two reasons, both real:
>
> 1. **The capability manifest** is built by scanning which feature groups a
>    deployment can actually populate — this is how the engine adapts to whatever
>    telemetry an estate ships (§7).
> 2. **The model-comparison track** ([model_comparison.md](model_comparison.md))
>    trains classical models (logistic regression, gradient boosting, …) on this
>    feature matrix, to answer "could a supervised model on tabular features beat
>    the shipped relational detector?" It is a benchmark, not the product.
>
> Keeping this straight prevents the most common misreading of the codebase.

Source: `ueba_pipeline/features/` — `aggregate.py` (extraction), `contract.py`
(classification and eligibility), `manifest.py` (capability gating).

---

## 1. Data flow

```
NormalizedEvent stream  (parsing/normalize.py — typed, canonical fields)
        │
        ▼
  entity resolution        _user_key(event): which account owns this event?
        │                  (excludes machine `$` and SYSTEM identities)
        ▼
  windowing                bucket by (account, floor(event_time → 1-hour UTC bucket))
        │
        ▼
  per-group extractors     one function per feature group, run only for the groups
        │                  the CapabilityManifest reports available
        ▼
  cross-entity / cross-group post-processing
        │                  password-spray fan-out (needs all users);
        │                  golden/silver-ticket indicators (need auth + kerberos)
        ▼
  FeatureVector            {feature_name: float} for one (account, hour),
        │                  plus provenance (which group produced each value)
        ▼
  feature contract         classify each feature; select the model-eligible subset
        │                  in a fixed, hashed column order
        ▼
  feature matrix           the tabular input the model-comparison track consumes
```

The entry points are `build_user_windows(events, manifest, window_hours)` →
`List[FeatureVector]`, and `observed_entity_windows(events, window_hours)` → the set
of `(account, window_start)` keys (used by the detector's rollup for its
multiple-testing correction; it runs none of the extractors).

---

## 2. The window model

A feature vector describes **one account in one fixed clock hour**.

- **Window size** is `window.feature_window_hours`, default **1.0 hour**. Windows
  are fixed UTC buckets (`floor(timestamp / window_seconds)`), not sliding — every
  event falls in exactly one bucket, so the same event never contributes to two
  windows and windows are directly comparable across accounts and days.
- **Why an hour.** It is long enough that an ordinary account produces a stable
  count profile, and short enough that a burst of activity (a spray, a Kerberoasting
  sweep) concentrates inside one or two windows instead of being averaged away over
  a day.

## 3. Entity resolution — whose behaviour is this?

Every event is attributed to exactly one account by `_user_key(event)`. The
correct account differs by event family, and getting it wrong would put a signal on
the wrong identity, so attribution is explicit:

| event family | attributed to | why not the obvious field |
|---|---|---|
| directory ops (4728/4732/4738/5136, …) | **`SubjectUserName`** — the actor | `TargetUserName` names the *group or object* acted on, not a person; attributing to it invents a pseudo-identity keyed on "Domain Admins" and leaves the real actor's row empty |
| Sysmon access/injection (EID 8, 10) | **`SourceUser`** — the accessing process's user | the target is the *victim* process's owner, often SYSTEM — the wrong entity to blame |
| everything else | **`TargetUserName`** — the subject of the event | this is the account the logon/ticket/etc. is *about* |

Each branch falls through a candidate chain (subject → user → source → target →
account name) so no event family is dropped for lacking its first-choice field.
**Machine accounts** (name ending `$`) and the well-known **SYSTEM SIDs**
(`S-1-5-18/19/20`) are excluded — they are not part of the human/service behavioural
model. Host-scoped Sysmon events that carry no user are resolved to the logged-on
account by the session resolver *on the detection path* ([graph.md](graph.md) §1.4);
in the feature layer they simply have no `SourceUser` and are attributed by the
fallback chain or skipped.

## 4. Causality — no feature may see the future

Every value in a window depends only on events **at or before that window's end**.
This is not a nicety; it is what makes a value reproducible at inference time, where
only the past exists. The subtle case is cross-window history: the golden/silver
ticket indicators (§6) consult an account's *prior* Kerberos ticket-issuance
addresses, and they do so strictly causally — each logon is tested only against
issuance that happened before it, via a binary search over a time-ordered history
(`_issuance_ips_before`). A flat set accumulated over the whole batch would let a
9 a.m. window "see" a ticket issued at 5 p.m. and retroactively mark an attacker's
address as familiar. `tests/unit/test_feature_causality.py` recomputes every window
against truncated event streams and fails if any value changes when later events are
withheld — a guard that also covers features not yet written.

---

## 5. Feature groups

There are **ten** feature groups. Each is computed by one extractor function over a
pre-filtered slice of the account's window (only the event types that group
consumes). A group is computed only if the capability manifest reports it available
(§7). Across the full manifest the extractors emit **83 features**: **60
model-eligible** behavioural statistics and **23 quarantined** indicators/verdicts
(§6 explains the split; the numbers are produced by the contract itself, not
hand-counted).

Naming convention: every feature name starts with `f_`. A `_flag` suffix marks a
boolean **indicator** — a hypothesis about a named technique — which is always
quarantined (never model input). Everything else is a count, rate, cardinality, or
statistic.

Legend for the *kind* column: **C**ount · **R**ate (∈[0,1]) · **K** cardinality
(distinct values) · **S**tatistic · **I**ndicator (quarantined).

### 5.1 `auth` — logon behaviour (17 features)

Events: 4624 (success), 4625 (failure), 4672 (special-privilege logon).

| feature | kind | meaning |
|---|---|---|
| `f_logon_count` | C | successful logons |
| `f_failed_logon_count` | C | failed logons |
| `f_fail_success_ratio` | R | failures ÷ successes — brute-force / spray pressure |
| `f_pct_type2_interactive` | R | share of console logons |
| `f_pct_type3_network` | R | share of network logons (share access, remote auth) |
| `f_pct_type8_cleartext` | R | share of cleartext-credential logons (rare, high-signal) |
| `f_pct_type9_newcred` | R | share of NewCredentials logons (runas /netonly — used by PtH tooling) |
| `f_pct_type10_rdp` | R | share of RDP logons |
| `f_pct_ntlm_auth` | R | share authenticated with NTLM rather than Kerberos (downgrade signal) |
| `f_privileged_logon_count` | C | 4672 special-privilege logons |
| `f_distinct_src_ips` | K | distinct source IPs the account logged on from |
| `f_distinct_workstations` | K | distinct source workstations |
| `f_spray_max_targets_per_ip` | C | *(cross-entity, §6)* distinct victims of the busiest failing source IP |
| `f_spray_distinct_fail_ips` | C | distinct source IPs that produced failures |
| `f_spray_has_cross_user_failure` | **I** | *(quarantined)* did any IP fail against >1 account |
| `f_golden_ticket_flag` | **I** | *(cross-group, §6; quarantined)* Kerberos logons from an address never issued a TGT |
| `f_silver_ticket_flag` | **I** | *(cross-group, §6; quarantined)* … never issued a TGS |

### 5.2 `kerberos` — ticketing behaviour (12 features)

Events: 4768 (TGT request), 4769 (service-ticket request), 4771 (pre-auth failure).

| feature | kind | meaning |
|---|---|---|
| `f_tgt_request_count` | C | TGT requests |
| `f_tgt_rc4_count` | C | TGTs issued with legacy RC4 encryption |
| `f_asrep_roast_flag` | **I** | AS-REP roasting pattern (pre-auth disabled + RC4 + success) |
| `f_tgs_request_count` | C | service-ticket requests |
| `f_tgs_rc4_count` | C | service tickets with RC4 |
| `f_tgs_rc4_pct` | R | RC4 share of service tickets — Kerberoasting downgrade pressure |
| `f_distinct_spns` | K | distinct services the account requested tickets for |
| `f_nonmachine_spn_count` | C | tickets for non-machine SPNs (Kerberoasting targets user-service SPNs) |
| `f_kerberoast_flag` | **I** | Kerberoasting pattern (RC4 + non-machine SPN + success) |
| `f_delegation_flag` | **I** | ticket carried transited-services (delegation) |
| `f_preauth_fail_count` | C | 4771 pre-authentication failures |
| `f_preauth_wrong_pw_count` | C | pre-auth failures specifically for a wrong password |

### 5.3 `sysmon_process` — endpoint process / network / injection (14 features)

Events: Sysmon 1 (process create), 3 (network connect), 7 (image load), 8
(CreateRemoteThread), 10 (ProcessAccess), 11 (file create), 22 (DNS query).

| feature | kind | meaning |
|---|---|---|
| `f_process_create_count` | C | processes created |
| `f_distinct_processes` | K | distinct process images |
| `f_masquerade_flag` | **I** | a process's on-disk name ≠ its PE original filename (renamed tool) |
| `f_outbound_conn_count` | C | initiated (outbound) network connections |
| `f_distinct_dest_ips` | K | distinct destination IPs |
| `f_unsigned_dll_load_count` | C | unsigned DLLs loaded |
| `f_remote_thread_count` | C | CreateRemoteThread events (cross-process injection) |
| `f_reflective_inject_flag` | **I** | remote thread with an empty start module (reflective/shellcode) |
| `f_lsass_access_flag` | **I** | a process opened `lsass.exe` (credential-store access) |
| `f_credential_dump_access_flag` | **I** | LSASS opened with a known credential-dump access mask |
| `f_temp_file_drop_count` | C | files created under `\temp\` or `\appdata\` (staging) |
| `f_per_process_dns_query_count` | C | Sysmon-observed DNS queries |
| `f_per_process_dns_diversity` | K | distinct query names |
| `f_ntds_dump_tool_flag` | **I** | a process command line named `vssadmin`/`ntdsutil`/`diskshadow` |

### 5.4 `dns` — DNS-analytical behaviour (7 features)

Events: DNS analytical 256 (query).

| feature | kind | meaning |
|---|---|---|
| `f_dns_query_count` | C | queries |
| `f_unique_domains` | K | distinct query names |
| `f_nxdomain_rate` | R | share resolving NXDOMAIN — DGA / tunnelling probing |
| `f_txt_query_count` | C | TXT queries (a common tunnelling carrier) |
| `f_any_query_count` | C | ANY queries |
| `f_avg_qname_entropy` | S | mean Shannon entropy of query names — encoded/tunnelled traffic |
| `f_max_qname_len` | S | longest query name — long labels carry exfiltrated data |

### 5.5 `powershell` — script-block behaviour (5 features)

Events: PowerShell 4104 (script-block logging).

| feature | kind | meaning |
|---|---|---|
| `f_ps_script_count` | C | distinct script blocks executed |
| `f_in_memory_exec_flag` | **I** | script ran with no on-disk path (fileless) |
| `f_encoded_cmd_flag` | **I** | `-EncodedCommand` present |
| `f_download_cradle_flag` | **I** | download-cradle keywords (`DownloadString`, `Invoke-WebRequest`, …) |
| `f_credential_dump_kw_flag` | **I** | credential-dump keywords (`Invoke-Mimikatz`, `sekurlsa`, …) |

### 5.6 `task_scheduler` — scheduled-task behaviour (4 features)

Events: Task Scheduler 106 (registered), 200 (action run), 201 (action completed).

| feature | kind | meaning |
|---|---|---|
| `f_task_registered_count` | C | tasks registered |
| `f_task_action_count` | C | task actions run |
| `f_task_action_lolbin_flag` | **I** | a task action ran a LOLBin (powershell, mshta, regsvr32, …) |
| `f_task_failed_count` | C | task actions with a non-zero result code |

### 5.7 `wmi` — WMI activity (3 features)

Events: WMI 5857 (operation), 5861 (permanent event-subscription).

| feature | kind | meaning |
|---|---|---|
| `f_wmi_operation_count` | C | WMI provider operations |
| `f_wmi_event_subscription_count` | C | permanent event subscriptions (a persistence primitive) |
| `f_wmi_distinct_consumers` | K | distinct subscription consumers |

### 5.8 `privilege_ad` — directory object access (5 features)

Events: 4662 (DS object access), 5136 (directory attribute modify). *Presence-gated
(§7).*

| feature | kind | meaning |
|---|---|---|
| `f_dcsync_flag` | **I** | a non-DC account accessed the directory-replication object (DCSync) |
| `f_ad_object_access_count` | C | 4662 object accesses |
| `f_rbcd_modify_flag` | **I** | `msDS-AllowedToActOnBehalfOfOtherIdentity` modified (RBCD abuse) |
| `f_spn_add_flag` | **I** | an SPN was added (Kerberoasting setup) |
| `f_ad_attr_modify_count` | C | 5136 attribute modifications |

### 5.9 `account_lifecycle` — identity lifecycle (13 features)

Events: 4720/4722/4724/4725/4726 (account create/enable/pw-reset/disable/delete),
4728/4729/4732/4733 (group membership), 4738 (attribute change), 4741/4742/4743
(computer account). *Presence-gated (§7).*

| feature | kind | meaning |
|---|---|---|
| `f_account_created_count` | C | accounts created |
| `f_account_deleted_count` | C | accounts deleted |
| `f_account_enabled_count` | C | accounts enabled |
| `f_account_disabled_count` | C | accounts disabled |
| `f_group_member_added_count` | C | group members added (4728 + 4732) |
| `f_group_member_removed_count` | C | group members removed |
| `f_account_changed_count` | C | account attribute changes |
| `f_computer_account_created` | C | computer accounts created |
| `f_computer_account_changed` | C | computer accounts changed |
| `f_computer_account_deleted` | C | computer accounts deleted |
| `f_password_reset_count` | C | administrative password resets |
| `f_privileged_group_add_flag` | **I** | member added to Domain/Enterprise/Schema Admins |
| `f_total_lifecycle_events` | C | sum of all lifecycle events in the window |

### 5.10 `defender` — first-party AV/EDR verdicts (3 features) — **entire group quarantined**

Events: Windows Defender 1116 (threat detected), 1117 (action taken). Every feature
here is quarantined — not because the signal is weak (a Defender verdict is among the
highest-value binary signals available) but because it is *another detector's output*
(§6). *Presence-gated (§7).*

| feature | kind | meaning |
|---|---|---|
| `f_malware_detected_flag` | **I** | Defender raised a detection |
| `f_malware_detection_count` | C→**quarantined** | number of detections |
| `f_malware_action_taken_count` | C→**quarantined** | number of remediation actions |

---

## 6. Cross-entity and cross-group features

Three signals cannot be computed inside a single account's single-hour window, so
`build_user_windows` computes them in a post-processing pass and overwrites the
per-group placeholders.

**Password-spray fan-out (cross-entity).** A spray is *one source failing against
many accounts*. Inside one victim's window there is only one victim, so a per-user
"distinct targets" count is structurally ≤ 1 and useless. The extractor instead
aggregates failed logons (4625 **and** 4771 — a real spray produces both) per
`(source_ip, hour)` **across all accounts**, then attributes each attacking IP's true
distinct-victim count back onto every victim window it touched. `provenance` records
these as `cross_entity_auth`. `f_spray_max_targets_per_ip` and
`f_spray_distinct_fail_ips` are the continuous, **eligible** forms;
`f_spray_has_cross_user_failure` is the quarantined `>1` threshold on the first.

**Golden / silver ticket (cross-group).** These need both `auth` (4624) and
`kerberos` (4768/4769) events, so they live in neither single-group extractor. A
forged Kerberos ticket never contacts the DC, so it presents from a host the account
was *never issued a ticket from*. For each Type-3 Kerberos logon, the extractor tests
its source address against the account's TGT (golden) and TGS (silver) issuance
history **strictly before that logon** and counts the misses. Both are indicators,
quarantined; the model's real forged-ticket detector is the graph track's novel
`user_src` edge ([graph.md](graph.md)).

Why compute quarantined indicators at all? Because analysts triage on them. They are
provenance shown next to an alert ("this window also matched the Kerberoasting
pattern"), and they are the ground the model-comparison track's *labels* can be
sanity-checked against — but they are never model input (§6.1).

## 6.1 The feature contract — what a model may learn from

`contract.py` is the boundary between the extractors and any model. It classifies
every feature and decides eligibility mechanically, so "this is a behavioural model,
not a rule engine" is a *checked property*, not a claim.

**Two families are excluded from model input:**

1. **Indicators (`*_flag`, 20 of them).** Each encodes an analyst's belief about a
   named technique. Training on them measures how well the flag was written and
   inflates any benchmark whose attacks came from the same technique list — the model
   would be memorising rules, not learning behaviour.
2. **The `defender` group (3 features).** A Defender verdict is label-adjacent: a
   model trained on it learns to agree with Defender and adds nothing where Defender
   is silent, which is the case that matters.

**Everything else is eligible** — counts, rates, cardinalities, entropies. Eligibility
is a rule (indicator suffix → out; ineligible group → out; else in) plus a small,
reasoned **override table** for the handful of names the rule would misclassify (e.g.
`f_spray_max_targets_per_ip` is a plain aggregate statistic despite its `spray` name,
so it is force-eligible). `validate()` raises if any emitted feature is left
unclassified, so a new extractor feature cannot silently default into model input.

Selection is only ever via `model_feature_names(manifest)` (the ordered eligible
columns) and `quarantined_feature_names(manifest)`. `contract_hash(manifest)` pins a
trained bundle to the exact columns, kinds and eligibility it was fit on;
`FEATURE_CONTRACT_VERSION` (currently `1.0.0`) bumps MINOR on a feature add, MAJOR on
a removal or a meaning change. `tests/unit/test_feature_contract.py` fails if any
`*_flag` or Defender feature becomes model-eligible.

**Feature kinds across the full contract:** 44 count, 20 indicator, 9 cardinality,
8 rate, 2 statistic.

---

## 7. The capability manifest — adapting to whatever an estate ships

Raw Windows/Sysmon telemetry has a variable schema: sources appear and disappear
with audit policy, Sysmon config and OS version. The manifest
(`build_capability_manifest`) is how the engine stays correct across that variation
instead of feeding all-zero vectors for a source a deployment does not run.

- It **scans the ingested data**, not a static list of expected sources, and enables
  a feature group only if that group's events reach a floor in the bootstrap window.
- The floor is an **absolute event count** (`min_events_for_capability`, default 5),
  deliberately not a fraction of total events. A fraction couples unrelated sources
  (a noisy Sysmon stream inflates the denominator and can push Kerberos below the
  bar) and is unstable on a small/rolling window (a group flips on and off between
  retrains from sampling noise, and every flip changes the feature order and
  invalidates the model). An absolute floor decides each source on its own count.
- **Rare-by-design groups bypass the floor** (`presence_gated_groups`, default
  `defender`, `privilege_ad`, `account_lifecycle`) and are admitted on the first
  occurrence — for them the presence of the event *is* the signal (a healthy 253-user
  estate produced 2 Defender events in 5 days; gating that on volume defeats the
  point).
- A group is claimed **only for events the parser can extract fields from**, so an
  unmapped event stream cannot mark a group "available" and then emit zeros.
- The manifest also records **zero-variance fields** (a field that is constant across
  a whole event type, e.g. DNS QTYPE always `1`) so downstream code drops them
  instead of rediscovering it per window.
- Fewer than `bootstrap_min_events` (default 200) total events → an empty manifest:
  "insufficient data to decide", never "no capabilities".

The manifest is pinned at fit time and reused for scoring, so a live batch missing a
source degrades honestly and `drift-check` reports the change. This is what makes
partial telemetry *correct* rather than quietly wrong.

---

## 8. Normalization, encoding, and importance

**Encoding.** Every feature is a `float`. Booleans (indicators) are `0.0`/`1.0`.
There is **no feature scaling or standardisation** in this layer, and that is
deliberate: the shipped detector does not consume these vectors at all, and the
model-comparison track's primary models are tree ensembles and a class-weighted
logistic regression, none of which need scaled inputs. `FeatureVector.as_array(order)`
emits the vector in a fixed column order, defaulting any absent feature to `0.0`.

**Normalization happens earlier, at parse time.** The canonical field maps and the
*derived flags* in `parsing/normalize.py` (`is_rc4_ticket`, `kerberoast_flag`,
`dcsync_flag`, `is_masquerade`, …) do the per-record semantic work once, so every
extractor and model reads the same typed fields instead of re-deriving them. Those
derived flags are what the indicator features surface.

**Importance.** Because the shipped detector uses none of these features, there is no
"feature importance" on the production path. Within the model-comparison track,
[model_comparison.md](model_comparison.md) reports that the signal is close to
linearly separable in these features (plain logistic regression wins on all four
split protocols), which is itself a finding about the feature set: a small number of
well-chosen behavioural statistics carry most of what a tabular model can use here.

## 9. Training vs inference use

- **Capability manifest:** built at `fit` time from the training data, pinned into
  the model bundle, reused unchanged at `score` time. This fixes the feature order so
  scoring can never silently misalign columns.
- **Feature vectors (model-comparison track):** built identically at train and test;
  the eligible subset feeds the supervised models; the split protocols
  ([model_comparison.md](model_comparison.md)) prevent leakage.
- **Shipped detector:** builds **no** feature vector. Its `score()` calls
  `observed_entity_windows` (keys only, for the Šidák test count) and scores graph
  edges. `build_user_windows` is never on that path — the engine's own comment notes
  that running the extractors there would "run every extractor and discard every
  value".

## 10. Limitations

- **Coverage is explicitly partial.** The ten groups cover a fraction of a mature
  SIEM's analytics surface. The design bet (stated in [architecture.md](architecture.md))
  is that a few well-calibrated behavioural and relational models generalise further
  than a large rule catalogue — not that this feature set is exhaustive.
- **No service-account / non-human-identity model class.** Service accounts are
  statistically distinct (strong periodicity, low entropy, narrow baselines) but are
  currently described by the same features as people. A periodicity model is the
  documented next capability ([evaluation.md](evaluation.md)).
- **Indicators are simulator-shaped.** The quarantined `*_flag` features encode
  techniques the simulator injects; on real data they are provenance, not ground
  truth (see the COMISET label caveats in [datasets.md](datasets.md)).

## References

- Rubin-Delanchy, Lawson & Heard. *Anomaly detection for cyber security applications.* 2016. (p-value modus operandi the eligible-feature philosophy mirrors.)
- MITRE ATT&CK technique pages for the indicators (T1110.003 spray, T1558.001/002 golden/silver ticket, T1003.006 DCSync, T1208/T1558.003 Kerberoasting, T1098 privileged-group change, …) — used to *name* provenance, never to gate detection.
- `tests/unit/test_feature_contract.py` and `test_feature_causality.py` — the executable specification of §6.1 (the no-rule-engine guarantee) and §4 (the no-look-ahead guarantee).
