# How the engine detects each attack — a personal, step-by-step walkthrough

*Plain-language companion to the code. For every technique it shows: the events
and fields involved, which detector fires, the exact edge/feature, why it looks
anomalous, and the honest detection status on the benchmark.*

There are **no attack signatures in the detection path.** Every detection below
comes from one mechanism answering one question — *has this principal formed a
relationship it has no business forming?* — nothing is special-cased per attack.
That is the design bet: a first-time-seen relationship generalises across
techniques where a rule catalogue does not.

---

## The detector (read this first)

### Graph edge-surprise — the engine

Every relevant event is projected onto a directed **edge** `(source → destination)`
in one of several *views*. Each edge is scored by how surprising it is under a
Dirichlet-smoothed model of the estate's learned access distribution:

```
surprise (nats) = max( −log P(dst | src),  −log P(src | dst) )
P(b | a)        = (count_ab + α·π_b) / (count_a + α)          # α = 1
```

- `π_b` is the global marginal for `b` in that view (how popular `b` is overall).
- **Novel edge to a popular destination → low surprise** (everyone eventually
  touches the DC / a file server — routine churn).
- **Novel edge to a rare destination → high surprise** (a genuine first contact).
- **Novel edge from a highly active source → higher surprise** (it had many
  chances and never did this — the absence is evidence).
- **Cold start (no baseline) → ~0 surprise** (nothing is surprising without
  evidence; a brand-new account's first edge does not alert).
- Both directions are taken because some views are only informative in reverse
  (e.g. "was this destination reached by someone new?").

The raw surprise is turned into a **calibrated p-value**: `p = P(surprise ≥ s |
benign)`. Two details carry most of the engine's honesty:

- **One null per view.** Views have wildly different benign baselines
  (`proc_access` sits near 5.5 nats for ordinary traffic; `user_src` near 0.3), so
  each relationship type is judged against its own distribution.
- **The null is held out.** The baseline is learnt from the earlier training
  period, and each null is measured on a *later* slice scored against that frozen
  baseline. That is what puts benign *novelty* into the null — a user legitimately
  reaching a new host. Calibrate in-sample and the null contains no novelty at all,
  so every first contact looks extreme.

A MIDAS burst term adds extra surprise when one edge repeats many times in a
single hour (fan-out, spray, rapid ticket reuse).

**The views** (all scored by the identical formula — no per-view gates):

| view | edge `(src → dst)` | catches |
|---|---|---|
| `user_src` | account → source host/IP | logon from a never-used host (PtH, forged tickets) |
| `src_dst` | source host → destination host | host-to-host lateral movement |
| `kerb_ctx` | account → (enc-type\|pre-auth) of a TGT (4768) | AS-REP roasting, RC4 downgrade |
| `tgs_enc` | account → encryption type of a service ticket (4769) | Kerberoasting (RC4 downgrade) |
| `proc_access` | `host\|source-image` → target-image (Sysmon 10) | LSASS credential access |
| `rare_proc` | host → image (Sysmon 1, image on ≤3 baseline hosts) | rare tools appearing somewhere new |
| `dir_change` | actor → `group:`/`adobj:`/`attr:` (4728/4662/5136) | privileged group add, DCSync, RBCD/SPN |

### Volumetric ECOD — supplementary, off by default

Per `(account, hour)` the engine can also build a vector of **behavioural counts**
(logon count, distinct source IPs, failed logons, TGT/TGS counts, …),
z-normalised against that account's own history and scored by **ECOD**. It is
**disabled by default** (`enable_volumetric`): on the benchmark it catches no
technique the graph misses, and fusing it in lowers overall recall because its
false positives consume the alert budget. It is kept for estates whose threat
model includes volume-based abuse a relational view cannot see — validate it on
that estate's data before trusting it.

Signature-style flags (`f_*_flag`, e.g. `f_dcsync_flag`) are **dropped** from the
ML vector — the detector sees only behavioural counts, never a hand-labelled
"this is DCSync" bit.

### Combination and alerting

Per event, the most significant **view** is taken (Tippett, Šidák-corrected for how
many views fired). Per `(entity, hour)` the most significant event is taken the
same way. Per entity, the most significant hour is Šidák-corrected for how many
hours it was observed. Alerts are the **N most significant entities per day**
(`alert_budget_per_day`, the single knob).

---

## Attack by attack

For each: **events → fields → detector/edge → why anomalous → status.**
Status is measured across 6 seeds, ~n instances each, held-out test window.

### Pass-the-Hash (T1550.002) — ✅ good (6/9)

- **Events:** `4624` (Type-3 network logon, `AuthenticationPackageName=NTLM`) +
  `4776` from a workstation the victim never uses.
- **Fields checked:** `TargetUserName` (victim), `IpAddress`/`WorkstationName`
  (attacker's foothold), `LogonType=3`.
- **Detector:** graph, `user_src` view. Edge = `(victim_account → foothold_IP)`.
- **Why anomalous:** the victim has authenticated only from their own
  workstation; the foothold IP is a novel source for them, and a
  relatively rare destination globally → high `−log P(src|victim)` surprise.
- **Note:** detection does **not** rely on "NTLM with no preceding Kerberos" (a
  signature). It relies purely on the novel `(account, source)` relationship —
  which is why it generalises.

### Golden Ticket (T1558.001) — ✅ strong (3/3)

- **Events:** `4624` Type-3 Kerberos logon presented from the attacker's host,
  with **no** preceding `4768` (the DC never issued the forged TGT).
- **Fields:** `TargetUserName` (impersonated victim), `IpAddress` (attacker host).
- **Detector:** graph, `user_src` view. Edge = `(victim_account → attacker_IP)`.
- **Why anomalous:** same mechanism as PtH — the victim's account appears from a
  source it never has. The "no 4768" fact is the *cause* of the anomaly in
  reality, but the engine detects the **novel source edge**, not the absence.

### Silver Ticket (T1558.002) — ✅ strong (6/6)

- **Events:** `4624` Type-3 Kerberos logon to a specific service host (e.g. SQL01)
  from the attacker's host, no `4769` on the DC.
- **Detector:** graph, `user_src` + `src_dst` views. Novel `(account → attacker_IP)`
  and novel `(attacker_IP → service_host)`.
- **Why anomalous:** the victim never authenticated from that host, and that host
  never reached that service — two novel edges reinforce.

### AS-REP Roasting (T1558.004) — ✅ strongest (10/10)

- **Events:** `4768` with `PreAuthType=0` (pre-auth disabled) + `EncryptionType=0x17`
  (RC4) + `Status=0x0`.
- **Fields:** `TargetUserName`, `PreAuthType`, `EncryptionType`.
- **Detector:** graph, `kerb_ctx` view. Edge = `(account → "0x17|0")` — the
  encryption/pre-auth *context* of the ticket.
- **Why anomalous:** the account has only ever requested modern (AES,
  pre-auth-required) tickets; a `RC4 | no-pre-auth` context is a novel, rare edge
  for that account and globally → high surprise.

### Kerberoasting (T1558.003) — ✅ good (3/4)

- **Events:** a burst of `4769` (service-ticket requests) with
  `TicketEncryptionType=0x17` (RC4) for many SPNs in seconds.
- **Fields:** `TargetUserName`, `TicketEncryptionType`, `ServiceName`.
- **Detector:** graph, `tgs_enc` view. Edge = `(account → "0x17")` — the ticket
  **encryption type** (deliberately *not* the SPN: keying on SPN floods the model
  with benign service diversity and collapsed detection; keying on the
  low-cardinality cipher is the generalised downgrade signal). Plus a MIDAS burst
  from many RC4 requests in one hour.
- **Why anomalous:** the account normally receives AES service tickets; a sudden
  run of RC4 tickets is a novel, rare, bursty context.
- **If the volumetric track is enabled** it also fires here (the RC4-TGS and
  distinct-SPN counts spike far outside the account's baseline), but the graph
  catches it without that track.

### DCSync (T1003.006) — ✅ strong (6/7)

- **Events:** `4662` (directory object access) with the *Replicating Directory
  Changes* rights, from a **non-machine** account; preceded by a `4624` Kerberos
  logon by the attacker.
- **Fields:** `SubjectUserName` (the actor — attributed correctly, not the object),
  `ObjectType`, `Properties` (replication GUIDs).
- **Detector:** graph, `dir_change` view. Edge = `(actor → "adobj:<object-class>")`.
- **Why anomalous:** normal directory replication is performed by DC **machine**
  accounts (excluded via the trailing `$`); a regular user account touching the
  directory-replication object is a novel edge to a rare destination.

### LSASS credential dump (T1003.001) — ✅ strong (5/5)

- **Events:** Sysmon `10` (ProcessAccess) with `TargetImage=lsass.exe` and a
  high `GrantedAccess` mask, from an unusual source image (rundll32/comsvcs).
- **Fields:** `SourceImage`, `TargetImage`, `GrantedAccess`; the **host is resolved
  to the logged-on account** via session attribution so the detection lands on an
  identity, not a hostname.
- **Detector:** graph, `proc_access` view. Edge = `(host|source_image → lsass.exe)`.
- **Why anomalous:** in the baseline only `wininit.exe` opens `lsass.exe`, so
  `π(lsass) ≈ 1` and the **forward** conditional scores it ~0 ("lsass is what
  things open"). The **reverse** conditional saves it: `lsass` has only ever been
  opened by `wininit`, so `rundll32 → lsass` is a novel edge into a rare
  destination. This is exactly why the engine scores **both directions**.

### Password Spray (T1110.003) — ✅ strong (4/4)

- **Events:** many `4625`/`4771` failures against distinct accounts from one
  external IP, off-hours, with wrong-password sub-status codes.
- **Fields:** `IpAddress` (single external source), `TargetUserName` (many
  victims), `SubStatus`/`Status`.
- **Detector:** graph `user_src`/`src_dst`. The external IP (e.g. `185.220.x.x`)
  is a novel, globally-rare source reaching many victims and the DC → high
  surprise, reinforced by a MIDAS burst from the fan-out.

### Account Manipulation — add to Domain Admins (T1098) — ❌ not detected (0/7)

- **Events:** `4728` (member added to a security-enabled group) where the group is
  a Tier-0 group (Domain Admins).
- **Fields:** `SubjectUserName` (actor — attributed correctly), `TargetUserName`
  (the group name), `MemberName`.
- **Detector:** graph, `dir_change` view. Edge = `(actor → "group:domain admins")`.
- **Why it *should* be anomalous:** the estate produces a steady baseline of
  routine group management (help-desk admins adding users to ordinary
  department/file-share groups). Against that baseline, an add to *Domain Admins*
  — a group nobody normally touches, performed by an account that does no group
  management — is a novel edge to a rare destination (~5 nats surprise).
- **Honest status:** the signal is real but **modest** (p ≈ 0.33), because
  first-time-ever group adds by legitimate admins produce comparable novelty, so
  the attack does not reliably clear the top-of-queue against ~250 entities.
  Distinguishing "attacker → Domain Admins" from "admin's first add to a new
  group" ultimately needs a notion that Domain Admins is *special* (a Tier-0
  label), which pure unsupervised novelty does not have. **This is an honest
  boundary of behavioural detection, not a bug.** The structural graph
  (`identity_graph.py`, analyst tooling) *does* carry Tier-0 designations and is
  the right place to fuse that context if it is ever benchmarked as its own track.

### NTDS.dit dump (T1003.003) — ❌ honest miss (0/5)

- **Events:** Sysmon `1` process-create of `vssadmin.exe` (shadow copy) then
  `ntdsutil.exe` (`ifm create full`) on a DC.
- **Why it's missed:** both tools **legitimately run on Domain Controllers and IT
  hosts** — `vssadmin` appears on 6 baseline hosts (backups), `ntdsutil` runs on
  DC01 for maintenance. So `(host → image)` novelty cannot separate the attack
  from routine administration; the discriminating signal is the **command-line**
  (`ifm create full`), which is a signature, not a behaviour. A pure
  behavioural/relational engine has no honest edge here.
- **What would catch it (documented, not implemented):** command-line features
  (signature-adjacent), or attributing the process to the *actor* and flagging a
  non-maintenance account running `ntdsutil` — which needs actor-in-edge
  resolution the current `rare_proc` view does not do.

---

## Summary table

| technique | detector / view | field(s) that carry it | status |
|---|---|---|---|
| Pass-the-Hash | graph `user_src` | account, source IP | ✅ 6/9 |
| Golden Ticket | graph `user_src` | account, source IP | ✅ 3/3 |
| Silver Ticket | graph `user_src`+`src_dst` | account, source, service host | ✅ 6/6 |
| AS-REP Roasting | graph `kerb_ctx` | account, enc-type, pre-auth | ✅ 10/10 |
| Kerberoasting | graph `tgs_enc` | account, ticket enc-type | ✅ 3/4 |
| DCSync | graph `dir_change` | subject (actor), object class | ✅ 6/7 |
| LSASS dump | graph `proc_access` (reverse) | source/target image, host→account | ✅ 5/5 |
| Password Spray | graph `user_src` + MIDAS burst | source IP, victim accounts | ✅ 4/4 |
| Account Manipulation | graph `dir_change` | subject (actor), group name | ❌ 0/7 |
| NTDS dump | (none — honest miss) | command line only | ❌ 0/5 |

The point worth internalising: **eight of ten techniques are caught by the same
edge-novelty mechanism**, with different views but the *same scoring formula* and
no per-attack logic. Add a technique that leaves a novel relational trace and it
tends to be caught for free. The two that are missed are exactly the two whose
signal is **not relational**: account manipulation needs to know that *Domain
Admins is special* (directory context — a Tier-0 label), and NTDS extraction uses
tools that legitimately run on domain controllers, so its signal is a command line.
Neither gap is a tuning failure; both are the honest boundary of relational
behavioural detection, and both have documented extension paths.
