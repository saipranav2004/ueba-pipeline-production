# Datasets and real-data validation

The engine's simulator numbers cannot, on their own, prove real-world behaviour —
the research survey is explicit that headline scores on real data collapse under
honest evaluation. This document records the public-dataset landscape that was
researched as an alternative to the simulator, which datasets were adopted, and
what has actually been run.

## What "validation" means here, split honestly

Two different claims need two different kinds of data, and no single public
dataset provides both:

1. **Ingestion correctness** — does the parser, the canonical field map, the
   feature contract, and the graph edge projection fire correctly on *real*
   Windows event schemas, not just on the simulator's output? This needs real
   attack telemetry, labelled by technique. It does **not** need a benign
   baseline.
2. **Detection performance** — recall and false-positive rate. This needs a
   large, real, *labelled* corpus with a realistic multi-day benign background to
   detect against and to raise false positives from.

Claim 1 is **done** on real data (OTRF, below). Claim 2 is **not**, and no amount
of code closes it — it requires a labelled corpus behind a data-use agreement.

## Datasets researched

| dataset | telemetry | labels | benign background | access | verdict |
|---|---|---|---|---|---|
| **OTRF Security-Datasets** (Mordor) | real Windows Security + Sysmon | ATT&CK technique | minimal (logs cleared per run) | GitHub, MIT, plain HTTP | **adopted** for ingestion correctness |
| **COMISET** (2025) | real Windows event logs via Winlogbeat | ATT&CK-labelled malicious | **real** (university network) + lab | Zenodo, **CC-BY-4.0**, direct download | **top recommendation** for detection performance |
| LANL 2015 (Comprehensive) | auth + process (flat) | red-team | real enterprise | DUA, no automation | blocked on manual DUA |
| LANL 2017 (Unified Host) | real Windows EventIDs | none | real enterprise | DUA | blocked on DUA |
| DARPA OpTC | eCAR (not Sysmon) | red-team | automated agents | open, ~1 TB | **no domain-controller logs** — see note below |
| LMDG / LMTrace (2025) | Windows AD, full topology | process-tree ground truth | simulated, multi-day | **repository is empty** | announced but not published |
| EVTX-ATTACK-SAMPLES | real EVTX (incl. 4662 DCSync, Sysmon 10) | by filename | none | GitHub | fixture library; needs EVTX binary parsing |
| Splunk BOTS v1–v3 | Sysmon + Suricata + more | scenario/CTF | incident-shaped | GitHub, CC0 | Splunk-indexed, not per-view structured |
| CERT Insider Threat | synthetic | insider labels | synthetic | open | not AD attack telemetry |
| AIT-LDS | Linux/web-centric | ground truth | synthetic | Zenodo | minimal Windows AD coverage |

Sources: [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) ·
[COMISET (Zenodo 10.5281/zenodo.15375146)](https://zenodo.org/records/15375146) ·
[LANL 2015](https://csr.lanl.gov/data/cyber1/) ·
[LANL 2017](https://csr.lanl.gov/data/2017/) ·
[DARPA OpTC](https://github.com/FiveDirections/OpTC-data) ·
[LMDG paper (arXiv:2508.02942)](https://arxiv.org/abs/2508.02942) ·
[LMTrace repo](https://github.com/WASPLab/LMTrace) ·
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)

### The AD-dataset gap is structural, not an oversight

Public datasets containing genuine **Active Directory attack** telemetry with
domain-controller logs are close to nonexistent. HADES (arXiv:2407.18858) states
the position directly: public datasets largely omit AD attacks because of the
emulation infrastructure required, and OpTC — the one public dataset that does
include AD-based attacks — carries system logs from domain-joined hosts only,
**with no logs from the domain controller**. Since 4662 (directory access), 4768
/4769 (Kerberos) and the account-lifecycle events are DC-side, OpTC cannot
exercise the views that carry DCSync, Kerberoasting or account manipulation.

This is the substantive justification for shipping a simulator at all, and it is
also why the simulator's numbers must never be presented as real-world
performance.

### Two claims corrected by direct verification

- **LMDG / LMTrace is not obtainable.** The paper describes a 25-day, 25-VM,
  22-account estate with 944 GB of logs and 35 multi-stage attacks, and names
  `github.com/WASPLab/LMTrace` as the distribution point. That repository is
  **empty** — zero commits, 0 KB, no release. It cannot currently be used, and
  any plan that depends on it is blocked.
- **OpTC's repository is documentation, not data.** The GitHub repository is
  ~428 KB (the eCAR specification and errata); the ~1 TB corpus is hosted
  elsewhere, and its format is eCAR rather than Sysmon, so it needs conversion
  that is lossy for process-access records.

### COMISET: the strongest available path to real detection numbers

[COMISET](https://zenodo.org/records/15375146) is the most promising real dataset
found, and unlike LANL it needs no agreement:

- **License** CC-BY-4.0; **access** direct HTTP from Zenodo, no registration.
- **Two environments**: `Comiset23_Lab_Environment_Dataset.zip` (4.91 GB, a
  small-company infrastructure emulation) and
  `Comiset23_Real_Environment_Dataset.zip` (31.7 GB, a **real** university
  network — genuine human benign background, which no other candidate offers).
- **~250 million events**, malicious events labelled against MITRE ATT&CK,
  covering multi-stage vectors including lateral movement and privilege
  escalation.
- **Format**, verified by decompressing the archive head over an HTTP range
  request rather than downloading it: newline-delimited JSON in Elasticsearch
  export shape — each record has `_source` carrying Winlogbeat/ECS fields, with
  the event id at `_source.z_elastic_ecs.event.code` and the provider at
  `_source.z_elastic_ecs.event.provider`, plus flattened per-event fields.

That shape is close to the flat NXLog form `parsing.normalize` already ingests, so
the adapter is a thin `_source` unwrap plus an event-id/channel mapping —
comparable in size to `evaluation/otrf_adapter.py`. **This is the recommended
next dataset integration**: it is the only identified corpus that supplies
labels *and* a real benign background *and* permissive redistribution, which is
exactly the combination detection-performance measurement requires.

Cost to be aware of before starting: the lab archive expands from 4.91 GB
compressed to a single JSON file, so ingestion should stream rather than
materialise it.

**Why OTRF was adopted first.** It is the only source that is simultaneously real
Windows/Sysmon telemetry, ATT&CK-labelled, and downloadable over plain HTTP with
no data-use agreement — so it can be wired into CI. Its captures clear the event
logs immediately before each attack, so it has no realistic benign baseline: it
is a detection-logic fixture library, not a validation corpus, and it is used here
strictly for ingestion correctness.

## What was run on OTRF

`ueba_pipeline/evaluation/otrf_adapter.py` reads an OTRF archive through the
**production** `normalize_event` path (no OTRF-specific parsing exists, so a pass
exercises the real parser). `scripts/validate_on_otrf.py` downloads a curated set
spanning the credential-access techniques the engine targets and checks that each
projects its expected behavioural graph view:

| dataset | technique | records | parsed | mapped | key behavioural view |
|---|---|---|---|---|---|
| dcsync | T1003.006 | 869 | 100% | 289 | `dir_op` edge `(pgustavo → adobjaccess)` |
| ntds_ntdsutil | T1003.003 | 11,184 | 100% | 8,161 | `proc_access` ×7,495 |
| lsass_comsvcs | T1003.001 | 184 | 100% | 101 | `proc_access` ×68 |
| pth_lsass | T1550.002 | 10,271 | 100% | 4,387 | `user_src` / `proc_access` |
| rubeus_ptt | T1550.003 | 1,179 | 100% | 490 | `user_src` / `proc_access` |

Every curated dataset ingests fully and projects its expected view. The DCSync
capture is the sharpest result: the real 4662 carries the Replicating-Directory-
Changes GUID and the engine projects the same signature-free `dir_op` edge it uses
on the simulator — confirming the behavioural detection path is exercising real
event structure, not a simulator artefact.

### Two parser bugs found only by real data

Running on OTRF surfaced two defects the simulator never could, both fixed:

1. **`_parse_iso` mangled a short fractional second followed by `Z`.** `.927Z`
   became `.927+00+00:00` and failed to parse, so every event carrying that common
   format was silently dropped for "missing time". Real 2023-era captures use it;
   the simulator did not. Fixed to defer to `datetime.fromisoformat` (which
   handles it) with a corrected fallback for 7-digit Windows fractions.
2. **The flat-envelope reader ignored the `TimeCreated` timestamp field.** Some
   captures carry the event time only under `TimeCreated`, not `EventTime` or
   `@timestamp`; those datasets parsed to zero usable events. Fixed by accepting
   all three field names.

Before the fixes, ~50% of the curated records were dropped; after, 100% parse.
Both fixes are guarded by `tests/unit/test_otrf_adapter.py`.

## Reproduce

```bash
# ingestion correctness on real OTRF telemetry (needs network)
python scripts/validate_on_otrf.py --cache-dir artifacts/otrf

# the adapter's offline regression tests (hermetic)
python -m pytest tests/unit/test_otrf_adapter.py -q

# the opt-in real-download test
UEBA_RUN_OTRF_DOWNLOAD=1 python -m pytest \
    tests/unit/test_otrf_adapter.py::test_real_otrf_dcsync_download_and_projection -q
```

## Remaining gap (unchanged, stated plainly)

Detection recall and false-positive rate on real data are still unmeasured,
because that needs a labelled real corpus with a benign background. LANL 2015 is
the natural target and the `lanl-eval` harness is ready for it; it sits behind a
data-use agreement that must be accepted manually. Adopting OTRF closes the
ingestion-correctness question on real data but not this one.
