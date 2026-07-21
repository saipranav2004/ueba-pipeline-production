# Benchmark

## Reproduce

```bash
export UEBA__SECURITY__MODEL_SIGNING_KEY=<32+ random bytes>
for s in 20250106 424242 777001 10101 20202 30303; do
  python enterprise_simulator/run_simulation.py --days 20 --seed $s \
      --inject-attacks all --attack-count 30 --attack-placement spread --quiet
  python -m ueba_pipeline.cli.main walk-forward-eval \
      --data-dir enterprise_simulator/output --contamination none
done
```

## Results

6 seeds × 20 days × 253 employees. 60 held-out test attacks across all ten
techniques. Alert budget 5 entities/day. The engine is the calibrated
authentication-graph detector.

| | recall | FP entities/day |
|---|---|---|
| **engine (graph track)** | **43/60 = 71.7%** | **3.44** |

Per-technique:

| technique | recall | | technique | recall |
|---|---|---|---|---|
| AS-REP roasting | 10/10 | | Kerberoasting | 4/4 |
| Pass-the-Hash | 8/9 | | golden ticket | 3/3 |
| DCSync | 5/7 | | silver ticket | 4/6 |
| LSASS dump | 5/5 | | account manipulation | 0/7 |
| password spray | 4/4 | | NTDS dump | 0/5 |

The contamination guard makes no measurable difference (`oracle` ≡ `none`).

## Null calibration — read this before comparing to any earlier number

A detector's null must answer: *what surprise does a benign event produce when
scored against the deployed, frozen baseline?* How that null is measured changes
the headline by more than any modelling choice, so all three candidates were
measured on the same six seeds:

| null calibration | recall | FP/day | verdict |
|---|---|---|---|
| in-sample (absorb all training, then score it) | 50/60 (83%) | 3.29 | **wrong** — every training edge is already "seen" and scores ≈0, so the null holds no benign-novelty mass and the detector treats any first contact as extreme |
| prequential (score each event, then absorb) | 41/60 (68%) | 3.48 | over-conservative — every account's cold-start first contact inflates the tail |
| **held-out slice (shipped)** | **43/60 (72%)** | **3.44** | **correct** — baseline learnt from the earlier training period, null measured on a later held-out slice scored against that frozen baseline: exactly what a live benign event meets |

The in-sample null is not a small optimism. Measured p99 benign surprise:

| view | in-sample | correctly calibrated |
|---|---|---|
| `user_src` | 3.26 | **8.49** |
| `proc_access` | 6.85 | **16.27** |
| `rare_proc` | 1.08 | **15.57** |

It claims 3.3 is the 99th percentile of benign `user_src` surprise when benign
novelty routinely reaches 8.5. A fixture with static addresses hides this — benign
novelty is artificially rare, so the over-flagging lands almost entirely on injected
attacks — which is one reason the estate now churns addresses realistically (below).
The shipped number is lower and honest; see [EVALUATION_AUDIT.md](EVALUATION_AUDIT.md).

## Robustness to address churn (the real-world false-positive driver)

The estate churns addresses the way a real one does: VPN pools hand out a
different address each remote session, DHCP leases rotate every few days, and the
same laptop appears on wired and Wi-Fi ranges — ~10 distinct source addresses per
user over 20 days, while the *device* identity stays stable (~1.1 per user).

This is the condition that historically makes authentication-graph detection
unusable in production, and it is entirely decided by what identifies "source":

| `(account → source)` keyed on | benign edges that are novel |
|---|---|
| IP address | **91.8%** |
| **device identity (shipped)** | **4.4%** |

Keyed on the address, 92% of ordinary logons look like first contacts and the view
is pure noise. Keyed on the device, novelty means something again. Detection is
unchanged by the churn:

| estate | recall | FP entities/day |
|---|---|---|
| static addresses | 43/60 | 3.46 |
| **realistic address churn** | **43/60** | **3.44** |

## Component evidence

Every component is held to measured contribution, on the corrected calibration.

| component | evidence | verdict |
|---|---|---|
| graph edge surprise | 43/60; carries the product | keep |
| per-view null calibration | each relationship type scored against its own null; without it the high-baseline views (`proc_access` ~5.5 nats benign) set the bar for low-baseline views (`user_src` ~0.29) | keep |
| `tgs_enc` view | Kerberoasting 4/4 (0/4 without it) | keep |
| MIDAS burst | fan-out / spray / rapid-reuse surfacing | keep |
| host→user session attribution | one identity space for alerting | keep |
| volumetric (ECOD) track | fused 30/60 vs graph-only 43/60 at higher FP (3.86 vs 3.46); catches no technique the graph misses | **off by default** |
| `dir_op` view | keyed on the operation class, not the object touched: **9% benign novelty** (72% when keyed on the group). Healthy, but starved of evidence (n≈27) so account manipulation stays 0/7 | keep (generalized directory coverage; extension is a row in `DIR_OP_CLASS`) |

`train` reports each view's benign novelty rate, which is the measurable test of
whether a relationship type can carry signal at all:

```
  view              edges  benign novelty
  proc_access        2059           0.0%     <- stable: a novel edge is real evidence
  tgs_enc            2122           0.4%
  kerb_ctx            989           0.2%
  src_dst             329           6.7%
  user_src            329           7.3%     <- 91.8% if keyed on IP instead of device
  dir_op               22           9.1%     <- 72.0% when keyed on the group object
```

A view whose benign edges are routinely novel cannot separate a first contact from
an attack, however it is calibrated. This one number drove three design decisions —
key the source edge on the device (7.3%) not the address (91.8%); key Kerberoasting
on the cipher, not the SPN; key directory operations on the operation class (9.1%),
not the object touched (72%). The rate is measured, not asserted, so admitting a new
view is an evidence-based decision rather than per-attack judgement.

The volumetric track is retained but disabled (`enable_volumetric`), for estates
whose threat model includes volume-based abuse a relational view cannot see. It
must be re-validated on that estate's data before being trusted.

## Scalability and performance

Measured on 253 employees × 20 days (~160k events): fit ~30k events/s, score
~37k events/s, signed bundle ~2.6 MB, `score()` bit-for-bit reproducible across
repeated calls. The graph track is plain counters with O(1) updates; the artifact
is bounded by feature/grid size, not by how much data was seen. Nothing above 253
entities has been measured — linear-in-events fit and O(1) counter updates predict
it holds, which is a prediction.

## Validation against public data (LANL 2015)

`lanl-eval` runs a per-authentication ROC (TPR at a fixed FPR, plus AUC) against
LANL 2015 using the production per-view calibrated scoring, reporting both
contamination bounds:

```bash
python -m ueba_pipeline.cli.main lanl-eval --auth auth.txt --redteam redteam.txt
```

The LANL files sit behind a data-use agreement and cannot be fetched
programmatically; accept it at `csr.lanl.gov/data/cyber1/` and point the command at
the downloaded files. The harness itself is exercised end to end on a synthetic
LANL-format fixture (`scripts/make_lanl_fixture.py`, `tests/unit/test_lanl_eval.py`),
which validates the adapter, red-team matching, causal split and ROC — **not**
real-world performance; the fixture's lateral movement is detectable by
construction.

Reference points for when real LANL is run: Bowman et al. (RAID 2020) ~0.85 TPR at
0.9% FPR with unsupervised graph learning; Euler (TOPS 2023) AUC 0.91–0.98; Jbeil
and later temporal-graph work ~0.99 AUC. Those upper numbers come from learned
temporal graph models — see "Not implemented" in
[docs/architecture.md](docs/architecture.md).

## Limitations

1. **No real-world validation.** All data is self-generated. The estate now churns
   addresses realistically, so FP/day is no longer the pure floor it was, but a
   simulator still cannot reproduce the full messiness of a real network
   (shared/kiosk hosts, service-account sprawl, M&A estates, cloud identity). This
   remains the largest open risk; only LANL 2015 / OpTC can retire it.
2. **Account manipulation (0/7).** Not a tuning failure — an evidence limit. The
   `dir_op` view sees only ~27 benign directory operations in the calibration
   slice, so its null floors the smallest assertable p at `1/(n+1) ≈ 0.036`; after
   correcting for the hours an entity is observed, that cannot reach the top of a
   250-entity queue however anomalous the behaviour is. Rare-operation views need a
   long baseline (months, not days) to earn the resolution. A Tier-0 watchlist
   would short-circuit it with directory context, which is a rule, not behaviour.
3. **NTDS dump (0/5).** Its tools (`vssadmin`, `ntdsutil`) run legitimately on
   domain controllers, so it leaves no novel relational trace; the discriminating
   signal is a command line or an execution sequence.
4. **n = 60.** A development baseline, not a product claim.
5. **`alpha = 1.0`** (Dirichlet concentration) is an uninformative default, not a
   tuned value.

## References

- Rubin-Delanchy, Lawson & Heard. *Anomaly detection for cyber security applications.* 2016.
- Heard & Rubin-Delanchy. *Choosing between methods of combining p-values.* Biometrika 105(1), 2018.
- Bowman et al. *Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI.* RAID, 2020.
- King & Huang. *Euler: Detecting Network Lateral Movement via Scalable Temporal Link Prediction.* ACM TOPS, 2023.
- Bhatia et al. *MIDAS: Microcluster-Based Detector of Anomalies in Edge Streams.* AAAI, 2020.
- Li et al. *ECOD: Unsupervised Outlier Detection Using Empirical Cumulative Distribution Functions.* TKDE, 2022.
