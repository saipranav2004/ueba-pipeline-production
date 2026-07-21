# Evaluation methodology audit

An independent, line-level audit of every way an ITDR benchmark is commonly wrong,
for both evaluation harnesses:

- `evaluation/honest_eval.py` — the simulator walk-forward (per-entity, budget).
- `evaluation/benchmark.py` + `lanl_adapter.py` — the LANL per-authentication ROC.

Status: ✅ verified sound · ⚠️ residual limitation (documented, not a defect).

---

## 1. Data leakage (test → train)

✅ **Sound.** `honest_eval.evaluate` splits by time (`train = events < split`,
`test = events ≥ split`), fits the engine on `train` only, and scores `test`
only. No test event enters `fit`. The capability manifest, per-view graph nulls,
volumetric null, and per-entity statistics are all built inside `fit(train)` and
reused unchanged for scoring. The LANL harness splits identically by `split_time`.

## 2. Threshold leakage

✅ **Sound.** No threshold is selected from the test set's benign scores. All
nulls are frozen at fit; `score()` never recalibrates (asserted by
`test_engine_calibrates_nulls_on_training_data_only`, which inspects the source of
`fit`/`_fit_graph` and `score`). The only operating knob,
`alert_budget_per_day`, is a fixed configuration value, not derived from labels.
The LANL ROC reports TPR at a fixed reference FPR (0.9%, Bowman) — a
characterisation of the detector's ranking, the literature-standard reporting, not
a threshold tuned on test then reported as if held out.

## 2b. In-sample null calibration — the most consequential defect found

❌→✅ **Found and fixed. It inflated every previously reported recall number.**

The null must answer: *what surprise does a benign event produce when scored
against the deployed (frozen) baseline?* The original calibration answered a
different question. It folded **every** training event into the baseline first,
then scored those same events against the completed baseline. Every training edge
was therefore already "seen" and scored ≈ 0, so **the null contained no benign
novelty mass whatsoever.**

Measured on the simulator, the difference is not subtle:

| view | in-sample null p99 | correctly calibrated p99 |
|---|---|---|
| `user_src` | 3.26 | **8.49** |
| `proc_access` | 6.85 | **16.27** |
| `rare_proc` | 1.08 | **15.57** |
| `tgs_enc` | 6.89 | **16.27** |

The in-sample null asserts that a surprise of 3.3 is the 99th percentile of benign
`user_src` behaviour, when benign novelty routinely reaches 8.5. The detector
therefore treats **any first contact** as highly significant. This is a
calibration leak: the model is scored against a distribution it has already
absorbed, which is the same class of error as evaluating a classifier on its
training set.

**Why it survived earlier review:** the simulator gives every employee a static IP
for the life of a run, so benign novelty is artificially rare and the
over-flagging lands almost exclusively on injected attacks. The fixture *hides*
the defect. A real estate — DHCP leases, VDI pools, roaming laptops, new project
shares — produces benign novelty constantly, and the same detector would flood the
queue. This is precisely the "FP figures are a floor" risk, and it was
structural, not merely optimistic.

**The fix** (`TwoTrackEngine._fit_graph`): learn the baseline from the earlier part
of the training period, then calibrate each view's null on a **held-out later
slice** scored against that frozen baseline (`absorb=False`) — exactly the
situation a live benign event meets. The held-out slice is folded into the
deployed baseline afterwards, so the null is calibrated against a slightly smaller
baseline than the one deployed, which can only make it conservative, never
optimistic. The same discipline is applied to the volumetric null (ECOD fitted on
the earlier slice, calibrated on held-out windows).

**Cost, reported honestly:** correcting the calibration lowers measured recall from
50/60 (83%) to **43/60 (72%)** at a comparable FP rate. Two alternatives were
measured and rejected: the in-sample null (83%, wrong) and a fully prequential
score-then-absorb null (41/60, over-conservative because every account's
cold-start first contact inflates the tail). The held-out design is the one that
matches deployment.

## 3. Look-ahead bias

✅ **Sound.** Features are per-(entity, hour) aggregates with no forward
dependence. The manifest is built on train only and pinned; test windows are built
against the pinned manifest. Session resolution (`graph/sessions.py`) is causal —
`resolve(host, when)` binds to the most recent logon at or before `when` and never
looks ahead (`test_session_resolution_is_causal_and_expires`). Graph counters are
updated in event-time order.

## 4. Contamination (attack events in the baseline)

✅ **Both bounds reported.** `oracle` excludes ground-truth attack-window events
from the training baseline (an upper bound no deployment has); `none` is the
unlabelled cold start. Measured across seeds the two are identical, because the
per-view nulls and Dirichlet back-off are robust to a handful of contaminating
edges. The LANL harness reports the same two bounds.

## 5. Transductive learning

✅ **Sound.** `models/inductive_ecod.py` freezes the per-column ECDF at fit; a
score is a pure function of the point scored, independent of batch composition
(`test_volumetric_scores_are_batch_independent`). The per-view graph nulls are
frozen quantile grids. `score()` does not mutate detector state
(`test_score_is_pure`); online adaptation is the explicit, separate `observe` /
`score_stream` path.

## 6. Attribution errors

✅ **Strict.** An attack counts only if an alerted entity is one of its principals
**and** the peak hour driving that entity's alert falls inside the attack span
(`test_attack_attribution_requires_the_alerts_peak_hour`). Under p-value scoring
nearly every (entity, hour) cell carries p < 1, so a looser "any detection during
the window" check would be satisfied by mere activity and would credit a later
attack to earlier behaviour. The LANL harness matches a red-team label on
(second, source-computer, destination-computer, user∈{src_user, dst_user}) —
exact, and robust to which side carries the compromised credential.

## 7. Train/test separation

✅ **Correct for the method.** Time-ordered split. Entity overlap between train
and test is *intended*: the method is a per-entity self-baseline, so an
entity-disjoint split would measure a different (and wrong) task. This is verified
non-defective, not overlooked.

## 8. Simulator bias

⚠️ **The largest residual limitation, documented as an FP floor.** The simulator's
employees hold static IPs for the life of a run, so it cannot produce the DHCP
churn, VDI pools, and roaming laptops that dominate real-world `user_src` novelty
false positives — the FP figures are a floor. Its per-department server access is
deterministic, which flatters any peer/volume model (the peer track was removed
partly for underperforming even under that bias). Attacks are grounded in MITRE
field signatures but are, by construction, detectable via the traces the engine
reads; the simulator cannot represent an attacker who blends into existing
relationships. **No self-generated fixture can retire this risk — only real data
(LANL 2015 / OpTC) can, which is why the `lanl-eval` harness exists.**

## 9. Misleading benchmark methodology

✅ **Addressed.** Attack placement is balanced and seed-varied so every technique
is scored (a positional schedule would silently test only a fixed subset).
Per-technique recall is reported with n; false positives are counted with no
exempt regions; six seeds; both contamination bounds. The LANL harness reports an
ROC (TPR@FPR + AUC), not a single hand-picked operating point.

## 10. Residual, honest limitations

- ⚠️ **Low-volume views have coarse p-value resolution.** A view seen only a few
  dozen times in training has its null floored near `1/(n+1)`, so its most extreme
  p-value cannot be very small. This is correct (you cannot assert significance you
  have no evidence for) and is exactly why `account_manipulation` — whose signal
  lives in the sparse `dir_op` view — is not detected (0 of 5 across the six
  committed seeds, contamination=none) rather than strong. It is a property of the
  evidence, not a tuning failure; the sparse-view remedies (empirical-Bayes
  pooling, EVT tail modelling) are documented as the extension path in the final
  report rather than claimed as implemented.
- ⚠️ **The LANL ROC point is in-sample.** TPR@FPR is read from the test-set ROC,
  the literature convention; a held-out threshold calibration would be stricter.
- ⚠️ **Online scoring on LANL adapts (`absorb=True`).** A repeated malicious edge
  is folded into the baseline unless it exceeds the MIDAS-F non-absorption
  threshold, which can lower recall on reused malicious connections — the
  streaming trade-off, stated.

## Verdict

Both harnesses are free of the leakage classes that inflate ITDR metrics. The one
irreducible gap is the absence of real-world data; the methodology is built so
that gap is visible (FP floor, ROC harness ready) rather than hidden.
