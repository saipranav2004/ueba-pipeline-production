# ITDR Behavioral Engine (`ueba-pipeline`): Evidence-Backed Next Steps, Limitations, and Validation Datasets

The single most important conclusion: **the engine's 71.7% recall is not evidence of real-world performance, because it is measured on a simulator written by the detector's own author, using view-design decisions that were themselves derived from that same simulator — and the published literature shows that headline detection scores on real data (LANL) collapse under honest evaluation.** Everything below is organized as the requested set of Markdown deliverable files (one per recommendation, one per dataset, plus a ranked index), with each claim tied to peer-reviewed papers, official documentation, or mature open-source projects, and with strength-of-evidence flagged throughout.

## TL;DR
- **Break the simulator circularity first.** The literature shows real-data detection scores are far weaker than paper AUCs suggest: on LANL (>1B events, 749 malicious), the prior state-of-the-art Euler achieves only 0.0448 average precision and the best redesign (ARGUS) only 0.3227 AP (Xu, Shu & Li, IEEE S&P 2024). The engine's simulator recall of 71.7% therefore cannot be treated as a real-world number.
- **The two structural failures (account manipulation 0/7, NTDS dump 0/5) are partly genuine evidence limits but are also addressable with published methods the engine does not use:** empirical-Bayes/hierarchical pooling for the sparse `dir_op` null, conformal p-values for calibration under sparsity, and Extreme Value Theory (peaks-over-threshold) to break the 1/(n+1) resolution floor.
- **No public dataset can validate all six views.** LANL feeds only `user_src`/`src_dst`; no realistic-benign public dataset *verifiably* feeds `dir_op` (4728/4732/4662) or `tgs_enc` (4769 encryption type). Those two views should be reclassified as **unvalidated** until LANL 2017 (real benign novelty) and LMDG/LMTrace 2025 are tested.

## Key Findings
1. **The core edge-surprise model is defensible in class; its benchmark is not.** The Dirichlet-smoothed conditional model belongs to the legitimate Heard/Turcotte/Sanna Passino Bayesian family used at LANL. The problem is the evaluation, not the model family.
2. **Literature AUCs on LANL are largely untrustworthy and not comparable across papers.** Independent replications expose the same leakage classes the project audits itself for (non-causal splits, contamination, protocol shortcuts). Euler's own reported LANL AP (~5.23%) was **not reproducible** by independent researchers using Euler's public code.
3. **The "benign novelty rate" view-admission criterion has no published support** as a validity criterion; the specific rates (7.3%/0.4%/9.1%) are simulator configuration artifacts.
4. **Several well-evidenced views are missing:** periodicity / human-vs-automated separation, logon-type transitions, NTLM-vs-Kerberos downgrade.
5. **The dead FDR mode is a fixable statistics problem** — EVT tail modelling and online-FDR (LORD / e-BH) are the evidence-backed fixes for the 1/(n+1) floor and the arbitrary daily budget.
6. **NHI modelling requires a different model class** (periodicity-first, low-entropy, tight baselines), supported by Heard/Rubin-Delanchy periodicity work.
7. **pickle+HMAC is not defensible for production** model persistence; safetensors is the independently audited alternative.
8. **Scaling above 253 entities is entirely unmeasured** — a real risk given the removed peer track already produced a ~2GB dense bundle at 253 entities.

---

## Details — Deliverable Markdown Files

### FILE: `recommendations/01-validate-on-real-data-lanl.md`

**What it is.** A program of work to move validation off the self-authored `enterprise_simulator/` onto real enterprise telemetry: LANL 2017 (Unified Host and Network Data Set) for benign-novelty and false-positive characterization, and LANL 2015 (Comprehensive, Multi-Source Cyber-Security Events) for labelled lateral-movement recall.

**Official source.** LANL 2017: https://csr.lanl.gov/data/2017/ ; LANL 2015: https://csr.lanl.gov/data/cyber1/

**Why it should be considered.** The project's deepest methodological problem is circularity: the six-view design decisions (device- vs IP-keying at 7.3% vs 91.8% benign novelty; cipher-keyed Kerberoasting at 0.4%; operation-class `dir_op` at 9.1% vs 72%) are all derived from the simulator, and performance is then measured on the same simulator. These are properties of the simulator's configuration, not of real Active Directory. LANL 2017 is real enterprise Windows telemetry (Windows Logging Service) with real EventIDs (4624/4625/4634/4672/4768/4769/4776), spanning 89 days and, per Turcotte et al., **27,436 enterprise Windows computers** — a genuine large-scale AD estate.

**How it would improve this project.** LANL 2017 can directly re-measure the real benign novelty rates for `user_src`, `src_dst` and `kerb_ctx`, testing the design premise that currently rests on simulator numbers. If the real device-keyed novelty rate is not ~7.3%, the whole view-admission logic must be revisited. LANL 2015 provides labelled red-team ground truth to measure real recall for `user_src`/`src_dst`.

**Limitations/requirements.** LANL 2017 has **no** red-team labels — it can measure the benign/null side (novelty, false-positive behaviour) but **not** recall. LANL 2015 is a flat 9-column CSV with no EventIDs, feeding only two of six views. Neither contains Sysmon. Methodologically, an unlabelled dataset can bound how often benign activity *looks* novel but cannot establish true-positive recall; that requires labels. Both are CC0 with no data-use agreement (only a courtesy email form).

---

### FILE: `recommendations/02-fix-benchmark-leakage.md`

**What it is.** Adopt the honest evaluation protocol emerging from independent LANL replications, and treat published AUCs as non-comparable until protocol-audited.

**Official source.** Xu, Shu & Li, "Understanding and Bridging the Gap Between Unsupervised Network Representation Learning and Security Analytics," IEEE S&P 2024 (https://c0ldstudy.github.io/commons/papers/SP2024_paper118.pdf); "Designing a reliable lateral movement detector using a graph foundation model," arXiv:2504.13527; Entente follow-up, arXiv:2503.14284.

**Why it should be considered.** Xu et al. show that on LANL, **Euler (prior state-of-the-art) reaches only 0.0448 average precision, and their improved ARGUS only 0.3227 AP** — versus AP >0.9 on non-security graphs (Enron/Colab/Facebook). AUC hides this collapse because it is insensitive to the ~0.00007% class imbalance. The graph-foundation-model paper documents a concrete leakage: filtering to only NTLM authentication events makes lateral movement artificially easy (red-team events coincide with NTLM), and restricting to the first 14 days mechanically inflates the malicious fraction. The Entente authors further note they **could not reproduce Euler's claimed ~5.23% LANL AP from its own GitHub code.** These are exactly the leakage classes (non-causal splits, contamination, invalid benchmarking) the project audits itself for.

**How it would improve this project.** Prevents the project from anchoring on paper AUCs of 0.91–0.99 (Euler, Jbeil) that do not survive honest protocols, and establishes precision/recall at a fixed operating point (not AUC) as the correct metric under extreme imbalance.

**Limitations/requirements.** Any cross-method comparison must be re-run under matched, causal, non-truncated splits; headline paper numbers cannot be cited as targets.

---

### FILE: `recommendations/03-empirical-bayes-pooling-sparse-views.md`

**What it is.** Hierarchical / empirical-Bayes pooling across sparse relationship views so a view with n≈27 benign observations borrows strength from related cells instead of flooring its null at 1/(n+1)≈0.036.

**Official source.** Heard & Rubin-Delanchy, "Network-wide anomaly detection via the Dirichlet process" (IEEE ISI 2016); Sanna Passino & Heard, Bayesian/Poisson-matrix-factorisation modelling of LANL authentication (Data Mining and Knowledge Discovery, 2021).

**Why it should be considered.** The project attributes account-manipulation 0/7 to an "evidence limit": the `dir_op` null floors at 1/(n+1) because n is tiny. Empirical-Bayes pooling is the standard statistical remedy for exactly this small-n resolution problem and is already established in the LANL modelling literature.

**How it would improve this project.** Directly targets the account-manipulation failure by improving null resolution below 0.036 — without inventing an attack-specific rule (consistent with the "no per-attack detectors" principle).

**Limitations/requirements.** Pooling assumes exchangeability across pooled cells; a wrong pooling structure introduces bias. Must be validated on real labelled data (Rec 01), not the simulator.

---

### FILE: `recommendations/04-conformal-pvalues.md`

**What it is.** Conformal anomaly detection to produce finite-sample-valid calibrated p-values (and composable e-values) under sparsity, replacing/augmenting the per-view empirical ECDF.

**Official source.** Hennhöfer et al., "Conformal Anomaly Detection in Python … `nonconform`," arXiv:2605.13642; online conformal p-value / e-value literature (arXiv:2509.03297; arXiv:2407.15733; e-BH boosting, arXiv:2404.17562).

**Why it should be considered.** The engine's calibration is an empirical ECDF floored at 1/(n+1). Conformal methods give distribution-free finite-sample guarantees and integrate with scikit-learn/pyod. E-values compose cleanly under dependence — directly relevant to the project's Tippett/Sidak combination across dependent views, where Sidak assumes independence the views do not have.

**How it would improve this project.** Turns heuristic p-values into calibrated ones with guarantees, and offers a principled dependency-aware alternative to Sidak correction.

**Limitations/requirements.** Conformal validity relies on exchangeability, which the streaming absorbing baseline violates; requires the non-absorbing path (Rec 08) to hold.

---

### FILE: `recommendations/05-evt-tail-modelling.md`

**What it is.** Extreme Value Theory / peaks-over-threshold (SPOT/DSPOT) tail modelling to replace the empirical null floored at 1/(n+1).

**Official source.** Siffer, Fouque, Termier & Largouët, "Anomaly Detection in Streams with Extreme Value Theory," KDD 2017 (https://www.eecs.yorku.ca/course_archive/2017-18/F/6412/reading/kdd17p1067.pdf); reference implementation https://github.com/cbhua/peak-over-threshold.

**Why it should be considered.** The 1/(n+1) floor is a hard resolution limit: no event can be scored more significant than the number of benign observations allows. EVT models the Generalized Pareto tail directly (Pickands–Balkema–de Haan), yielding calibrated probabilities far into the tail from limited data, and DSPOT adds drift handling. On network-flow data, Siffer et al. report, verbatim: *"we get a true positive rate equal to 86% with less than 4%"* false-positive rate using SPOT.

**How it would improve this project.** Breaks the resolution floor the project cites as the root cause of two structural failures, and provides an adaptive statistical threshold instead of a fixed daily alert budget.

**Limitations/requirements.** POT assumes i.i.d./stationary exceedances (DSPOT relaxes this via a moving local mean); tail-fit quality (parameter γ, σ) must be checked. Validate on real data.

---

### FILE: `recommendations/06-online-fdr-alerting.md`

**What it is.** Replace the broken FDR mode and the fixed `alert_budget_per_day=5` with online FDR control (LORD / alpha-investing) or conformal e-value BH variants for dependent tests.

**Official source.** Online-FDR and e-BH literature (e-BH boosting, arXiv:2404.17562; online conformal selection, arXiv:2509.03297; admissible online closed testing with e-values, arXiv:2407.15733).

**Why it should be considered.** The current FDR mode alerts on nothing because the empirical null floors at 1/(n+1); the fallback is an arbitrary budget of 5/day. Online FDR procedures (LORD, alpha-investing) are designed precisely for streaming hypothesis testing under dependency, giving a principled, drift-aware alerting rate with a controllable false-discovery guarantee.

**How it would improve this project.** Replaces an arbitrary alert budget with a defensible, tunable FDR guarantee and revives the dead FDR path.

**Limitations/requirements.** Requires valid p-values first (Recs 04/05); the dependency structure across views/hours must be modelled or conservatively bounded.

---

### FILE: `recommendations/07-add-periodicity-nhi-view.md`

**What it is.** Add a periodicity / human-vs-automated separation component and a distinct NHI (service account / machine identity) model class.

**Official source.** Heard, Rubin-Delanchy & Lawson, "Filtering automated polling traffic in computer network flow data," 2014 IEEE JISIC, pp. 268–271; "Classification of periodic arrivals in event time data for filtering computer network traffic," Statistics and Computing 2020 (https://link.springer.com/article/10.1007/s11222-020-09943-9); reference code https://github.com/fraspass/human_activity; Price-Williams, Heard & Turcotte, "Detecting periodic subsequences in cyber security data," arXiv:1707.00640.

**Why it should be considered.** The engine has almost nothing NHI-specific beyond an Entra sign-in connector, yet supporting NHIs is a stated product requirement. Machine identities differ statistically from humans: strong periodicity, low entropy, narrow baselines. The Heard/Rubin-Delanchy method classifies an edge as automated via the p-value from a Fourier g-test and separates automated from human events on mixed edges — a well-established primitive for building realistic normal-behaviour models. Detecting deviation from a learned period is a strong NHI-compromise signal that the current model class cannot express. (Note: the frequently cited "~7% of tuples are periodic" figure appears in vendor/patent restatements and is **unconfirmed** in the primary papers — treat the *method* as the evidence, not that specific number.)

**How it would improve this project.** Provides genuine NHI behavioural modelling and reduces false positives by modelling automated traffic explicitly rather than lumping it with human activity.

**Limitations/requirements.** Fourier/periodicity tests need sufficient events per edge; cold-start NHIs lack history. Vendor material on NHI detection (Astrix, Obsidian, Aembit) is marketing, not peer-reviewed, and should not be cited as evidence — only the Heard/Rubin-Delanchy work is strong evidence here.

---

### FILE: `recommendations/08-non-absorbing-baseline-poisoning.md`

**What it is.** Harden the streaming path (`absorb=True`) against baseline poisoning by a persistent attacker, using MIDAS-F-style non-absorption plus robust-statistics data sanitization.

**Official source.** Bhatia et al., "Real-Time Anomaly Detection in Edge Streams," TKDD 2022 (MIDAS-F); poisoning/robustness literature (arXiv:2207.03576, "Robustness Evaluation of Deep Unsupervised Learning Algorithms for Intrusion Detection"; Rubinstein et al., "Antidote"; provenance-IDS poisoning discussion in KAIROS, arXiv:2308.05034).

**Why it should be considered.** `absorb=True` lets a slow attacker fold malicious activity into the baseline until it looks normal — a documented failure mode for all anomaly-based IDS. MIDAS-F's non-absorption of anomalous scores is a start but is not, by itself, a complete poisoning defense; the security literature is explicit that data-sanitization/outlier-filtering defenses can be bypassed by "inlier" poison and mimicry.

**How it would improve this project.** Reduces the "boil-the-frog" evasion path; robust-statistics sanitization adds a second, independent layer.

**Limitations/requirements.** No defense is complete — mimicry attacks that stay under threshold remain possible. Requires explicit evaluation against a modelled poisoning adversary rather than assuming MIDAS-F suffices.

---

### FILE: `recommendations/09-replace-pickle-persistence.md`

**What it is.** Replace pickle+HMAC model persistence with a versioned, non-executable serialization format (safetensors for arrays; an explicit schema/JSON for counter and graph structures).

**Official source.** "PickleBall: Secure Deserialization of Pickle-based ML Models," ACM CCS 2025 (https://cs.brown.edu/~vpk/papers/pickleball.ccs25.pdf); safetensors independent audit (Trail of Bits, 2023).

**Why it should be considered.** Pickle implements a virtual machine that permits near-arbitrary code execution on deserialization; numerous malicious pickle models have been found in the wild. HMAC protects integrity only — it does not remove the fundamental unsafety if a signing key leaks or a loader is misused. safetensors is independently audited, non-executable, and considered safe.

**How it would improve this project.** Removes a remote-code-execution class from the model-loading path of a security product — a category error to ship in an ITDR tool.

**Limitations/requirements.** safetensors stores tensors, not arbitrary Python objects, so the bundle's counters/graphs need an explicit schema (JSON or a typed columnar format). Migration effort and a versioned format contract are required.

---

### FILE: `recommendations/10-scale-testing.md`

**What it is.** Measure scaling behaviour from 253 to 10k–100k+ identities before claiming production readiness, and adopt sketching if needed.

**Official source.** King & Huang, "Euler," ACM TOPS 2023 (distributed temporal-graph scaling); MIDAS (Bhatia et al., AAAI 2020) count-min sketch for constant-memory edge streams.

**Why it should be considered.** Real AD estates are 10k–100k+ identities. The removed peer track already produced a dense O(users × dests) ~2GB bundle at only 253 entities, demonstrating memory blow-up risk. O(1) counter updates do not bound the number of *distinct* edges/cells, which can grow super-linearly with estate size. The claim of linear-in-events fit and a ~2.6MB bundle is untested above 253 entities.

**How it would improve this project.** Establishes whether bundle size, fit time and memory remain viable at enterprise scale, or whether count-min-style sketching (as MIDAS uses) is mandatory.

**Limitations/requirements.** Needs a large realistic dataset — LANL 2017's 27,436 Windows computers over 89 days is the natural first scale test.

---

### FILE: `datasets/lanl-2015.md`
**What it is.** LANL Comprehensive, Multi-Source Cyber-Security Events (2015): 58 days, ~1.6B events, with `redteam.txt` ground-truth labels.
**Official source.** https://csr.lanl.gov/data/cyber1/ (CC0, LA-UR-15-23810, no DUA).
**Views fed.** `user_src`, `src_dst` **only** (verified). No EventIDs, no Sysmon, no 4769 encryption type, no `dir_op`.
**Labels / benign realism / size / licence.** Red-team labels present; real enterprise background; ~1.6B events; CC0.
**Why / how it helps.** The only large real dataset with labelled lateral movement for the two authentication views — the baseline recall benchmark.
**Limitations.** Only 2/6 views; flat 9-column schema; extreme class imbalance; well-documented benchmark-leakage pitfalls (NTLM-only filtering, truncated 14-day windows) that must be avoided (Rec 02).

### FILE: `datasets/lanl-2017.md`
**What it is.** LANL Unified Host and Network Data Set: 89–90 days, real Windows hosts via Windows Logging Service, JSON with real EventIDs, ~27,436 Windows computers.
**Official source.** https://csr.lanl.gov/data/2017/ (CC0).
**Views fed.** `user_src`, `src_dst`, `kerb_ctx` (4768/4769/4776 present). No Sysmon → no `proc_access`/`rare_proc`. Presence of the 4769 encryption-type field is **unconfirmed**; no 4728/4732/4662 → no `dir_op`.
**Labels / benign realism / size / licence.** **No** red-team labels; real enterprise background; ~27,436 hosts; CC0.
**Why / how it helps.** The premier source for measuring **real** benign novelty rates to test the simulator-derived 7.3%/0.4%/9.1% premises (Rec 01), and the natural first scale test (Rec 10).
**Limitations.** No labels → cannot measure recall; can only characterise the benign/null side. This is exactly the "measure real benign novelty without labels" use case, which is methodologically sound for validating the *false-positive* side of the design but says nothing about detection power.

### FILE: `datasets/darpa-optc.md`
**What it is.** DARPA Operationally Transparent Cyber: ~17.4B eCAR events, 500–1000 Windows 10 hosts, three multi-day APT scenarios (PowerShell Empire lateral movement, Netcat/RDP exfiltration, malicious software-update trojan).
**Official source.** https://github.com/FiveDirections/OpTC-data ; eCAR spec https://github.com/FiveDirections/OpTC-data/blob/master/ecar.md ; https://ieee-dataport.org/open-access/operationally-transparent-cyber-optc ; analysis arXiv:2103.03080.
**Views fed.** Process/file/flow/registry/module telemetry supports process-lineage modelling relevant to `rare_proc`, and lsass credential-access activity is represented — but eCAR is **not** Windows Security/Sysmon: **no** 4769/4728/4732/4662, and **no** Sysmon-EID-10-format ProcessAccess record (PROCESS actions are principally CREATE/TERMINATE).
**Labels / benign realism / size / licence.** Red-team ground-truth PDF; benign background is **automated VMware agents** ("programmed to complete general tasks … mimicking generic daily user activities"), i.e., simulated not real humans; ~1TB; open access. Malicious events ≈0.0016% (realistic imbalance).
**Why / how it helps.** Best large-scale labelled endpoint dataset for the process/endpoint side of the engine; its imbalance mirrors production.
**Limitations.** Benign is simulator-generated; eCAR requires conversion to Sysmon-like events (lossy for EID 10); no Windows Security EventIDs; network is flow-level only (no pcap); documented data errata.

### FILE: `datasets/otrf-security-datasets.md`
**What it is.** OTRF Security-Datasets (formerly Mordor): pre-recorded Windows Security + Sysmon logs from ATT&CK-mapped attack simulations, by Roberto & Jose Rodriguez.
**Official source.** https://github.com/OTRF/Security-Datasets ; https://securitydatasets.com/create/windows.html
**Views fed.** With proper audit policy can contain Sysmon EID 1/10 (`rare_proc`/`proc_access`) and Kerberos/dir events, but the specific presence of 4769-encryption / 4728 / 4732 / 4662 at file level is **unconfirmed** (repository tree is robots-blocked to automated inspection).
**Labels / benign realism / size / licence.** ATT&CK-technique labelled; **atomic** short single-technique captures — the documented workflow clears the Security and Sysmon logs before each run, so there is minimal incidental benign activity; small scale; open. The PicoDomain authors note Mordor's "main constraint is scale."
**Why / how it helps.** Excellent for unit-testing that the engine's parsers and feature extraction fire correctly on real per-technique attack telemetry.
**Limitations.** No realistic multi-day benign baseline → cannot measure false positives or benign novelty. It is a detection-logic fixture library, not a validation corpus.

### FILE: `datasets/lmdg-lmtrace.md`
**What it is.** LMDG (Lateral Movement Dataset Generation) / LMTrace, 2025. Per the paper (verbatim): *"a 25-day dataset within a 25-VM enterprise environment containing 22 user accounts. The dataset includes 944 GB of host and network logs and embeds 35 multi-stage LM attacks, with malicious events comprising less than 1% of total activity."*
**Official source.** Mabrouk, Hatem, Mamun & Saad, arXiv:2508.02942 ; code https://github.com/WASPLab/LMTrace
**Views fed.** Windows Event Logs across Win10/11 clients + Server 2022 DCs, full multi-domain AD topology. The attack set (AS-REP roasting, Pass-the-Hash, Pass-the-TGT, delegation abuse incl. DCSync, password spray, silver ticket, golden ticket) would generate 4769/4728/4732/4662 — but explicit event-ID presence is **unconfirmed** and must be checked in the repo.
**Labels / benign realism / size / licence.** Fine-grained ground truth via novel "process-tree labeling" mapped to MITRE ATT&CK; benign background is automated-simulated (login/logout timing, breaks, browsing, internal-server access) but multi-day with a realistic <1% malicious ratio.
**Why / how it helps.** The **closest public fit** to the engine's full AD/Kerberos scope with a realistic-ratio multi-day background and fine-grained labels — the best single candidate to attempt validation of `dir_op`/`tgs_enc` if the event IDs are confirmed present.
**Limitations.** New (2025), less independently validated; benign is simulated (not real humans); event-ID coverage needs direct confirmation before relying on it for `dir_op`/`tgs_enc`.

### FILE: `datasets/evtx-attack-samples.md`
**What it is.** sbousseaden/EVTX-ATTACK-SAMPLES: >270 per-technique EVTX captures explicitly including the AD/Kerberos and Sysmon events the engine needs.
**Official source.** https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
**Views fed.** **Confirmed** via README: Sysmon EID 1 (ProcessCreate, many files) and EID 10 (ProcessAccess/lsass — e.g., procdump/taskmgr lsass dump "sysmon 10 & 11", Mimikatz "sysmon 7 and 10"); **4662 DCSync** (`CA_DCSync_4662.evtx`, with the Replicating Directory Changes extended right); SPN-add/Kerberoasting ACL artifacts. This confirms real fixtures exist for `proc_access`, `rare_proc`, and a `dir_op` (4662) sample.
**Labels / benign realism / size / licence.** Implicitly labelled by filename/technique; **no** benign background; atomic; open.
**Why / how it helps.** The only confirmed public source of a real 4662 DCSync capture plus Sysmon-EID-10 lsass-access samples — ideal ground-truth positive fixtures to prove the engine's feature extraction fires on genuine `dir_op`/`proc_access` telemetry.
**Limitations.** No benign background, no timeline → detection-logic unit tests only, never validation of false-positive rate or recall.

### FILE: `datasets/others-assessed.md`
- **Splunk BOTS v1/v2/v3** (CC0; https://github.com/splunk/botsv3): realistic multi-source incident data including Sysmon, Suricata, and more, but distributed Splunk-indexed and scenario/CTF-oriented — not structured for per-view benign-novelty measurement.
- **AIT-LDS v1.1/v2.0** (Zenodo, DOI 10.5281/zenodo.5789064): labelled with ground truth, but explicitly **synthetic**, Linux/web-server-centric (Apache, Horde, Exim, Suricata), with minimal Windows AD telemetry.
- **PicoDomain** (https://github.com/iHeartGraph/PicoDomain): compact Zeek logs with red-team labels; small, simulated, network-level only (no Windows Security/Sysmon; no `proc_access`/`dir_op`).
- **CERT Insider Threat r4.2/r6.2:** confirmed **synthetic**; insider-threat focus, not AD attack telemetry.
- **DAPT-2020 / Unraveled:** semi-synthetic APT datasets, network-flow-centric, weak Windows AD event coverage.
- **GOAD (Game of Active Directory)** (https://github.com/Orange-Cyberdefense/GOAD) **and DetectionLab:** deployable vulnerable AD **labs**, NOT datasets — they ship no pre-recorded labelled logs and no benign background; you would have to generate and label telemetry yourself.
- **DARPA TC Engagements 3/5:** Linux/FreeBSD-centric provenance (THEIA/TRACE/CADETS), not Windows AD; ground-truth documents are notoriously hard to convert to entity-level labels.

---

## Recommendations (ranked — the README/index)

**Do FIRST (weeks) — nothing else is meaningful until the circularity is broken:**
1. **Rec 01 + Rec 02** — Validate on LANL 2017 (real benign novelty for `user_src`/`src_dst`/`kerb_ctx`) and LANL 2015 (labelled recall), under leakage-audited protocols. **Decision threshold:** if the real device-keyed benign novelty rate diverges materially from the simulator's 7.3%, the view-admission logic must be redesigned before any further tuning.
2. **Rec 09** — Replace pickle persistence with safetensors + explicit schema. Low effort, removes an RCE class from a security product.

**Do SECOND (1–2 months):**
3. **Rec 05 (EVT/POT) + Rec 03 (empirical Bayes)** — Attack the 1/(n+1) floor underlying the account-manipulation and NTDS failures. **Benchmark:** does account-manipulation recall exceed 0/7 on real labelled data **without** any attack-specific rule? If not, the "evidence limit" claim is confirmed; if yes, it was a fixable resolution limit.
4. **Rec 06** — Fix the dead FDR path with online FDR (LORD / e-BH) once valid p-values exist.
5. **Rec 10** — Scale-test on LANL 2017's 27,436 hosts; adopt count-min sketching if memory/latency break.

**Do THIRD (quarter+):**
6. **Rec 07** — Add the periodicity / NHI model class (a stated product requirement currently almost absent).
7. **Rec 04** — Conformal calibration, once the non-absorbing path (Rec 08) makes exchangeability defensible.
8. **Rec 08** — Poisoning hardening beyond MIDAS-F, evaluated against an explicit adversary.

**STOP doing:**
- **Stop citing simulator recall (71.7%) as evidence of real-world performance.** It is an in-distribution self-test.
- **Stop treating `dir_op` and `tgs_enc` as validated.** No public realistic-benign dataset verifiably feeds them; reclassify as **unvalidated** pending confirmation of event-ID coverage in LMDG/LMTrace and EVTX-ATTACK-SAMPLES fixtures. If no realistic-benign source can be found, these views cannot claim a measured false-positive rate and may need to be cut or gated behind an "unvalidated" flag.
- **Stop chasing paper AUCs of 0.91–0.99 (Euler/Jbeil) as targets.** On honest LANL protocols the achievable average precision is a fraction of that (Euler 0.0448 AP; best redesign ~0.32 AP), and even those numbers have reproducibility problems.
- **Do not add per-attack detectors** for account manipulation or NTDS dump. Fix the statistical resolution (Recs 03/05) instead — this is the architecturally correct response.

## Caveats
- The account-manipulation (0/7) and NTDS-dump (0/5) recall figures are **partly genuine evidence limits**; the recommended fixes (empirical Bayes, EVT, conformal) are hypotheses to test on real labelled data, not guaranteed wins. NTDS dump specifically involves tools (`vssadmin`, `ntdsutil`) that run legitimately on DCs — behavioral separation there may remain hard even with better statistics, and process-lineage/command-line modelling would need real DC baselines to validate.
- Several dataset event-ID claims are **unconfirmed at file level** and must be verified by direct inspection: LMDG/LMTrace's 4769-encryption/4728/4732/4662 presence; OTRF's specific AD event IDs; and whether LANL 2017's 4769 records carry the ticket encryption-type field. These are load-bearing for whether `tgs_enc`/`dir_op` can *ever* be validated on public data.
- The published detection AUCs (Euler 0.91–0.98 on some datasets; Jbeil ~0.99 on LANL) are **claims from the originating papers**; the independent IEEE S&P 2024 replication (Euler AP 0.0448 on LANL) and the Entente non-reproducibility note are the stronger evidence about real-world behaviour and should be weighted accordingly.
- NHI vendor material (Astrix, Obsidian, Aembit, Entro) is **marketing, not peer-reviewed**, and is excluded from the evidence base for Rec 07; only the Heard/Rubin-Delanchy/Turcotte periodicity work is treated as strong evidence.
- The "~7% of authentication tuples are periodic" figure sometimes attributed to the LANL periodicity work is **unconfirmed** in the primary papers; rely on the *method* (Fourier g-test edge classification), not that specific rate.