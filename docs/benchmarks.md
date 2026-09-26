# Benchmarks and results

## Headline table

All numbers come from `results/*.json`, produced by the scripts in `benchmarks/` on public data (see [Datasets](datasets.md)). Baselines run on identical inputs.

| question | data | THROUGHLINE | best single engine / baseline |
| --- | --- | --- | --- |
| Is the emulated technique the **top** claim? (hit@1) | 95 labelled OTRF attack captures | **0.400** (MRR 0.511) | Sigma alone 0.337 (MRR 0.457); paired bootstrap p = 0.013 on MRR |
| Is it claimed at all? (recall) | same | 0.695 | Sigma alone 0.674, provenance alone 0.432 |
| Probability quality after cross-validated calibration (Brier, lower is better) | 769 technique claims | **0.110** (ECE 0.036; raw fused ECE 0.379) | Sigma alone 0.130 (ECE 0.032) |
| Alert load | same | **376 incidents** | 5,994 Sigma alerts (15.9x more) |
| Confident attribution that is right, temporal hold-out | 17 ATT&CK campaigns, v10.1 profiles | **41%**, 0% confidently wrong | DRAGNET 24%, OCCAM 24%, TTP similarity 18% |
| Confidently wrong under planted false flags (level 2) | same | **0%** | TTP similarity 88%, DRAGNET 18%, OCCAM 0% |
| Close detection gaps from the investigation (feedback loop) | 31 undetected captures | 4 gaps closed; 20 of 25 drafts stopped by the false-positive gate | ANVIL keyword drafter: 3 closed, 17 of 20 stopped |
| Scale, full APT29 evaluation day 1 | 196,081 Windows events | 152,833 claims, 2,888 alerts into 60 incidents in 13 min; one investigation in 49-114 ms | - |
| Which commit introduced a vulnerable pin? | healthchecks' 236 pin changes + OSV | 15/15 agree with `git blame` at HEAD | (TRACEGATE's own benchmark: 97.5% on 365 pins) |

What does **not** work well, measured the same way: behaviour-only attribution of the real APT29 telemetry does not name APT29 (THROUGHLINE correctly refuses to name anyone with confidence); at the "name anyone" operating point the fused verdict still follows DRAGNET onto a planted decoy in 41% of level-2 false-flag cases, where OCCAM alone stays at 0%; and raw fused confidence is a good ranking score but not a probability until calibrated. Details and caveats are below.

## In detail

### B1 - Siloed vs unified technique identification (95 real attack captures)

Each [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) atomic capture is real Windows telemetry (Sysmon, Security, PowerShell logs) recorded while one known ATT&CK technique was emulated. It is replayed through ANVIL (2,410 compiled SigmaHQ Windows rules), REVENANT and the correlation engine. A claim is correct if its parent technique matches the label. Script: `benchmarks/bench_otrf.py`, output: `results/otrf_core.json`.

| analyst | recall | hit@1 [95% CI] | MRR [95% CI] | AUC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Sigma alert queue alone (ANVIL, confidence from rule level) | 0.674 | 0.337 [0.24, 0.43] | 0.457 [0.37, 0.54] | 0.665 | 0.269 | 0.371 |
| Provenance heuristics alone (REVENANT) | 0.432 | 0.305 | 0.358 | 0.724 | 0.198 | 0.216 |
| Both engines, unfused (max) | 0.695 | 0.347 | 0.464 | 0.707 | 0.252 | 0.365 |
| **THROUGHLINE fused** (incident-level noisy-OR over independent engines) | **0.695** | **0.400 [0.31, 0.49]** | **0.511 [0.43, 0.59]** | **0.754** | 0.257 | 0.379 |
| Sigma alone + Platt map, 5-fold cross-validated by capture | - | - | - | 0.641 | 0.130 | 0.032 |
| both unfused + Platt map | - | - | - | 0.678 | 0.117 | 0.028 |
| **fused + Platt map** | - | - | - | 0.744 | **0.110** | 0.036 |

![methods](figures/otrf_methods.png) ![reliability](figures/otrf_reliability.png)

- The gain is in **ranking**: when ANVIL and REVENANT independently point at the same technique inside one incident, noisy-OR lifts it above single-engine noise. Fused beats Sigma alone on MRR with paired-bootstrap p = 0.013, and beats the unfused union with p = 0.022. Recall barely moves, because fusion cannot find what no engine saw.
- **Raw confidence, fused or not, is over-confident** (ECE 0.37-0.38): most claimed techniques in a capture are real detections of *incidental* behaviour, not the labelled one. A cross-validated Platt map fixes calibration for any engine (ECE about 0.03), so calibration is not a fusion effect. What fusion adds is discrimination (AUC 0.74 vs 0.64 after calibration), which is why its calibrated Brier score is the best (0.110 vs 0.130 for Sigma alone). The fused map ships in the package and incidents report both numbers ([ADR-0006](adr/0006-engine-scores-and-calibration.md)).
- Sigma-alone recall (67.4%) matches GAUNTLET's independent measurement of the same rule set on the same captures (66.7%, 96 captures), a useful sanity check.
- "Precision" is not reported as a headline because the labels are single-technique: a capture labelled T1003.001 in which PowerShell (T1059.001) also genuinely ran counts the PowerShell claim as wrong.

### B2 - Alert-to-incident compression

The same run clusters processes that carry technique claims by their **story root** (the child of a session or service boundary process such as `explorer.exe`, `services.exe` or `wmiprvse.exe`). Across the 95 captures, **5,994 Sigma alerts become 376 incidents** (15.9x; median 17 alerts and 2 incidents per capture). The labelled technique is in the top-ranked incident for 55.8% of captures and in some incident for 67.4%, which is also the ceiling set by detection recall.

### B3 - Attribution: two ACH engines fused vs each alone vs naive similarity

Cases are MITRE ATT&CK campaigns with an `attributed-to` group; evidence is the campaign's techniques and software. In the **temporal** setting the group profiles come from ATT&CK v10.1 (Nov 2021) and only campaigns documented later in v19.2 are scored (17 whose culprit exists in v10.1). The **retrospective** setting uses v19.2 for both (25 campaigns, optimistic). False flags follow DRAGNET's stress test: a copied Rich header and decoy-language strings (level 1), plus a malware family exclusive to the decoy group (level 2). OCCAM receives equivalent spoofable markers. Script: `benchmarks/bench_attribution.py`.

"Confident" means each method's own confidence rule: DRAGNET MEDIUM or higher, OCCAM moderate or higher, the similarity baseline p >= 0.8, THROUGHLINE fused confidence >= 0.5 ([ADR-0008](adr/0008-attribution-fusion.md)).

| temporal hold-out (n = 17) | TTP similarity | DRAGNET | OCCAM | **THROUGHLINE fused** |
| --- | ---: | ---: | ---: | ---: |
| clean: top-1 (named the right actor, any confidence) | **0.53** | 0.41 | 0.47 | 0.41 |
| clean: confident and right | 0.18 | 0.24 | 0.24 | **0.41** |
| clean: named a wrong actor (any confidence) | 0.47 | 0.12 | 0.24 | **0.06** |
| false flag L1: confidently wrong | 0.71 | 0.00 | 0.00 | 0.00 |
| false flag L2: confidently wrong | 0.88 | 0.18 | 0.00 | **0.00** |
| false flag L2: named the decoy (any confidence) | 0.88 | 0.53 | **0.00** | 0.41 |

| retrospective (n = 25) | TTP similarity | DRAGNET | OCCAM | **fused** |
| --- | ---: | ---: | ---: | ---: |
| clean: top-1 | 0.40 | 0.56 | 0.36 | **0.64** |
| clean: confident and right | 0.04 | 0.20 | 0.08 | **0.24** |
| false flag L2: confidently wrong | 1.00 | 0.24 | 0.04 | 0.04 |

![attribution](figures/attribution.png)

When the two engines agree, fused confidence rises past 0.5 and the platform commits; when either abstains or they disagree, `UNKNOWN` competes and it does not. That doubles the confident-and-right rate on the clean temporal cases without adding a confident error. It does **not** improve plain top-1 accuracy on the temporal hold-out: the naive TTP-similarity baseline names the right actor first more often (0.53 vs 0.41), but it also names a wrong one in 47% of clean cases and is confidently wrong under every level of false flag; the fused verdict trades some top-1 hits for abstaining (`UNKNOWN`) when the engines disagree. It does **not** make the platform robust at the "name anyone" operating point: a planted exclusive malware family pulls DRAGNET, and with it the top-ranked fused hypothesis, onto the decoy in 41% of level-2 cases, while OCCAM alone never names the decoy. n is small (17 and 25 cases), so one case moves a rate by 4-6 points.

### B4 - End to end on the APT29 evaluation (day 1, 196,081 events)

MITRE's ATT&CK Evaluations round 2 emulated APT29 on a small Windows domain; OTRF published the host logs. The capture has no per-event labels but the actor is known. Script: `benchmarks/demo_apt29.py`, output: `results/apt29_day1.json`.

- **Graph:** 25,453 nodes, 52,415 edges, 152,833 claims from 145,483 normalised events (the rest are event types the connector deliberately does not model). No record rejected.
- **Alerts to incidents:** 2,888 Sigma alerts, 60 incidents. The top incident is rooted at the RTLO-named payload `‮cod.3aka3.scr` (the evaluation's initial access), groups 42 processes and 1,048 alerts, and carries 38 techniques led by LSASS dumping (0.87) and PowerShell (0.82).
- **Root cause, as the investigator reports it:** `Explorer.EXE -> ‮cod.3aka3.scr -> cmd.exe -> sdclt.exe -> control.exe -> PowerShell.exe -noni -noexit -ep bypass -window hidden ...`, which is the evaluation's documented UAC bypass through `sdclt`. ROOTLINE independently traces the same incident back to the attacker's C2 socket `192.168.0.5:443`.
- **Corroboration:** the investigator reports that LSASS dumping in that incident is backed by two independent engines (ANVIL's Sigma rules and REVENANT's provenance heuristics), with the claim ids.
- **Posture:** of 63 observed techniques, VANTAGE marks 59 detected and 4 missed (a detection existed for a log source that was present, but none fired), and names the CIS v8 safeguards that claim to mitigate 46 of them; GAUNTLET emits a dry-run Atomic Red Team plan for the 4 missed ones.
- **Attribution:** neither engine names APT29 from the observed techniques. DRAGNET abstains (APT29 ranks 45th of 176 on the top incident) and OCCAM's shortlist does not include it; the fused verdict is `UNKNOWN` at 0.25. Behaviour-only attribution of noisy endpoint detections is weak, and the platform says so instead of guessing.
- **Cost:** 803 s end to end on a laptop (ANVIL 216 s, REVENANT 346 s, ROOTLINE 49 s, graph build and the other engines the rest), 1.1 GB peak Python heap. Investigating one incident (seven read-only graph queries with citations) takes 49-114 ms on the 25k-node graph.

### B5 - The feedback loop: undetected -> drafted -> gated

Of the 95 captures, Sigma detected the labelled technique in 64; the other **31 are gaps**. For each gap, `throughline.reasoning.loop` keeps the command lines and PowerShell script blocks that occur in no *unrelated* capture (everything else is lab background noise), hands them to ANVIL's heuristic drafter, and accepts a draft only if it fires on its own capture and on **zero** events of every unrelated capture. ANVIL's naive keyword drafter is the baseline. Script: `benchmarks/bench_loop.py`, output: `results/feedback_loop.json`.

| | heuristic drafter | keyword baseline |
| --- | ---: | ---: |
| gaps with novel behaviour / with drafts | 21 / 17 | 21 / 20 |
| drafts | 25 | 20 |
| **rejected by the false-positive gate** | **20 (80%)** | 17 (85%) |
| accepted (fire on own capture, 0 hits elsewhere) | 4 | 3 |
| coverage before -> after (in-sample) | 67.4% -> 71.6% | 67.4% -> 70.5% |
| accepted rule also fires on another capture of the same technique | 0 | 1 |

The measurable value is the **gate**: four out of five automatically drafted rules would have fired on unrelated activity and never reach review. The coverage gain is in-sample by construction (the rule was mined from the capture it is scored on), and no accepted heuristic draft generalised to a second capture of its technique, so this is a triage aid for a detection engineer, not a self-improving detector. The drafts also show why review stays mandatory: the accepted Zerologon rule keys on `/target:MORDORDC.theshire.local`, a lab hostname the drafter's IOC filter missed. Every accepted draft is written `status: experimental`, `reviewed: false`.

### Supply chain on a real repository

TRACEGATE walks the 236 first-parent commits that changed a pin in [healthchecks](https://github.com/healthchecks/healthchecks)'s `requirements.txt`; OSV's PyPI dump says which pinned versions carry an advisory. The graph then answers "which commit, by whom, introduced this vulnerable version, and for how long was it pinned?" as an ordinary root-cause walk. 311 distinct pinned versions, 119 of which carry at least one OSV advisory (262 advisories; most were published *after* the pin, so this is exposure in hindsight, not negligence). Median time such a version stayed pinned: 30 days. None is still pinned at the analysed commit. For the 15 pins present at HEAD, the graph's introducing commit agrees with `git blame` 15/15. Script: `benchmarks/demo_supplychain.py`.

## Reproducibility

```bash
python scripts/download_data.py all
python benchmarks/bench_otrf.py          # B1 + B2, ~15 min; per-capture rows cached, --from-cache re-scores
python benchmarks/bench_attribution.py   # B3, ~2 min
python benchmarks/demo_apt29.py --day 1  # B4, ~15 min, ~2.6 GB RSS
python benchmarks/bench_loop.py          # B5
python benchmarks/demo_supplychain.py
python benchmarks/figures.py
```

`make data`, `make bench` and `make demo-real` wrap the same commands. Everything is deterministic: no random seeds are involved except the bootstrap CIs (seed 0) and DRAGNET's decoy choice (seed 7). Sibling engines are pinned by commit, datasets by commit and checksum. Timings are from a Windows laptop running Python 3.14 with other jobs in parallel: compiling the 2,410 SigmaHQ rules takes about a minute once per process, a typical atomic capture about 6 s through ANVIL + REVENANT + correlation, and the 196k-event APT29 day 803 s end to end (ANVIL 216 s, REVENANT 346 s, ROOTLINE 49 s).
