# THROUGHLINE

**One evidence-first security knowledge graph that thirteen separate tools write into, so "what happened, how did it start, who did it, and how sure are we?" becomes a single query with a cited, confidence-graded answer.**

**Contribution:** every engine's conclusion becomes a reliability-graded *claim* in one graph, and only *independent* engines are fused (noisy-OR over the best claim of each engine), with `UNKNOWN` as a competing attribution hypothesis. On public data this ranks the emulated technique first more often than the best single engine or an unfused union (hit@1 0.37 vs 0.26 for Sigma alone, +0.11 [0.05, 0.18], 97 real attack captures) and makes confident attributions right more often without adding confident errors (19.2% vs 13.0%, exact McNemar p = 0.0003, 448 leakage-controlled cases). The [ablation](evaluation.md#b1-technique-identification-and-the-ablation) isolates which part of the evidence model carries the gain.

[![The investigation console on a real OTRF capture](assets/console.png)](demo/index.html)

<div class="grid cards" markdown>

- **[Try it](#try-it-in-60-seconds)**: the live console, `pip install` or a container.
- **[How it works](how-it-works.md)**: one real capture followed from raw event to cited answer.
- **[Evaluation](evaluation.md)**: methodology, every result with its interval, what did not work.
- **[Reproduce](reproduce.md)**: exact commands, expected numbers, runtimes.

</div>

## Try it in 60 seconds

1. **In the browser:** the [live console](demo/index.html) opens on a real OTRF capture (LSASS dumped through `comsvcs.dll`) run through every engine. Click a claim id to see how its confidence was computed.
2. **On your machine** (Python 3.11+):
   ```bash
   pip install "throughline @ git+https://github.com/rakshit-737/throughline-security-knowledge-graph"
   throughline demo            # synthetic supply-chain intrusion, a cited root-cause chain in about a second
   ```
3. **In a container:** `docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/throughline-security-knowledge-graph:latest`, then open the console link it logs.

## Headline results

| question | THROUGHLINE | best single engine / baseline |
| --- | --- | --- |
| Emulated technique is the top claim (hit@1, 97 OTRF captures, ties in expectation) | **0.372** [0.288, 0.462] | Sigma alone 0.259 [0.201, 0.324] |
| Calibrated Brier on one shared set of 785 claims | **0.111** | Sigma alone 0.123 (difference -0.013 [-0.020, -0.006]) |
| Confident attribution that is right (448 leave-report-out cases) | **19.2%**, 0.7% confidently wrong | DRAGNET 13.0%, OCCAM 13.2% |
| Lateral movement stitched on the APT29 evaluation (days 1 + 2) | **3 of 3 true host pairs, 0 false** | 1.0.0: 3 true of 6 joined pairs |
| Technique ranking vs the APT29 emulation plan (precision@10, day 1 / day 2) | **0.40 / 0.33** | Sigma alone 0.33 / 0.22 |

What does **not** work is measured on the same pages: incident grouping adds nothing to technique ranking, incident prioritisation is no better than Sigma severity, the 15.8x alert compression is 2.2x against de-duplicated alerts, new malware families cannot be attributed from behaviour, and neither intel engine names APT29 even from the emulation plan's own techniques. See [Evaluation](evaluation.md) and [Limitations](limitations.md).

## Safety

THROUGHLINE reasons about attacks; it performs none. Attack data is replayed from public logs, the simulation slot only emits a dry-run plan, CI only ever runs read-only administration commands on its own throwaway runner, and drafted detections stay unreviewed. See [Security](security.md).
