# THROUGHLINE

**One evidence-first security knowledge graph that thirteen separate tools write into, so "what happened, how did it start, who did it, and how sure are we?" becomes a single query with a cited, confidence-graded answer.**

Every node and edge is a *claim* with a source, a method, an Admiralty reliability grade and a confidence computed from independent corroboration and contradiction. The sibling projects of this portfolio plug in as engines that read and write only that graph (Sigma detection, provenance reconstruction, ACH attribution, control posture, emulation plans, supply-chain lineage, attack paths, malware and network analysis). THROUGHLINE adds what none of them has alone: cross-engine correlation into incidents, fused and calibrated confidence, a read-only investigator that cites every claim, and a detection feedback loop.

> Every tool here already exists separately. The point is that the answer lives in one graph, and that the graph says how sure it is.

<div class="grid cards" markdown>

- **[Getting started](getting-started.md)**: install, run the synthetic demo, then a real capture.
- **[Live demo](demo/index.html)**: the investigation console, pre-rendered on the synthetic supply-chain intrusion (type `checkout-7`).
- **[Benchmarks](benchmarks.md)**: five benchmarks on public data, each against a single-engine baseline.
- **[Architecture](architecture.md)**: engines, the claim model, correlation.

</div>

## Headline numbers

| question | THROUGHLINE | best single engine / baseline |
| --- | --- | --- |
| Emulated technique is the top claim (hit@1, 95 OTRF captures) | **0.400** | Sigma alone 0.337 |
| Calibrated probability quality (Brier) | **0.110** | Sigma alone 0.130 |
| Alert load | **376 incidents** | 5,994 Sigma alerts |
| Confident attribution that is right (temporal hold-out) | **41%**, 0% confidently wrong | DRAGNET 24%, OCCAM 24% |

What does not work well is reported on the same pages: see [Benchmarks](benchmarks.md) and [Limitations](limitations.md).

## Safety

THROUGHLINE reasons about attacks; it performs none. Attack data is replayed from public logs, the simulation slot only emits a dry-run plan, and drafted detections stay unreviewed. See [Security](security.md).
