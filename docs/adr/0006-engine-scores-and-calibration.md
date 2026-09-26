# ADR-0006: Engines may report their own probability; calibration is a separate, fitted map

**Status:** Accepted (amends ADR-0003)

## Context
ADR-0003 derives every base confidence from `method prior x source reliability`. That throws away information the engines already have: REVENANT's heuristic weights, DRAGNET's ACH score, OCCAM's ICD-203 likelihood band. ADR-0003 also left its constants uncalibrated.

## Decision
1. `add_claim(..., score=p)` sets `base = p x RELIABILITY_WEIGHT[grade]`: the engine's probability, discounted by how far the platform trusts that engine (its grade). Without `score`, ADR-0003 applies unchanged. Sigma rules carry no probability, so ANVIL maps the rule `level` to the grade (critical A ... informational E).
2. Fusion stays transparent: best claim per independent source, noisy-OR, then the strongest-contradiction discount. At incident level, correlation takes the best claim of each engine across *all members*, so REVENANT flagging a parent process and ANVIL flagging its child still corroborate each other. The member claims are cited, not counted a second time.
3. Calibration is measured (Brier, ECE, AUC, reliability curves) and fitted as Platt scaling on the fused confidence, cross-validated by capture on labelled OTRF data. The raw rule-based confidence stays in every claim; the calibrated value is reported next to it, never instead of it.

## Consequences
- Fused confidence is a good *ranking* score but not a probability out of the box (see `results/otrf_core.json`: high ECE before calibration). Consumers that need probabilities use the calibrated map.
- The Platt parameters depend on the data. They are fitted on emulated attacks, where every capture contains an attack, so they will over-state probabilities on ordinary production telemetry. This is recorded as a limitation, not hidden.
