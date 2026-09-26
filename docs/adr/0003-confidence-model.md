# ADR-0003: Transparent rule-based confidence model

**Status:** Accepted

## Context
Confidence is the core differentiator, and it must be auditable. The spec says "ACH/confidence: transparent scoring (rules)".

## Decision
- `base = METHOD_PRIOR[method] x RELIABILITY_WEIGHT[source grade]`. The method priors are observed 0.9 > inferred 0.7 > stated 0.6 > predicted 0.5, and the source grade uses the A-F scale.
- Corroboration is a noisy-OR over **independent sources**: only the best claim per source counts, so repeated reports from one feed do not inflate confidence.
- Contradiction discounts the result by `1 - 0.6 x strongest contradicting claim`. `ATTRIBUTED_TO` is exclusive per subject.
- The result is capped at 0.99. Nothing is certain.
- `explain()` returns every input. `brier()` is provided for calibration benchmarking.

## Consequences
- The model is simple, explainable and deterministic. Its constants are uncalibrated guesses (a Grade D TODO: calibrate them against labeled range data using Brier scores).
- Noisy-OR assumes sources are independent, but real feeds copy each other. Source-lineage deduplication is a TODO.
