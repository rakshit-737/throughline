# ADR-0008: Two ACH engines each write one competing attribution claim; UNKNOWN is a hypothesis

**Status:** Accepted

## Context
DRAGNET and OCCAM both implement Analysis of Competing Hypotheses over ATT&CK group profiles, with different weaknesses: DRAGNET gives more weight to rare but forgeable artefacts, while OCCAM withholds a verdict more often. A platform that shows only one engine inherits that engine's failure mode. One that averages them hides the disagreement.

## Decision
- Each engine writes exactly **one** `Incident ATTRIBUTED_TO Actor:<group>` claim: its leading hypothesis, scored with its own probability and graded by its own confidence band. Writing the runner-ups too would make an engine contradict itself.
- An engine that concludes *insufficient evidence* or *false flag* writes `ATTRIBUTED_TO Actor:UNKNOWN` instead. `ATTRIBUTED_TO` is exclusive (ADR-0003), so UNKNOWN competes with the named actors and discounts them.
- The platform names an actor *with confidence* only when the fused claim is at least 0.5. Below that it reports the ranked hypotheses without committing.

## Consequences
- Agreement raises confidence (noisy-OR over independent engines) and disagreement lowers both. This is the "confidence honesty" behaviour the spec asks for.
- Measured on ATT&CK campaigns (`results/attribution.json`), the fused verdict at the >= 0.5 operating point never named a wrong actor in the temporal hold-out, clean or with planted false flags. At the "name anyone" operating point it still inherits part of DRAGNET's susceptibility to a planted, group-exclusive malware family; OCCAM alone is more robust there. Both results are reported.
