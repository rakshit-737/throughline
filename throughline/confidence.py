"""Transparent, rule-based confidence & evidence engine.

Rules (documented in docs/adr/0003-confidence-model.md):
  base      = METHOD_PRIOR[method] * RELIABILITY_WEIGHT[reliability]
  combined  = 1 - prod(1 - c_i)  over the claim and corroborating claims from
              *independent* sources (one best claim per source counts)
  final     = combined * (1 - max(contradicting confidences) * CONFLICT_WEIGHT)
Every number is explainable via `explain()`.
"""
from __future__ import annotations

from .contracts import Claim

METHOD_PRIOR = {"observed": 0.9, "inferred": 0.7, "stated": 0.6, "predicted": 0.5}
RELIABILITY_WEIGHT = {"A": 1.0, "B": 0.9, "C": 0.75, "D": 0.6, "E": 0.4, "F": 0.5}
CONFLICT_WEIGHT = 0.6
CAP = 0.99


def base_confidence(method: str, reliability: str) -> float:
    return round(METHOD_PRIOR.get(method, 0.3) * RELIABILITY_WEIGHT.get(reliability, 0.5), 4)


def scored_confidence(score: float, reliability: str) -> float:
    """Base confidence for an engine that reports its own probability (ADR-0006)."""
    return round(max(0.0, min(float(score), CAP)) * RELIABILITY_WEIGHT.get(reliability, 0.5), 4)


def _independent(claims: list[Claim]) -> list[float]:
    best: dict[str, float] = {}
    for c in claims:
        best[c.source] = max(best.get(c.source, 0.0), c.base_confidence)
    return list(best.values())


def combine(primary: Claim, supporting: list[Claim], contradicting: list[Claim]) -> float:
    vals = _independent([primary, *supporting])
    miss = 1.0
    for v in vals:
        miss *= 1.0 - v
    combined = 1.0 - miss
    if contradicting:
        worst = max(c.base_confidence for c in contradicting)
        combined *= 1.0 - worst * CONFLICT_WEIGHT
    return round(min(combined, CAP), 4)


def explain(primary: Claim, supporting: list[Claim], contradicting: list[Claim]) -> dict:
    return {
        "claim": primary.claim_id,
        "assertion": primary.assertion,
        "base": primary.base_confidence,
        "method": primary.method,
        "reliability": primary.reliability,
        "independent_sources": sorted({c.source for c in [primary, *supporting]}),
        "supporting": [c.claim_id for c in supporting],
        "contradicting": [c.claim_id for c in contradicting],
        "final": combine(primary, supporting, contradicting),
        "rule": "noisy-OR over independent sources, discounted by strongest contradiction",
    }


def brier(predictions: list[tuple[float, bool]]) -> float:
    """Calibration metric for benchmarking claim confidence vs ground truth."""
    if not predictions:
        return 0.0
    return sum((p - float(y)) ** 2 for p, y in predictions) / len(predictions)
