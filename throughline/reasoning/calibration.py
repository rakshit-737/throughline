"""Confidence calibration: measure it (Brier, ECE, reliability curve) and fit it.

ADR-0003 left the confidence constants as uncalibrated guesses. This module
closes that TODO without hiding the model: calibration is a *separate*, fitted
map from the transparent fused confidence to an empirical probability,

    p = sigmoid(a * logit(confidence) + b)            (Platt scaling)

fitted on labelled data (OTRF captures with known emulated techniques) and
evaluated only on held-out folds. The raw rule-based confidence stays in every
claim; the calibrated value is reported next to it. Pure Python on purpose.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

EPS = 1e-4


def _logit(p: float) -> float:
    p = min(max(p, EPS), 1 - EPS)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    if x >= 0:
        return 1 / (1 + math.exp(-x))
    z = math.exp(x)
    return z / (1 + z)


def brier(pairs: list[tuple[float, bool]]) -> float:
    return sum((p - float(y)) ** 2 for p, y in pairs) / len(pairs) if pairs else float("nan")


def ece(pairs: list[tuple[float, bool]], bins: int = 10) -> float:
    """Expected calibration error with equal-width bins."""
    if not pairs:
        return float("nan")
    tot = 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(p, y) for p, y in pairs if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if sel:
            conf = sum(p for p, _ in sel) / len(sel)
            acc = sum(float(y) for _, y in sel) / len(sel)
            tot += len(sel) / len(pairs) * abs(conf - acc)
    return tot


def reliability(pairs: list[tuple[float, bool]], bins: int = 10) -> list[dict]:
    out = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [(p, y) for p, y in pairs if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if sel:
            out.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": len(sel),
                        "mean_conf": round(sum(p for p, _ in sel) / len(sel), 4),
                        "accuracy": round(sum(float(y) for _, y in sel) / len(sel), 4)})
    return out


def auc(pairs: list[tuple[float, bool]]) -> float:
    """ROC AUC via the rank statistic (ties count half)."""
    pos = [p for p, y in pairs if y]
    neg = [p for p, y in pairs if not y]
    if not pos or not neg:
        return float("nan")
    ranked = sorted(pairs, key=lambda x: x[0])
    ranks: dict[int, float] = {}
    i = 0
    while i < len(ranked):
        j = i
        while j + 1 < len(ranked) and ranked[j + 1][0] == ranked[i][0]:
            j += 1
        for k in range(i, j + 1):
            ranks[k] = (i + j) / 2 + 1
        i = j + 1
    rsum = sum(ranks[k] for k, (_, y) in enumerate(ranked) if y)
    return (rsum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))


@dataclass
class Platt:
    a: float = 1.0
    b: float = 0.0
    n: int = 0

    def __call__(self, p: float) -> float:
        return _sigmoid(self.a * _logit(p) + self.b)

    @classmethod
    def fit(cls, pairs: list[tuple[float, bool]], iters: int = 100, l2: float = 1e-3) -> Platt:
        """Newton-Raphson logistic regression on logit(confidence), with Platt's
        smoothed targets to avoid overconfidence on small samples."""
        if not pairs:
            return cls()
        n_pos = sum(1 for _, y in pairs if y)
        n_neg = len(pairs) - n_pos
        t_pos, t_neg = (n_pos + 1) / (n_pos + 2), 1 / (n_neg + 2)
        xs = [_logit(p) for p, _ in pairs]
        ts = [t_pos if y else t_neg for _, y in pairs]
        a, b = 1.0, 0.0
        for _ in range(iters):
            ga = gb = haa = hab = hbb = 0.0
            for x, t in zip(xs, ts):
                p = _sigmoid(a * x + b)
                r = p - t
                w = p * (1 - p)
                ga += r * x
                gb += r
                haa += w * x * x
                hab += w * x
                hbb += w
            ga += l2 * a
            haa += l2
            hbb += l2
            det = haa * hbb - hab * hab
            if abs(det) < 1e-12:
                break
            da = (hbb * ga - hab * gb) / det
            db = (haa * gb - hab * ga) / det
            a, b = a - da, b - db
            if abs(da) < 1e-9 and abs(db) < 1e-9:
                break
        return cls(round(a, 6), round(b, 6), len(pairs))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> Platt:
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))


def summary(pairs: list[tuple[float, bool]]) -> dict:
    return {"n": len(pairs), "positives": sum(1 for _, y in pairs if y),
            "brier": round(brier(pairs), 4), "ece": round(ece(pairs), 4), "auc": round(auc(pairs), 4)}
