"""Shared helpers for the benchmark scripts (paths, result writing, bootstrap CIs)."""
from __future__ import annotations

import json
import platform
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
sys.path.insert(0, str(ROOT))


def write(name: str, obj: dict) -> Path:
    RESULTS.mkdir(exist_ok=True)
    obj = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"), "python": platform.python_version(), **obj}
    p = RESULTS / f"{name}.json"
    p.write_text(json.dumps(obj, indent=1, sort_keys=False, default=str), encoding="utf-8")
    return p


def bootstrap_ci(values: list[float], iters: int = 2000, seed: int = 0, alpha: float = 0.05) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean."""
    if not values:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(values)
    means = sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(iters))
    return (round(means[int(alpha / 2 * iters)], 4), round(means[int((1 - alpha / 2) * iters) - 1], 4))


def paired_bootstrap(a: list[float], b: list[float], iters: int = 2000, seed: int = 0) -> float:
    """Share of bootstrap resamples where mean(a) <= mean(b) (one-sided p-value for a > b)."""
    rng = random.Random(seed)
    n = len(a)
    worse = 0
    for _ in range(iters):
        idx = [rng.randrange(n) for _ in range(n)]
        if sum(a[i] for i in idx) <= sum(b[i] for i in idx):
            worse += 1
    return round(worse / iters, 4)


def fmt(x, nd: int = 3) -> str:
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)
