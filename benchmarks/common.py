"""Shared helpers for the benchmark scripts: paths, result writing with provenance, statistics.

Result files (``results/*.json``) are small, committed summaries. Each one records
*how* it was produced (sibling engine versions and commits, THROUGHLINE commit,
dataset pins, platform), so a number can be traced to the engine set that made it.
Per-case rows go to ``results/raw/*.json.gz`` (git-ignored; the bench workflow
uploads them as an artefact) and never into git.

Statistics used across the benchmarks:

* :func:`bootstrap_ci` - percentile bootstrap of a mean over independent units;
* :func:`cluster_bootstrap_ci` - the same, resampling *clusters* (cases, captures)
  with all of their rows, for metrics whose rows are not independent;
* :func:`wilson` - Wilson score interval for a proportion (does not collapse to
  [0, 0] or [1, 1] at the boundaries the way a bootstrap does);
* :func:`mcnemar` - exact two-sided McNemar test on paired binary outcomes;
* :func:`paired_diff` - paired bootstrap CI of a difference of means, with the
  one-sided bootstrap p-value labelled as such;
* :func:`tie_aware` - hit@1 and reciprocal rank *in expectation over a uniformly
  random order of tied scores* (sorting ties by id favours whatever sorts first).
"""
from __future__ import annotations

import gzip
import json
import math
import os
import platform
import random
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
RAW = RESULTS / "raw"
MAX_RESULT_BYTES = 900_000  # results/*.json are committed; the repository cap is 1,000,000 bytes
sys.path.insert(0, str(ROOT))


def _git_sha() -> str | None:
    if os.environ.get("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                             timeout=20)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def provenance() -> dict:
    """What produced a result: engines (installed version + commit), THROUGHLINE commit, data pins."""
    from throughline import __version__
    from throughline.engines import installed_versions

    pins = {}
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import download_data as dd

        pins = {"attack": dd.ATTACK_COMMIT[:12], "sigma": dd.SIGMA_COMMIT[:12], "otrf": dd.OTRF_COMMIT[:12],
                "misp": dd.MISP_COMMIT[:12]}
        sums = dd.CHECKSUMS
        if sums.exists():
            import hashlib

            pins["checksums_sha256"] = hashlib.sha256(sums.read_bytes()).hexdigest()[:16]
    except (ImportError, AttributeError):
        pass
    return {"throughline": __version__, "commit": _git_sha(), "platform": f"{platform.system()} {platform.machine()}",
            "python": platform.python_version(), "engines": installed_versions(), "data_pins": pins,
            "ci_run": os.environ.get("GITHUB_RUN_ID")}


def _finite(x):
    """NaN / infinity -> None and tuples -> lists, so result files are strict JSON."""
    if isinstance(x, float) and not math.isfinite(x):
        return None
    if isinstance(x, dict):
        return {k: _finite(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_finite(v) for v in x]
    return x


def write(name: str, obj: dict) -> Path:
    """Write ``results/<name>.json`` with provenance; refuse anything near the size cap."""
    RESULTS.mkdir(exist_ok=True)
    obj = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "provenance": provenance(), **obj}
    text = json.dumps(_finite(obj), indent=1, sort_keys=False, default=str, allow_nan=False)
    if len(text.encode("utf-8")) > MAX_RESULT_BYTES:
        raise SystemExit(f"results/{name}.json would be {len(text):,} bytes (cap {MAX_RESULT_BYTES:,}): "
                         "move per-case rows to write_raw()")
    p = RESULTS / f"{name}.json"
    p.write_text(text, encoding="utf-8")
    return p


def write_raw(name: str, obj) -> Path:
    """Per-case rows: ``results/raw/<name>.json.gz`` (git-ignored, uploaded as a CI artefact)."""
    RAW.mkdir(parents=True, exist_ok=True)
    p = RAW / f"{name}.json.gz"
    with gzip.open(p, "wt", encoding="utf-8") as fh:
        json.dump(obj, fh, separators=(",", ":"), default=str)
    return p


# ------------------------------------------------------------------------------ intervals
def bootstrap_ci(values: list[float], iters: int = 2000, seed: int = 0, alpha: float = 0.05) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean of independent values."""
    if not values:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(values)
    means = sorted(sum(values[rng.randrange(n)] for _ in range(n)) / n for _ in range(iters))
    return (round(means[int(alpha / 2 * iters)], 4), round(means[int((1 - alpha / 2) * iters) - 1], 4))


def cluster_bootstrap_ci(clusters: list, stat, iters: int = 2000, seed: int = 0,
                         alpha: float = 0.05) -> tuple[float, float]:
    """Percentile CI of ``stat(rows)`` resampling whole clusters (each a list of rows)."""
    if not clusters:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(clusters)
    vals = []
    for _ in range(iters):
        rows = [r for _ in range(n) for r in clusters[rng.randrange(n)]]
        v = stat(rows)
        if v is not None and not (isinstance(v, float) and math.isnan(v)):
            vals.append(v)
    if not vals:
        return (float("nan"), float("nan"))
    vals.sort()
    m = len(vals)
    return (round(vals[int(alpha / 2 * m)], 4), round(vals[max(0, int((1 - alpha / 2) * m) - 1)], 4))


def wilson(k: float, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for k successes in n trials (k may be an expected count)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 4), round(min(1.0, c + h), 4))


def mcnemar(a: list[bool], b: list[bool]) -> dict:
    """Exact two-sided McNemar test: ``a_only`` cases right only under a, ``b_only`` only under b."""
    a_only = sum(1 for x, y in zip(a, b, strict=True) if x and not y)
    b_only = sum(1 for x, y in zip(a, b, strict=True) if y and not x)
    n = a_only + b_only
    if n == 0:
        return {"a_only": 0, "b_only": 0, "p": 1.0}
    k = min(a_only, b_only)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return {"a_only": a_only, "b_only": b_only, "p": round(min(1.0, 2 * tail), 4)}


def paired_bootstrap(a: list[float], b: list[float], iters: int = 2000, seed: int = 0) -> float:
    """Share of bootstrap resamples where mean(a) <= mean(b): a ONE-SIDED p-value for a > b."""
    rng = random.Random(seed)
    n = len(a)
    worse = 0
    for _ in range(iters):
        idx = [rng.randrange(n) for _ in range(n)]
        if sum(a[i] for i in idx) <= sum(b[i] for i in idx):
            worse += 1
    return round(worse / iters, 4)


def paired_diff(a: list[float], b: list[float], iters: int = 2000, seed: int = 0) -> dict:
    """Mean of a - b over paired units, its percentile bootstrap 95% CI, and the one-sided
    bootstrap p-value for a > b (share of resamples with a <= b)."""
    d = [x - y for x, y in zip(a, b, strict=True)]
    return {"diff": round(sum(d) / len(d), 4) if d else None, "ci": bootstrap_ci(d, iters, seed),
            "p_one_sided": paired_bootstrap(a, b, iters, seed)}


# ------------------------------------------------------------------------------ ranking
def tie_aware(scored: list[tuple[float, bool]]) -> dict:
    """Ranking metrics of one query in expectation over a random order of tied scores.

    ``scored`` holds (score, correct) for every ranked candidate. Returns the expected
    hit@1 and reciprocal rank, plus the optimistic / pessimistic hit@1 bounds (ties broken
    for / against the correct candidate). Candidates are grouped into tie blocks; if the
    first block holding a correct candidate starts after ``s`` others and has ``g``
    members of which ``k`` are correct, the first correct one sits at ``s + J`` with
    ``P(J = j) = C(g - j, k - 1) / C(g, k)``.
    """
    if not scored:
        return {"hit1": 0.0, "rr": 0.0, "hit1_opt": 0.0, "hit1_pes": 0.0, "found": False}
    blocks: dict[float, list[bool]] = {}
    for s, y in scored:
        blocks.setdefault(s, []).append(bool(y))
    s_before = 0
    for score in sorted(blocks, reverse=True):
        ys = blocks[score]
        g, k = len(ys), sum(ys)
        if k:
            tot = math.comb(g, k)
            rr = sum(math.comb(g - j, k - 1) / tot / (s_before + j) for j in range(1, g - k + 2))
            first = s_before == 0
            return {"hit1": k / g if first else 0.0, "rr": rr, "hit1_opt": 1.0 if first else 0.0,
                    "hit1_pes": 1.0 if first and k == g else 0.0, "found": True}
        s_before += g
    return {"hit1": 0.0, "rr": 0.0, "hit1_opt": 0.0, "hit1_pes": 0.0, "found": False}


def expected_precision_at_k(scored: list[tuple[float, bool]], k: int) -> float | None:
    """Expected share of correct items among the top ``k`` when ties are in random order (a tie
    block straddling the cut contributes its correct share of the remaining slots)."""
    if not scored or k <= 0:
        return None
    blocks: dict[float, list[bool]] = {}
    for s, y in scored:
        blocks.setdefault(s, []).append(bool(y))
    left, hits = min(k, len(scored)), 0.0
    for score in sorted(blocks, reverse=True):
        ys = blocks[score]
        take = min(left, len(ys))
        hits += take * sum(ys) / len(ys)
        left -= take
        if not left:
            break
    return hits / min(k, len(scored))


def expected_first_position(keys: list[tuple], correct: list[bool]) -> float | None:
    """Expected 1-based position of the first correct item when items are read in
    descending ``keys`` order and equal keys are in random order (None if none correct)."""
    if not any(correct):
        return None
    blocks: dict[tuple, list[bool]] = {}
    for k, y in zip(keys, correct, strict=True):
        blocks.setdefault(k, []).append(y)
    before = 0
    for key in sorted(blocks, reverse=True):
        ys = blocks[key]
        g, k = len(ys), sum(ys)
        if k:
            return before + (g + 1) / (k + 1)
        before += g
    return None


def fmt(x, nd: int = 3) -> str:
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)
