"""Check the result files a benchmark run produced (used by the bench workflow and before a release).

For every benchmark selected with ``--which`` it checks that the expected
``results/*.json`` exist and

* were written by *this* run (``generated`` at or after ``--since``),
* are strict JSON under the 1,000,000-byte repository cap,
* record the engine versions they were produced with, and those equal the pinned
  commits in ``throughline.engines.SIBLINGS`` (``--pins``),
* have the expected shape and non-degenerate metrics (no benchmark where every method
  scores exactly 0 or exactly 1 on its headline metric).

    python benchmarks/check_results.py --which all --since "2026-10-03T08:00:00Z"
    python benchmarks/check_results.py --which all --pins          # committed files, no freshness check
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
sys.path.insert(0, str(ROOT))
MAX_BYTES = 1_000_000

EXPECTED = {
    "otrf": ["otrf_core"],
    "attribution": ["attribution"],
    "apt29": ["apt29_day1", "apt29_day2"],
    "compound": ["compound"],
    "loop": ["feedback_loop"],
    "supplychain": ["supplychain_healthchecks"],
}
EXPECTED["all"] = [n for v in EXPECTED.values() for n in v]


def _between_0_1(xs) -> bool:
    xs = [x for x in xs if x is not None]
    return any(0 < x < 1 for x in xs)


def shape(name: str, d: dict) -> list[str]:
    errs = []
    if name == "otrf_core":
        if d.get("captures", 0) < 90:
            errs.append(f"only {d.get('captures')} captures scored")
        for m in ("sigma", "revenant", "max", "noisy_or_all", "per_process", "fused", "fused_no_grade", "rba"):
            if m not in d.get("methods", {}):
                errs.append(f"method {m} missing")
        if not _between_0_1(v.get("hit@1") for v in d.get("methods", {}).values()):
            errs.append("hit@1 degenerate for every method")
        for k in ("calibration", "corroboration", "prioritisation", "triage", "compression"):
            if k not in d:
                errs.append(f"{k} missing")
    elif name == "attribution":
        for s in ("temporal", "temporal_families", "temporal_all", "report_lro", "retrospective"):
            if s not in d or "clean" not in d[s]:
                errs.append(f"setting {s} missing")
                continue
            ms = d[s]["clean"]["methods"]
            # new malware families may genuinely be unattributable from behaviour: no degeneracy check
            if s != "temporal_families" and not _between_0_1(v.get("top1") for v in ms.values()):
                errs.append(f"{s}: top-1 degenerate for every method")
            if "top1_wilson" not in ms.get("fused", {}):
                errs.append(f"{s}: no confidence intervals")
        if len(d.get("drift_dose", {}).get("doses", {})) != 5:
            errs.append("drift_dose incomplete")
    elif name.startswith("apt29_day"):
        if d.get("incidents", 0) <= 0:
            errs.append("no incidents")
        if "stitching" not in d or "pair_precision" not in d["stitching"]:
            errs.append("stitching / truth scoring missing")
        if "analysts" not in d.get("plan", {}):
            errs.append("plan scoring missing (download apt29plan)")
    elif name == "compound":
        caps = {r["capture"] for r in d.get("captures", [])}
        if len(caps) != 9:
            errs.append(f"{len(caps)} of 9 compound captures")
    elif name == "feedback_loop":
        if not d.get("backends", {}).get("heuristic", {}).get("drafts"):
            errs.append("no drafts")
    elif name == "supplychain_healthchecks":
        if "advisory_published_vs_pin" not in d:
            errs.append("advisory dates missing")
    return errs


def check(name: str, since: str | None, pins: bool) -> list[str]:
    p = RESULTS / f"{name}.json"
    if not p.exists():
        return [f"{name}: missing"]
    raw = p.read_bytes()
    errs = []
    if len(raw) > MAX_BYTES:
        errs.append(f"{len(raw):,} bytes (cap {MAX_BYTES:,})")
    try:
        d = json.loads(raw, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except ValueError as e:
        return [f"{name}: not strict JSON ({e})"]
    gen = str(d.get("generated", ""))
    if since and gen.replace(" ", "T").rstrip("Z") < since.replace(" ", "T").rstrip("Z"):
        errs.append(f"stale: generated {gen}, run started {since}")
    if pins:
        from throughline.engines import SIBLINGS

        recorded = (d.get("provenance") or {}).get("engines")
        if not recorded:
            errs.append("no engine provenance recorded")
        else:
            for s in SIBLINGS:
                r = recorded.get(s.project)
                if r and r.get("commit") and r["commit"] != s.sha:
                    errs.append(f"{s.project} commit {r['commit'][:7]} != pinned {s.sha[:7]} ({s.tag})")
    errs += shape(name, d)
    return [f"{name}: {e}" for e in errs]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--which", default="all", choices=sorted(EXPECTED))
    ap.add_argument("--since", default=None, help="UTC start time of the run (results must be newer)")
    ap.add_argument("--pins", action="store_true", help="recorded engine commits must equal the pins")
    a = ap.parse_args(argv)
    errs = [e for n in EXPECTED[a.which] for e in check(n, a.since, a.pins)]
    for n in EXPECTED[a.which]:
        print(("FAIL " if any(e.startswith(n + ":") for e in errs) else "ok   ") + n)
    for e in errs:
        print("  " + e)
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
