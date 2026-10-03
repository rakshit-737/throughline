#!/usr/bin/env python3
"""Re-validate the feedback loop's accepted detections against a fresh re-emulation.

The loop (``benchmarks/bench_loop.py``, B5) drafts Sigma rules from the unseen behaviour of
an undetected OTRF capture and accepts a draft only if it fires on that capture and on no
unrelated capture. That gate is in-sample. The spec's last step is *re-emulate and check
that the detection fires now*. The ``loop-revalidation`` CI job does that on a fresh,
throwaway Windows runner (nothing leaves the runner):

1. turn on Security process-creation auditing with command lines (event 4688);
2. record a **baseline** session of ordinary administration (whoami, ipconfig, tasklist ...);
3. **re-emulate** the benign discovery behaviour an accepted draft was mined from
   (``net localgroup Administrators``, ATT&CK T1069.001) - only commands that read local
   configuration are ever run, no attack tooling;
4. export the 4688 events and run every accepted draft over both windows with ANVIL.

This script is step 4. A draft passes if it fires on the re-emulation window (when its
behaviour was re-emulated) and on **zero** baseline events - a false-positive check on a
host, user and Windows build the drafts have never seen.

    python scripts/revalidate_loop.py --events events.jsonl --windows windows.json --out revalidation.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# behaviour re-emulated by the CI job: draft title fragment -> what was run (benign, read-only)
REEMULATED = {"net localgroup": "net localgroup Administrators", "net1 localgroup": "net1 localgroup Administrators"}


def load_drafts(path: Path) -> list[dict]:
    """Accepted drafts of every backend (``accepted_rules``; older files only kept two examples)."""
    d = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for backend, v in d.get("backends", {}).items():
        rows = v.get("accepted_rules") or [{"title": "", "yaml": y} for y in v.get("example_yaml", [])]
        for r in rows:
            out.append({"backend": backend, **r})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--events", required=True, help="JSON lines of exported Windows events")
    ap.add_argument("--windows", required=True, help='JSON {"baseline": [start, end], "emulation": [start, end]} (UTC ISO)')
    ap.add_argument("--loop", default=str(ROOT / "results" / "feedback_loop.json"))
    ap.add_argument("--out", default="revalidation.json")
    a = ap.parse_args(argv)

    import yaml
    from anvil.models import Rule
    from anvil.runner import Library
    from anvil.telemetry import normalise

    from throughline.connectors.windows import event_ts

    win = json.loads(Path(a.windows).read_text(encoding="utf-8-sig"))
    events = [json.loads(line) for line in Path(a.events).read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    drafts = load_drafts(Path(a.loop))
    rules, meta = [], {}
    for dft in drafts:
        r = Rule.from_dict(yaml.safe_load(dft["yaml"]))
        rules.append(r)
        meta[r.id] = dft
    lib = Library.build(rules)

    def window(ts: str) -> str | None:
        for name, (lo, hi) in win.items():
            if lo <= ts <= hi:
                return name
        return None

    hits = {rid: {"baseline": 0, "emulation": 0} for rid in meta}
    counted = {"baseline": 0, "emulation": 0}
    for ev in events:
        w = window(event_ts(ev))
        if not w:
            continue
        counted[w] += 1
        for rid in lib.match_event(normalise(dict(ev))):
            if rid in hits:
                hits[rid][w] += 1
    rows = []
    for rid, dft in meta.items():
        title = Rule.from_dict(yaml.safe_load(dft["yaml"])).title
        reemulated = next((cmd for frag, cmd in REEMULATED.items() if frag in title), None)
        ok_fp = hits[rid]["baseline"] == 0
        ok_fire = hits[rid]["emulation"] > 0 if reemulated else None
        rows.append({"backend": dft["backend"], "title": title, "technique": dft.get("technique"),
                     "compiled": rid in lib.compiled, "re_emulated": reemulated, **hits[rid],
                     "fires_on_reemulation": ok_fire, "silent_on_baseline": ok_fp})
    out = {"events": counted, "drafts": len(rows), "compiled": sum(r["compiled"] for r in rows),
           "re_emulated": sum(1 for r in rows if r["re_emulated"]),
           "fired_on_reemulation": sum(1 for r in rows if r["fires_on_reemulation"]),
           "baseline_false_positives": sum(r["baseline"] for r in rows), "rules": rows}
    Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "rules"}))
    for r in rows:
        print(f"  {r['backend']:9} fire={r['fires_on_reemulation']} baseline_hits={r['baseline']} "
              f"emulation_hits={r['emulation']}  {r['title'][:80]}")
    bad = [r["title"] for r in rows if r["re_emulated"] and not r["fires_on_reemulation"]]
    bad += [r["title"] for r in rows if not r["silent_on_baseline"]]
    if counted["baseline"] == 0 or counted["emulation"] == 0:
        bad.append("no events captured in a window (is process-creation auditing on?)")
    if out["re_emulated"] == 0:
        bad.append("no accepted draft covers re-emulated behaviour")
    for b in bad:
        print("FAIL", b)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
