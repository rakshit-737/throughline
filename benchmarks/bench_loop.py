"""B5 - the feedback loop on real captures: undetected -> drafted -> gated -> coverage delta.

1. Replay every OTRF capture through ANVIL's SigmaHQ library; a capture is
   *detected* if any alert carries a technique with the labelled parent id.
2. For each undetected capture, run ``throughline.reasoning.loop.close_gap``:
   mine the novel behaviour, draft rules with ANVIL's heuristic drafter (and,
   as a baseline, ANVIL's naive keyword drafter), and accept a draft only if it
   fires on its own capture and on zero events of every unrelated capture.
3. Report coverage before/after, acceptance, false-positive rejections, and
   whether accepted rules also fire on *other* captures of the same technique
   (the only out-of-sample signal available at this scale).

Coverage "after" is in-sample by construction (the rule was mined from the
capture it is scored on); the FP gate and the cross-capture check are the
parts that carry information.

    python benchmarks/bench_loop.py
"""
from __future__ import annotations

import time

from common import write

from throughline.connectors.otrf import load_catalog
from throughline.reasoning.loop import close_gap, view
from throughline.stack import Stack, capture_records


def parent(t: str) -> str:
    return t.split(".")[0]


def main() -> int:
    st = Stack.from_data_dir(engines=("anvil",))
    caps = [c for c in load_catalog(st.paths.otrf) if c.available and c.techniques]
    st.registry()
    views, detected = [], {}
    t0 = time.perf_counter()
    for cap in caps:
        recs = capture_records(cap)
        if not recs:
            continue
        kg, _, _ = st.run(recs, st.registry())
        claimed = {o.split(":", 1)[1] for _, o, k in kg.g.edges(keys=True) if k == "EXHIBITS"}
        detected[cap.id] = bool({parent(t) for t in claimed} & {parent(t) for t in cap.techniques})
        views.append(view(cap.id, cap.techniques, (r[1] for r in recs)))
    gaps = [v for v in views if not detected[v.id]]
    print(f"{len(views)} captures, {len(views) - len(gaps)} detected, {len(gaps)} gaps", flush=True)
    res: dict = {"captures": len(views), "detected_before": len(views) - len(gaps), "gaps": len(gaps), "backends": {}}
    for backend in ("heuristic", "keywords"):
        rows = []
        for g in gaps:
            others = [v for v in views if v.id != g.id]
            r = close_gap(g, others, backend=backend)
            rows.append(r)
            print(f"  [{backend}] {g.id} {g.techniques}: novel={r.novel_commands} drafted={r.drafted} "
                  f"accepted={len(r.accepted)} fp_rejected={sum(1 for x in r.rejected if x['fp_hits'])} "
                  f"generalises={r.generalises_to}", flush=True)
        closed = [r for r in rows if r.accepted]
        drafted = sum(r.drafted for r in rows)
        res["backends"][backend] = {
            "gaps_with_novel_behaviour": sum(1 for r in rows if r.novel_commands),
            "gaps_with_drafts": sum(1 for r in rows if r.drafted),
            "drafts": drafted,
            "accepted_drafts": sum(len(r.accepted) for r in rows),
            "rejected_fp": sum(1 for r in rows for x in r.rejected if x["fp_hits"]),
            "rejected_no_own_hit": sum(1 for r in rows for x in r.rejected if not x["fp_hits"] and not x["own_hits"]),
            "gaps_closed": len(closed),
            "coverage_before": round((len(views) - len(gaps)) / len(views), 4),
            "coverage_after_in_sample": round((len(views) - len(gaps) + len(closed)) / len(views), 4),
            "closed_with_same_technique_elsewhere": sum(1 for r in closed if r.generalises_to),
            "rows": [{"capture": r.capture, "technique": r.technique, "novel": r.novel_commands,
                      "drafted": r.drafted, "accepted": [{k: x[k] for k in ("title", "own_hits", "fp_hits")}
                                                         for x in r.accepted],
                      "rejected": [{k: x[k] for k in ("title", "own_hits", "fp_hits")} for x in r.rejected],
                      "generalises_to": r.generalises_to} for r in rows],
            "example_yaml": [x["yaml"] for r in closed for x in r.accepted][:2],
        }
    res["seconds"] = round(time.perf_counter() - t0, 1)
    print("wrote", write("feedback_loop", res))
    for b, v in res["backends"].items():
        print(b, {k: v[k] for k in ("drafts", "accepted_drafts", "rejected_fp", "gaps_closed",
                                    "coverage_before", "coverage_after_in_sample")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
