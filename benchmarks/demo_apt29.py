"""E2E on real telemetry: the OTRF APT29 evaluation (day 1 or 2) through every engine.

MITRE ATT&CK Evaluations round 2 emulated APT29 on a small Windows domain;
OTRF published the host logs. The capture has no per-event labels, but the
actor is known, so this run asks the platform's headline question end to end
("what happened, how, who, and how sure are we?") and reports what each
engine contributed, the attribution the two intel engines reach from the
*observed* techniques alone, and the cost of doing it (B4: scale).

    python benchmarks/demo_apt29.py [--day 1|2]
"""
from __future__ import annotations

import argparse
import time
import tracemalloc

from common import write

from throughline.connectors.otrf import APT29_DAY1, APT29_DAY2, iter_records
from throughline.reasoning.investigator import Investigator
from throughline.stack import Stack


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--day", type=int, default=1, choices=[1, 2])
    ap.add_argument("--top", type=int, default=5)
    ap.add_argument("--capture", default=None, help="another OTRF compound capture (path under otrf/)")
    ap.add_argument("--name", default=None, help="result name (default apt29_day<N>)")
    a = ap.parse_args(argv)
    st = Stack.from_data_dir()
    path = st.paths.otrf / (a.capture or (APT29_DAY1 if a.day == 1 else APT29_DAY2))
    t0 = time.perf_counter()
    reg = st.registry()
    setup = time.perf_counter() - t0
    t0 = time.perf_counter()
    records = [("windows", r, "B") for r in iter_records(path)]
    load_s = time.perf_counter() - t0
    tracemalloc.start()
    t0 = time.perf_counter()
    kg, summary, ctx = st.run(records, reg)
    run_s = time.perf_counter() - t0
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    incs = ctx.get("incidents", [])
    eng = ctx["engines"]
    top = []
    lat = []
    for inc in incs[: a.top]:
        t1 = time.perf_counter()
        r = Investigator(kg).investigate(inc["incident"])
        lat.append(time.perf_counter() - t1)
        attrs = kg.g.nodes[inc["incident"]]["attrs"]
        attrib = sorted(((o.split(":", 1)[1], round(d.get("confidence", 0.0), 3),
                          sorted({kg.claims[c].source for c in d.get("claims", [])}))
                         for _, o, k, d in kg.g.out_edges(inc["incident"], keys=True, data=True)
                         if k == "ATTRIBUTED_TO"), key=lambda x: -x[1])
        top.append({"incident": inc["incident"], "score": inc["score"], "breadth": inc["breadth"],
                    "alerts": inc["alerts"], "members": inc["members"],
                    "techniques": inc["technique_conf"],
                    "technique_sources": {t: sorted(s) for t, s in inc["technique_sources"].items()},
                    "attribution": attrib, "dragnet": attrs.get("dragnet_verdict"),
                    "occam": attrs.get("occam_verdict"), "rootline_root_causes": attrs.get("rootline_root_causes"),
                    "report": r["report"]})
    all_techs = sorted({t for i in incs for t in i["technique_conf"]})
    # cross-host stitching: clusters of incidents on >1 host joined by a shared rare destination
    by_cluster: dict = {}
    for i in incs:
        by_cluster.setdefault(i.get("cluster"), []).append(i)
    multi = []
    for cid, members in by_cluster.items():
        hosts = sorted({m["incident"].split(":", 1)[1].split("/", 1)[0] for m in members})
        if len(hosts) > 1:
            multi.append({"cluster": cid, "hosts": hosts, "incidents": len(members),
                          "via": sorted({v for m in members for v in (m.get("cluster_via") or [])})[:10],
                          "max_score": max(m["score"] for m in members),
                          "members": sorted(m["incident"] for m in members)[:20]})
    multi.sort(key=lambda c: (-len(c["hosts"]), -c["incidents"], str(c["cluster"])))
    hosts_all = sorted({i["incident"].split(":", 1)[1].split("/", 1)[0] for i in incs})
    stitching = {"hosts_with_incidents": hosts_all, "clusters": len(by_cluster),
                 "multi_host_clusters": len(multi),
                 "incidents_in_multi_host_clusters": sum(c["incidents"] for c in multi),
                 "top_multi_host": multi[:10]}
    res = {
        "capture": str(path.name), "day": a.day, "records": len(records),
        "load_seconds": round(load_s, 1), "engine_setup_seconds": round(setup, 1),
        "pipeline_seconds": round(run_s, 1), "peak_python_mem_mb": round(peak / 1e6, 1),
        "graph": {k: summary[k] for k in ("nodes", "edges", "claims", "events")},
        "rejected_total": summary["rejected_total"], "skipped_records": sum(summary["skipped"].values()),
        "engine_claims": summary["engines"], "engine_seconds": summary["timings_s"],
        "skipped_engines": summary["skipped_engines"],
        "alerts": sum(len(d.get("claims", [])) for _, _, k, d in kg.g.edges(keys=True, data=True)
                      if k == "ALERTED_ON"),
        "incidents": len(incs), "techniques_observed": all_techs,
        "posture": ctx.get("posture", {}), "emulation_plan": ctx.get("emulation_plan", [])[:15],
        "investigate_latency_ms": [round(x * 1000, 1) for x in lat],
        "top_incidents": top, "stitching": stitching,
        "rootline": dict(eng["provenance:rootline"].stats) if "provenance:rootline" in eng else None,
    }
    out = write(a.name or f"apt29_day{a.day}", res)
    print({k: res[k] for k in ("records", "pipeline_seconds", "graph", "alerts", "incidents", "engine_seconds")})
    print({k: v for k, v in stitching.items() if k != "top_multi_host"})
    for t in top:
        print(t["incident"], t["score"], t["breadth"], t["attribution"][:3], t["dragnet"], "|", t["occam"])
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
