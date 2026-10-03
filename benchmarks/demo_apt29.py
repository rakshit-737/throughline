"""B4 - end to end on real telemetry: the OTRF APT29 evaluation (day 1 or 2) through every engine.

MITRE's ATT&CK Evaluations round 2 emulated APT29 on a four-host Windows domain; OTRF
published the host logs. The capture has no per-event labels, but the CTID emulation plan
the evaluation followed lists every procedure with its step id and ATT&CK technique
(``python scripts/download_data.py apt29plan``), and its lateral movement can be resolved
to host pairs (``benchmarks/truth/apt29_lateral.yaml``). This run asks the platform's
headline question end to end and scores what can be scored:

* **technique identification** against the day's plan: recall of the plan's (parent)
  techniques, the share of plan steps covered, and tie-aware precision@k of each
  engine's technique ranking (Sigma alone, REVENANT alone, their union, THROUGHLINE's
  incident-level fusion);
* **cross-host stitching** against the lateral-movement truth: precision and recall of
  the host pairs that end up in one cluster, with the evidence of each join;
* **attribution**, including an oracle run of both intel engines on the plan's *own*
  technique list (separates detection error from attribution error) and how much of
  the plan ATT&CK's APT29 profile contains;
* **cost**: wall time per engine, peak resident memory (psutil), investigation latency.

    python benchmarks/demo_apt29.py [--day 1|2] [--capture compound/... --name compound_x]
"""
from __future__ import annotations

import argparse
import threading
import time
from pathlib import Path

from common import ROOT, expected_precision_at_k, wilson, write

from throughline.connectors.otrf import APT29_DAY1, APT29_DAY2, iter_records
from throughline.engines.intel import Evidence
from throughline.reasoning.investigator import Investigator
from throughline.stack import Stack, data_dir

TRUTH = ROOT / "benchmarks" / "truth" / "apt29_lateral.yaml"


def parent(t: str) -> str:
    return t.split(".")[0]


class PeakRSS:
    """Peak resident set size of this process, sampled every 0.25 s (None without psutil)."""

    def __init__(self) -> None:
        self.peak = 0
        self._stop = threading.Event()
        try:
            import psutil
            self._p = psutil.Process()
        except ImportError:
            self._p = None

    def __enter__(self):
        if self._p:
            threading.Thread(target=self._run, daemon=True).start()
        return self

    def _run(self) -> None:
        while not self._stop.is_set():
            self.peak = max(self.peak, self._p.memory_info().rss)
            self._stop.wait(0.25)

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._p:
            self.peak = max(self.peak, self._p.memory_info().rss)

    @property
    def mb(self) -> float | None:
        return round(self.peak / 1e6, 1) if self._p else None


# ------------------------------------------------------------------------------- plan
def load_plan(path: Path) -> list[dict]:
    """Procedures of the CTID APT29 plan: step id, day (scenario 1 = steps 1-10), technique."""
    import yaml

    out = []
    for x in yaml.safe_load(path.read_text(encoding="utf-8")) or []:
        if not isinstance(x, dict) or "procedure_step" not in x:
            continue
        step = str(x["procedure_step"])
        out.append({"step": step, "day": 1 if int(step.split(".")[0]) <= 10 else 2,
                    "technique": str(x["technique"]["attack_id"]).upper(), "tactic": x.get("tactic"),
                    "name": x.get("name")})
    return out


def technique_scores(kg, ctx) -> dict[str, dict[str, float]]:
    """technique -> score for each analyst: Sigma alone, REVENANT alone, union (max), fused."""
    sigma: dict[str, float] = {}
    rev: dict[str, float] = {}
    for s, o, k, d in kg.g.edges(keys=True, data=True):
        if k != "EXHIBITS" or not s.startswith(("Process:", "Host:")):
            continue
        t = o.split(":", 1)[1]
        for cid in d.get("claims", []):
            c = kg.claims[cid]
            if c.source == "anvil":
                sigma[t] = max(sigma.get(t, 0.0), c.base_confidence)
            elif c.source == "revenant":
                rev[t] = max(rev.get(t, 0.0), c.base_confidence)
    union = {t: max(sigma.get(t, 0.0), rev.get(t, 0.0)) for t in set(sigma) | set(rev)}
    fused: dict[str, float] = {}
    for inc in ctx.get("incidents", []):
        for t, cf in inc["technique_conf"].items():
            fused[t] = max(fused.get(t, 0.0), cf)
    return {"sigma": sigma, "revenant": rev, "union": union, "fused": fused}


def plan_eval(scores: dict[str, dict[str, float]], plan: list[dict], day: int) -> dict:
    steps = [p for p in plan if p["day"] == day]
    truth = {parent(p["technique"]) for p in steps}
    out: dict = {"plan_steps": len(steps), "plan_techniques": sorted({p["technique"] for p in steps}),
                 "plan_parent_techniques": len(truth), "analysts": {}}
    for m, sc in scores.items():
        par: dict[str, float] = {}
        for t, v in sc.items():
            par[parent(t)] = max(par.get(parent(t), 0.0), v)
        hit = truth & set(par)
        ranked = [(v, t in truth) for t, v in par.items()]
        out["analysts"][m] = {
            "observed_parent_techniques": len(par),
            "plan_recall": round(len(hit) / len(truth), 4), "plan_recall_wilson": wilson(len(hit), len(truth)),
            "steps_covered": round(sum(1 for p in steps if parent(p["technique"]) in par) / len(steps), 4),
            "in_plan_share": round(len(hit) / len(par), 4) if par else None,
            **{f"precision@{k}": round(v, 4) if (v := expected_precision_at_k(ranked, k)) is not None else None
               for k in (5, 10, 20)},
            "missed": sorted(truth - set(par)),
        }
    return out


def oracle(eng: dict, plan: list[dict], day: int, observed: list[str]) -> dict:
    """Both intel engines (and their fusion) on the plan's own techniques vs the observed ones,
    plus the rank ATT&CK's APT29 gets; and how much of the plan the APT29 profile contains."""
    from bench_attribution import fuse

    dr, oc = eng.get("intel:dragnet"), eng.get("intel:occam")
    if not dr or not oc:
        return {"skipped": "DRAGNET/OCCAM not installed"}
    plan_t = sorted({p["technique"] for p in plan if p["day"] == day})
    gid = next((g for g, o in dr.attack.groups.items() if o.name == "APT29"), None)
    profile = {parent(t) for t in dr.attack.techniques_of(gid)} if gid else set()
    out: dict = {"apt29_profile_parent_techniques": len(profile),
                 "plan_in_apt29_profile": round(len({parent(t) for t in plan_t} & profile)
                                                / max(1, len({parent(t) for t in plan_t})), 4),
                 "observed_in_apt29_profile": round(len({parent(t) for t in observed} & profile)
                                                    / max(1, len({parent(t) for t in observed})), 4)}
    for name, techs in (("plan_techniques", plan_t), ("observed_fused", observed)):
        ev = Evidence(techs, [])
        vd, vo = dr.attribute(ev), oc.attribute(ev)
        vf = fuse([(vd, "dragnet"), (vo, "occam")])
        row = {"n_techniques": len(techs)}
        for m, v in (("dragnet", vd), ("occam", vo), ("fused", vf)):
            rank = v.ranked.index("APT29") + 1 if "APT29" in v.ranked else None
            row[m] = {"named": v.leading, "p": round(v.probability, 3), "grade": v.grade, "apt29_rank": rank,
                      "ranked": len(v.ranked)}
        out[name] = row
    return out


# ------------------------------------------------------------------------------- stitching
def stitching_eval(incs: list[dict], day: int | None) -> dict:
    by_cluster: dict = {}
    for i in incs:
        by_cluster.setdefault(i.get("cluster"), []).append(i)
    multi = []
    for cid, members in by_cluster.items():
        hosts = sorted({m["incident"].split(":", 1)[1].split("/", 1)[0] for m in members})
        if len(hosts) > 1:
            via = sorted({v for m in members for v in (m.get("cluster_via") or [])})
            multi.append({"cluster": cid, "hosts": hosts, "incidents": len(members), "via": via[:10],
                          "lateral_evidence": sum(1 for v in via if v.startswith("lateral ")),
                          "max_score": max(m["score"] for m in members),
                          "members": sorted(m["incident"] for m in members)[:20]})
    multi.sort(key=lambda c: (-len(c["hosts"]), -c["incidents"], str(c["cluster"])))
    hosts_all = sorted({i["incident"].split(":", 1)[1].split("/", 1)[0] for i in incs})
    out = {"hosts_with_incidents": hosts_all, "clusters": len(by_cluster), "multi_host_clusters": len(multi),
           "incidents_in_multi_host_clusters": sum(c["incidents"] for c in multi), "top_multi_host": multi[:10]}
    if day and TRUTH.exists():
        import yaml

        truth_rows = (yaml.safe_load(TRUTH.read_text(encoding="utf-8")) or {}).get(f"day{day}", [])
        truth = {frozenset((r["from"], r["to"])) for r in truth_rows}
        pred = {frozenset((a, b)) for c in multi for a in c["hosts"] for b in c["hosts"] if a < b}
        tp = pred & truth
        out["truth_pairs"] = sorted("-".join(sorted(p)) for p in truth)
        out["predicted_pairs"] = sorted("-".join(sorted(p)) for p in pred)
        out["pair_precision"] = round(len(tp) / len(pred), 4) if pred else None
        out["pair_recall"] = round(len(tp) / len(truth), 4) if truth else None
        out["true_pairs_found"] = sorted("-".join(sorted(p)) for p in tp)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--day", type=int, default=1, choices=[1, 2], help="APT29 evaluation day")
    ap.add_argument("--top", type=int, default=5, help="incidents to investigate and report")
    ap.add_argument("--capture", default=None, help="another OTRF compound capture (path under otrf/)")
    ap.add_argument("--name", default=None, help="result name (default apt29_day<N>)")
    a = ap.parse_args(argv)
    st = Stack.from_data_dir()
    path = st.paths.otrf / (a.capture or (APT29_DAY1 if a.day == 1 else APT29_DAY2))
    with PeakRSS() as rss:
        t0 = time.perf_counter()
        reg = st.registry()
        setup = time.perf_counter() - t0
        t0 = time.perf_counter()
        records = [("windows", r, "B") for r in iter_records(path)]
        load_s = time.perf_counter() - t0
        t0 = time.perf_counter()
        kg, summary, ctx = st.run(records, reg)
        run_s = time.perf_counter() - t0
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
        ranks = {}
        for src in ("intel:dragnet", "intel:occam"):
            v = getattr(eng.get(src), "verdicts", {}).get(inc["incident"])
            if v is not None:
                ranks[src.split(":")[1]] = {"apt29_rank": v.ranked.index("APT29") + 1 if "APT29" in v.ranked else None,
                                            "ranked": len(v.ranked), "shortlist": v.ranked[:10]}
        any_engine = sum(1 for _, _, k in kg.g.in_edges(inc["incident"], keys=True) if k == "PART_OF")
        top.append({"incident": inc["incident"], "score": inc["score"], "breadth": inc["breadth"],
                    "alerts": inc["alerts"], "members_lineage": inc["members"],
                    "members_any_engine": any_engine,
                    "techniques": inc["technique_conf"],
                    "technique_sources": {t: sorted(s) for t, s in inc["technique_sources"].items()},
                    "attribution": attrib, "attribution_ranks": ranks, "dragnet": attrs.get("dragnet_verdict"),
                    "occam": attrs.get("occam_verdict"), "rootline_root_causes": attrs.get("rootline_root_causes"),
                    "report": r["report"]})
    all_techs = sorted({t for i in incs for t in i["technique_conf"]})
    day = a.day if not a.capture else None
    res = {
        "capture": str(path.name), "day": day, "records": len(records),
        "load_seconds": round(load_s, 1), "engine_setup_seconds": round(setup, 1),
        "pipeline_seconds": round(run_s, 1), "total_seconds": round(setup + load_s + run_s, 1),
        "peak_rss_mb": rss.mb,
        "graph": {k: summary[k] for k in ("nodes", "edges", "claims", "events")},
        "rejected_total": summary["rejected_total"], "skipped_records": sum(summary["skipped"].values()),
        "engine_claims": summary["engines"], "engine_seconds": summary["timings_s"],
        "engine_load_seconds": st.load_s, "skipped_engines": summary["skipped_engines"],
        "alerts": sum(len(d.get("claims", [])) for _, _, k, d in kg.g.edges(keys=True, data=True)
                      if k == "ALERTED_ON"),
        "incidents": len(incs), "techniques_observed": all_techs,
        "posture": ctx.get("posture", {}), "emulation_plan": ctx.get("emulation_plan", [])[:15],
        "investigate_latency_ms": [round(x * 1000, 1) for x in lat],
        "top_incidents": top, "stitching": stitching_eval(incs, day),
        "rootline": dict(eng["provenance:rootline"].stats) if "provenance:rootline" in eng else None,
    }
    scores = technique_scores(kg, ctx)
    res["analyst_techniques"] = {m: sorted(v) for m, v in scores.items()}
    plan_path = data_dir() / "apt29plan" / "APT29.yaml"
    if day and plan_path.exists():
        plan = load_plan(plan_path)
        res["plan"] = plan_eval(scores, plan, day)
        res["attribution_oracle"] = oracle(eng, plan, day, all_techs)
    elif day:
        res["plan"] = {"skipped": "run scripts/download_data.py apt29plan"}
    out = write(a.name or f"apt29_day{a.day}", res)
    print({k: res[k] for k in ("records", "pipeline_seconds", "peak_rss_mb", "graph", "alerts", "incidents")})
    print({k: v for k, v in res["stitching"].items() if k != "top_multi_host"})
    if "plan" in res and "analysts" in res["plan"]:
        for m, v in res["plan"]["analysts"].items():
            print(m, {k: v[k] for k in ("plan_recall", "steps_covered", "in_plan_share", "precision@10")})
        print(res.get("attribution_oracle"))
    for t in top:
        print(t["incident"], t["score"], t["breadth"], t["attribution"][:3], t["attribution_ranks"])
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
