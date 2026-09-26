"""B1/B2 - siloed vs unified technique identification on real OTRF attack captures.

Every OTRF atomic capture is real Windows telemetry recorded while one known
ATT&CK technique was emulated (ground truth from its metadata). Each capture is
replayed through THROUGHLINE with ANVIL (Sigma), REVENANT (provenance
heuristics) and the correlation engine. For every technique any engine claims
we score four "analysts":

* ``sigma``     - siloed Sigma alert queue (ANVIL alone): confidence from the rule level
* ``revenant``  - siloed provenance heuristics (REVENANT alone)
* ``max``       - both engines, no fusion (take the more confident one)
* ``fused``     - THROUGHLINE: incident-level noisy-OR over independent engines
* ``<method>+cal`` - that method's confidence through a Platt map fitted on the other
  folds (5-fold by capture), reported for every method so calibration and fusion are
  not confused

Metrics: capture recall (the emulated technique is claimed at all), hit@1 and
MRR (is it the top-ranked claim?), and calibration of the claimed confidences
(Brier, ECE, AUC) where a claim is correct if its parent technique matches a
labelled one. Also B2: alerts vs incidents (alert-to-incident compression).

    python benchmarks/bench_otrf.py [--limit N] [--subset core|all]
"""
from __future__ import annotations

import argparse
import json
import statistics
import time

from common import bootstrap_ci, paired_bootstrap, write

from throughline.connectors.otrf import load_catalog
from throughline.reasoning import calibration as cal
from throughline.stack import Stack, capture_records, data_dir

METHODS = ("sigma", "revenant", "max", "fused")


def parent(t: str) -> str:
    return t.split(".")[0]


def correct(t: str, truth: list[str]) -> bool:
    return parent(t) in {parent(x) for x in truth}


def capture_rows(kg, ctx) -> dict[str, dict]:
    """technique -> per-method confidence for one capture."""
    rows: dict[str, dict] = {}
    for s, o, k, d in kg.g.edges(keys=True, data=True):
        if k != "EXHIBITS" or not s.startswith(("Process:", "Host:")):
            continue
        t = o.split(":", 1)[1]
        r = rows.setdefault(t, {"sigma": 0.0, "revenant": 0.0, "processes": 0})
        r["processes"] += 1
        for cid in d.get("claims", []):
            c = kg.claims[cid]
            if c.source == "anvil":
                r["sigma"] = max(r["sigma"], c.base_confidence)
            elif c.source == "revenant":
                r["revenant"] = max(r["revenant"], c.base_confidence)
    for inc in ctx.get("incidents", []):
        for t, conf in inc["technique_conf"].items():
            if t in rows:
                rows[t]["fused"] = max(rows[t].get("fused", 0.0), conf)
    for r in rows.values():
        r["max"] = max(r["sigma"], r["revenant"])
        r.setdefault("fused", r["max"])
    return rows


def rank_metrics(rows: dict[str, dict], truth: list[str], method: str) -> tuple[bool, float, bool]:
    scored = sorted(((r[method], t) for t, r in rows.items() if r[method] > 0), key=lambda x: (-x[0], x[1]))
    hit = any(correct(t, truth) for _, t in scored)
    rr = next((1.0 / i for i, (_, t) in enumerate(scored, 1) if correct(t, truth)), 0.0)
    top1 = bool(scored) and correct(scored[0][1], truth)
    return hit, rr, top1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--subset", default="core", choices=["core", "all"])
    ap.add_argument("--from-cache", action="store_true", help="re-score the cached per-capture rows")
    a = ap.parse_args(argv)
    cache = data_dir() / "cache" / f"otrf_rows_{a.subset}.json"
    if a.from_cache:
        per_capture, meta = json.loads(cache.read_text(encoding="utf-8")).values()
        return score_all(per_capture, meta, a.subset)
    st = Stack.from_data_dir(engines=("anvil", "revenant", "correlation"), sigma_subset=a.subset)
    caps = [c for c in load_catalog(st.paths.otrf) if c.available and c.techniques]
    if a.limit:
        caps = caps[: a.limit]
    reg_t0 = time.perf_counter()
    st.registry()
    per_capture = []
    t0 = time.perf_counter()
    for i, cap in enumerate(caps, 1):
        recs = capture_records(cap)
        if not recs:
            continue
        kg, summary, ctx = st.run(recs, st.registry())
        rows = capture_rows(kg, ctx)
        alerts = sum(len(d.get("claims", [])) for _, _, k, d in kg.g.edges(keys=True, data=True) if k == "ALERTED_ON")
        incs = ctx.get("incidents", [])
        truth_inc_rank = next((j for j, inc in enumerate(incs, 1)
                               if any(correct(t, cap.techniques) for t in inc["technique_conf"])), None)
        per_capture.append({"id": cap.id, "title": cap.title, "truth": cap.techniques, "events": len(recs),
                            "alerts": alerts, "incidents": len(incs), "truth_incident_rank": truth_inc_rank,
                            "rows": rows, "seconds": sum(summary["timings_s"].values())})
        print(f"[{i}/{len(caps)}] {cap.id} {cap.techniques} events={len(recs)} alerts={alerts} "
              f"incidents={len(incs)} claimed={len(rows)}", flush=True)
    elapsed = time.perf_counter() - t0
    meta = {"sigma_rules": len(st.sigma_library().compiled), "seconds_total": round(elapsed, 1),
            "seconds_setup": round(t0 - reg_t0, 1), "engine_load_s": st.load_s}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps({"per_capture": per_capture, "meta": meta}), encoding="utf-8")
    return score_all(per_capture, meta, a.subset)


def score_all(per_capture: list[dict], meta: dict, subset: str) -> int:
    # ---- ranking / recall
    res: dict = {"captures": len(per_capture), "sigma_subset": subset, **meta, "methods": {}}
    for m in METHODS:
        hits, rrs, top1s = [], [], []
        for pc in per_capture:
            h, rr, t1 = rank_metrics(pc["rows"], pc["truth"], m)
            hits.append(float(h))
            rrs.append(rr)
            top1s.append(float(t1))
        res["methods"][m] = {"recall": round(statistics.mean(hits), 4), "recall_ci": bootstrap_ci(hits),
                             "hit@1": round(statistics.mean(top1s), 4), "hit@1_ci": bootstrap_ci(top1s),
                             "mrr": round(statistics.mean(rrs), 4), "mrr_ci": bootstrap_ci(rrs),
                             "_rr": rrs}

    # ---- calibration over claimed (capture, technique) pairs
    folds = 5
    pairs: dict[str, list[tuple[float, bool, int]]] = {m: [] for m in METHODS}
    for i, pc in enumerate(per_capture):
        for t, r in pc["rows"].items():
            y = correct(t, pc["truth"])
            for m in METHODS:
                if r[m] > 0:
                    pairs[m].append((r[m], y, i % folds))
    for m in METHODS:
        pm = [(p, y) for p, y, _ in pairs[m]]
        res["methods"][m]["calibration"] = cal.summary(pm)
        res["methods"][m]["reliability"] = cal.reliability(pm)
        # cross-validated Platt scaling (folds by capture), for every method, so the effect
        # of calibration is not confused with the effect of fusion
        calibrated: list[tuple[float, bool]] = []
        params = []
        for f in range(folds):
            pl = cal.Platt.fit([(p, y) for p, y, fo in pairs[m] if fo != f])
            params.append({"a": pl.a, "b": pl.b})
            calibrated += [(pl(p), y) for p, y, fo in pairs[m] if fo == f]
        res["methods"][f"{m}+cal"] = {"calibration": cal.summary(calibrated),
                                      "reliability": cal.reliability(calibrated), "platt_folds": params}
    fused = [(p, y) for p, y, _ in pairs["fused"]]
    full = cal.Platt.fit(fused)
    res["platt_full"] = {"a": full.a, "b": full.b, "n": full.n}
    res["p_fused_vs_sigma_mrr"] = paired_bootstrap(res["methods"]["fused"]["_rr"], res["methods"]["sigma"]["_rr"])
    res["p_fused_vs_max_mrr"] = paired_bootstrap(res["methods"]["fused"]["_rr"], res["methods"]["max"]["_rr"])
    for m in METHODS:
        res["methods"][m].pop("_rr")

    # ---- B2 alert -> incident compression
    alerts = [pc["alerts"] for pc in per_capture]
    incs = [pc["incidents"] for pc in per_capture]
    ranks = [pc["truth_incident_rank"] for pc in per_capture]
    res["compression"] = {
        "alerts_total": sum(alerts), "incidents_total": sum(incs),
        "alerts_per_capture_median": statistics.median(alerts),
        "incidents_per_capture_median": statistics.median(incs),
        "ratio": round(sum(alerts) / max(1, sum(incs)), 2),
        "truth_in_top_incident": round(sum(1 for r in ranks if r == 1) / len(ranks), 4),
        "truth_in_any_incident": round(sum(1 for r in ranks if r) / len(ranks), 4),
    }
    res["per_capture"] = [{k: v for k, v in pc.items() if k != "rows"} | {
        "claimed": len(pc["rows"]),
        "fused_top": sorted(((round(r["fused"], 3), t) for t, r in pc["rows"].items()), reverse=True)[:5]}
        for pc in per_capture]
    p = write(f"otrf_{subset}", res)
    print(f"wrote {p}")
    for m, v in res["methods"].items():
        c = v["calibration"]
        print(f"{m:10} recall={v.get('recall', '-')} hit@1={v.get('hit@1', '-')} mrr={v.get('mrr', '-')} "
              f"brier={c['brier']} ece={c['ece']} auc={c['auc']} n={c['n']}")
    print(res["compression"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
