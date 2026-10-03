"""B1/B2 - siloed vs unified technique identification on real OTRF attack captures.

Every OTRF atomic capture is real Windows telemetry recorded while one known
ATT&CK technique was emulated (ground truth from its metadata). Each capture is
replayed through THROUGHLINE with ANVIL (Sigma), REVENANT (provenance
heuristics) and the correlation engine. Every technique any engine claims in a
capture is a candidate; each "analyst" below scores the candidates and ranks them.

Analysts (the ablation isolates each part of the evidence model):

* ``sigma``          A0 - Sigma alert queue alone (ANVIL), confidence from the rule level
* ``revenant``       REVENANT's provenance heuristics alone
* ``max``            A1 - both engines, no fusion (the more confident one)
* ``noisy_or_all``   A2 - noisy-OR over every claim in the incident (no independence rule:
                     twenty overlapping Sigma hits count twenty times)
* ``per_process``    A3 - noisy-OR of the best claim per engine on the *same process* only
                     (no incident grouping)
* ``fused``          A4 - THROUGHLINE: incident-level noisy-OR of the best claim per
                     independent engine
* ``fused_no_grade`` A5 - A4 with every reliability grade set to A (Sigma level and
                     REVENANT grade ignored)
* ``rba``            A6 - risk-based alerting: risk (100 x base confidence) summed per
                     technique per host, as in risk-based alerting practice

Metrics (all over captures, the independent unit):

* capture recall (the emulated technique is claimed at all);
* hit@1 and MRR **in expectation over a random order of tied scores** (Sigma's
  confidence takes five values, so ties are common; breaking them by technique id
  favours whatever sorts first), with optimistic / pessimistic hit@1 bounds and the
  old alphabetical tie-break kept for reference;
* paired differences against A4 with bootstrap CIs (the p-value printed is the
  one-sided paired-bootstrap share of resamples where A4 is not better);
* calibration (Brier, ECE, AUC, Brier skill vs the base rate) of each method's own
  claims and, **like for like**, on one shared claim universe (every candidate any
  engine claimed; a method that did not claim it scores 0), each through a Platt map
  fitted on the other folds (5-fold by capture), with capture-clustered CIs;
* the corroboration curve (claims backed by >= 1 vs 2 engines: precision, recall);
* incident prioritisation (AUROC of incident scores: Sigma severity, alert count,
  risk sum, fused score) over the same incidents;
* B2: raw alerts, de-duplicated alerts (rule x host) and incidents per capture, and
  triage effort - alerts read (by time, by severity) vs incidents opened and
  technique lines read before reaching the labelled technique.

    python benchmarks/bench_otrf.py [--limit N] [--subset core|all] [--from-cache]
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import time
from collections import defaultdict

from common import (
    bootstrap_ci,
    cluster_bootstrap_ci,
    expected_first_position,
    paired_diff,
    tie_aware,
    wilson,
    write,
    write_raw,
)

from throughline.confidence import RELIABILITY_WEIGHT
from throughline.connectors.otrf import load_catalog
from throughline.reasoning import calibration as cal
from throughline.reasoning.correlation import NON_SIGNAL_SOURCES, noisy_or, story_root
from throughline.stack import Stack, capture_records, data_dir

METHODS = ("sigma", "revenant", "max", "noisy_or_all", "per_process", "fused", "fused_no_grade", "rba")
ABLATION = {"sigma": "A0", "max": "A1", "noisy_or_all": "A2", "per_process": "A3", "fused": "A4",
            "fused_no_grade": "A5", "rba": "A6"}
GRADE_LEVEL = {"A": "critical", "B": "high", "C": "medium", "D": "low", "E": "informational"}
LEVEL_RANK = {"informational": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
FOLDS = 5


def parent(t: str) -> str:
    return t.split(".")[0]


def correct(t: str, truth: list[str]) -> bool:
    return parent(t) in {parent(x) for x in truth}


# ------------------------------------------------------------------------- capture
def capture_rows(kg, ctx) -> dict[str, dict]:
    """technique -> per-method confidence for one capture (sigma, revenant, max, fused)."""
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


def capture_claims(kg) -> tuple[list, list]:
    """Signal claims ``[technique, source, base, grade, node, root]`` and alerts
    ``[rule, level, ts, node, root, techniques]`` of one capture (for the ablations)."""
    roots: dict[str, str] = {}

    def root(n: str) -> str:
        if n not in roots:
            roots[n] = story_root(kg, n)[0] if n.startswith("Process:") else n
        return roots[n]

    claims = []
    for s, o, k, d in kg.g.edges(keys=True, data=True):
        if k != "EXHIBITS" or not s.startswith(("Process:", "Host:")):
            continue
        t = o.split(":", 1)[1]
        for cid in d.get("claims", []):
            c = kg.claims[cid]
            if c.source in NON_SIGNAL_SOURCES:
                continue
            claims.append([t, c.source, c.base_confidence, c.reliability, s, root(s)])
    alerts = []
    for s, o, k, d in kg.g.edges(keys=True, data=True):
        if k != "ALERTED_ON":
            continue
        rule = s.split(":", 1)[1]
        techs = sorted({x.split(":", 1)[1] for _, x, kk in kg.g.out_edges(s, keys=True) if kk == "DETECTS"})
        level = kg.g.nodes[s]["attrs"].get("level", "medium")
        for cid in d.get("claims", []):
            alerts.append([rule, level, kg.claims[cid].timestamp, o, root(o), techs])
    return claims, alerts


# ------------------------------------------------------------------------- scoring
def raw_score(c: list) -> float:
    """The claim's confidence before its reliability grade was applied."""
    return c[2] / RELIABILITY_WEIGHT.get(c[3], 0.5)


def method_scores(pc: dict) -> dict[str, dict[str, float]]:
    """technique -> score for every analyst in METHODS, from one capture's cached rows."""
    out = {m: {} for m in METHODS}
    for t, r in pc["rows"].items():
        for m in ("sigma", "revenant", "max", "fused"):
            if r.get(m, 0) > 0:
                out[m][t] = r[m]
    by_root: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    by_node: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    host_risk: dict[tuple[str, str], float] = defaultdict(float)
    for c in pc["claims"]:
        t, src, base, grade, node, root = c
        by_root[root][t].append(c)
        by_node[node][t].append(c)
        host = node.split(":", 1)[1].split("/", 1)[0]
        host_risk[(host, t)] += 100 * base

    def best_per_source(cs, grade_free=False):
        best: dict[str, float] = {}
        for c in cs:
            v = min(raw_score(c), 0.99) if grade_free else c[2]
            best[c[1]] = max(best.get(c[1], 0.0), v)
        return best

    for root, techs in by_root.items():
        host_level = not root.startswith("Process:")
        for t, cs in techs.items():
            if host_level:  # host-level claims are not grouped into incidents: max of the sources
                v_all = max(best_per_source(cs).values())
                v_ng = max(best_per_source(cs, True).values())
            else:
                v_all = noisy_or(c[2] for c in cs)
                v_ng = noisy_or(best_per_source(cs, True).values())
            out["noisy_or_all"][t] = max(out["noisy_or_all"].get(t, 0.0), v_all)
            out["fused_no_grade"][t] = max(out["fused_no_grade"].get(t, 0.0), v_ng)
    for _node, techs in by_node.items():
        for t, cs in techs.items():
            out["per_process"][t] = max(out["per_process"].get(t, 0.0), noisy_or(best_per_source(cs).values()))
    for (_host, t), v in host_risk.items():
        out["rba"][t] = max(out["rba"].get(t, 0.0), round(v, 4))
    return out


def rank_alphabetical(scores: dict[str, float], truth: list[str]) -> tuple[float, float]:
    """The pre-1.1 tie-break (technique id ascending), kept for reference only."""
    scored = sorted(((v, t) for t, v in scores.items()), key=lambda x: (-x[0], x[1]))
    rr = next((1.0 / i for i, (_, t) in enumerate(scored, 1) if correct(t, truth)), 0.0)
    return float(bool(scored) and correct(scored[0][1], truth)), rr


def ranking(per_capture: list[dict], scores: list[dict]) -> dict:
    res: dict = {}
    per_method_rows: dict[str, dict[str, list[float]]] = {}
    for m in METHODS:
        hit, h1, rr, opt, pes, a_h1, a_rr = [], [], [], [], [], [], []
        for pc, sc in zip(per_capture, scores, strict=True):
            ta = tie_aware([(v, correct(t, pc["truth"])) for t, v in sc[m].items()])
            hit.append(float(ta["found"]))
            h1.append(ta["hit1"])
            rr.append(ta["rr"])
            opt.append(ta["hit1_opt"])
            pes.append(ta["hit1_pes"])
            x, y = rank_alphabetical(sc[m], pc["truth"])
            a_h1.append(x)
            a_rr.append(y)
        per_method_rows[m] = {"hit1": h1, "rr": rr}
        res[m] = {"ablation": ABLATION.get(m), "recall": round(statistics.mean(hit), 4),
                  "recall_ci": wilson(sum(hit), len(hit)),
                  "hit@1": round(statistics.mean(h1), 4), "hit@1_ci": bootstrap_ci(h1),
                  "hit@1_optimistic": round(statistics.mean(opt), 4),
                  "hit@1_pessimistic": round(statistics.mean(pes), 4),
                  "mrr": round(statistics.mean(rr), 4), "mrr_ci": bootstrap_ci(rr),
                  "hit@1_alphabetical": round(statistics.mean(a_h1), 4),
                  "mrr_alphabetical": round(statistics.mean(a_rr), 4)}
    ref = per_method_rows["fused"]
    for m in METHODS:
        if m == "fused":
            continue
        res[m]["fused_minus_this"] = {
            "hit@1": paired_diff(ref["hit1"], per_method_rows[m]["hit1"]),
            "mrr": paired_diff(ref["rr"], per_method_rows[m]["rr"])}
    return res


def _cv_platt(pairs: list[tuple[float, bool, int]]) -> list[tuple[float, bool, int]]:
    """Platt map fitted on the other folds; returns (calibrated p, y, capture index)."""
    out = []
    for f in range(FOLDS):
        pl = cal.Platt.fit([(p, y) for p, y, ci in pairs if ci % FOLDS != f])
        out += [(pl(p), y, ci) for p, y, ci in pairs if ci % FOLDS == f]
    return out


def _skill(pairs: list[tuple[float, bool]]) -> float:
    if not pairs:
        return float("nan")
    base = sum(y for _, y in pairs) / len(pairs)
    ref = base * (1 - base)
    return round(1 - cal.brier(pairs) / ref, 4) if ref else float("nan")


def calibration(per_capture: list[dict], scores: list[dict]) -> dict:
    own: dict[str, list] = {m: [] for m in METHODS}
    shared: dict[str, list] = {m: [] for m in METHODS}
    for i, (pc, sc) in enumerate(zip(per_capture, scores, strict=True)):
        universe = set(pc["rows"])
        for t in universe:
            y = correct(t, pc["truth"])
            for m in METHODS:
                v = sc[m].get(t, 0.0)
                if m == "rba":  # unbounded risk sum -> (0, 1) for the calibration map
                    v = v / (v + 100.0) if v else 0.0
                shared[m].append((v, y, i))
                if v > 0:
                    own[m].append((v, y, i))
    out: dict = {"folds": FOLDS, "universe_claims": len(shared["fused"]),
                 "universe_positives": sum(1 for _, y, _ in shared["fused"] if y), "methods": {}}
    cal_shared: dict[str, list] = {}
    for m in METHODS:
        if m == "rba":
            raw_own = None
        else:
            raw_own = cal.summary([(p, y) for p, y, _ in own[m]])
        c_own = _cv_platt(own[m])
        c_sh = _cv_platt(shared[m])
        cal_shared[m] = c_sh
        out["methods"][m] = {
            "own_claims": {"raw": raw_own, "platt_cv": cal.summary([(p, y) for p, y, _ in c_own]),
                           "skill": _skill([(p, y) for p, y, _ in c_own]),
                           "reliability_raw": cal.reliability([(p, y) for p, y, _ in own[m]]) if raw_own else None},
            "shared_universe": {"platt_cv": cal.summary([(p, y) for p, y, _ in c_sh]),
                                "skill": _skill([(p, y) for p, y, _ in c_sh]),
                                "reliability": cal.reliability([(p, y) for p, y, _ in c_sh])}}
    # capture-clustered CIs of the like-for-like Brier difference fused - other
    n_caps = len(per_capture)
    for m in METHODS:
        if m == "fused":
            continue
        clusters: list[list] = [[] for _ in range(n_caps)]
        # both lists come from the same shared universe in the same order (see above)
        for (pf, y, ci), (po, _, _) in zip(cal_shared["fused"], cal_shared[m], strict=True):
            clusters[ci].append(((pf - y) ** 2) - ((po - y) ** 2))
        clusters = [c for c in clusters if c]
        diffs = [d for c in clusters for d in c]
        out["methods"][m]["shared_universe"]["brier_fused_minus_this"] = {
            "diff": round(sum(diffs) / len(diffs), 4),
            "ci_capture_clustered": cluster_bootstrap_ci(clusters, lambda rows: sum(rows) / len(rows))}
    return out


def corroboration(per_capture: list[dict]) -> dict:
    """Claims backed by >= 1 vs both engines: precision (claim level) and capture recall."""
    out = {}
    for need in (1, 2):
        n = pos = 0
        caps_hit = []
        for pc in per_capture:
            hit = False
            for t, r in pc["rows"].items():
                k = (r["sigma"] > 0) + (r["revenant"] > 0)
                if k >= need:
                    n += 1
                    if correct(t, pc["truth"]):
                        pos += 1
                        hit = True
            caps_hit.append(float(hit))
        out[f">={need}_engines"] = {"claims": n, "precision": round(pos / n, 4) if n else None,
                                    "precision_ci": wilson(pos, n), "capture_recall": round(statistics.mean(caps_hit), 4),
                                    "capture_recall_ci": wilson(sum(caps_hit), len(caps_hit))}
    return out


def incidents_of(pc: dict) -> list[dict]:
    """THROUGHLINE's incidents of one capture, with the alternative scores for each."""
    by_root: dict[str, dict] = {}
    for c in pc["claims"]:
        t, src, base, grade, node, root = c
        if not root.startswith("Process:"):
            continue
        g = by_root.setdefault(root, {"techs": set(), "risk": 0.0, "severity": 0, "alerts": 0})
        g["techs"].add(t)
        g["risk"] += 100 * base
    for a in pc["alerts"]:
        rule, level, ts, node, root, techs = a
        if root in by_root:
            g = by_root[root]
            g["alerts"] += 1
            g["severity"] = max(g["severity"], LEVEL_RANK.get(level, 3))
    fused = {i["root"]: i for i in pc["incidents"]}
    out = []
    for root, g in by_root.items():
        inc = fused.get(root)
        if not inc:
            continue
        out.append({"y": any(correct(t, pc["truth"]) for t in g["techs"]), "fused": inc["score"],
                    "severity": g["severity"], "alerts": g["alerts"], "risk": round(g["risk"], 3),
                    "breadth": len(g["techs"]), "techniques": inc["technique_conf"]})
    return out


def prioritisation(per_capture: list[dict]) -> dict:
    clusters = [[(i, ci) for i in incidents_of(pc)] for ci, pc in enumerate(per_capture)]
    clusters = [c for c in clusters if c]
    rows = [r for c in clusters for r in c]
    out = {"incidents": len(rows), "positive": sum(1 for i, _ in rows if i["y"]), "auroc": {}}
    for key in ("severity", "alerts", "risk", "fused"):
        def stat(rs, key=key):
            v = cal.auc([(i[key], i["y"]) for i, _ in rs])
            return v
        out["auroc"][key] = {"auc": round(stat(rows), 4), "ci_capture_clustered": cluster_bootstrap_ci(clusters, stat)}
    return out


def triage(per_capture: list[dict], seed: int = 0, shuffles: int = 400) -> dict:
    """Items an analyst reads before reaching the labelled technique: alert queues
    (time order, severity order, de-duplicated by rule x host) vs THROUGHLINE's ranked
    incidents (incidents opened; technique lines read, incidents in score order and
    techniques inside an incident by confidence). Ties are random (expected values)."""
    rng = random.Random(seed)
    per = []
    for pc in per_capture:
        al = pc["alerts"]
        ts_rank = {t: i for i, t in enumerate(sorted({a[2] for a in al}))}
        ok = [any(correct(t, pc["truth"]) for t in a[5]) for a in al]
        by_time = expected_first_position([(-ts_rank[a[2]],) for a in al], ok)
        by_sev = expected_first_position([(LEVEL_RANK.get(a[1], 3), -ts_rank[a[2]]) for a in al], ok)
        dedup: dict[tuple, list] = {}
        for a in al:
            host = a[3].split(":", 1)[1].split("/", 1)[0]
            k = (a[0], host)
            if k not in dedup or a[2] < dedup[k][2]:
                dedup[k] = a
        dl = list(dedup.values())
        by_dedup = expected_first_position([(LEVEL_RANK.get(a[1], 3), -ts_rank[a[2]]) for a in dl],
                                           [any(correct(t, pc["truth"]) for t in a[5]) for a in dl])
        incs = incidents_of(pc)
        inc_open = expected_first_position([(i["fused"],) for i in incs], [i["y"] for i in incs])
        lines = None
        if inc_open is not None:
            tot = 0.0
            for _ in range(shuffles):
                order = sorted(incs, key=lambda i: (-i["fused"], rng.random()))
                n = 0
                for inc in order:
                    n += 1  # the incident's summary line
                    techs = sorted(inc["techniques"].items(), key=lambda kv: (-kv[1], rng.random()))
                    hit = next((j for j, (t, _) in enumerate(techs, 1) if correct(t, pc["truth"])), None)
                    if hit:
                        n += hit
                        break
                    n += len(techs)
                tot += n
            lines = tot / shuffles
        per.append({"alerts": len(al), "dedup_alerts": len(dl), "incidents": len(incs), "alert_time": by_time,
                    "alert_severity": by_sev, "dedup_severity": by_dedup, "incidents_opened": inc_open,
                    "incident_lines": lines})
    out: dict = {"captures": len(per)}
    for key in ("alert_time", "alert_severity", "dedup_severity", "incidents_opened", "incident_lines"):
        found = [p[key] for p in per if p[key] is not None]
        out[key] = {"found": len(found), "median": round(statistics.median(found), 2) if found else None,
                    "mean": round(statistics.mean(found), 2) if found else None,
                    "mean_ci": bootstrap_ci(found) if found else None}
    both = [p for p in per if p["alert_severity"] is not None and p["incident_lines"] is not None]
    out["paired"] = {"captures": len(both)}
    for key in ("alert_time", "alert_severity", "dedup_severity", "incidents_opened", "incident_lines"):
        xs = [p[key] for p in both if p[key] is not None]
        out["paired"][key] = {"median": round(statistics.median(xs), 2) if xs else None,
                              "mean": round(statistics.mean(xs), 2) if xs else None,
                              "mean_ci": bootstrap_ci(xs) if xs else None}
    out["paired"]["lines_vs_alert_severity"] = paired_diff([p["alert_severity"] for p in both],
                                                           [p["incident_lines"] for p in both])
    return out


def compression(per_capture: list[dict]) -> dict:
    alerts = [pc["alerts_n"] for pc in per_capture]
    dedup = [len({(a[0], a[3].split(":", 1)[1].split("/", 1)[0]) for a in pc["alerts"]}) for pc in per_capture]
    incs = [pc["incidents_n"] for pc in per_capture]
    ranks = [pc["truth_incident_rank"] for pc in per_capture]
    return {"alerts_total": sum(alerts), "dedup_alerts_total": sum(dedup), "incidents_total": sum(incs),
            "alerts_per_capture_median": statistics.median(alerts),
            "dedup_alerts_per_capture_median": statistics.median(dedup),
            "incidents_per_capture_median": statistics.median(incs),
            "ratio": round(sum(alerts) / max(1, sum(incs)), 2),
            "ratio_dedup": round(sum(dedup) / max(1, sum(incs)), 2),
            "truth_in_top_incident": round(sum(1 for r in ranks if r == 1) / len(ranks), 4),
            "truth_in_any_incident": round(sum(1 for r in ranks if r) / len(ranks), 4)}


def score_all(per_capture: list[dict], meta: dict, subset: str) -> int:
    scores = [method_scores(pc) for pc in per_capture]
    res: dict = {"captures": len(per_capture), "sigma_subset": subset, **meta,
                 "ties": "hit@1 and MRR are expectations over a uniformly random order of tied scores",
                 "p_values": "one-sided paired bootstrap over captures (2000 resamples, seed 0)"}
    res["methods"] = ranking(per_capture, scores)
    res["calibration"] = calibration(per_capture, scores)
    fused_pairs = [(r["fused"], correct(t, pc["truth"])) for pc in per_capture for t, r in pc["rows"].items()]
    full = cal.Platt.fit(fused_pairs)
    res["platt_full"] = {"a": full.a, "b": full.b, "n": full.n}
    res["corroboration"] = corroboration(per_capture)
    res["prioritisation"] = prioritisation(per_capture)
    res["triage"] = triage(per_capture)
    res["compression"] = compression(per_capture)
    res["per_capture"] = [{"id": pc["id"], "truth": pc["truth"], "events": pc["events"], "alerts": pc["alerts_n"],
                           "incidents": pc["incidents_n"], "truth_incident_rank": pc["truth_incident_rank"],
                           "claimed": len(pc["rows"]), "seconds": round(pc["seconds"], 2),
                           "fused_top": sorted(((round(r["fused"], 3), t) for t, r in pc["rows"].items()),
                                               reverse=True)[:3]}
                          for pc in per_capture]
    p = write(f"otrf_{subset}", res)
    print(f"wrote {p}")
    for m, v in res["methods"].items():
        c = res["calibration"]["methods"][m]["shared_universe"]["platt_cv"]
        print(f"{m:15} recall={v['recall']} hit@1={v['hit@1']} [{v['hit@1_optimistic']}/{v['hit@1_pessimistic']}] "
              f"mrr={v['mrr']} (alpha {v['hit@1_alphabetical']}/{v['mrr_alphabetical']}) shared brier={c['brier']} "
              f"auc={c['auc']}")
    print(res["compression"])
    print(res["corroboration"])
    print(res["prioritisation"])
    print({k: v for k, v in res["triage"].items() if k != "paired"}, res["triage"]["paired"])
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--limit", type=int, default=0, help="score only the first N captures")
    ap.add_argument("--subset", default="core", choices=["core", "all"], help="SigmaHQ rule subset")
    ap.add_argument("--from-cache", action="store_true", help="re-score the cached per-capture rows")
    a = ap.parse_args(argv)
    cache = data_dir() / "cache" / f"otrf_claims_{a.subset}.json"
    if a.from_cache:
        d = json.loads(cache.read_text(encoding="utf-8"))
        return score_all(d["per_capture"], d["meta"], a.subset)
    st = Stack.from_data_dir(engines=("anvil", "revenant", "correlation"), sigma_subset=a.subset)
    caps = [c for c in load_catalog(st.paths.otrf) if c.available and c.techniques]
    if a.limit:
        caps = caps[: a.limit]
    reg_t0 = time.perf_counter()
    st.registry()
    per_capture = []
    unreadable = []
    t0 = time.perf_counter()
    for i, cap in enumerate(caps, 1):
        try:
            recs = capture_records(cap)
        except OSError as exc:  # endpoint antivirus quarantines some attack logs
            unreadable.append(cap.id)
            print(f"[{i}/{len(caps)}] {cap.id} unreadable: {exc}", flush=True)
            continue
        if not recs:
            unreadable.append(cap.id)
            continue
        kg, summary, ctx = st.run(recs, st.registry())
        rows = capture_rows(kg, ctx)
        claims, alerts = capture_claims(kg)
        incs = ctx.get("incidents", [])
        truth_inc_rank = next((j for j, inc in enumerate(incs, 1)
                               if any(correct(t, cap.techniques) for t in inc["technique_conf"])), None)
        per_capture.append({"id": cap.id, "title": cap.title, "truth": cap.techniques, "events": len(recs),
                            "alerts_n": len(alerts), "incidents_n": len(incs), "truth_incident_rank": truth_inc_rank,
                            "rows": rows, "claims": claims, "alerts": alerts,
                            "incidents": [{"root": inc["root"], "score": inc["score"],
                                           "technique_conf": inc["technique_conf"]} for inc in incs],
                            "seconds": sum(summary["timings_s"].values())})
        print(f"[{i}/{len(caps)}] {cap.id} {cap.techniques} events={len(recs)} alerts={len(alerts)} "
              f"incidents={len(incs)} claimed={len(rows)}", flush=True)
    elapsed = time.perf_counter() - t0
    meta = {"sigma_rules": len(st.sigma_library().compiled), "seconds_total": round(elapsed, 1),
            "seconds_setup": round(t0 - reg_t0, 1), "engine_load_s": st.load_s,
            "labelled_captures": len(caps), "unreadable_captures": unreadable,
            "seconds_per_capture_median": round(statistics.median(pc["seconds"] for pc in per_capture), 2),
            "seconds_per_capture_mean": round(statistics.mean(pc["seconds"] for pc in per_capture), 2)}
    cache.parent.mkdir(parents=True, exist_ok=True)
    blob = {"per_capture": per_capture, "meta": meta}
    cache.write_text(json.dumps(blob), encoding="utf-8")
    write_raw(f"otrf_claims_{a.subset}", blob)
    return score_all(per_capture, meta, a.subset)


if __name__ == "__main__":
    raise SystemExit(main())
