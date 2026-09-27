"""B3 - attribution: two ACH engines fused in the graph vs each alone vs naive similarity.

Cases are MITRE ATT&CK campaigns with an ``attributed-to`` group. Evidence is the
campaign's techniques and software. Two settings:

* ``temporal``      - group profiles from ATT&CK **v10.1** (Nov 2021); only campaigns
  documented later (in v19.2) are scored, so the answer was not in the knowledge
  base when the profiles were built.
* ``retrospective`` - profiles and campaigns from v19.2 (optimistic upper bound).
* ``group_drift``   - the larger case set (since 1.1.0): every ATT&CK group present in
  both versions becomes a case whose evidence is only what ATT&CK *learned about it
  after* v10.1 (techniques and software in v19.2 but not in its v10.1 entry);
  profiles from v10.1. Evidence is subsampled to at most ``DRIFT_MAX`` signals per
  case over ``SEEDS`` seeds (an analyst rarely sees a group's whole new repertoire);
  CIs are bootstrap over all case x seed rows, plus the across-seed spread.
* ``group_retrospective`` - every v19.2 group, evidence subsampled from its own
  v19.2 repertoire (in-sample: the largest case set, an optimistic upper bound).

Each is run clean and with planted false flags (DRAGNET's stress test: a copied
Rich header + decoy-language strings pointing at a decoy group from another
country; level 2 adds an exclusive decoy malware family). OCCAM receives the
equivalent spoofable markers pointing at the same decoy.

Methods: ``similarity`` (IDF-cosine nearest profile, the "single-signal"
baseline), ``dragnet``, ``occam``, and ``fused`` - both verdicts written as
``ATTRIBUTED_TO`` claims into a THROUGHLINE graph, where the confidence engine
combines agreeing engines by noisy-OR and discounts competing hypotheses
(``UNKNOWN`` included). Two operating points per method: *named* (it names any
actor) and *confident* (its own confidence rule: DRAGNET MEDIUM+, OCCAM
moderate+, similarity p >= 0.8, THROUGHLINE fused confidence >= 0.5).

    python benchmarks/bench_attribution.py
"""
from __future__ import annotations

import statistics

from common import bootstrap_ci, write

from throughline.engines.intel import DragnetIntelEngine, Evidence, OccamIntelEngine, Verdict, record_verdict
from throughline.graph import KnowledgeGraph
from throughline.reasoning import calibration as cal
from throughline.stack import DataPaths, data_dir


def fuse(vs: list[tuple[Verdict, str]]) -> Verdict:
    kg = KnowledgeGraph()
    kg.add_claim("Incident", "case", "EXISTS", None, None, source="bench", method="observed", reliability="A",
                 timestamp="2020-01-01T00:00:00Z")
    for v, src in vs:
        record_verdict(kg, "Incident:case", v, src)
    rows = sorted(((o.split(":", 1)[1], d.get("confidence", 0.0))
                   for _, o, k, d in kg.g.out_edges("Incident:case", keys=True, data=True) if k == "ATTRIBUTED_TO"),
                  key=lambda x: (-x[1], x[0]))
    top, conf = rows[0]
    return Verdict("fused", None if top == "UNKNOWN" else top, conf, "", [r[0] for r in rows])


def similarity(oc: OccamIntelEngine, ev: Evidence) -> Verdict:
    from occam.attribution import SimilarityAttributor
    r = SimilarityAttributor(oc.profiles, oc.kb).attribute(oc.evidence(ev))
    return Verdict("similarity", oc.names.get(r.leading, r.leading), float(r.probability), r.confidence)


def confident(method: str, v: dict) -> bool:
    """Each method's own "I am confident" rule: DRAGNET MEDIUM+, OCCAM moderate+, the
    similarity baseline's high band (p >= 0.8), THROUGHLINE fused confidence >= 0.5."""
    if not v["named"]:
        return False
    if method == "dragnet":
        return v["grade"] in ("MEDIUM", "HIGH")
    if method == "occam":
        return v["grade"] in ("moderate", "high")
    if method == "similarity":
        return v["p"] >= 0.8
    return v["p"] >= 0.5


def score(rows: list[dict], method: str) -> dict:
    named = [r for r in rows if r[method]["named"]]
    conf = [r for r in rows if confident(method, r[method])]
    top1 = [float(r[method]["named"] in r["truth"]) for r in rows]
    committed_ok = [float(r[method]["named"] in r["truth"]) for r in named]
    pairs = [(r[method]["p"], r[method]["named"] in r["truth"]) for r in rows if r[method]["named"]]
    out = {"n": len(rows), "top1": round(statistics.mean(top1), 4) if rows else None, "top1_ci": bootstrap_ci(top1),
           "coverage": round(len(named) / len(rows), 4) if rows else None,
           "selective_acc": round(statistics.mean(committed_ok), 4) if named else None,
           "wrong_named": round(sum(1 for r in named if r[method]["named"] not in r["truth"]) / len(rows), 4),
           "brier_top1": round(cal.brier([(r[method]["p"] if r[method]["named"] else 0.0,
                                           r[method]["named"] in r["truth"]) for r in rows]), 4)}
    out["confident_correct"] = round(sum(1 for r in conf if r[method]["named"] in r["truth"]) / len(rows), 4)
    out["confident_wrong"] = round(sum(1 for r in conf if r[method]["named"] not in r["truth"]) / len(rows), 4)
    if rows and "decoy" in rows[0]:
        out["decoy_named"] = round(sum(1 for r in rows if r[method]["named"] == r["decoy"]) / len(rows), 4)
        out["decoy_confident"] = round(sum(1 for r in conf if r[method]["named"] == r["decoy"]) / len(rows), 4)
    out["_pairs"] = pairs
    return out


def run_setting(dr: DragnetIntelEngine, oc: OccamIntelEngine, cases, level: int) -> dict:
    from dragnet.bench import plant_false_flags, reference_rich_headers
    from dragnet.models import SignalKind

    kg_saved = dr.kg
    if level:
        dr.kg = reference_rich_headers(kg_saved)
        cases = plant_false_flags(cases, kg_saved, level)
    sw_ids = {}
    for sid, e in oc.data.software.items():
        for n in [e.name, *e.aliases]:
            sw_ids.setdefault(n.lower(), sid)
    rows = []
    for c in cases:
        techs = sorted(s.value for s in c.signals if s.kind == SignalKind.TTP)
        sw = sorted({sw_ids[s.value.lower()] for s in c.signals
                     if s.kind in (SignalKind.FAMILY, SignalKind.TOOL) and s.value.lower() in sw_ids
                     and s.source != "planted"})
        decoy = c.meta.get("decoy")
        planted = [decoy] * 3 if decoy else []
        if level >= 2 and decoy:  # the planted exclusive family is real software of the decoy
            fam = next((s.value for s in c.signals if s.source == "planted" and s.kind == SignalKind.FAMILY), None)
            if fam and fam.lower() in sw_ids:
                sw.append(sw_ids[fam.lower()])
        ev = Evidence(techs, sw, planted)
        vd = dr.attribute(Evidence([], []), extra_signals=c.signals)
        vo = oc.attribute(ev)
        vs = similarity(oc, ev)
        vf = fuse([(vd, "dragnet"), (vo, "occam")])
        row = {"case": c.case_id, "name": c.name, "truth": sorted(c.truth)}
        if decoy:
            row["decoy"] = decoy
        for m, v in (("dragnet", vd), ("occam", vo), ("similarity", vs), ("fused", vf)):
            row[m] = {"named": v.leading, "p": round(v.probability, 4), "grade": v.grade}
        rows.append(row)
    dr.kg = kg_saved
    out = {m: score(rows, m) for m in ("similarity", "dragnet", "occam", "fused")}
    return {"methods": out, "rows": rows}


SEEDS = (0, 1, 2, 3, 4)
DRIFT_MAX = 10
DRIFT_MIN_TTP = 3


def group_drift_cases(new, old, seed: int, drift: bool = True):
    """Cases from what each group gained between ``old`` (profiles) and ``new`` ATT&CK.
    ``drift=False``: the group's whole ``new`` repertoire (in-sample upper bound, new == old)."""
    import random

    from dragnet.bench import Case
    from dragnet.models import Signal, SignalKind

    rng = random.Random(seed)
    known = {t.attack_id for t in old.techniques.values()}  # evidence must be expressible in the old KB
    out = []
    for gid, g in sorted(new.groups.items(), key=lambda kv: kv[1].attack_id):
        if gid not in old.groups:
            continue
        techs = sorted((new.techniques_of(gid) - (old.techniques_of(gid) if drift else set())) & known)
        sw = sorted(new.software_of(gid) - (old.software_of(gid) if drift else set()))
        if len(techs) < DRIFT_MIN_TTP:
            continue
        sigs = [Signal(SignalKind.TTP, t, gid) for t in techs]
        for sid in sw:
            o = new.software[sid]
            sigs.append(Signal(SignalKind.FAMILY if o.type == "malware" else SignalKind.TOOL, o.name, gid))
        if len(sigs) > DRIFT_MAX:
            ttp = [x for x in sigs if x.kind == SignalKind.TTP]
            rest = [x for x in sigs if x.kind != SignalKind.TTP]
            keep = rng.sample(ttp, min(len(ttp), max(DRIFT_MIN_TTP, DRIFT_MAX - min(len(rest), DRIFT_MAX // 2))))
            keep += rng.sample(rest, min(len(rest), DRIFT_MAX - len(keep)))
            sigs = keep
        out.append(Case(g.attack_id, g.name, sigs, {old.groups[gid].name},
                        {"group": g.name, "new_ttp": len(techs), "new_software": len(sw), "seed": seed}))
    return out


def run_group_drift(p: DataPaths, drift: bool = True) -> dict:
    from dragnet.sources.attack import load_attack

    kb = p.attack_old if drift else p.attack
    dr = DragnetIntelEngine(kb, p.misp)
    oc = OccamIntelEngine(kb, shortlist=25)
    new = load_attack(p.attack)
    res: dict = {"kg_version": dr.attack.version, "seeds": list(SEEDS), "max_signals": DRIFT_MAX}
    methods = ("similarity", "dragnet", "occam", "fused")
    for level in (0, 1):
        key = "clean" if level == 0 else f"false_flag_l{level}"
        rows, per_seed = [], {m: [] for m in methods}
        for seed in SEEDS:
            cases = group_drift_cases(new, dr.attack, seed, drift)
            r = run_setting(dr, oc, cases, level)
            for row in r["rows"]:
                row["seed"] = seed
            rows += r["rows"]
            for m in methods:
                per_seed[m].append(r["methods"][m]["top1"])
        res["cases"] = len(cases)
        agg = {m: score(rows, m) for m in methods}
        for m in methods:
            agg[m].pop("_pairs")
            xs = per_seed[m]
            agg[m]["top1_seed_mean"] = round(statistics.mean(xs), 4)
            agg[m]["top1_seed_sd"] = round(statistics.pstdev(xs), 4)
        res[key] = {"methods": agg, "rows": rows}
        print(f"  group_{'drift' if drift else 'retro'} {key} ({res['cases']} cases x {len(SEEDS)} seeds):",
              {m: (s["top1"], s["top1_ci"], s["wrong_named"], s["confident_wrong"]) for m, s in agg.items()},
              flush=True)
    return res


def main() -> int:
    p = DataPaths(data_dir())
    from dragnet.bench import attack_campaign_cases
    from dragnet.sources.attack import load_attack

    res: dict = {}
    for name, kg_path in (("temporal", p.attack_old), ("retrospective", p.attack)):
        dr = DragnetIntelEngine(kg_path, p.misp)
        oc = OccamIntelEngine(kg_path, shortlist=25)
        attack_eval = load_attack(p.attack)
        after = dr.attack.released if name == "temporal" else None
        cases = [c for c in attack_campaign_cases(attack_eval, dr.attack, created_after=after) if c.truth]
        print(f"{name}: {len(cases)} campaigns with the culprit in the v{dr.attack.version} knowledge base", flush=True)
        res[name] = {"kg_version": dr.attack.version, "cases": len(cases)}
        for level in (0, 1, 2):
            r = run_setting(dr, oc, cases, level)
            key = "clean" if level == 0 else f"false_flag_l{level}"
            res[name][key] = r
            print(f"  {key}:", {m: {k: v for k, v in s.items() if k in ("top1", "wrong_named", "decoy_named",
                                                                            "confident_correct", "confident_wrong")}
                                for m, s in r["methods"].items()}, flush=True)
    res["group_drift"] = run_group_drift(p)
    res["group_retrospective"] = run_group_drift(p, drift=False)
    # pooled calibration of the committed verdicts across all settings
    pooled = {m: [] for m in ("similarity", "dragnet", "occam", "fused")}
    for name in ("temporal", "retrospective"):
        for key in ("clean", "false_flag_l1", "false_flag_l2"):
            for m in pooled:
                pooled[m] += res[name][key]["methods"][m].pop("_pairs")
    res["committed_calibration"] = {m: cal.summary(v) for m, v in pooled.items()}
    out = write("attribution", res)
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
