"""B3 - attribution: two ACH engines fused in the graph vs each alone vs naive similarity.

Every case is a set of ATT&CK techniques (and sometimes software) with a known culprit
group. Settings, from strictest to most optimistic:

* ``temporal``          ATT&CK campaigns documented after v10.1 (Nov 2021) whose group
                        exists in v10.1; group profiles from **v10.1**, so the answer was
                        not in the knowledge base when the profiles were built.
* ``temporal_families`` malware families first published in ATT&CK after v10.1, used by
                        exactly one group that exists in v10.1, with >= 5 techniques
                        expressible in v10.1; evidence is the family's techniques only (the
                        family itself is unknown to v10.1). Profiles from v10.1.
* ``temporal_all``      the two temporal sets pooled - the headline case set.
* ``report_lro``        one case per (group, cited report) in v19.2 with >= 5 techniques
                        (DRAGNET's per-report cases, at most 8 reports per group) under
                        **leave-report-out**: 5 folds by report; for each fold every group
                        ``uses`` relationship whose citations all belong to that fold's
                        reports is removed from the STIX bundle both engines load, so a case
                        is never attributed with knowledge only its own report contributed.
* ``drift_dose``        behaviour drift as a dose-response curve: 8 signals per group, a
                        fraction f in {0, .25, .5, .75, 1} drawn from what ATT&CK learned
                        about the group after v10.1 and the rest from its v10.1 profile;
                        profiles from v10.1 (f = 0 is in-sample by construction, f = 1 is
                        pure drift); 3 seeds.
* ``retrospective``     campaigns scored against v19.2 profiles (optimistic upper bound:
                        ATT&CK copies most campaign techniques onto the group).

Each temporal / per-report setting runs clean and with planted false flags (DRAGNET's
stress test: a copied Rich header + decoy-language strings pointing at a decoy group from
another country; level 2 adds a malware family exclusive to the decoy). OCCAM receives the
equivalent spoofable markers.

Methods: ``similarity`` (IDF-cosine nearest profile), ``dragnet``, ``occam``, and
``fused`` - both verdicts as ``ATTRIBUTED_TO`` claims in a THROUGHLINE graph, where the
confidence engine combines agreeing engines by noisy-OR and discounts competing
hypotheses (``UNKNOWN`` included). Operating points: *named* (any actor named) and
*confident* (each method's own rule: DRAGNET MEDIUM+, OCCAM moderate+, similarity
p >= 0.8, fused confidence >= 0.5).

Statistics: Wilson 95% intervals for every rate (they do not collapse at 0 or 1);
cluster bootstrap over culprit groups where one group contributes several cases (and over
all seeds of a group for ``drift_dose``); exact McNemar tests of fused vs each method on
paired cases; risk-coverage (selective risk among the most confident cases, abstentions
last) and its area (AURC, lower is better).

    python benchmarks/bench_attribution.py [--quick]
"""
from __future__ import annotations

import argparse
import gc
import json
import random
import statistics
import time
import zlib

from common import cluster_bootstrap_ci, mcnemar, wilson, write, write_raw

from throughline.engines.intel import DragnetIntelEngine, Evidence, OccamIntelEngine, Verdict, record_verdict
from throughline.graph import KnowledgeGraph
from throughline.reasoning import calibration as cal
from throughline.stack import DataPaths, data_dir

METHODS = ("similarity", "dragnet", "occam", "fused")
LEVELS = (0, 1, 2)
LRO_FOLDS = 5
LRO_MAX_PER_GROUP = 8
LRO_MIN_TTP = 5
DOSES = (0.0, 0.25, 0.5, 0.75, 1.0)
DOSE_SIGNALS = 8
DOSE_SEEDS = (0, 1, 2)
FAMILY_MIN_TTP = 5


def level_key(level: int) -> str:
    return "clean" if level == 0 else f"false_flag_l{level}"


# ------------------------------------------------------------------------------ methods
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


def run_cases(dr: DragnetIntelEngine, oc: OccamIntelEngine, cases, level: int) -> list[dict]:
    """Every method on every case; one row per case."""
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
        row = {"case": c.case_id, "name": c.name, "truth": sorted(c.truth),
               "group": c.meta.get("group") or next(iter(sorted(c.truth)), ""), "meta": {
                   k: v for k, v in c.meta.items() if k in ("seed", "dose", "n_ttp", "kind", "report", "fold")}}
        if decoy:
            row["decoy"] = decoy
        for m, v in (("dragnet", vd), ("occam", vo), ("similarity", vs), ("fused", vf)):
            row[m] = {"named": v.leading, "p": round(v.probability, 4), "grade": v.grade}
        rows.append(row)
    dr.kg = kg_saved
    return rows


# ------------------------------------------------------------------------------ scoring
def _ok(r: dict, m: str) -> bool:
    return r[m]["named"] in r["truth"]


def _rate(rows: list[dict], pred) -> float | None:
    return sum(1 for r in rows if pred(r)) / len(rows) if rows else None


def _rc(rows: list[dict], m: str) -> dict:
    from dragnet.protocols import risk_coverage

    pts = [(r[m]["p"] if r[m]["named"] else -1.0, _ok(r, m)) for r in rows]
    rc = risk_coverage(pts)
    return {"aurc": round(rc["aurc"], 4), "risk_at": {k: round(v, 4) for k, v in rc["risk_at"].items()}}


def score(rows: list[dict], m: str, seeded: bool = False) -> dict:
    """Rates with Wilson CIs, group-clustered bootstrap CIs and the risk-coverage summary."""
    n = len(rows)
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r["group"], []).append(r)
    clusters = list(groups.values())
    named = [r for r in rows if r[m]["named"]]
    conf = [r for r in rows if confident(m, r[m])]
    out = {"n": n, "groups": len(groups)}
    for key, pred in (("top1", lambda r: _ok(r, m)),
                      ("named", lambda r: bool(r[m]["named"])),
                      ("wrong_named", lambda r: bool(r[m]["named"]) and not _ok(r, m)),
                      ("confident_correct", lambda r: confident(m, r[m]) and _ok(r, m)),
                      ("confident_wrong", lambda r: confident(m, r[m]) and not _ok(r, m))):
        k = sum(1 for r in rows if pred(r))
        out[key] = round(k / n, 4) if n else None
        out[f"{key}_k"] = k
        out[f"{key}_wilson"] = wilson(k, n)
        if len(groups) < n:
            out[f"{key}_ci_group_clustered"] = cluster_bootstrap_ci(clusters, lambda rs, p=pred: _rate(rs, p))
    out["selective_acc"] = round(sum(1 for r in named if _ok(r, m)) / len(named), 4) if named else None
    out["confident_precision"] = round(sum(1 for r in conf if _ok(r, m)) / len(conf), 4) if conf else None
    out["confident_coverage"] = round(len(conf) / n, 4) if n else None
    out["brier_top1"] = round(cal.brier([(r[m]["p"] if r[m]["named"] else 0.0, _ok(r, m)) for r in rows]), 4)
    out["risk_coverage"] = _rc(rows, m)
    if rows and "decoy" in rows[0]:
        out["decoy_named"] = round(sum(1 for r in rows if r[m]["named"] == r.get("decoy")) / n, 4)
        out["decoy_confident"] = round(sum(1 for r in conf if r[m]["named"] == r.get("decoy")) / n, 4)
        out["decoy_named_wilson"] = wilson(sum(1 for r in rows if r[m]["named"] == r.get("decoy")), n)
    if seeded:
        by_seed: dict = {}
        for r in rows:
            by_seed.setdefault(r["meta"].get("seed"), []).append(_ok(r, m))
        xs = [sum(v) / len(v) for v in by_seed.values()]
        out["top1_seed_sd"] = round(statistics.pstdev(xs), 4) if len(xs) > 1 else 0.0
    return out


def paired(rows: list[dict], ref: str = "fused") -> dict:
    """Exact McNemar tests of ``ref`` against every other method on the same cases."""
    out = {}
    for m in METHODS:
        if m == ref:
            continue
        out[m] = {key: mcnemar([pred(r, ref) for r in rows], [pred(r, m) for r in rows])
                  for key, pred in (("top1", lambda r, x: _ok(r, x)),
                                    ("confident_correct", lambda r, x: confident(x, r[x]) and _ok(r, x)),
                                    ("confident_wrong", lambda r, x: confident(x, r[x]) and not _ok(r, x)))}
    return out


def summarise(rows: list[dict], seeded: bool = False) -> dict:
    return {"methods": {m: score(rows, m, seeded) for m in METHODS}, "fused_vs": paired(rows)}


def short(s: dict) -> dict:
    return {m: (v["top1"], v["confident_correct"], v["confident_wrong"]) for m, v in s["methods"].items()}


# ------------------------------------------------------------------------------ case sets
def family_cases(new, old) -> list:
    """Malware families first published after ``old`` was released, used by exactly one group
    that exists in ``old``; evidence = their techniques expressible in ``old``."""
    from dragnet.bench import Case
    from dragnet.models import Signal, SignalKind

    known = {t.attack_id for t in old.techniques.values()}
    out = []
    for sid, gids in sorted(new.software_attribution().items(), key=lambda kv: new.software[kv[0]].attack_id):
        sw = new.software[sid]
        if sw.type != "malware" or len(gids) != 1 or not sw.created or sw.created <= old.released:
            continue
        og = old.resolve_group(next(iter(gids)))
        if not og:
            continue
        tids = sorted(new.techniques_of(sid) & known)
        if len(tids) < FAMILY_MIN_TTP:
            continue
        name = old.groups[og].name
        out.append(Case(sw.attack_id, sw.name, [Signal(SignalKind.TTP, t, sw.attack_id) for t in tids], {name},
                        {"group": name, "n_ttp": len(tids), "kind": "family", "created": sw.created}))
    return out


def lro_cases(new) -> list:
    from dragnet.protocols import fold_of, report_cases

    by_group: dict[str, list] = {}
    for c in report_cases(new, min_ttps=LRO_MIN_TTP):
        by_group.setdefault(c.meta["group"], []).append(c)
    out = []
    for _g, cs in sorted(by_group.items()):
        cs = sorted(cs, key=lambda c: zlib.crc32(c.case_id.encode()))[:LRO_MAX_PER_GROUP]
        for c in cs:
            c.meta["fold"] = fold_of(c.meta["report"], LRO_FOLDS)
            c.meta["kind"] = "report"
            out.append(c)
    return out


def dose_cases(new, old, dose: float, seed: int) -> list:
    """8 signals per eligible group: round(dose * 8) learned after ``old``, the rest from the
    group's ``old`` profile; groups need >= 8 of each so every dose is feasible."""
    from dragnet.bench import Case
    from dragnet.models import Signal, SignalKind

    known_t = {t.attack_id for t in old.techniques.values()}
    rng = random.Random(seed * 1000 + int(dose * 100))
    out = []
    for gid, g in sorted(new.groups.items(), key=lambda kv: kv[1].attack_id):
        if gid not in old.groups:
            continue

        def ttp(t, gid=gid):
            return Signal(SignalKind.TTP, t, gid)

        def soft(o, gid=gid):
            return Signal(SignalKind.FAMILY if o.type == "malware" else SignalKind.TOOL, o.name, gid)

        old_t, new_t = old.techniques_of(gid), new.techniques_of(gid)
        old_s, new_s = old.software_of(gid), new.software_of(gid)
        pool_old = [ttp(t) for t in sorted(old_t)] + [soft(old.software[s]) for s in sorted(old_s)]
        pool_new = [ttp(t) for t in sorted((new_t - old_t) & known_t)]
        pool_new += [soft(old.software[s]) for s in sorted((new_s - old_s) & set(old.software))]
        if len(pool_old) < DOSE_SIGNALS or len(pool_new) < DOSE_SIGNALS:
            continue
        k = round(dose * DOSE_SIGNALS)
        sigs = rng.sample(pool_new, k) + rng.sample(pool_old, DOSE_SIGNALS - k)
        name = old.groups[gid].name
        out.append(Case(g.attack_id, g.name, sigs, {name},
                        {"group": name, "seed": seed, "dose": dose, "kind": "drift"}))
    return out


def filtered_bundle(bundle: dict, held: set[str]) -> tuple[dict, int]:
    """``bundle`` without the group ``uses`` relationships cited only by ``held`` reports
    (the same rule as ``dragnet.protocols.drop_cited``, applied to the STIX both engines load)."""
    keep, dropped = [], 0
    for o in bundle["objects"]:
        if (o.get("type") == "relationship" and o.get("relationship_type") == "uses"
                and str(o.get("source_ref", "")).startswith("intrusion-set--")):
            refs = {r["source_name"] for r in o.get("external_references", []) if r.get("source_name")
                    and not r["source_name"].startswith("mitre-") and r["source_name"] != "capec"}
            if refs and refs <= held:
                dropped += 1
                continue
        keep.append(o)
    return {**bundle, "objects": keep}, dropped


# ------------------------------------------------------------------------------ runs
def run_temporal(p: DataPaths, new, quick: bool) -> tuple[dict, dict]:
    from dragnet.bench import attack_campaign_cases

    dr = DragnetIntelEngine(p.attack_old, p.misp)
    oc = OccamIntelEngine(p.attack_old, shortlist=25)
    camps = [c for c in attack_campaign_cases(new, dr.attack, created_after=dr.attack.released) if c.truth]
    for c in camps:
        c.meta["kind"] = "campaign"
    fams = family_cases(new, dr.attack)
    if quick:
        camps, fams = camps[:4], fams[:6]
    res: dict = {}
    raw: dict = {}
    for name, cases in (("temporal", camps), ("temporal_families", fams)):
        res[name] = {"kg_version": dr.attack.version, "cases": len(cases),
                     "groups": len({c.meta.get("group") for c in cases})}
        for level in LEVELS:
            rows = run_cases(dr, oc, cases, level)
            raw[f"{name}/{level_key(level)}"] = rows
            res[name][level_key(level)] = summarise(rows)
            print(f"  {name} {level_key(level)} n={len(rows)}:", short(res[name][level_key(level)]), flush=True)
    res["temporal_all"] = {"kg_version": dr.attack.version, "cases": len(camps) + len(fams),
                           "groups": len({c.meta.get("group") for c in camps + fams})}
    for level in LEVELS:
        rows = raw[f"temporal/{level_key(level)}"] + raw[f"temporal_families/{level_key(level)}"]
        res["temporal_all"][level_key(level)] = summarise(rows)
        print(f"  temporal_all {level_key(level)} n={len(rows)}:", short(res["temporal_all"][level_key(level)]),
              flush=True)
    doses: dict = {"kg_version": dr.attack.version, "signals": DOSE_SIGNALS, "seeds": list(DOSE_SEEDS), "doses": {}}
    for dose in DOSES:
        rows = []
        for seed in (DOSE_SEEDS[:1] if quick else DOSE_SEEDS):
            cases = dose_cases(new, dr.attack, dose, seed)
            rows += run_cases(dr, oc, cases[:5] if quick else cases, 0)
        raw[f"drift_dose/{dose}"] = rows
        doses["groups"] = len({r["group"] for r in rows})
        doses["doses"][f"{dose:.2f}"] = summarise(rows, seeded=True)
        print(f"  drift_dose f={dose} n={len(rows)}:", short(doses["doses"][f"{dose:.2f}"]), flush=True)
    res["drift_dose"] = doses
    return res, raw


def run_retrospective(p: DataPaths, new, quick: bool) -> tuple[dict, dict]:
    from dragnet.bench import attack_campaign_cases

    dr = DragnetIntelEngine(p.attack, p.misp)
    oc = OccamIntelEngine(p.attack, shortlist=25)
    cases = [c for c in attack_campaign_cases(new, dr.attack) if c.truth]
    if quick:
        cases = cases[:4]
    res: dict = {"kg_version": dr.attack.version, "cases": len(cases)}
    raw = {}
    for level in LEVELS:
        rows = run_cases(dr, oc, cases, level)
        raw[f"retrospective/{level_key(level)}"] = rows
        res[level_key(level)] = summarise(rows)
        print(f"  retrospective {level_key(level)} n={len(rows)}:", short(res[level_key(level)]), flush=True)
    return res, raw


def run_lro(p: DataPaths, new, quick: bool) -> tuple[dict, dict]:
    cases = lro_cases(new)
    if quick:
        cases = [c for c in cases if c.meta["fold"] == 0][:6]
    bundle = json.loads(p.attack.read_text(encoding="utf-8"))
    tmp = data_dir() / "cache" / "attack-lro-fold.json"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    rows_by_level: dict[int, list] = {lv: [] for lv in LEVELS}
    leak = {"before": [], "after": []}
    dropped_total = 0
    folds = sorted({c.meta["fold"] for c in cases})
    for f in folds:
        fold_cases = [c for c in cases if c.meta["fold"] == f]
        held = {c.meta["report"] for c in cases if c.meta["fold"] == f}
        fb, dropped = filtered_bundle(bundle, held)
        dropped_total += dropped
        tmp.write_text(json.dumps(fb), encoding="utf-8")
        del fb
        dr = DragnetIntelEngine(tmp, p.misp)
        oc = OccamIntelEngine(tmp, shortlist=25)
        for c in fold_cases:  # how much of the case's evidence is still in its group's profile
            gid = next((g for g, o in dr.attack.groups.items() if o.name == c.meta["group"]), None)
            ttps = {s.value for s in c.signals if s.kind.name == "TTP"}
            leak["after"].append(len(ttps & dr.attack.techniques_of(gid)) / len(ttps) if gid and ttps else 0.0)
            leak["before"].append(len(ttps & new.techniques_of(c.meta["group_id"])) / len(ttps) if ttps else 0.0)
        for level in LEVELS:
            rows = run_cases(dr, oc, fold_cases, level)
            for r in rows:
                r["meta"]["fold"] = f
            rows_by_level[level] += rows
        print(f"  report_lro fold {f}: {len(fold_cases)} cases, {dropped} relationships held out", flush=True)
        del dr, oc
        gc.collect()
    tmp.unlink(missing_ok=True)
    res: dict = {"kg_version": new.version, "cases": len(cases), "groups": len({c.meta["group"] for c in cases}),
                 "folds": LRO_FOLDS, "max_reports_per_group": LRO_MAX_PER_GROUP, "min_ttp": LRO_MIN_TTP,
                 "relationships_held_out": dropped_total,
                 "evidence_in_own_profile": {"full_kb": round(statistics.mean(leak["before"]), 4),
                                             "leave_report_out": round(statistics.mean(leak["after"]), 4)}}
    raw = {}
    for level in LEVELS:
        raw[f"report_lro/{level_key(level)}"] = rows_by_level[level]
        res[level_key(level)] = summarise(rows_by_level[level])
        print(f"  report_lro {level_key(level)} n={len(rows_by_level[level])}:", short(res[level_key(level)]),
              flush=True)
    return res, raw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--quick", action="store_true", help="a few cases per setting (smoke test)")
    a = ap.parse_args(argv)
    from dragnet.sources.attack import load_attack

    p = DataPaths(data_dir())
    t0 = time.perf_counter()
    new = load_attack(p.attack)
    res: dict = {"protocol": __doc__.split("\n\n")[1].strip()[:200]}
    raw: dict = {}
    for name, fn in (("temporal", run_temporal), ("retrospective", run_retrospective), ("report_lro", run_lro)):
        print(name, flush=True)
        r, rw = fn(p, new, a.quick)
        raw.update(rw)
        if name == "temporal":
            res.update(r)
        else:
            res[name] = r
    # calibration of the committed (named) verdicts, pooled over the clean leakage-controlled sets
    pooled = {m: [] for m in METHODS}
    for key in ("temporal/clean", "temporal_families/clean", "report_lro/clean"):
        for r in raw.get(key, []):
            for m in METHODS:
                if r[m]["named"]:
                    pooled[m].append((r[m]["p"], _ok(r, m)))
    res["committed_calibration"] = {m: cal.summary(v) for m, v in pooled.items()}
    res["seconds"] = round(time.perf_counter() - t0, 1)
    if a.quick:  # smoke test: nothing under results/ changes
        print("quick run ok:", write_raw("attribution_quick", {"summary": res, "rows": raw}), f"({res['seconds']} s)")
        return 0
    write_raw("attribution_rows", raw)
    out = write("attribution", res)
    print("wrote", out, f"({res['seconds']} s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
