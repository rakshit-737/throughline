"""Supply-chain slice on real data: a public repo's dependency history + OSV advisories.

TRACEGATE walks every first-parent commit that changed a pin in
``healthchecks/healthchecks``'s requirements.txt; OSV's PyPI dump says which
of those pinned versions carried a published advisory. In the graph this is
one question per vulnerability: *which commit, by whom, introduced it, and how
long was it exposed?* For each vulnerable pin the advisory's OSV ``published`` date
is compared with the day the pin was introduced, so "exposure in hindsight" vs
"pinned while already known" is measured, not assumed. The introducing commit is
compared with ``git blame`` for the pins present at HEAD - an *agreement* check with
TRACEGATE's own blame helper (both read the same pin parser), not an independent
oracle.

    python benchmarks/demo_supplychain.py
"""
from __future__ import annotations

import json
import statistics
import time
from collections import Counter
from datetime import UTC, datetime

from common import wilson, write

from throughline.engines.supplychain import TracegateSupplyChainEngine
from throughline.graph import KnowledgeGraph
from throughline.stack import data_dir

SEV = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def main() -> int:
    from tracegate.gitlineage import blame_introducers, parse_requirements
    from tracegate.ids import normalize_name

    root = data_dir()
    repo = root / "repos" / "healthchecks"
    osv_zip = root / "osv" / "PyPI-all.zip"
    kg = KnowledgeGraph()
    eng = TracegateSupplyChainEngine(repo, "requirements.txt", osv_zip=osv_zip)
    t0 = time.perf_counter()
    eng.run(kg, {})
    build_s = time.perf_counter() - t0
    hist = eng.history
    ts_of = {mc.sha[:12]: mc.timestamp for mc in hist}
    vuln_deps = {o: [s.split(":", 1)[1] for s, _, k in kg.g.in_edges(o, keys=True) if k == "AFFECTS"]
                 for o in kg.g if o.startswith("Dependency:")}
    vuln_deps = {d: v for d, v in vuln_deps.items() if v}
    rows = []
    t0 = time.perf_counter()
    for dep, vids in sorted(vuln_deps.items()):
        chain = kg.root_cause_chain(dep)
        commit = next((c for c in chain if c.startswith("Commit:")), None)
        author = next((c for c in chain if c.startswith("Author:")), None)
        a = kg.g.nodes[dep]["attrs"]
        added = ts_of.get(commit.split(":", 1)[1]) if commit else None
        removed = ts_of.get(a.get("removed_by", "")) if a.get("removed_by") else None
        sev = max((kg.g.nodes[f"Vulnerability:{v}"]["attrs"].get("severity", "UNKNOWN") for v in vids),
                  key=lambda s: SEV.get(s, 0))
        rows.append({"dependency": dep.split(":", 1)[1], "advisories": len(vids), "worst_severity": sev,
                     "introduced_by": commit, "author_domain": (author or "").rsplit("@", 1)[-1],
                     "introduced": datetime.fromtimestamp(added, UTC).strftime("%Y-%m-%d") if added else None,
                     "exposed_days": round((removed - added) / 86400, 1) if added and removed else None,
                     "still_pinned": not a.get("removed_by")})
    query_ms = (time.perf_counter() - t0) * 1000 / max(1, len(vuln_deps))
    # when was each advisory published, relative to the day its vulnerable version was pinned?
    from tracegate.osv import iter_zip_records

    wanted = {v for vids in vuln_deps.values() for v in vids}
    published: dict[str, str] = {}
    for rec in iter_zip_records(osv_zip):
        if rec.get("id") in wanted and rec.get("published"):
            published[rec["id"]] = rec["published"][:10]
    before = after = unknown = 0
    known_at_pin = 0
    for dep, vids in vuln_deps.items():
        row = next((r for r in rows if r["dependency"] == dep.split(":", 1)[1]), None)
        pinned = row and row["introduced"]
        any_before = False
        for v in vids:
            if not pinned or v not in published:
                unknown += 1
            elif published[v] <= pinned:
                before += 1
                any_before = True
            else:
                after += 1
        known_at_pin += any_before
    head_pins = parse_requirements((repo / "requirements.txt").read_text(encoding="utf-8"))
    blame = blame_introducers(repo, "requirements.txt")
    agree = total = 0
    for name, ver in head_pins.items():
        dep = f"Dependency:{name}=={ver}"
        if dep not in kg.g:
            continue
        total += 1
        chain = kg.root_cause_chain(dep)
        commit = next((c.split(":", 1)[1] for c in chain if c.startswith("Commit:")), None)
        agree += bool(commit and blame.get(normalize_name(name), "").startswith(commit))
    exposed = [r["exposed_days"] for r in rows if r["exposed_days"] is not None]
    res = {
        "repo": "healthchecks/healthchecks", "commit": "3731fc452b", "manifest": "requirements.txt",
        "osv": json.loads((root / "osv" / "MANIFEST.json").read_text()),
        "pin_changing_commits": len(hist), "distinct_pinned_versions": sum(1 for n in kg.g if n.startswith("Dependency:")),
        "vulnerable_versions_introduced": len(rows),
        "advisories": sum(1 for n in kg.g if n.startswith("Vulnerability:")),
        "by_worst_severity": dict(Counter(r["worst_severity"] for r in rows)),
        "vulnerable_still_pinned_at_head": [r["dependency"] for r in rows if r["still_pinned"]],
        "exposure_days_median": statistics.median(exposed) if exposed else None,
        "exposure_days_p90": sorted(exposed)[int(0.9 * (len(exposed) - 1))] if exposed else None,
        "advisory_published_vs_pin": {"published_before_or_on_pin_day": before, "published_after_pin": after,
                                      "date_unknown": unknown,
                                      "versions_with_an_advisory_known_when_pinned": known_at_pin},
        "blame_agreement_at_head": {"agree": agree, "total": total, "wilson": wilson(agree, total),
                                    "note": "agreement with tracegate.gitlineage.blame_introducers, which "
                                            "shares the pin parser; not an independent oracle"},
        "graph": kg.stats(), "build_seconds": round(build_s, 1), "root_cause_ms_per_query": round(query_ms, 3),
        "worst": sorted(rows, key=lambda r: (-SEV.get(r["worst_severity"], 0), -(r["exposed_days"] or 0)))[:10],
    }
    print("wrote", write("supplychain_healthchecks", res))
    print({k: res[k] for k in ("pin_changing_commits", "distinct_pinned_versions", "vulnerable_versions_introduced",
                               "advisories", "by_worst_severity", "exposure_days_median", "advisory_published_vs_pin",
                               "blame_agreement_at_head", "vulnerable_still_pinned_at_head")})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
