"""The other OTRF compound (multi-stage / multi-host) captures through the whole stack.

APT3 (Empire and CALDERA emulations, several hosts) and the seven LSASS
credential-dumping campaigns (Metasploit + a different dumping tool each). None
has per-event labels; the LSASS campaigns' metadata names the emulated
techniques, so for those this reports recall of that list for each analyst (Sigma
alone, REVENANT alone, union, THROUGHLINE fused), alongside incidents, cross-host
clusters and cost. Each capture is also written as its own result file
(``results/compound_<name>.json``). Exits non-zero when a capture is missing, so a
partial run is never mistaken for a complete one.

    python benchmarks/bench_compound.py
"""
from __future__ import annotations

import json
import sys

import demo_apt29
from common import RESULTS, wilson, write

from throughline.stack import Stack

CAPTURES = {
    "apt3_empire": "compound/windows/apt3/empire_apt3.tar.gz",
    "apt3_caldera_r1": "compound/windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz",
    **{f"lsass_0{i}_{n}": f"compound/LSASS_campaign_0{i}/metasploit_{n}_lsass_memory_dump.zip"
       for i, n in enumerate(("logonpasswords", "procdump", "comsvcs", "out-minidump", "sharpdump",
                              "outflank-dumpert", "nanodump"), 1)},
}
ANALYSTS = ("sigma", "revenant", "union", "fused")


def parent(t: str) -> str:
    return t.split(".")[0]


def expected_techniques(root, name: str) -> list[str]:
    """ATT&CK ids in the capture's OTRF metadata YAML, when it has one."""
    import yaml

    if not name.startswith("lsass"):
        return []
    meta = root / "compound" / "_metadata" / f"LSASS_campaign_0{name[6]}.yaml"
    if not meta.exists():
        return []
    d = yaml.safe_load(meta.read_text(encoding="utf-8")) or {}
    out = set()
    for m in d.get("attack_mappings") or []:
        t = str(m.get("technique") or "").upper()
        if t and t != "T0000":
            sub = m.get("sub-technique")
            out.add(f"{t}.{int(sub):03d}" if str(sub or "").isdigit() else t)
    return sorted(out)


def main() -> int:
    st = Stack.from_data_dir()
    missing = [rel for rel in CAPTURES.values() if not (st.paths.otrf / rel).exists()]
    if missing:
        print("missing (run scripts/download_data.py otrf):", missing)
        return 1
    rows = []
    for name, rel in CAPTURES.items():
        print("==", name, flush=True)
        demo_apt29.main(["--capture", rel, "--name", f"compound_{name}", "--top", "3"])
        d = json.loads((RESULTS / f"compound_{name}.json").read_text(encoding="utf-8"))
        exp = expected_techniques(st.paths.otrf, name)
        row = {"capture": name, "records": d["records"], "pipeline_seconds": d["pipeline_seconds"],
               "peak_rss_mb": d["peak_rss_mb"], "alerts": d["alerts"], "incidents": d["incidents"],
               "hosts": d["stitching"]["hosts_with_incidents"],
               "multi_host_clusters": d["stitching"]["multi_host_clusters"],
               "cluster_via": [c["via"][:3] for c in d["stitching"]["top_multi_host"][:3]],
               "techniques_observed": len(d["techniques_observed"]), "expected": exp,
               "top_attribution": d["top_incidents"][0]["attribution"][:2] if d["top_incidents"] else []}
        if exp:
            # parent-technique match: T1003.001 expected, T1003 observed counts (and vice versa)
            for m in ANALYSTS:
                seen = {parent(t) for t in d["analyst_techniques"][m]}
                row[f"recall_{m}"] = round(sum(1 for t in exp if parent(t) in seen) / len(exp), 3)
        rows.append(row)
        print(row, flush=True)
    lsass = [r for r in rows if r["expected"]]
    pooled = {}
    for m in ANALYSTS:
        k = sum(round(r[f"recall_{m}"] * len(r["expected"])) for r in lsass)
        n = sum(len(r["expected"]) for r in lsass)
        pooled[m] = {"hit": k, "expected": n, "recall": round(k / n, 4) if n else None, "wilson": wilson(k, n)}
    out = write("compound", {"captures": rows, "lsass_pooled_recall": pooled})
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
