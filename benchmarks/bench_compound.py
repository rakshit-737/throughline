"""The other OTRF compound (multi-stage / multi-host) captures through the whole stack.

APT3 (Empire and CALDERA emulations, several hosts) and the seven LSASS
credential-dumping campaigns (Metasploit + a different dumping tool each). None
has per-event labels; the metadata names the emulated techniques, so this reports
technique recall against that list where OTRF gives one, the incident count,
cross-host clusters and cost. Each capture is also written as its own result file.

    python benchmarks/bench_compound.py
"""
from __future__ import annotations

import json

import demo_apt29
from common import RESULTS, write

from throughline.stack import Stack

CAPTURES = {
    "apt3_empire": "compound/windows/apt3/empire_apt3.tar.gz",
    "apt3_caldera_r1": "compound/windows/apt3/caldera_attack_evals_round1_day1_2019-10-20201108.tar.gz",
    **{f"lsass_0{i}_{n}": f"compound/LSASS_campaign_0{i}/metasploit_{n}_lsass_memory_dump.zip"
       for i, n in enumerate(("logonpasswords", "procdump", "comsvcs", "out-minidump", "sharpdump",
                              "outflank-dumpert", "nanodump"), 1)},
}


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
    rows = []
    for name, rel in CAPTURES.items():
        if not (st.paths.otrf / rel).exists():
            print("missing", rel, "- run scripts/download_data.py otrf")
            continue
        print("==", name, flush=True)
        demo_apt29.main(["--capture", rel, "--name", f"compound_{name}", "--top", "3"])
        d = json.loads((RESULTS / f"compound_{name}.json").read_text(encoding="utf-8"))
        exp = expected_techniques(st.paths.otrf, name)
        seen = set(d["techniques_observed"])
        # parent-technique match: T1003.001 expected, T1003 observed counts (and vice versa)
        hit = [t for t in exp if t in seen or t.split(".")[0] in {s.split(".")[0] for s in seen}]
        rows.append({"capture": name, "records": d["records"], "pipeline_seconds": d["pipeline_seconds"],
                     "alerts": d["alerts"], "incidents": d["incidents"],
                     "hosts": d["stitching"]["hosts_with_incidents"],
                     "multi_host_clusters": d["stitching"]["multi_host_clusters"],
                     "techniques_observed": len(seen), "expected": exp,
                     "expected_recall": round(len(hit) / len(exp), 3) if exp else None,
                     "top_attribution": d["top_incidents"][0]["attribution"][:2] if d["top_incidents"] else []})
        print(rows[-1], flush=True)
    out = write("compound", {"captures": rows})
    print("wrote", out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
