"""Correlation: many alerts -> few incidents (one incident = one graph cluster).

Reads only the graph. Every process carrying a technique claim (from any
engine) or an alert is a *signal*. Signals are grouped by their **story
root**: walk ``SPAWNED`` predecessors until the parent is a session/service
boundary process (services.exe, explorer.exe, wmiprvse.exe, ...). Everything a
user or service launched under one boundary child is one incident; this is the
same notion of "story" REVENANT and ROOTLINE use, applied across engines.

Each incident gets

* ``<process> PART_OF Incident:<host>/<root>`` for every signal and every
  process on the path from the root down to it (source ``correlation``),
* ``Incident EXHIBITS Technique`` roll-ups: the best claim of each independent
  engine across all members, combined by noisy-OR (the member claims are cited
  in ``evidence_ref``, not re-counted), so intel engines read "what this
  incident did" in one hop and cross-engine agreement raises confidence, and
* display attributes: ``score`` (its most confident technique), ``breadth``,
  ``pivot`` (the strongest member), alert/technique counts.
"""
from __future__ import annotations

from collections import defaultdict

from ..contracts import Claim
from ..graph import KnowledgeGraph

SOURCE = "correlation"
# processes that sit above user/service activity: a story root is a child of one
BOUNDARY = frozenset({
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "userinit.exe", "wmiprvse.exe", "taskhostw.exe", "taskeng.exe",
    "runtimebroker.exe", "sihost.exe", "dllhost.exe", "?",
})
# engines whose technique claims are annotations of an incident, not signals
NON_SIGNAL_SOURCES = frozenset({SOURCE, "dragnet", "occam", "vantage"})


def image(key: str) -> str:
    return key.rsplit("/", 1)[-1].lower() if key.startswith("Process:") else ""


def story_root(kg: KnowledgeGraph, key: str, max_hops: int = 64) -> tuple[str, list[str]]:
    """(root, path root->key) following SPAWNED parents up to a boundary process."""
    path = [key]
    cur = key
    seen = {key}
    for _ in range(max_hops):
        parents = [p for p, _, k in kg.g.in_edges(cur, keys=True) if k == "SPAWNED" and p not in seen]
        if not parents:
            break
        parent = min(parents, key=lambda p: kg.g.nodes[p]["first_seen"])
        if image(parent) in BOUNDARY:
            break
        seen.add(parent)
        path.append(parent)
        cur = parent
    return cur, list(reversed(path))


def signal_techniques(kg: KnowledgeGraph, key: str) -> dict[str, dict[str, float]]:
    """technique -> {source: best base confidence} over the signal claims on one node."""
    out: dict[str, dict[str, float]] = {}
    for _, t, k, d in kg.g.out_edges(key, keys=True, data=True):
        if k != "EXHIBITS":
            continue
        tid = t.split(":", 1)[1]
        for cid in d.get("claims", []):
            c = kg.claims[cid]
            if c.source in NON_SIGNAL_SOURCES:
                continue
            best = out.setdefault(tid, {})
            best[c.source] = max(best.get(c.source, 0.0), c.base_confidence)
    return out


def noisy_or(values) -> float:
    miss = 1.0
    for v in values:
        miss *= 1.0 - v
    return min(1.0 - miss, 0.99)


class CorrelationEngine:
    name = "correlation"
    project = "THROUGHLINE"
    reads = ("EXHIBITS", "ALERTED_ON", "SPAWNED")
    writes = ("PART_OF", "EXHIBITS")

    def __init__(self, min_confidence: float = 0.0):
        self.min_confidence = min_confidence
        self.incidents: list[dict] = []

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        signals: dict[str, dict[str, dict[str, float]]] = {}
        alerts: dict[str, int] = defaultdict(int)
        for n in list(kg.g.nodes):
            if not n.startswith("Process:"):
                continue
            techs = {t: srcs for t, srcs in signal_techniques(kg, n).items()
                     if noisy_or(srcs.values()) >= self.min_confidence}
            n_alerts = sum(len(d.get("claims", [])) for _, _, k, d in kg.g.in_edges(n, keys=True, data=True)
                           if k == "ALERTED_ON")
            if techs or n_alerts:
                signals[n] = techs
                alerts[n] = n_alerts
        groups: dict[str, dict] = {}
        for n, techs in signals.items():
            root, path = story_root(kg, n)
            host = n.split(":", 1)[1].split("/", 1)[0]
            g = groups.setdefault(root, {"host": host, "root": root, "members": set(), "signals": {},
                                         "sources": defaultdict(dict), "alerts": 0})
            g["members"].update(path)
            g["signals"][n] = techs
            g["alerts"] += alerts[n]
            for t, srcs in techs.items():
                best = g["sources"][t]
                for src, v in srcs.items():
                    best[src] = max(best.get(src, 0.0), v)
        out: list[Claim] = []
        self.incidents = []
        for root, g in groups.items():
            inc_id = f"{g['host']}/{root.split('/', 1)[1] if '/' in root else root}"
            inc_key = f"Incident:{inc_id}"
            ts = min(kg.g.nodes[m]["first_seen"] for m in g["members"])
            for m in sorted(g["members"]):
                mt, mid = m.split(":", 1)
                techs = g["signals"].get(m, {})
                conf = max((noisy_or(s.values()) for s in techs.values()), default=0.5)
                out.append(kg.add_claim(mt, mid, "PART_OF", "Incident", inc_id, source=SOURCE, method="inferred",
                                        reliability="B" if m in g["signals"] else "C", timestamp=ts,
                                        score=conf))
            tconf: dict[str, float] = {}
            for t, best in sorted(g["sources"].items()):
                # incident-level fusion: best claim per independent engine across all members,
                # combined by noisy-OR. The member claims are cited, not re-counted.
                tconf[t] = noisy_or(best.values())
                support = [cid for m, techs in g["signals"].items() if t in techs
                           for _, o, k, d in kg.g.out_edges(m, keys=True, data=True)
                           if k == "EXHIBITS" and o == f"Technique:{t}" for cid in d.get("claims", [])]
                c = kg.tag_technique(inc_key, t, "", source=SOURCE, ts=ts, score=tconf[t], reliability="A")
                c.evidence_ref = f"fused from {len(best)} engine(s) {sorted(best)}: " + ",".join(support[:20])
                out.append(c)
            pivot = max(g["signals"], key=lambda m: (max((noisy_or(s.values()) for s in g["signals"][m].values()),
                                                          default=0.0), alerts[m], m))
            info = {"engine": "THROUGHLINE", "root": root, "score": round(max(tconf.values(), default=0.0), 4),
                    "breadth": len(tconf),
                    "pivot": pivot, "alerts": g["alerts"], "signals": len(g["signals"]),
                    "members": len(g["members"]), "techniques": ",".join(sorted(tconf))[:1000]}
            kg.set_attrs(inc_key, info)
            self.incidents.append({"incident": inc_key, **info, "technique_conf": dict(sorted(tconf.items())),
                                   "technique_sources": {t: dict(b) for t, b in sorted(g["sources"].items())}})
        self.incidents.sort(key=lambda i: (-i["score"], -i["breadth"], -i["alerts"], i["incident"]))
        context["incidents"] = self.incidents
        return out
