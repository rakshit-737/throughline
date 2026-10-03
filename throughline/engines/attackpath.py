"""Attack-path engine (LINCHPIN): ranked attacker paths and the fixes that cut them.

LINCHPIN builds an attack graph from already-collected scanner, identity and
exploit-intel exports, enumerates k-shortest entry-to-crown-jewel paths and
computes the minimum remediation cut. THROUGHLINE records

* ``Vulnerability AFFECTS Host`` for every scanner finding on a path
  (observed via the scanner, reliability B), and
* ``<u> CAN_REACH <v>`` for every hop of every ranked path (inferred, scored
  ``exp(-edge cost)`` so cheap hops are more likely), with services collapsed
  into their host,

and marks recommended fixes on the nodes (``linchpin_fix_rank``,
``linchpin_fix``) so an investigation can say "the one fix that breaks the most
paths" next to the evidence.
"""
from __future__ import annotations

import math

from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require

_TYPES = {"host": "Host", "vuln": "Vulnerability", "priv": "Privilege", "cred": "Credential",
          "user": "User", "ds": "CloudResource", "internet": "NetworkSegment", "group": "Role"}


def lp_node(nid: str) -> tuple[str, str] | None:
    """LINCHPIN node id -> (THROUGHLINE type, id). Services collapse into their host."""
    if nid == "internet":
        return ("NetworkSegment", "internet")
    kind, _, rest = nid.partition(":")
    if kind == "svc":
        return ("Host", rest.split(":", 1)[0])
    if kind == "vuln":
        cve = rest.split("@", 1)[0]
        return ("Vulnerability", cve)
    t = _TYPES.get(kind)
    return (t, rest[:200]) if t else None


def path_claims(kg: KnowledgeGraph, paths, remediations=(), ts: str = "1970-01-01T00:00:00Z",
                source: str = "linchpin", edge_costs: dict | None = None) -> list[Claim]:
    """Claims from LINCHPIN ``AttackPath``/``Remediation`` objects (duck-typed)."""
    out: list[Claim] = []
    for p in paths:
        seq = [n for n in (lp_node(x) for x in p.nodes) if n]
        collapsed = [seq[0]] if seq else []
        for n in seq[1:]:
            if n != collapsed[-1]:
                collapsed.append(n)
        per_hop = p.total_cost / max(1, len(collapsed) - 1)
        for (ut, uid), (vt, vid) in zip(collapsed, collapsed[1:]):
            out.append(kg.add_claim(ut, uid, "CAN_REACH", vt, vid, source=source, method="inferred",
                                    reliability="C", timestamp=ts, score=math.exp(-per_hop)))
            if vt == "Vulnerability" and ut == "Host":
                out.append(kg.add_claim("Vulnerability", vid, "AFFECTS", "Host", uid, source=source,
                                        method="observed", reliability="B", timestamp=ts))
        cj = lp_node(p.crown_jewel)
        if cj:
            kg.set_attrs(f"{cj[0]}:{cj[1]}", {"crown_jewel": True})
    for rank, r in enumerate(remediations, 1):
        n = lp_node(r.target_node)
        if n and f"{n[0]}:{n[1]}" in kg.g:
            kg.set_attrs(f"{n[0]}:{n[1]}", {"linchpin_fix_rank": rank, "linchpin_fix": r.action,
                                            "linchpin_paths_broken": f"{r.paths_broken}/{r.paths_total}"})
    return out


class LinchpinAttackPathEngine:
    """LINCHPIN attack paths as ``CAN_REACH`` hops, ``Vulnerability AFFECTS Host`` and ranked fixes."""
    name = "attack-path:linchpin"
    project = "LINCHPIN"
    reads = ("Host", "Vulnerability", "User")
    writes = ("CAN_REACH", "AFFECTS")

    def __init__(self, store=None, k: int = 20, budget: int = 3, synth_hosts: int = 20, seed: int = 0):
        self.store, self.k, self.budget = store, k, budget
        self.synth_hosts, self.seed = synth_hosts, seed
        self.paths: list = []
        self.fixes: list = []

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Rank attack paths in a LINCHPIN store (the context's, or LINCHPIN's own labelled synthetic
        network) and write the paths and recommended fixes as claims.
        """
        require("LINCHPIN")
        from linchpin.engine.optimizer import recommend
        from linchpin.engine.paths import rank_paths
        from linchpin.graph.store import GraphStore

        store = self.store or context.get("linchpin_store")
        if store is None:  # sibling's own synthetic network (clearly labelled synthetic)
            from linchpin.synth.generator import generate
            findings, _gt = generate(self.synth_hosts, 5, self.seed)
            store = GraphStore()
            store.upsert_findings(findings)
            store.build_attack_graph()
        self.paths = rank_paths(store, k=self.k)
        self.fixes = recommend(store, paths=self.paths, budget=self.budget)
        return path_claims(kg, self.paths, self.fixes)
