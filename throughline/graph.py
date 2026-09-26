"""Temporal security knowledge graph where every node and edge is a claim.

Backed by networkx (in-memory). `neo4j_adapter` can mirror it to Neo4j.
Every assertion keeps ALL claims that support it; confidence is recomputed by
the confidence engine whenever evidence changes.
"""
from __future__ import annotations

from collections import defaultdict

import networkx as nx

from . import confidence as conf
from .attack import TECHNIQUES
from .contracts import CanonicalEvent, Claim, ContractError, EDGE_TYPES, NODE_TYPES, node_key

# Predicates where one subject should have a single true object: competing
# objects from different sources contradict each other (e.g. attribution).
EXCLUSIVE_PREDICATES = {"ATTRIBUTED_TO"}


class KnowledgeGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()
        self.claims: dict[str, Claim] = {}
        self._by_assertion: dict[tuple, list[str]] = defaultdict(list)
        self.events: dict[str, CanonicalEvent] = {}

    # ---------- writes ----------
    def _ensure_node(self, ntype: str, nid: str, ts: str) -> str:
        if ntype not in NODE_TYPES:
            raise ContractError(f"unknown node type {ntype!r}")
        key = node_key(ntype, nid)
        if key not in self.g:
            self.g.add_node(key, type=ntype, id=nid, first_seen=ts, last_seen=ts)
        else:
            d = self.g.nodes[key]
            d["first_seen"] = min(d["first_seen"], ts)
            d["last_seen"] = max(d["last_seen"], ts)
        return key

    def add_claim(self, subj_type: str, subj_id: str, predicate: str, obj_type: str | None,
                  obj_id: str | None, *, source: str, method: str, reliability: str,
                  timestamp: str, evidence_ref: str | None = None,
                  corroboration: list[str] | None = None) -> Claim:
        s = self._ensure_node(subj_type, subj_id, timestamp)
        o = None
        if obj_type is not None:
            if predicate not in EDGE_TYPES:
                raise ContractError(f"unknown edge type {predicate!r}")
            o = self._ensure_node(obj_type, obj_id, timestamp)
        key = (s, predicate, o)
        cid = f"c{len(self.claims) + 1:05d}"
        claim = Claim(
            claim_id=cid,
            assertion=f"{s} {predicate} {o}" if o else f"{s} EXISTS",
            subject=s, predicate=predicate, obj=o, source=source, method=method,
            timestamp=timestamp, reliability=reliability,
            base_confidence=conf.base_confidence(method, reliability),
            corroboration=list(corroboration or []), evidence_ref=evidence_ref,
        )
        self.claims[cid] = claim
        self._by_assertion[key].append(cid)
        if o is not None:
            if not self.g.has_edge(s, o, key=predicate):
                self.g.add_edge(s, o, key=predicate, predicate=predicate, first_seen=timestamp,
                                claims=[])
            self.g.edges[s, o, predicate]["claims"].append(cid)
        else:
            self.g.nodes[s].setdefault("claims", []).append(cid)
        self._recompute(s, predicate)
        return claim

    def ingest(self, ev: CanonicalEvent) -> Claim:
        ev.validate()
        self.events[ev.event_id] = ev
        return self.add_claim(ev.actor_type, ev.actor_id, ev.action, ev.object_type, ev.object_id,
                              source=ev.source, method=ev.method, reliability=ev.reliability,
                              timestamp=ev.ts, evidence_ref=ev.raw_ref)

    def tag_technique(self, subj_key: str, technique: str, reason: str, *, source: str,
                      ts: str, corroboration: list[str] | None = None) -> Claim:
        ntype, nid = subj_key.split(":", 1)
        c = self.add_claim(ntype, nid, "EXHIBITS", "Technique", technique, source=source,
                           method="inferred", reliability="C", timestamp=ts,
                           corroboration=corroboration)
        self.g.nodes[node_key("Technique", technique)]["name"] = TECHNIQUES.get(technique, "")
        c.evidence_ref = reason
        return c

    # ---------- confidence ----------
    def _group(self, s: str, predicate: str) -> dict[str | None, list[Claim]]:
        out: dict[str | None, list[Claim]] = defaultdict(list)
        for (ks, kp, ko), cids in self._by_assertion.items():
            if ks == s and kp == predicate:
                out[ko].extend(self.claims[c] for c in cids)
        return out

    def _recompute(self, s: str, predicate: str) -> None:
        groups = self._group(s, predicate)
        for o, claims in groups.items():
            contra: list[Claim] = []
            if predicate in EXCLUSIVE_PREDICATES:
                for o2, other in groups.items():
                    if o2 != o:
                        contra.extend(other)
            for c in claims:
                support = [x for x in claims if x is not c]
                support += [self.claims[x] for x in c.corroboration if x in self.claims]
                c.confidence = conf.combine(c, support, contra)
                c.contradicts = [x.claim_id for x in contra]
            if o is not None:
                self.g.edges[s, o, predicate]["confidence"] = max(c.confidence for c in claims)

    def edge_confidence(self, s: str, o: str, predicate: str) -> float:
        return self.g.edges[s, o, predicate].get("confidence", 0.0)

    def explain_claim(self, cid: str) -> dict:
        c = self.claims[cid]
        groups = self._group(c.subject, c.predicate)
        same = [x for x in groups.get(c.obj, []) if x is not c]
        same += [self.claims[x] for x in c.corroboration if x in self.claims]
        contra = [self.claims[x] for x in c.contradicts]
        return conf.explain(c, same, contra)

    # ---------- reads ----------
    def neighborhood(self, key: str, radius: int = 2) -> nx.MultiDiGraph:
        und = self.g.to_undirected(as_view=True)
        nodes = nx.single_source_shortest_path_length(und, key, cutoff=radius).keys()
        return self.g.subgraph(nodes)

    def root_cause_chain(self, key: str, max_hops: int = 12) -> list[str]:
        """Walk causal predecessors back to the earliest origin (longest ancestor chain)."""
        chain = [key]
        cur = key
        seen = {key}
        for _ in range(max_hops):
            preds = [p for p in self.g.predecessors(cur)
                     if p not in seen and not p.startswith(("Technique:", "Actor:", "Campaign:"))]
            if not preds:
                break
            preds.sort(key=lambda p: self.g.nodes[p]["first_seen"])
            cur = preds[0]
            seen.add(cur)
            chain.append(cur)
        return list(reversed(chain))

    def blast_radius(self, key: str) -> set[str]:
        return {n for n in nx.descendants(self.g, key)
                if not n.startswith(("Technique:", "Actor:", "Campaign:"))}

    def stats(self) -> dict:
        return {"nodes": self.g.number_of_nodes(), "edges": self.g.number_of_edges(),
                "claims": len(self.claims), "events": len(self.events)}

    def to_json(self) -> dict:
        return {
            "nodes": [{"key": n, **{k: v for k, v in d.items()}} for n, d in self.g.nodes(data=True)],
            "edges": [{"src": s, "dst": o, **d} for s, o, d in self.g.edges(data=True)],
            "claims": [c.to_dict() for c in self.claims.values()],
        }
