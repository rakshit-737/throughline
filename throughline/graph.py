"""Temporal security knowledge graph where every node and edge is a claim.

Backed by networkx (in-memory). `neo4j_adapter` can mirror it to Neo4j.
Every assertion keeps ALL claims that support it; confidence is recomputed by
the confidence engine whenever evidence changes.
"""
from __future__ import annotations

from collections import defaultdict

import networkx as nx

from . import confidence as conf
from .attack import canonical_technique, technique_name
from .contracts import EDGE_TYPES, NODE_TYPES, CanonicalEvent, Claim, ContractError, node_key

# Predicates where one subject should have a single true object: competing
# objects from different sources contradict each other (e.g. attribution).
EXCLUSIVE_PREDICATES = {"ATTRIBUTED_TO"}
# Predicates that mean "caused / produced" (root cause walks these backwards).
CAUSAL_PREDICATES = frozenset({"AUTHORED", "INTRODUCED", "BUILT_INTO", "DEPLOYED_AS", "RUNS", "SPAWNED",
                               "INJECTED_INTO", "DEPENDS_ON"})
# Predicates that annotate rather than propagate (blast radius does not follow them).
ANNOTATION_PREDICATES = frozenset({"EXHIBITS", "ATTRIBUTED_TO", "PART_OF", "DETECTS", "SHOULD_DETECT",
                                   "MITIGATES", "ALERTED_ON", "USES"})


class KnowledgeGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()
        self.claims: dict[str, Claim] = {}
        self._by_assertion: dict[tuple, list[str]] = defaultdict(list)
        # (subject, predicate) -> objects, so confidence recomputation touches only the
        # competing assertions of one subject instead of scanning every assertion.
        self._objects: dict[tuple[str, str], set] = defaultdict(set)
        self.events: dict[str, CanonicalEvent] = {}
        self.defer_confidence = False  # bulk loads: recompute once in finalize()
        self._dirty: set[tuple[str, str]] = set()

    # ---------- writes ----------
    def _ensure_node(self, ntype: str, nid: str, ts: str) -> str:
        if ntype not in NODE_TYPES:
            raise ContractError(f"unknown node type {ntype!r}")
        key = node_key(ntype, nid)
        if key not in self.g:
            self.g.add_node(key, type=ntype, id=nid, first_seen=ts, last_seen=ts, attrs={})
        else:
            d = self.g.nodes[key]
            d["first_seen"] = min(d["first_seen"], ts)
            d["last_seen"] = max(d["last_seen"], ts)
        return key

    def add_claim(self, subj_type: str, subj_id: str, predicate: str, obj_type: str | None,
                  obj_id: str | None, *, source: str, method: str, reliability: str,
                  timestamp: str, evidence_ref: str | None = None,
                  corroboration: list[str] | None = None, score: float | None = None) -> Claim:
        """Record one claim. ``score`` lets an engine report its own probability for the
        assertion; the base confidence is then ``score x reliability weight`` instead of
        ``method prior x reliability weight`` (ADR-0006)."""
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
            base_confidence=(conf.base_confidence(method, reliability) if score is None
                             else conf.scored_confidence(score, reliability)),
            corroboration=list(corroboration or []), evidence_ref=evidence_ref,
        )
        self.claims[cid] = claim
        self._by_assertion[key].append(cid)
        self._objects[(s, predicate)].add(o)
        if o is not None:
            if not self.g.has_edge(s, o, key=predicate):
                self.g.add_edge(s, o, key=predicate, predicate=predicate, first_seen=timestamp,
                                claims=[])
            self.g.edges[s, o, predicate]["claims"].append(cid)
        else:
            self.g.nodes[s].setdefault("claims", []).append(cid)
        if self.defer_confidence:
            self._dirty.add((s, predicate))
        else:
            self._recompute(s, predicate, o)
        return claim

    def finalize(self) -> None:
        """Recompute confidence for everything touched while ``defer_confidence`` was on."""
        dirty, self._dirty = self._dirty, set()
        for s, p in dirty:
            self._recompute(s, p)

    def set_attrs(self, key: str, attrs: dict) -> None:
        """Attach display metadata (image, command line, ...) to a node. Not a claim."""
        if key in self.g and attrs:
            self.g.nodes[key]["attrs"].update(attrs)

    def ingest(self, ev: CanonicalEvent) -> Claim:
        ev.validate()
        self.events[ev.event_id] = ev
        c = self.add_claim(ev.actor_type, ev.actor_id, ev.action, ev.object_type, ev.object_id,
                           source=ev.source, method=ev.method, reliability=ev.reliability,
                           timestamp=ev.ts, evidence_ref=ev.raw_ref)
        if ev.attributes:
            actor = {k[6:]: v for k, v in ev.attributes.items() if k.startswith("actor.")}
            obj = {k[7:]: v for k, v in ev.attributes.items() if k.startswith("object.")}
            self.set_attrs(c.subject, actor)
            if c.obj:
                self.set_attrs(c.obj, obj)
        return c

    def tag_technique(self, subj_key: str, technique: str, reason: str, *, source: str,
                      ts: str, corroboration: list[str] | None = None, method: str = "inferred",
                      reliability: str = "C", score: float | None = None) -> Claim:
        ntype, nid = subj_key.split(":", 1)
        technique = canonical_technique(technique)
        c = self.add_claim(ntype, nid, "EXHIBITS", "Technique", technique, source=source,
                           method=method, reliability=reliability, timestamp=ts,
                           corroboration=corroboration, score=score)
        tnode = self.g.nodes[node_key("Technique", technique)]
        if not tnode.get("name"):
            tnode["name"] = technique_name(technique)
        c.evidence_ref = reason
        return c

    # ---------- confidence ----------
    def _group(self, s: str, predicate: str) -> dict[str | None, list[Claim]]:
        out: dict[str | None, list[Claim]] = defaultdict(list)
        for o in self._objects.get((s, predicate), ()):
            out[o].extend(self.claims[c] for c in self._by_assertion[(s, predicate, o)])
        return out

    def claims_for(self, s: str, predicate: str, o: str | None) -> list[Claim]:
        return [self.claims[c] for c in self._by_assertion.get((s, predicate, o), [])]

    def _recompute(self, s: str, predicate: str, only: str | None = None) -> None:
        """Recompute confidence of the claims about ``(s, predicate, *)``.

        For non-exclusive predicates each object is independent, so ``only`` limits the
        work to one assertion; exclusive predicates (attribution) always recompute the
        whole competing set because every alternative contradicts the others.
        """
        if predicate in EXCLUSIVE_PREDICATES or only is None:
            groups = self._group(s, predicate)
        else:
            groups = {only: [self.claims[c] for c in self._by_assertion[(s, predicate, only)]]}
        for o, claims in groups.items():
            contra: list[Claim] = []
            if predicate in EXCLUSIVE_PREDICATES:
                for o2, other in groups.items():
                    if o2 != o:
                        contra.extend(other)
            best: dict[str, float] = {}
            for c in claims:
                best[c.source] = max(best.get(c.source, 0.0), c.base_confidence)
            worst = max((x.base_confidence for x in contra), default=None)
            contra_ids = [x.claim_id for x in contra]
            for c in claims:
                extra = [self.claims[x] for x in c.corroboration if x in self.claims]
                c.confidence = conf.combine_best(best, extra, worst)
                c.contradicts = list(contra_ids)
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
        """Walk causal predecessors back to the earliest origin (longest ancestor chain).

        Only causal predicates are followed (who spawned / built / introduced what);
        annotations such as ALERTED_ON, PART_OF or EXHIBITS are not causes."""
        chain = [key]
        cur = key
        seen = {key}
        for _ in range(max_hops):
            preds = {p for p, _, k in self.g.in_edges(cur, keys=True)
                     if k in CAUSAL_PREDICATES and p not in seen}
            if not preds:
                break
            cur = min(preds, key=lambda p: (self.g.nodes[p]["first_seen"], p))
            seen.add(cur)
            chain.append(cur)
        return list(reversed(chain))

    def blast_radius(self, key: str, max_nodes: int = 10_000) -> set[str]:
        """Everything causally downstream of ``key`` (annotation edges are not followed)."""
        out: set[str] = set()
        stack = [key]
        while stack and len(out) < max_nodes:
            cur = stack.pop()
            for _, o, k in self.g.out_edges(cur, keys=True):
                if k in ANNOTATION_PREDICATES or o in out or o == key:
                    continue
                out.add(o)
                stack.append(o)
        return out

    def stats(self) -> dict:
        return {"nodes": self.g.number_of_nodes(), "edges": self.g.number_of_edges(),
                "claims": len(self.claims), "events": len(self.events)}

    def to_json(self) -> dict:
        return {
            "nodes": [{"key": n, **{k: v for k, v in d.items()}} for n, d in self.g.nodes(data=True)],
            "edges": [{"src": s, "dst": o, **d} for s, o, d in self.g.edges(data=True)],
            "claims": [c.to_dict() for c in self.claims.values()],
        }
