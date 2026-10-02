"""Optional Neo4j mirror of the knowledge graph, claim layer included.

Cypher generation is pure (testable offline); :func:`push` needs the ``neo4j``
driver and a server you run (``docker-compose.neo4j.yml``). Values are always
passed as parameters, never string-interpolated; labels and relationship types
come from the frozen schema and are validated.

Mirrored model:

* every entity as ``(:TLNode:<Type> {key, id, first_seen})``;
* every assertion as ``(a)-[:<PREDICATE> {confidence, claims, first_seen}]->(b)``;
* every claim as ``(:TLClaim:Claim {key, assertion, predicate, source, method,
  reliability, base_confidence, confidence, ts, evidence_ref})`` with
  ``-[:SUBJECT]->`` and ``-[:OBJECT]->`` links to the entities it is about and
  ``-[:CORROBORATED_BY]->`` links to the claims it cites, so "which engines
  support technique X in incident Y" is one Cypher query.
"""
from __future__ import annotations

import re

from .graph import KnowledgeGraph

_LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def _safe(label: str) -> str:
    if not _LABEL.match(label):
        raise ValueError(f"unsafe label {label!r}")
    return label


def statements(kg: KnowledgeGraph) -> list[tuple[str, dict]]:
    """One parameterised statement per entity and per assertion (for ``throughline export``)."""
    out: list[tuple[str, dict]] = []
    for key, d in kg.g.nodes(data=True):
        out.append((f"MERGE (n:{_safe(d['type'])} {{key:$key}}) SET n.id=$id, n.first_seen=$fs",
                    {"key": key, "id": d["id"], "fs": d["first_seen"]}))
    for s, o, p, d in kg.g.edges(keys=True, data=True):
        out.append((f"MATCH (a {{key:$s}}),(b {{key:$o}}) MERGE (a)-[r:{_safe(p)}]->(b) "
                    "SET r.confidence=$c, r.claims=$claims, r.first_seen=$fs",
                    {"s": s, "o": o, "c": d.get("confidence", 0.0), "claims": d["claims"],
                     "fs": d["first_seen"]}))
    return out


def _claim_row(c) -> dict:
    return {"key": c.claim_id, "assertion": c.assertion[:500], "predicate": c.predicate, "source": c.source,
            "method": c.method, "reliability": c.reliability, "base": c.base_confidence, "conf": c.confidence,
            "ts": c.timestamp, "ref": (c.evidence_ref or "")[:500], "s": c.subject, "o": c.obj,
            "corr": list(c.corroboration)[:50]}


def batches(kg: KnowledgeGraph, size: int = 500, claims: bool = True) -> list[tuple[str, dict]]:
    """The graph as ``UNWIND`` batches grouped per label / relationship type (a few dozen
    round trips instead of one per node, edge and claim)."""
    nodes: dict[str, list[dict]] = {}
    for key, d in kg.g.nodes(data=True):
        nodes.setdefault(_safe(d["type"]), []).append({"key": key, "id": d["id"], "fs": d["first_seen"]})
    edges: dict[str, list[dict]] = {}
    for s, o, p, d in kg.g.edges(keys=True, data=True):
        edges.setdefault(_safe(p), []).append({"s": s, "o": o, "c": d.get("confidence", 0.0),
                                               "claims": d["claims"], "fs": d["first_seen"]})
    out: list[tuple[str, dict]] = []
    for label, rows in sorted(nodes.items()):
        for i in range(0, len(rows), size):
            out.append((f"UNWIND $rows AS r MERGE (n:TLNode {{key:r.key}}) SET n:{label}, n.id=r.id, "
                        "n.first_seen=r.fs", {"rows": rows[i:i + size]}))
    for rel, rows in sorted(edges.items()):
        for i in range(0, len(rows), size):
            out.append((f"UNWIND $rows AS r MATCH (a:TLNode {{key:r.s}}),(b:TLNode {{key:r.o}}) "
                        f"MERGE (a)-[e:{rel}]->(b) SET e.confidence=r.c, e.claims=r.claims, e.first_seen=r.fs",
                        {"rows": rows[i:i + size]}))
    if claims:
        rows = [_claim_row(c) for c in kg.claims.values()]
        for i in range(0, len(rows), size):
            chunk = rows[i:i + size]
            out.append(("UNWIND $rows AS r MERGE (c:TLClaim {key:r.key}) SET c:Claim, c.assertion=r.assertion, "
                        "c.predicate=r.predicate, c.source=r.source, c.method=r.method, c.reliability=r.reliability, "
                        "c.base_confidence=r.base, c.confidence=r.conf, c.ts=r.ts, c.evidence_ref=r.ref "
                        "WITH c, r MATCH (s:TLNode {key:r.s}) MERGE (c)-[:SUBJECT]->(s)",
                        {"rows": chunk}))
            objs = [r for r in chunk if r["o"]]
            if objs:
                out.append(("UNWIND $rows AS r MATCH (c:TLClaim {key:r.key}),(o:TLNode {key:r.o}) "
                            "MERGE (c)-[:OBJECT]->(o)", {"rows": objs}))
        links = [{"a": r["key"], "b": b} for r in rows for b in r["corr"]]
        for i in range(0, len(links), size):
            out.append(("UNWIND $rows AS r MATCH (a:TLClaim {key:r.a}),(b:TLClaim {key:r.b}) "
                        "MERGE (a)-[:CORROBORATED_BY]->(b)", {"rows": links[i:i + size]}))
    return out


def push(kg: KnowledgeGraph, uri: str = "bolt://localhost:7687", auth=("neo4j", "neo4j")) -> dict:
    """Mirror the graph into a Neo4j server (idempotent MERGE). Returns counts read back."""
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install neo4j to use the Neo4j adapter") from e
    stmts = batches(kg)
    with GraphDatabase.driver(uri, auth=auth) as drv, drv.session() as s:  # pragma: no cover
        s.run("CREATE CONSTRAINT tl_key IF NOT EXISTS FOR (n:TLNode) REQUIRE n.key IS UNIQUE")
        s.run("CREATE CONSTRAINT tl_claim IF NOT EXISTS FOR (c:TLClaim) REQUIRE c.key IS UNIQUE")
        for q, params in stmts:
            s.run(q, params).consume()
        n = s.run("MATCH (n:TLNode) RETURN count(n) AS c").single()["c"]
        r = s.run("MATCH (:TLNode)-[r]->(:TLNode) RETURN count(r) AS c").single()["c"]
        c = s.run("MATCH (c:TLClaim) RETURN count(c) AS c").single()["c"]
    return {"statements": len(stmts), "nodes": n, "edges": r, "claims": c}
