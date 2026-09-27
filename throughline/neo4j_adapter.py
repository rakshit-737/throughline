"""Optional Neo4j mirror. Cypher generation is pure (testable offline);
`push()` needs the `neo4j` driver and a LOCAL server (Grade B, you run it).
Values are always passed as parameters, never string-interpolated.
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


def batches(kg: KnowledgeGraph, size: int = 500) -> list[tuple[str, dict]]:
    """Same graph as :func:`statements`, grouped per label / relationship type into
    ``UNWIND`` batches (a few dozen round trips instead of one per node and edge)."""
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
        for q, params in stmts:
            s.run(q, params).consume()
        n = s.run("MATCH (n:TLNode) RETURN count(n) AS c").single()["c"]
        r = s.run("MATCH (:TLNode)-[r]->(:TLNode) RETURN count(r) AS c").single()["c"]
    return {"statements": len(stmts), "nodes": n, "edges": r}
