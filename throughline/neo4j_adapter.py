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


def push(kg: KnowledgeGraph, uri: str = "bolt://localhost:7687", auth=("neo4j", "neo4j")) -> int:
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install neo4j to use the Neo4j adapter") from e
    stmts = statements(kg)
    with GraphDatabase.driver(uri, auth=auth) as drv, drv.session() as s:  # pragma: no cover
        for q, params in stmts:
            s.run(q, params)
    return len(stmts)
