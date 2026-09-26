"""Ingest -> normalize -> graph -> engines, and the one-query investigation."""
from __future__ import annotations

from .contracts import ContractError
from .graph import KnowledgeGraph
from .modules import EngineRegistry, default_registry
from .normalizer import normalize


def _raw_context(connector: str, raw: dict) -> dict:
    ctx = {}
    if raw.get("untrusted"):
        ctx["dependency_untrusted"] = True
    if raw.get("external"):
        ctx["external_ip"] = True
    if raw.get("kind") == "process_create":
        ctx["child_name"] = raw.get("image", "")
    return ctx


def build(records, registry: EngineRegistry | None = None) -> tuple[KnowledgeGraph, dict]:
    kg = KnowledgeGraph()
    raw_ctx, rejected = {}, []
    for connector, raw, rel in records:
        try:
            ev = normalize(raw, connector, reliability=rel)
        except (ContractError, KeyError) as e:
            rejected.append({"connector": connector, "error": str(e)})
            continue
        kg.ingest(ev)
        raw_ctx[ev.event_id] = _raw_context(connector, raw)
    reg = registry or default_registry()
    engine_counts = reg.run_all(kg, {"raw_context": raw_ctx})
    return kg, {"rejected": rejected, "engines": engine_counts, **kg.stats()}


def resolve(kg: KnowledgeGraph, query: str) -> str:
    if query in kg.g:
        return query
    hits = [n for n in kg.g if n.split(":", 1)[1] == query or n.endswith(query)]
    if not hits:
        raise KeyError(f"no entity matches {query!r}")
    return sorted(hits)[0]


def investigate(kg: KnowledgeGraph, query: str, min_conf: float = 0.0) -> dict:
    """Bounded, read-only investigation around an entity. Every fact cites claim ids."""
    key = resolve(kg, query)
    sub = kg.neighborhood(key, radius=2)
    # include the full causal chain + everything downstream of the pod
    chain = kg.root_cause_chain(key)
    nodes = set(sub.nodes) | set(chain)
    for n in list(nodes):
        if n.startswith("Pod:") or n == key:
            nodes |= kg.blast_radius(n)
    # add annotations (techniques, attribution) of included nodes
    for n in list(nodes):
        for _, o, p in kg.g.out_edges(n, keys=True):
            if p in ("EXHIBITS", "ATTRIBUTED_TO"):
                nodes.add(o)
    view = kg.g.subgraph(nodes)
    facts = []
    for s, o, p, d in view.edges(keys=True, data=True):
        c = d.get("confidence", 0.0)
        if c >= min_conf:
            facts.append({"subject": s, "predicate": p, "object": o, "confidence": c,
                          "claims": d["claims"]})
    facts.sort(key=lambda f: (kg.g.nodes[f["subject"]]["first_seen"], f["predicate"]))
    techniques = sorted({f["object"].split(":", 1)[1] for f in facts if f["predicate"] == "EXHIBITS"})
    attributions: dict[str, float] = {}
    for f in facts:
        if f["predicate"] == "ATTRIBUTED_TO":
            attributions[f["object"]] = max(attributions.get(f["object"], 0), f["confidence"])
    return {
        "query": query, "entity": key,
        "root_cause_chain": chain,
        "origin": chain[0] if chain else key,
        "techniques": techniques,
        "attribution": dict(sorted(attributions.items(), key=lambda kv: -kv[1])),
        "facts": facts,
        "nodes": sorted(nodes),
        "note": "Hypotheses only where method != observed; see /claims/{id}/explain.",
    }
