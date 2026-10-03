"""Ingest -> normalize -> graph -> engines, and the one-query investigation."""
from __future__ import annotations

from collections import Counter

from .connectors.windows import Skip
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


def build(records, registry: EngineRegistry | None = None, *, context: dict | None = None,
          max_rejected: int = 100) -> tuple[KnowledgeGraph, dict]:
    """Normalize -> graph -> engines.

    ``records`` are ``(connector, raw, reliability)`` tuples. Every raw record is kept in
    ``context["records"]`` as ``(connector, raw, reliability, raw_ref)`` so engines that
    need full event fields (Sigma, provenance) read the event store, while everything
    they *conclude* goes into the graph. Records a connector deliberately does not model
    (:class:`Skip`) are counted, not rejected.
    """
    kg = KnowledgeGraph()
    kg.defer_confidence = True
    raw_ctx: dict = {}
    rejected: list[dict] = []
    n_rejected = 0
    skipped: Counter = Counter()
    kept: list[tuple] = []
    for connector, raw, rel in records:
        try:
            ev = normalize(raw, connector, reliability=rel)
        except Skip as e:
            skipped[str(e).split(":")[0][:60]] += 1
            kept.append((connector, raw, rel, None))
            continue
        except (ContractError, KeyError) as e:
            n_rejected += 1
            if len(rejected) < max_rejected:
                rejected.append({"connector": connector, "error": str(e)})
            continue
        kg.ingest(ev)
        raw_ctx[ev.event_id] = _raw_context(connector, raw)
        kept.append((connector, raw, rel, ev.raw_ref))
    kg.finalize()
    ctx = context if context is not None else {}
    ctx.update(raw_context=raw_ctx, records=kept)
    reg = registry or default_registry()
    engine_counts = reg.run_all(kg, ctx)
    summary = {"rejected": rejected, "rejected_total": n_rejected, "skipped": dict(skipped),
               "engines": engine_counts, **kg.stats()}
    return kg, summary


def resolve(kg: KnowledgeGraph, query: str) -> str:
    """Resolve a query to a node key: an exact key, an id, or a key suffix (first match sorted).

    Raises:
        KeyError: nothing matches.
    """
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
