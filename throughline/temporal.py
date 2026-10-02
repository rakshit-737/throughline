"""Temporal views of the claim graph: what the platform knew *as of* a point in time.

Every claim carries the event time of the evidence it rests on, so the graph is
temporal by construction. Two kinds of claims are distinguished:

* **first-order** claims are made from one event at the time it happened: the
  normalised telemetry itself (``observed``) and per-event engine claims such as a
  Sigma alert or a provenance heuristic tag;
* **derived** claims are conclusions over many events (correlation incidents and
  their fused roll-ups, story membership, attribution, posture). Their meaning
  depends on everything seen so far, so they are not filtered by timestamp but
  *re-derived*.

:func:`as_of` keeps the first-order claims with ``timestamp <= ts`` (confidence
recomputed from exactly that evidence) and drops the derived ones;
:func:`replay` then re-runs the derived engines (by default correlation) on that
view. The result is the investigation an analyst would have seen at ``ts``.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime

from .graph import KnowledgeGraph

#: engines whose claims are conclusions over many events (re-derived, never time-filtered)
DERIVED_SOURCES = frozenset({"correlation", "dragnet", "occam", "vantage", "rootline", "gauntlet", "stratum",
                             "linchpin"})
#: predicates that are derived whatever their source (story / incident membership)
DERIVED_PREDICATES = frozenset({"PART_OF"})

_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def parse_ts(ts: str) -> datetime:
    """Parse the ISO-8601 timestamps connectors emit (``Z`` or offset, 0-9 fractional digits)."""
    s = str(ts).strip().replace(" ", "T")
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = _FRACTION.sub(r"\1", s, count=1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise ValueError(f"not an ISO-8601 timestamp: {ts!r}") from e
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _first_order(c) -> bool:
    return c.source not in DERIVED_SOURCES and c.predicate not in DERIVED_PREDICATES


def as_of(kg: KnowledgeGraph, ts: str | datetime) -> KnowledgeGraph:
    """A new graph holding the first-order claims of ``kg`` made at or before ``ts``.

    Node display attributes are copied for the nodes that remain; confidence is
    recomputed from the remaining evidence only (corroboration links to claims that
    are not yet known are dropped)."""
    cut = ts if isinstance(ts, datetime) else parse_ts(ts)
    keep = [c for c in kg.claims.values() if _first_order(c) and parse_ts(c.timestamp) <= cut]
    keep.sort(key=lambda c: (parse_ts(c.timestamp), c.claim_id))
    out = KnowledgeGraph()
    out.defer_confidence = True
    remap: dict[str, str] = {}
    for c in keep:
        st, sid = c.subject.split(":", 1)
        ot, oid = c.obj.split(":", 1) if c.obj else (None, None)
        new = out.add_claim(st, sid, c.predicate, ot, oid, source=c.source, method=c.method,
                            reliability=c.reliability, timestamp=c.timestamp, evidence_ref=c.evidence_ref,
                            corroboration=[remap[x] for x in c.corroboration if x in remap])
        new.base_confidence = c.base_confidence  # engine-reported scores are kept as they were
        remap[c.claim_id] = new.claim_id
    out.finalize()
    out.defer_confidence = False
    for n, d in out.g.nodes(data=True):
        src = kg.g.nodes.get(n)
        if src is not None:
            d["attrs"] = {k: v for k, v in src.get("attrs", {}).items() if not k.startswith(("cluster", "dragnet_",
                                                                                              "occam_", "rootline_"))}
            if src.get("name"):
                d["name"] = src["name"]
    return out


def replay(kg: KnowledgeGraph, ts: str | datetime, engines: Iterable | None = None) -> tuple[KnowledgeGraph, dict]:
    """:func:`as_of` plus the derived engines re-run on it (default: correlation)."""
    from .modules import EngineRegistry
    from .reasoning.correlation import CorrelationEngine

    view = as_of(kg, ts)
    reg = EngineRegistry()
    for e in engines if engines is not None else (CorrelationEngine(),):
        reg.register(e)
    ctx: dict = {}
    reg.run_all(view, ctx)
    return view, ctx
