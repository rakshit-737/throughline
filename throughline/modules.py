"""Pluggable capability-engine interface.

Engines interact ONLY through the graph + canonical contracts. The real
sibling engines live in :mod:`throughline.engines` and are assembled by
:class:`throughline.stack.Stack`. The default registry here serves the
synthetic demo: the built-in ATT&CK mapper plus the declared slots, which keep
the contract visible and return no claims on synthetic data.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .attack import map_event
from .contracts import Claim, node_key
from .graph import KnowledgeGraph


@runtime_checkable
class Engine(Protocol):
    """The frozen engine protocol: ``name``, ``reads``, ``writes`` and ``run(kg, context) -> claims``.
    Engines talk to each other only through the graph (ADR-0001).
    """
    name: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]: ...


class AttackMappingEngine:
    """Detection-ish engine: tags events' actor nodes with ATT&CK techniques."""
    name = "attack-mapping"
    reads = ("events",)
    writes = ("EXHIBITS",)

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Tag processes with ATT&CK techniques from the built-in event mapping."""
        raw_ctx: dict = context.get("raw_context", {})
        out = []
        for ev in list(kg.events.values()):
            for tech, reason in map_event(ev, raw_ctx.get(ev.event_id, {})):
                subj = node_key(ev.object_type, ev.object_id) if ev.action in ("INTRODUCED", "SPAWNED") \
                    else node_key(ev.actor_type, ev.actor_id)
                base = kg._by_assertion.get(
                    (node_key(ev.actor_type, ev.actor_id), ev.action, node_key(ev.object_type, ev.object_id)), [])
                out.append(kg.tag_technique(subj, tech, reason, source=self.name, ts=ev.ts,
                                            corroboration=list(base)))
        return out


@dataclass
class SiblingEngineStub:
    """Declared slot for a sibling project in the synthetic demo (the real adapter lives in
    ``throughline.engines`` and runs through ``Stack``)."""
    name: str
    project: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    todo: str = "integrate sibling project behind this interface"
    grade: str = "B/C"

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Placeholder for a sibling engine that is not installed: writes nothing."""
        return []


SIBLING_SLOTS = [
    SiblingEngineStub("attack-path", "LINCHPIN", ("Host", "Vulnerability", "User"), ("EXPLOITS",)),
    SiblingEngineStub("posture", "VANTAGE", ("Control", "Detection", "Technique"), ("SHOULD_DETECT", "MITIGATES")),
    SiblingEngineStub("provenance", "REVENANT + ROOTLINE", ("Process", "File"), ("SPAWNED", "WROTE")),
    SiblingEngineStub("malware", "VITRINE + SPECIMEN", ("Sample",), ("EXHIBITS", "ATTRIBUTED_TO")),
    SiblingEngineStub("supply-chain", "TRACEGATE", ("Commit", "Dependency", "Build"), ("INTRODUCED", "BUILT_INTO")),
    SiblingEngineStub("detection", "FEINT + ANVIL", ("events", "Technique"), ("Detection",)),
    SiblingEngineStub("intel", "OCCAM + DRAGNET", ("IOC", "Technique"), ("ATTRIBUTED_TO",)),
    SiblingEngineStub("simulation", "GAUNTLET", ("Technique",), ("events",), grade="B/D"),
]


@dataclass
class EngineRegistry:
    """Ordered set of engines; runs them in registration order and times each one."""
    engines: list = field(default_factory=list)

    def register(self, engine: Engine) -> None:
        """Add an engine (later engines read what earlier ones wrote)."""
        if not isinstance(engine, Engine):
            raise TypeError(f"{engine!r} does not satisfy the Engine protocol")
        self.engines.append(engine)

    def run_all(self, kg: KnowledgeGraph, context: dict | None = None) -> dict[str, int]:
        """Run engines in registration order. Confidence is recomputed in bulk after each
        engine, so later engines (correlation, intel) read settled confidences."""
        ctx = context or {}
        out: dict[str, int] = {}
        timings: dict[str, float] = ctx.setdefault("timings_s", {})
        for e in self.engines:
            t0 = time.perf_counter()
            kg.defer_confidence = True
            try:
                out[e.name] = len(e.run(kg, ctx))
            finally:
                kg.finalize()
                kg.defer_confidence = False
            timings[e.name] = round(time.perf_counter() - t0, 3)
        return out


def default_registry() -> EngineRegistry:
    """The engines of the synthetic demo (built-in ATT&CK mapping + correlation)."""
    reg = EngineRegistry()
    reg.register(AttackMappingEngine())
    for s in SIBLING_SLOTS:
        reg.register(s)
    return reg
