"""Simulation engine (GAUNTLET): emulation plans for the gaps an investigation found.

THROUGHLINE never executes anything. GAUNTLET contributes two things:

* its CTI-weighted technique prioritisation, and
* a *dry-run* Atomic Red Team manifest (test names + GUIDs) for every technique
  the posture engine marked ``missed`` or ``blind`` - the "re-emulate" step of
  the feedback loop, to be run by an operator inside an isolated lab only.

The labelled telemetry that plays the role of the emulation range in the
benchmarks is replayed from OTRF recordings (``throughline.connectors.otrf``).
"""
from __future__ import annotations

from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require


class GauntletSimulationEngine:
    """GAUNTLET dry-run emulation plans for the techniques posture marked as missed or blind."""
    name = "simulation:gauntlet"
    project = "GAUNTLET"
    reads = ("Technique",)
    writes = ()

    def __init__(self, per_technique: int = 2):
        self.per_technique = per_technique
        self.plan: list[dict] = []

    def gaps(self, kg: KnowledgeGraph) -> list[str]:
        """Techniques posture marked as missed or blind in this run."""
        return sorted(n.split(":", 1)[1] for n, d in kg.g.nodes(data=True)
                      if n.startswith("Technique:") and d.get("attrs", {}).get("posture") in ("missed", "blind"))

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Plan Atomic Red Team tests for the gaps: ``context['emulation_plan']`` plus a note on each
        technique node. A dry-run manifest only; nothing is executed.
        """
        require("GAUNTLET")
        from gauntlet.atomics import load_index, manifest

        index = load_index()
        gaps = self.gaps(kg)
        self.plan = manifest(gaps, index, self.per_technique)
        for step in self.plan:
            key = f"Technique:{step['technique']}"
            kg.set_attrs(key, {"emulation_tests": "; ".join(t["name"] for t in step["atomic_tests"])[:1000]
                               or "no Atomic Red Team test"})
        context["emulation_plan"] = self.plan
        return []
