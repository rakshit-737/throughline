"""The full real-data stack: every installed sibling engine, in dependency order.

    stack = Stack.from_data_dir()            # $THROUGHLINE_DATA or ../../datasets/throughline
    kg, summary, ctx = stack.run(records)    # records = [("windows", raw, "B"), ...]

Order matters only through the graph: detection (ANVIL) and provenance
(REVENANT) write technique claims -> correlation clusters them into incidents
-> ROOTLINE re-derives incident membership from its own provenance graph ->
intel (DRAGNET, OCCAM) attributes incidents -> posture (VANTAGE) checks what
should have fired -> simulation (GAUNTLET) plans re-emulation of the gaps.
Engines whose sibling package is not installed are skipped and reported.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import attack as attack_mod
from .engines import EngineUnavailable, sibling
from .graph import KnowledgeGraph
from .modules import EngineRegistry
from .pipeline import build
from .reasoning.correlation import CorrelationEngine

ROOT = Path(__file__).resolve().parents[1]
ALL_ENGINES = ("anvil", "revenant", "correlation", "rootline", "dragnet", "occam", "vantage", "gauntlet")


def data_dir() -> Path:
    """Dataset root: ``$THROUGHLINE_DATA``; in a source checkout ``../../datasets/throughline``
    if that folder exists, else ``<checkout>/data``; for an installed package
    ``~/.throughline/data`` (never inside site-packages)."""
    env = os.environ.get("THROUGHLINE_DATA")
    if env:
        return Path(env)
    if not (ROOT / "pyproject.toml").exists():  # installed from a wheel
        return Path.home() / ".throughline" / "data"
    sib = ROOT.parents[1] / "datasets" / "throughline"
    return sib if sib.exists() else ROOT / "data"


@dataclass
class DataPaths:
    """Where each public dataset lives under the data root."""
    root: Path

    @property
    def attack(self) -> Path:
        """ATT&CK Enterprise v19.2 STIX bundle."""
        return self.root / "attack" / "enterprise-attack-19.2.json"

    @property
    def attack_old(self) -> Path:
        """ATT&CK Enterprise v10.1 STIX bundle (temporal hold-out profiles)."""
        return self.root / "attack" / "enterprise-attack-10.1.json"

    @property
    def sigma(self) -> Path:
        """SigmaHQ checkout at the pinned commit."""
        return self.root / "sigma"

    @property
    def otrf(self) -> Path:
        """OTRF Security-Datasets root (atomic and compound captures)."""
        return self.root / "otrf"

    @property
    def cis(self) -> Path:
        """CIS Controls v8 -> ATT&CK mapping workbook."""
        return self.root / "cis" / "cis_v8_attack_v82_master_mapping.xlsx"

    @property
    def misp(self) -> Path:
        """MISP galaxy threat-actor cluster."""
        return self.root / "misp" / "misp-threat-actor.json"

    @property
    def baseline(self) -> Path:
        """Optional benign Windows baseline (evtx-baseline)."""
        return self.root / "evtx-baseline" / "win10-client"

    def missing(self) -> list[str]:
        """Names of the required datasets that are absent."""
        return [n for n, p in (("attack", self.attack), ("sigma", self.sigma / "rules"), ("otrf", self.otrf))
                if not p.exists()]


@dataclass
class Stack:
    """Every installed sibling engine wired in dependency order over one data root.

    Heavy objects (ATT&CK, the compiled Sigma library, DRAGNET/OCCAM knowledge bases,
    the VANTAGE catalog) are loaded once and reused across runs.
    """
    paths: DataPaths
    engines: tuple[str, ...] = ALL_ENGINES
    sigma_subset: str = "core"
    _cache: dict = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)
    load_s: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_data_dir(cls, root: str | Path | None = None, **kw) -> Stack:
        """A stack over ``root`` (default: :func:`data_dir`)."""
        return cls(DataPaths(Path(root) if root else data_dir()), **kw)

    # ------------------------------------------------------------ heavy, cached objects
    def _get(self, key: str, factory):
        if key not in self._cache:
            t0 = time.perf_counter()
            self._cache[key] = factory()
            self.load_s[key] = round(time.perf_counter() - t0, 2)
        return self._cache[key]

    def attack(self) -> attack_mod.AttackCatalog:
        """The ATT&CK catalog (loaded once, made the active catalog)."""
        cat = self._get("attack", lambda: attack_mod.AttackCatalog.load(self.paths.attack))
        attack_mod.set_active(cat)
        return cat

    def sigma_library(self):
        """ANVIL's compiled Sigma library for the configured subset (loaded once)."""
        from .engines.detection import load_library, sigma_dirs
        return self._get(f"sigma-{self.sigma_subset}",
                         lambda: load_library(sigma_dirs(self.paths.sigma, self.sigma_subset)))

    def _factory(self, name: str):
        from .engines import detection, intel, posture, provenance, simulation
        p = self.paths
        if name == "anvil":
            return lambda: detection.AnvilDetectionEngine(self.sigma_library())
        if name == "revenant":
            return provenance.RevenantProvenanceEngine
        if name == "correlation":
            return CorrelationEngine
        if name == "rootline":
            return provenance.RootlineProvenanceEngine
        if name == "dragnet":
            eng = self._get("dragnet", lambda: intel.DragnetIntelEngine(p.attack, p.misp))
            return lambda: _fresh(eng)
        if name == "occam":
            eng = self._get("occam", lambda: intel.OccamIntelEngine(p.attack))
            return lambda: _fresh(eng)
        if name == "vantage":
            cat = self._get("vantage", lambda: posture.build_catalog(p.attack, p.sigma / "rules", p.cis))
            return lambda: posture.VantagePostureEngine(cat)
        if name == "gauntlet":
            return simulation.GauntletSimulationEngine
        raise KeyError(name)

    def registry(self) -> EngineRegistry:
        """A fresh engine registry; engines whose sibling is missing are recorded in ``skipped``."""
        self.attack()
        reg = EngineRegistry()
        for name in self.engines:
            if name != "correlation":
                s = sibling(name)
                if not s.installed:
                    self.skipped[name] = f"not installed ({s.pip_spec})"
                    continue
            try:
                reg.register(self._factory(name)())
            except (EngineUnavailable, FileNotFoundError, OSError) as e:
                self.skipped[name] = str(e)[:200]
        return reg

    def run(self, records, registry: EngineRegistry | None = None) -> tuple[KnowledgeGraph, dict, dict]:
        """Build a graph from raw records and run every engine.

        Returns:
            ``(graph, summary, context)``; the context holds incidents, clusters and engine objects.
        """
        reg = registry or self.registry()
        ctx: dict = {}
        kg, summary = build(records, reg, context=ctx)
        summary["skipped_engines"] = dict(self.skipped)
        summary["timings_s"] = ctx.get("timings_s", {})
        by_name = {e.name: e for e in reg.engines}
        return kg, summary, {"engines": by_name, **ctx}


def _fresh(engine):
    """Shallow copy of a cached engine with its per-run verdicts cleared."""
    import copy
    e = copy.copy(engine)
    e.verdicts = {}
    return e


def capture_records(capture, reliability: str = "B") -> list[tuple[str, dict, str]]:
    """A capture's records in the ``(connector, raw, reliability)`` form :meth:`Stack.run` takes."""
    return [("windows", r, reliability) for r in capture.records()]
