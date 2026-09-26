"""Sibling portfolio projects wired in as capability engines.

Every engine implements the frozen ``Engine`` protocol (``name``, ``reads``,
``writes``, ``run(kg, context) -> list[Claim]``) and talks to the rest of the
platform only through the knowledge graph (ADR-0001). The sibling packages are
*optional extras* installed from pinned git refs (``pip install
throughline[engines]``); an engine whose package is missing reports itself as
unavailable instead of failing, so the core stays dependency-light.

The table below is the single source of truth for which sibling fills which
slot, and at which release tag (or commit, for a sibling without a release)
it was validated.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass


@dataclass(frozen=True)
class Sibling:
    project: str          # portfolio project name
    slot: str             # engine slot (spec section 5)
    package: str          # importable top-level package
    dist: str             # pip distribution name
    commit: str           # validated release tag (vX.Y.Z) or full commit SHA on github.com/rakshit-737/<repo>
    module: str           # throughline adapter module
    note: str = ""

    @property
    def repo(self) -> str:
        return f"https://github.com/rakshit-737/{self.project.lower()}"

    @property
    def pip_spec(self) -> str:
        return f"{self.dist} @ git+{self.repo}@{self.commit}"

    @property
    def installed(self) -> bool:
        return importlib.util.find_spec(self.package) is not None


SIBLINGS: tuple[Sibling, ...] = (
    Sibling("ANVIL", "detection", "anvil", "anvil-dac", "v1.0.0",
            "detection", "Sigma engine over raw endpoint events"),
    Sibling("FEINT", "detection", "feint", "feint", "v1.0.0",
            "network", "adversarially-hardened flow classifier"),
    Sibling("REVENANT", "provenance", "revenant", "revenant", "4cbd2c38b6005ada3d481862efb563b919db2162",
            "provenance", "causal stories + ATT&CK heuristics"),
    Sibling("ROOTLINE", "provenance", "rootline", "rootline", "v1.0.0",
            "provenance", "IOC-seeded attack reconstruction"),
    Sibling("DRAGNET", "intel", "dragnet", "dragnet", "v1.0.0",
            "intel", "specificity-weighted ACH attribution"),
    Sibling("OCCAM", "intel", "occam", "occam", "v1.0.0",
            "intel", "Heuer ACH with false-flag hypotheses"),
    Sibling("VANTAGE", "posture", "vantage", "vantage", "v1.0.0",
            "posture", "control -> detection -> technique coverage"),
    Sibling("GAUNTLET", "simulation", "gauntlet", "gauntlet", "v1.0.0",
            "simulation", "labelled replay + Atomic emulation plans"),
    Sibling("TRACEGATE", "supply-chain", "tracegate", "tracegate", "v1.0.0",
            "supplychain", "manifest lineage -> introducing commit"),
    Sibling("STRATUM", "supply-chain", "stratum", "stratum", "v1.0.0",
            "cnapp", "Kubernetes posture + image provenance"),
    Sibling("LINCHPIN", "attack-path", "linchpin", "linchpin", "v1.0.0",
            "attackpath", "attack paths + fix prioritisation"),
    Sibling("VITRINE", "malware", "vitrine", "vitrine", "v1.0.0",
            "malware", "static PE triage (never executes)"),
    Sibling("SPECIMEN", "malware", "specimen", "specimen", "v1.0.0",
            "malware", "behaviour + family attribution from reports"),
)


def sibling(project: str) -> Sibling:
    for s in SIBLINGS:
        if s.project.lower() == project.lower():
            return s
    raise KeyError(project)


def status() -> list[dict]:
    """Installed / missing status of every sibling engine (for the CLI and API)."""
    return [{"project": s.project, "slot": s.slot, "installed": s.installed, "commit": s.commit[:7],
             "adapter": f"throughline.engines.{s.module}", "note": s.note} for s in SIBLINGS]


class EngineUnavailable(RuntimeError):
    """A sibling package is not installed (install the ``engines`` extra)."""


def require(project: str):
    s = sibling(project)
    if not s.installed:
        raise EngineUnavailable(f"{s.project} is not installed: pip install \"{s.pip_spec}\" "
                                "(or pip install -e .[engines])")
    return importlib.import_module(s.package)
