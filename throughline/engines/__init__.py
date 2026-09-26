"""Sibling portfolio projects wired in as capability engines.

Every engine implements the frozen ``Engine`` protocol (``name``, ``reads``,
``writes``, ``run(kg, context) -> list[Claim]``) and talks to the rest of the
platform only through the knowledge graph (ADR-0001). The sibling packages are
*optional extras* installed from pinned git commits (``pip install
throughline[engines]``); an engine whose package is missing reports itself as
unavailable instead of failing, so the core stays dependency-light.

The table below is the single source of truth for which sibling fills which
slot, and at which commit it was validated.
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
    commit: str           # validated commit on github.com/rakshit-737/<repo>
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
    Sibling("ANVIL", "detection", "anvil", "anvil-dac", "c8cf57f571c4b347709cef042c0a382824cb9466",
            "detection", "Sigma engine over raw endpoint events"),
    Sibling("FEINT", "detection", "feint", "feint", "ff76b5c82c77d876279d1a06e04422627da46b4a",
            "network", "adversarially-hardened flow classifier"),
    Sibling("REVENANT", "provenance", "revenant", "revenant", "624be3f3082419e3323bfc9b3dcdad76290103ef",
            "provenance", "causal stories + ATT&CK heuristics"),
    Sibling("ROOTLINE", "provenance", "rootline", "rootline", "7f25f29d6eeb9211c52349cb6740bf0cb01fb7f4",
            "provenance", "IOC-seeded attack reconstruction"),
    Sibling("DRAGNET", "intel", "dragnet", "dragnet", "8583ebb14a61d3a538f13aff3b0eb825dd4f8bd2",
            "intel", "specificity-weighted ACH attribution"),
    Sibling("OCCAM", "intel", "occam", "occam", "6fda4cc409b61c661060baf6e1df3f387e556d45",
            "intel", "Heuer ACH with false-flag hypotheses"),
    Sibling("VANTAGE", "posture", "vantage", "vantage", "945eb3860244a3c3650f4ee0042adccc064e88e5",
            "posture", "control -> detection -> technique coverage"),
    Sibling("GAUNTLET", "simulation", "gauntlet", "gauntlet", "8ff400ccaa54efc247d15ef85412ba0b9e04ac25",
            "simulation", "labelled replay + Atomic emulation plans"),
    Sibling("TRACEGATE", "supply-chain", "tracegate", "tracegate", "014faa3839544ae9ab95538199e80291a95cc9cb",
            "supplychain", "manifest lineage -> introducing commit"),
    Sibling("STRATUM", "supply-chain", "stratum", "stratum", "1341f1c9633636339b4190c8cd6679533702fcf0",
            "cnapp", "Kubernetes posture + image provenance"),
    Sibling("LINCHPIN", "attack-path", "linchpin", "linchpin", "dc16710d7f07be2bde7fbfcf29dd31bfe798de04",
            "attackpath", "attack paths + fix prioritisation"),
    Sibling("VITRINE", "malware", "vitrine", "vitrine", "76ee8dd8011a5764a86c0b22a7782b11cc863220",
            "malware", "static PE triage (never executes)"),
    Sibling("SPECIMEN", "malware", "specimen", "specimen", "fd01f88d952d07b971281311feaf491118032d37",
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
