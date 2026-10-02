"""Sibling portfolio projects wired in as capability engines.

Every engine implements the frozen ``Engine`` protocol (``name``, ``reads``,
``writes``, ``run(kg, context) -> list[Claim]``) and talks to the rest of the
platform only through the knowledge graph (ADR-0001). The sibling packages are
*optional extras* installed from pinned release tags
(``pip install -e .[engines]`` in a checkout); an engine whose package is
missing reports itself as unavailable instead of failing, so the core stays
dependency-light.

The table below is the single source of truth for which sibling fills which
slot, at which release tag, and which commit that tag pointed to when it was
validated. ``pyproject.toml``'s ``engines``/``network`` extras must list exactly
:attr:`Sibling.pip_spec` for each row (``tests/test_engines.py`` checks), and
``scripts/check_sibling_tags.py`` fails when a newer release exists or a pinned
tag has been moved to another commit.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import json
from dataclasses import dataclass
from types import ModuleType


@dataclass(frozen=True)
class Sibling:
    """One sibling project and the release it is pinned to."""

    project: str          # portfolio project name (the GitHub repo is its lower-case form)
    slot: str             # engine slot (spec section 5)
    package: str          # importable top-level package
    dist: str             # pip distribution name at the pinned tag
    tag: str              # pinned release tag, vX.Y.Z
    sha: str              # commit the tag pointed to when validated (a moved tag is an error)
    module: str           # throughline adapter module under throughline.engines
    note: str = ""
    extra: str = "engines"  # pyproject extra that installs it

    @property
    def repo(self) -> str:
        return f"https://github.com/rakshit-737/{self.project.lower()}"

    @property
    def pip_spec(self) -> str:
        return f"{self.dist} @ git+{self.repo}@{self.tag}"

    @property
    def installed(self) -> bool:
        return importlib.util.find_spec(self.package) is not None

    def installed_version(self) -> str | None:
        """Version of the installed distribution, or ``None`` when it is not installed."""
        try:
            return importlib.metadata.version(self.dist)
        except importlib.metadata.PackageNotFoundError:
            return None

    def installed_commit(self) -> str | None:
        """Commit the installed distribution was built from (PEP 610 ``direct_url.json``)."""
        try:
            raw = importlib.metadata.distribution(self.dist).read_text("direct_url.json")
        except importlib.metadata.PackageNotFoundError:
            return None
        if not raw:
            return None
        try:
            vcs = json.loads(raw).get("vcs_info") or {}
        except ValueError:
            return None
        return vcs.get("commit_id")


SIBLINGS: tuple[Sibling, ...] = (
    Sibling("ANVIL", "detection", "anvil", "anvil-dac", "v1.1.0", "9cc3f53f539ace9c92467b350348d66611312d7b",
            "detection", "Sigma engine over raw endpoint events"),
    Sibling("FEINT", "detection", "feint", "feint", "v1.0.0", "daf668b6189c4fbed82c15b99683208696fe9c85",
            "network", "adversarially-hardened flow classifier", extra="network"),
    Sibling("REVENANT", "provenance", "revenant", "revenant", "v1.1.0", "aa0971cf0c8e9d435174493f534a87a44de419a2",
            "provenance", "causal stories + ATT&CK heuristics"),
    Sibling("ROOTLINE", "provenance", "rootline", "rootline", "v1.1.0", "c69b228bf7bdfaa59614c57ea632911846d6adae",
            "provenance", "IOC-seeded attack reconstruction"),
    Sibling("DRAGNET", "intel", "dragnet", "dragnet-attribution", "v1.1.0",
            "fede50f1079129a24f2742ff441b510e20d1ab69", "intel", "specificity-weighted ACH attribution"),
    Sibling("OCCAM", "intel", "occam", "occam", "v1.1.0", "3e51fe0b26763444832461c91d38d7d64c2f03a5",
            "intel", "Heuer ACH with false-flag hypotheses"),
    Sibling("VANTAGE", "posture", "vantage", "vantage", "v1.1.0", "54fcf281be74e59e165b51ef6131433d525d1ed0",
            "posture", "control -> detection -> technique coverage"),
    Sibling("GAUNTLET", "simulation", "gauntlet", "gauntlet-coverage", "v1.1.0",
            "cd41fa891cc33501cc0087637488c9cfc64d4880", "simulation", "labelled replay + Atomic emulation plans"),
    Sibling("TRACEGATE", "supply-chain", "tracegate", "tracegate", "v1.1.0",
            "d975888e91473a9b6e2c9cf147b6f1d974a90d5a", "supplychain", "manifest lineage -> introducing commit"),
    Sibling("STRATUM", "supply-chain", "stratum", "stratum", "v1.1.0", "5348cd68abde122829d9205f75d76d14321aab6f",
            "supplychain", "Kubernetes posture + image provenance"),
    Sibling("LINCHPIN", "attack-path", "linchpin", "linchpin-attackpath", "v1.1.0",
            "f95a91f31aee35f44de1ecdfa56c2fc5a56d0b5d", "attackpath", "attack paths + fix prioritisation"),
    Sibling("VITRINE", "malware", "vitrine", "vitrine", "v1.1.0", "126f64c59fef2e00cc305e653a5db530c2560dd8",
            "malware", "static PE triage (never executes)"),
    Sibling("SPECIMEN", "malware", "specimen", "specimen", "v1.1.0", "55eebd992ed5b4c6700610842ae58d949289ae66",
            "malware", "behaviour + family attribution from reports"),
)


def sibling(project: str) -> Sibling:
    """The :class:`Sibling` row for a project name (case-insensitive); ``KeyError`` if unknown."""
    for s in SIBLINGS:
        if s.project.lower() == project.lower():
            return s
    raise KeyError(project)


def status() -> list[dict]:
    """Installed / missing status of every sibling engine (for the CLI and API).

    ``pinned`` is the release tag the table validates; ``installed_version`` and
    ``installed_commit`` describe what is actually installed (they differ from the
    pin when someone installed another ref by hand)."""
    out = []
    for s in SIBLINGS:
        commit = s.installed_commit()
        out.append({"project": s.project, "slot": s.slot, "installed": s.installed, "pinned": s.tag,
                    "pinned_commit": s.sha[:7], "installed_version": s.installed_version(),
                    "installed_commit": commit[:7] if commit else None,
                    "matches_pin": (commit == s.sha) if commit else None,
                    "adapter": f"throughline.engines.{s.module}", "extra": s.extra, "note": s.note})
    return out


def installed_versions() -> dict[str, dict]:
    """Installed sibling versions and commits, recorded in every benchmark result file."""
    return {s.project: {"dist": s.dist, "pinned": s.tag, "version": s.installed_version(),
                        "commit": s.installed_commit()} for s in SIBLINGS if s.installed}


class EngineUnavailable(RuntimeError):
    """A sibling package is not installed (install the ``engines`` extra)."""


def require(project: str) -> ModuleType:
    """Import a sibling's top-level package or raise :class:`EngineUnavailable` with the install hint."""
    s = sibling(project)
    if not s.installed:
        raise EngineUnavailable(f"{s.project} is not installed: pip install \"{s.pip_spec}\" "
                                f"(or, in a checkout, pip install -e .[{s.extra}])")
    return importlib.import_module(s.package)
