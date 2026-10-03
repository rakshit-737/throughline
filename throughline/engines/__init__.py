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
        """GitHub URL of the sibling project."""
        return f"https://github.com/rakshit-737/{self.project.lower()}"

    @property
    def pip_spec(self) -> str:
        """The pinned direct-URL requirement, exactly as the pyproject extra lists it."""
        return f"{self.dist} @ git+{self.repo}@{self.tag}"

    @property
    def installed(self) -> bool:
        """Whether the sibling's import package can be found."""
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
    Sibling("ANVIL", "detection", "anvil", "anvil-dac", "v1.1.1", "09a93769812dc03bc9eb8fcd9339e4ffb24f1cf3",
            "detection", "Sigma engine over raw endpoint events"),
    Sibling("FEINT", "detection", "feint", "feint", "v1.1.0", "61807529077fbf38bcb4962942cc3680a86a99ff",
            "network", "adversarially-hardened flow classifier", extra="network"),
    Sibling("REVENANT", "provenance", "revenant", "revenant", "v1.1.1", "d29e186a53f2269ac261e5d1a03683a197e168bf",
            "provenance", "causal stories + ATT&CK heuristics"),
    Sibling("ROOTLINE", "provenance", "rootline", "rootline", "v1.1.1", "1effc9a27d97bd8c190ff5d18d9c9d657c4ff7eb",
            "provenance", "IOC-seeded attack reconstruction"),
    Sibling("DRAGNET", "intel", "dragnet", "dragnet-attribution", "v1.1.1", "3c74827c487e3fb2f2064e7e3e1fe8e56165f7cf", "intel", "specificity-weighted ACH attribution"),
    Sibling("OCCAM", "intel", "occam", "occam", "v1.1.1", "a0376183f866805ab42836bc4d09e7c848a57f2f",
            "intel", "Heuer ACH with false-flag hypotheses"),
    Sibling("VANTAGE", "posture", "vantage", "vantage", "v1.1.1", "d81498ef5849283d743c0364886baabeefdd99b1",
            "posture", "control -> detection -> technique coverage"),
    Sibling("GAUNTLET", "simulation", "gauntlet", "gauntlet-coverage", "v1.1.1", "a31b502490116201e56c5f073c482862c8975bd1", "simulation", "labelled replay + Atomic emulation plans"),
    Sibling("TRACEGATE", "supply-chain", "tracegate", "tracegate", "v1.1.1", "6779935bc5d2f0d702751db03ad5202be649e5a3", "supplychain", "manifest lineage -> introducing commit"),
    Sibling("STRATUM", "supply-chain", "stratum", "stratum-cnapp", "v1.1.1", "fd20018c2264d02c5458934794872142db3e4449",
            "supplychain", "Kubernetes posture + image provenance"),
    Sibling("LINCHPIN", "attack-path", "linchpin", "linchpin-attackpath", "v1.1.1", "e574dc816ef92041a4f65573306a1ad76bb30314", "attackpath", "attack paths + fix prioritisation"),
    Sibling("VITRINE", "malware", "vitrine", "vitrine", "v1.1.2", "b534eba899c1f622e4a9ca84b74ded66126d468d",
            "malware", "static PE triage (never executes)"),
    Sibling("SPECIMEN", "malware", "specimen", "specimen", "v1.1.2", "be11eac7ab2799f33db42cd04bce02d90870337b",
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
