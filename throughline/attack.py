"""MITRE ATT&CK knowledge: the full Enterprise STIX bundle, plus a tiny rule mapper.

* :class:`AttackCatalog` loads the official STIX 2.1 bundle (techniques,
  tactics, groups, software, campaigns, mitigations and their ``uses`` /
  ``attributed-to`` / ``mitigates`` relationships). Revoked and deprecated
  objects are dropped; revoked technique ids are resolvable via ``resolve``.
* :func:`map_event` is the built-in, hand-written mapper from canonical events
  to technique ids (the reference "attack-mapping" engine). Its output is a
  *claim* with ``method=inferred``, never a fact.

When no bundle is loaded, the catalog falls back to a handful of technique
names so the offline demo and tests stay self-contained.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import CanonicalEvent

TECHNIQUES = {
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1059": "Command and Scripting Interpreter",
    "T1105": "Ingress Tool Transfer",
    "T1053": "Scheduled Task/Job",
}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class AttackObject:
    """One ATT&CK object (technique, group, software, campaign) as the catalog keeps it."""
    stix_id: str
    attack_id: str
    name: str
    type: str
    aliases: list[str] = field(default_factory=list)
    created: str = ""
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)


@dataclass
class AttackCatalog:
    """MITRE ATT&CK Enterprise STIX loaded into lookup tables (techniques, groups, software,
    campaigns, mitigations, ``uses`` relations, revoked-id forwarding).
    """
    version: str = ""
    released: str = ""
    techniques: dict[str, AttackObject] = field(default_factory=dict)   # T-id -> object
    groups: dict[str, AttackObject] = field(default_factory=dict)       # G-id -> object
    software: dict[str, AttackObject] = field(default_factory=dict)     # S-id -> object
    campaigns: dict[str, AttackObject] = field(default_factory=dict)    # C-id -> object
    mitigations: dict[str, AttackObject] = field(default_factory=dict)  # M-id -> object
    tactics: dict[str, str] = field(default_factory=dict)               # shortname -> name
    uses: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # G/S/C -> T/S ids
    attributed: dict[str, str] = field(default_factory=dict)            # C-id -> G-id
    mitigates: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # M -> T
    revoked: dict[str, str] = field(default_factory=dict)               # old T-id -> new T-id

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, path: str | Path) -> AttackCatalog:
        """Load a STIX 2.1 bundle file (e.g. ``enterprise-attack-19.2.json``)."""
        with open(path, encoding="utf-8") as fh:
            return cls.from_bundle(json.load(fh))

    @classmethod
    def from_bundle(cls, bundle: dict) -> AttackCatalog:
        """Build the catalog from an already parsed STIX bundle."""
        cat = cls()
        objs = bundle.get("objects", [])
        by_stix: dict[str, AttackObject] = {}
        revoked_stix: dict[str, str] = {}
        for o in objs:
            t = o.get("type")
            if t == "x-mitre-collection":
                cat.version = str(o.get("x_mitre_version", ""))
                cat.released = str(o.get("modified", ""))
                continue
            if t == "x-mitre-tactic":
                cat.tactics[o.get("x_mitre_shortname", "")] = o.get("name", "")
                continue
            ext = next((r.get("external_id", "") for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), "")
            if not ext:
                continue
            if o.get("revoked"):
                revoked_stix[o["id"]] = ext
                continue
            if o.get("x_mitre_deprecated"):
                continue
            obj = AttackObject(
                o["id"], ext, o.get("name", ""), t,
                aliases=[a for a in (o.get("aliases") or o.get("x_mitre_aliases") or []) if a != o.get("name")],
                created=str(o.get("created", "")),
                tactics=[p["phase_name"] for p in o.get("kill_chain_phases", [])
                         if p.get("kill_chain_name") == "mitre-attack"],
                platforms=list(o.get("x_mitre_platforms", [])))
            bucket = {"attack-pattern": cat.techniques, "intrusion-set": cat.groups, "malware": cat.software,
                      "tool": cat.software, "campaign": cat.campaigns,
                      "course-of-action": cat.mitigations}.get(t)
            if bucket is None:
                continue
            bucket[ext] = obj
            by_stix[o["id"]] = obj
        for o in objs:
            if o.get("type") != "relationship" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            rel, src, dst = o.get("relationship_type"), by_stix.get(o.get("source_ref")), \
                by_stix.get(o.get("target_ref"))
            if rel == "revoked-by" and o.get("source_ref") in revoked_stix and dst:
                cat.revoked[revoked_stix[o["source_ref"]]] = dst.attack_id
            if not src or not dst:
                continue
            if rel == "uses":
                cat.uses[src.attack_id].add(dst.attack_id)
            elif rel == "attributed-to" and src.type == "campaign" and dst.type == "intrusion-set":
                cat.attributed[src.attack_id] = dst.attack_id
            elif rel == "mitigates" and src.type == "course-of-action":
                cat.mitigates[src.attack_id].add(dst.attack_id)
        return cat

    # ------------------------------------------------------------------ queries
    def resolve(self, tid: str) -> str | None:
        """Current id for a (possibly revoked) technique id, or ``None`` if unknown."""
        tid = tid.upper()
        seen = set()
        while tid in self.revoked and tid not in seen:
            seen.add(tid)
            tid = self.revoked[tid]
        return tid if tid in self.techniques else None

    def name(self, tid: str) -> str:
        """Technique name for an id (``T1003.001`` -> ``OS Credential Dumping: LSASS Memory``)."""
        t = self.techniques.get(tid)
        if not t:
            return TECHNIQUES.get(tid, "")
        if "." in tid and tid.split(".")[0] in self.techniques:
            return f"{self.techniques[tid.split('.')[0]].name}: {t.name}"
        return t.name

    def techniques_of(self, entity: str) -> set[str]:
        """Technique ids an ATT&CK entity (group, software, campaign) is documented to use."""
        return {x for x in self.uses.get(entity, ()) if x.startswith("T")}

    def software_of(self, entity: str) -> set[str]:
        """Software ids an ATT&CK entity is documented to use."""
        return {x for x in self.uses.get(entity, ()) if x.startswith("S")}

    def group_profile(self, gid: str, via_software: bool = True) -> set[str]:
        """Techniques a group uses directly, plus (optionally) via its software."""
        out = set(self.techniques_of(gid))
        if via_software:
            for s in self.software_of(gid):
                out |= self.techniques_of(s)
        return out

    def summary(self) -> dict:
        """Object counts and the ATT&CK version, for reports."""
        return {"version": self.version, "techniques": len(self.techniques), "groups": len(self.groups),
                "software": len(self.software), "campaigns": len(self.campaigns),
                "mitigations": len(self.mitigations), "attributed_campaigns": len(self.attributed)}


_ACTIVE: AttackCatalog | None = None


def set_active(cat: AttackCatalog | None) -> None:
    """Make ``cat`` the catalog used for technique names across the process."""
    global _ACTIVE
    _ACTIVE = cat


def active() -> AttackCatalog | None:
    """The catalog installed by :func:`set_active`, or ``None`` (built-in names only)."""
    return _ACTIVE


def canonical_technique(tid: str) -> str:
    """Upper-case id, with revoked ids forwarded to their replacement when a catalog is loaded."""
    tid = tid.strip().upper()
    if _ACTIVE is not None:
        return _ACTIVE.resolve(tid) or tid
    return tid


def technique_name(tid: str) -> str:
    """Human-readable technique name from the active catalog, falling back to a built-in table."""
    return _ACTIVE.name(tid) if _ACTIVE else TECHNIQUES.get(tid, "")


SUSPICIOUS_INTERPRETERS = ("sh", "bash", "powershell", "cmd", "python")


def map_event(ev: CanonicalEvent, context: dict | None = None) -> list[tuple[str, str]]:
    """Return [(technique_id, reason)] for the synthetic/cicd event vocabulary."""
    ctx = context or {}
    out: list[tuple[str, str]] = []
    if ev.action == "INTRODUCED" and ctx.get("dependency_untrusted"):
        out.append(("T1195.001", "untrusted dependency introduced by commit"))
    if ev.action == "CONNECTED_TO":
        port = ev.object_id.rsplit(":", 1)[-1]
        if port in {"80", "443", "8080"} and ctx.get("external_ip"):
            out.append(("T1071.001", "process beacons to external web endpoint"))
    if ev.action == "SPAWNED":
        name = ctx.get("child_name", "")
        if name.split("/")[-1] in SUSPICIOUS_INTERPRETERS:
            out.append(("T1059", f"spawned interpreter {name}"))
    if ev.action == "WROTE" and ev.object_id.startswith(("/tmp/", "/dev/shm/")):
        out.append(("T1105", "file dropped in world-writable temp path"))
    return out
