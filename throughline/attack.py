"""ATT&CK mapping STUB: small, hand-curated rules from canonical events to
technique IDs. Output is a *claim* with method=inferred, never a fact.
TODO(Grade C): load full STIX ATT&CK bundle; TODO(Grade D): tune rules.
"""
from __future__ import annotations

from .contracts import CanonicalEvent

TECHNIQUES = {
    "T1195.001": "Supply Chain Compromise: Compromise Software Dependencies and Development Tools",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1059": "Command and Scripting Interpreter",
    "T1105": "Ingress Tool Transfer",
    "T1053": "Scheduled Task/Job",
}

SUSPICIOUS_INTERPRETERS = ("sh", "bash", "powershell", "cmd", "python")


def map_event(ev: CanonicalEvent, context: dict | None = None) -> list[tuple[str, str]]:
    """Return [(technique_id, reason)]."""
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
