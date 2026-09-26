"""Connector output -> canonical event schema (+ integrity hashing).

Connectors are UNTRUSTED: every raw record is validated, hashed, and stored
by reference; nothing reaches the graph without passing `CanonicalEvent.validate`.
"""
from __future__ import annotations

from collections.abc import Callable

from .confidence import base_confidence
from .contracts import CanonicalEvent, ContractError, canonical_hash

Mapper = Callable[[dict], dict]
_MAPPERS: dict[str, Mapper] = {}

MAX_FIELD_LEN = 512


def register_connector(name: str):
    def deco(fn: Mapper) -> Mapper:
        _MAPPERS[name] = fn
        return fn
    return deco


def connectors() -> list[str]:
    return sorted(_MAPPERS)


@register_connector("canonical")
def _canonical(raw: dict) -> dict:
    return {k: raw[k] for k in ("ts", "layer", "actor_type", "actor_id", "action",
                                 "object_type", "object_id") if k in raw} | {
        k: raw[k] for k in ("method", "reliability", "source") if k in raw}


@register_connector("endpoint")
def _endpoint(raw: dict) -> dict:
    """Sysmon/eBPF-like process + network + file records."""
    kind = raw["kind"]
    host_proc = raw.get("pid_key") or f"{raw['host']}/{raw['pid']}"
    if kind == "process_create":
        return dict(layer="runtime", actor_type="Process", actor_id=f"{raw['host']}/{raw['ppid']}",
                    action="SPAWNED", object_type="Process", object_id=host_proc)
    if kind == "network_connect":
        return dict(layer="network", actor_type="Process", actor_id=host_proc,
                    action="CONNECTED_TO", object_type="IPAddress",
                    object_id=f"{raw['dst_ip']}:{raw['dst_port']}")
    if kind == "file_write":
        return dict(layer="runtime", actor_type="Process", actor_id=host_proc,
                    action="WROTE", object_type="File", object_id=raw["path"])
    if kind == "module_load":
        return dict(layer="runtime", actor_type="Process", actor_id=host_proc,
                    action="LOADED", object_type="Dependency", object_id=raw["module"])
    raise ContractError(f"endpoint: unsupported kind {kind!r}")


@register_connector("cicd")
def _cicd(raw: dict) -> dict:
    kind = raw["kind"]
    if kind == "commit":
        return dict(layer="code", actor_type="Author", actor_id=raw["author"],
                    action="AUTHORED", object_type="Commit", object_id=raw["sha"])
    if kind == "dependency_added":
        return dict(layer="code", actor_type="Commit", actor_id=raw["sha"],
                    action="INTRODUCED", object_type="Dependency", object_id=raw["package"])
    if kind == "build":
        return dict(layer="code", actor_type="Dependency", actor_id=raw["package"],
                    action="BUILT_INTO", object_type="ImageLayer", object_id=raw["image"])
    if kind == "deploy":
        return dict(layer="infra", actor_type="ImageLayer", actor_id=raw["image"],
                    action="DEPLOYED_AS", object_type="Pod", object_id=raw["pod"])
    if kind == "pod_process":
        return dict(layer="infra", actor_type="Pod", actor_id=raw["pod"],
                    action="RUNS", object_type="Process", object_id=raw["pid_key"])
    raise ContractError(f"cicd: unsupported kind {kind!r}")


@register_connector("cti")
def _cti(raw: dict) -> dict:
    return dict(layer="threat", actor_type=raw.get("subject_type", "IOC"), actor_id=raw["subject"],
                action=raw.get("relation", "ATTRIBUTED_TO"),
                object_type=raw.get("object_type", "Actor"), object_id=raw["object"],
                method="stated")


def _clean(v):
    if isinstance(v, str):
        v = "".join(ch for ch in v if ch.isprintable())
        if len(v) > MAX_FIELD_LEN:
            raise ContractError("field too long")
    return v


def normalize(raw: dict, connector: str, source: str | None = None,
              reliability: str = "B", raw_ref: str | None = None) -> CanonicalEvent:
    if connector not in _MAPPERS:
        raise ContractError(f"unknown connector {connector!r}")
    if not isinstance(raw, dict):
        raise ContractError("raw event must be a mapping")
    try:
        mapped = {k: _clean(v) for k, v in _MAPPERS[connector](raw).items()}
    except KeyError as e:
        raise ContractError(f"{connector}: missing field {e}") from None
    h = canonical_hash(raw)
    attributes = {str(k): ("".join(ch if ch.isprintable() else " " for ch in v) if isinstance(v, str) else v)
                  for k, v in (mapped.pop("attributes", None) or {}).items()}
    ts = mapped.pop("ts", None)
    method = mapped.pop("method", raw.get("method", "observed"))
    rel = mapped.pop("reliability", raw.get("reliability", reliability))
    src = mapped.pop("source", source or raw.get("source") or connector)
    ev = CanonicalEvent(
        event_id=f"ev-{h[:16]}",
        ts=str(raw.get("ts") or ts or "1970-01-01T00:00:00Z"),
        layer=mapped["layer"], actor_type=mapped["actor_type"], actor_id=str(mapped["actor_id"]),
        action=mapped["action"], object_type=mapped["object_type"], object_id=str(mapped["object_id"]),
        source=str(src), method=method, confidence=base_confidence(method, rel),
        raw_ref=raw_ref or f"raw://{connector}/{h}", hash=h, reliability=rel,
        attributes=dict(attributes),
    )
    return ev.validate()


@register_connector("windows")
def _windows(raw: dict) -> dict:
    """Sysmon / Security event log records (OTRF, Winlogbeat, NXLog JSON)."""
    from .connectors.windows import map_windows
    return map_windows(raw)


@register_connector("ocsf")
def _ocsf(raw: dict) -> dict:
    from .connectors.ocsf import map_ocsf
    return map_ocsf(raw)


def verify(event: CanonicalEvent, raw: dict) -> bool:
    """Integrity check: does the stored raw record still match the event hash?"""
    return canonical_hash(raw) == event.hash
