"""OCSF 1.x connector: the common event classes -> canonical events.

Covers Process Activity (1007), File System Activity (1001), Network Activity
(4001), DNS Activity (4003) and Authentication (3002). Other classes raise
:class:`~throughline.connectors.windows.Skip`. Process identity follows the
Windows connector (``host/pid/image``) so OCSF-normalised EDR data and raw
Sysmon about the same process land on the same graph node.
"""
from __future__ import annotations

from typing import Any

from .windows import Skip, _trim, basename


def _host(rec: dict[str, Any]) -> str:
    dev = rec.get("device") or {}
    h = dev.get("hostname") or dev.get("name") or "unknown-host"
    return str(h).split(".")[0].lower()


def _pkey(host: str, p: dict[str, Any] | None) -> str:
    p = p or {}
    img = (p.get("file") or {}).get("path") or p.get("name") or "?"
    return f"{host}/{p.get('pid', '?')}/{basename(img)}"


def _ts(rec: dict[str, Any]) -> str:
    t = rec.get("time_dt") or rec.get("time")
    if isinstance(t, (int, float)):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(t / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return str(t) if t else "1970-01-01T00:00:00Z"


def map_ocsf(rec: dict[str, Any]) -> dict[str, Any]:
    cls = int(rec.get("class_uid", 0))
    host = _host(rec)
    actor_proc = (rec.get("actor") or {}).get("process")
    ev: dict[str, Any] = {"layer": "runtime", "ts": _ts(rec), "actor_type": "Process"}
    if cls == 1007:
        proc = rec.get("process") or {}
        parent = proc.get("parent_process") or actor_proc
        ev.update(actor_id=_pkey(host, parent), action="SPAWNED", object_type="Process",
                  object_id=_pkey(host, proc),
                  attributes={"object.cmdline": proc.get("cmd_line"), "object.image": (proc.get("file") or {}).get("path")})
    elif cls == 1001:
        f = rec.get("file") or {}
        action = {1: "WROTE", 2: "READ", 3: "MODIFIED", 4: "DELETED"}.get(int(rec.get("activity_id", 0)))
        if not action:
            raise Skip("file activity not modelled")
        ev.update(actor_id=_pkey(host, actor_proc), action=action, object_type="File",
                  object_id=str(f.get("path", "")).lower())
    elif cls == 4001:
        dst = rec.get("dst_endpoint") or {}
        ev.update(layer="network", actor_id=_pkey(host, actor_proc), action="CONNECTED_TO",
                  object_type="IPAddress", object_id=f"{dst.get('ip', '?')}:{dst.get('port', '?')}")
    elif cls == 4003:
        q = (rec.get("query") or {}).get("hostname", "")
        ev.update(layer="network", actor_id=_pkey(host, actor_proc), action="RESOLVED",
                  object_type="Domain", object_id=str(q).lower())
    elif cls == 3002:
        user = (rec.get("user") or {}).get("name", "")
        if not user:
            raise Skip("authentication without user")
        ev.update(layer="identity", actor_type="User", actor_id=str(user).lower(), action="LOGGED_ON",
                  object_type="Host", object_id=host)
    else:
        raise Skip(f"OCSF class {cls} not modelled")
    if not ev.get("object_id"):
        raise Skip("empty object")
    ev["attributes"] = _trim(ev.get("attributes", {}))
    return ev
