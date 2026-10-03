"""Windows endpoint connector: Sysmon + Security event log records -> canonical events.

Accepts the flattened JSON exported by NXLog/Winlogbeat (the OTRF / Mordor
format: one object per line with ``Channel``, ``EventID``, ``Hostname`` and
the EventData fields at the top level).

Process identity is ``<host>/<pid>/<image basename>``. Sysmon's ProcessGuid is
more precise, but the Security log (4688, 5156) has no GUID; keying on
(host, pid, image) lets Sysmon and Security records *corroborate* each other
in the graph (two independent sensors -> noisy-OR), at the price of merging
two processes that reuse a PID with the same image inside one capture. See
docs/adr/0005-windows-process-identity.md.

Unmodelled event ids raise :class:`Skip` (a ContractError subclass), so the
pipeline can count them separately from genuinely malformed records.
"""
from __future__ import annotations

from typing import Any

from ..contracts import MAX_ATTRIBUTE_LEN, ContractError

SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"


class Skip(ContractError):
    """A well-formed record this connector deliberately does not model."""


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def short_host(rec: dict[str, Any]) -> str:
    h = rec.get("Hostname") or rec.get("Computer") or rec.get("host_name") or rec.get("host") or ""
    if isinstance(h, dict):
        h = h.get("name", "")
    return str(h).strip().split(".")[0].lower() or "unknown-host"


def basename(path: Any) -> str:
    p = _s(path).replace("\\", "/").rstrip("/")
    return (p.rsplit("/", 1)[-1] or "?").lower()


def _pid(v: Any) -> str:
    s = _s(v).strip()
    if not s:
        return "?"
    try:
        return str(int(s, 16) if s.lower().startswith("0x") else int(s))
    except ValueError:
        return s.lower()


def guid_tag(guid: Any) -> str:
    """Stable per-host id from a Sysmon ProcessGuid (the first block is a per-machine constant)."""
    g = _s(guid).strip("{} ").lower()
    return "g-" + g.split("-", 1)[1] if "-" in g else ("g-" + g if g else "?")


def proc_id(host: str, pid: Any, image: Any, guid: Any = None) -> str:
    """``host/pid/image``; when an export dropped the pid (some NXLog captures keep only
    ProcessGuid), the GUID stands in so distinct processes are not merged into ``?``."""
    p = _pid(pid)
    if p == "?" and guid:
        p = guid_tag(guid)
    return f"{host}/{p}/{basename(image)}"


def _first(rec: dict[str, Any], *names: str) -> Any:
    for n in names:
        v = rec.get(n)
        if v not in (None, ""):
            return v
    return None


def event_ts(rec: dict[str, Any]) -> str:
    """Event time in ISO-8601 UTC (Sysmon UtcTime > @timestamp > EventTime)."""
    u = rec.get("UtcTime")
    if u:
        u = str(u).strip().replace(" ", "T")
        return u if u.endswith("Z") else u + "Z"
    for k in ("@timestamp", "TimeCreated", "EventTime", "timestamp"):
        v = rec.get(k)
        if v:
            v = str(v).strip().replace(" ", "T")
            return v if v.endswith("Z") or "+" in v[10:] else v + "Z"
    return "1970-01-01T00:00:00Z"


def channel(rec: dict[str, Any]) -> str:
    c = rec.get("Channel") or rec.get("channel") or rec.get("log_name") or ""
    return str(c).lower()


def event_id(rec: dict[str, Any]) -> int:
    try:
        return int(rec.get("EventID", rec.get("event_id", -1)))
    except (TypeError, ValueError):
        return -1


def _trim(attrs: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for k, v in attrs.items():
        if v in (None, ""):
            continue
        v = _s(v)
        out[k] = v if len(v) <= MAX_ATTRIBUTE_LEN else v[: MAX_ATTRIBUTE_LEN - 3] + "..."
    return out


def _sha256(hashes: Any) -> str:
    for part in _s(hashes).split(","):
        if part.upper().startswith("SHA256="):
            return part.split("=", 1)[1].lower()
    return ""


def acting_process(rec: dict[str, Any]) -> str | None:
    """Graph key of the process an event is *about* (the new process for a process
    creation, otherwise the acting process); ``None`` for non-process events."""
    host, ch, eid = short_host(rec), channel(rec), event_id(rec)
    if ch == SYSMON:
        if eid in (8, 10):
            return "Process:" + proc_id(host, _first(rec, "SourceProcessId", "SourceProcessID"), rec.get("SourceImage"),
                                        _first(rec, "SourceProcessGuid", "SourceProcessGUID"))
        if rec.get("Image"):
            return "Process:" + proc_id(host, _first(rec, "ProcessId", "ProcessID"), rec.get("Image"),
                                        _first(rec, "ProcessGuid", "ProcessGUID"))
    if ch == SECURITY:
        if eid == 4688:
            return "Process:" + proc_id(host, rec.get("NewProcessId"), rec.get("NewProcessName"))
        if eid in (5156, 5158) and rec.get("Application"):
            return "Process:" + proc_id(host, rec.get("ProcessID") or rec.get("ProcessId"), rec.get("Application"))
        if rec.get("ProcessId") and rec.get("ProcessName"):
            return "Process:" + proc_id(host, rec.get("ProcessId"), rec.get("ProcessName"))
    if ch.startswith("microsoft-windows-powershell") and rec.get("ExecutionProcessID"):
        return "Process:" + proc_id(host, rec.get("ExecutionProcessID"), "powershell.exe")
    return None


def _proc(ev: dict, host: str, role: str, pid: Any, image: Any, guid: Any = None, **attrs: Any) -> None:
    ev[f"{role}_type"] = "Process"
    ev[f"{role}_id"] = proc_id(host, pid, image, guid)
    ev.setdefault("attributes", {}).update(
        {f"{role if role == 'actor' else 'object'}.{k}": v for k, v in
         {"image": image, "host": host, "pid": _pid(pid), **attrs}.items()})


def map_sysmon(rec: dict[str, Any]) -> dict[str, Any]:
    eid, host = event_id(rec), short_host(rec)
    ev: dict[str, Any] = {"layer": "runtime", "ts": event_ts(rec)}
    img = rec.get("Image")
    if eid == 1:
        _proc(ev, host, "actor", _first(rec, "ParentProcessId", "ParentProcessID"), rec.get("ParentImage"),
              _first(rec, "ParentProcessGuid", "ParentProcessGUID"), cmdline=rec.get("ParentCommandLine"))
        _proc(ev, host, "object", _first(rec, "ProcessId", "ProcessID"), img,
              _first(rec, "ProcessGuid", "ProcessGUID"), cmdline=rec.get("CommandLine"),
              user=rec.get("User"), integrity=rec.get("IntegrityLevel"), sha256=_sha256(rec.get("Hashes")))
        ev["action"] = "SPAWNED"
    elif eid in (8, 10):
        _proc(ev, host, "actor", _first(rec, "SourceProcessId", "SourceProcessID"), rec.get("SourceImage"),
              _first(rec, "SourceProcessGuid", "SourceProcessGUID"))
        _proc(ev, host, "object", _first(rec, "TargetProcessId", "TargetProcessID"), rec.get("TargetImage"),
              _first(rec, "TargetProcessGuid", "TargetProcessGUID"))
        ev["action"] = "INJECTED_INTO" if eid == 8 else "ACCESSED"
        if eid == 10:
            ev["attributes"]["object.granted_access"] = rec.get("GrantedAccess")
    else:
        if img is None:
            raise Skip(f"sysmon {eid}: no Image")
        _proc(ev, host, "actor", _first(rec, "ProcessId", "ProcessID"), img, _first(rec, "ProcessGuid", "ProcessGUID"))
        if eid == 3:
            # Inbound connections (Initiated=false) put the *local* address in Destination*;
            # they are skipped like inbound WFP 5156 events, so CONNECTED_TO always points at
            # the remote end. The local address of an outbound connection is kept on the
            # process (``local_ip``): correlation uses it to map addresses to hosts.
            if _s(rec.get("Initiated")).lower() == "false":
                raise Skip("inbound sysmon connection")
            ev.update(layer="network", action="CONNECTED_TO", object_type="IPAddress",
                      object_id=f"{rec.get('DestinationIp', '?')}:{rec.get('DestinationPort', '?')}")
            ev["attributes"]["object.hostname"] = rec.get("DestinationHostname")
            if rec.get("SourceIp"):
                ev["attributes"]["actor.local_ip"] = rec.get("SourceIp")
        elif eid == 7:
            ev.update(action="LOADED", object_type="ModuleLoad", object_id=_s(rec.get("ImageLoaded")).lower())
            ev["attributes"]["object.signed"] = rec.get("Signed")
        elif eid in (11, 15):
            ev.update(action="WROTE", object_type="File", object_id=_s(rec.get("TargetFilename")).lower())
        elif eid == 2:
            ev.update(action="MODIFIED", object_type="File", object_id=_s(rec.get("TargetFilename")).lower())
        elif eid in (12, 13, 14):
            ev.update(action="MODIFIED", object_type="RegistryKey", object_id=_s(rec.get("TargetObject")))
            if eid == 13:
                ev["attributes"]["object.details"] = rec.get("Details")
        elif eid == 22:
            ev.update(layer="network", action="RESOLVED", object_type="Domain",
                      object_id=_s(rec.get("QueryName")).lower())
        elif eid in (23, 26):
            ev.update(action="DELETED", object_type="File", object_id=_s(rec.get("TargetFilename")).lower())
        else:
            raise Skip(f"sysmon {eid} not modelled")
    if not ev.get("object_id"):
        raise Skip(f"sysmon {eid}: empty object")
    ev["attributes"] = _trim(ev.get("attributes", {}))
    return ev


def map_security(rec: dict[str, Any]) -> dict[str, Any]:
    eid, host = event_id(rec), short_host(rec)
    ev: dict[str, Any] = {"layer": "runtime", "ts": event_ts(rec)}
    if eid == 4688:
        _proc(ev, host, "actor", rec.get("ProcessId"), rec.get("ParentProcessName") or "?")
        _proc(ev, host, "object", rec.get("NewProcessId"), rec.get("NewProcessName"),
              cmdline=rec.get("CommandLine"), user=rec.get("SubjectUserName"))
        ev["action"] = "SPAWNED"
    elif eid in (5156, 5158) and rec.get("Application"):
        if eid == 5158:
            raise Skip("5158 bind not modelled")
        _proc(ev, host, "actor", rec.get("ProcessID") or rec.get("ProcessId"), rec.get("Application"))
        direction = _s(rec.get("Direction")).lower()
        if "inbound" in direction or direction.endswith("14592"):
            raise Skip("inbound WFP connection")
        ev.update(layer="network", action="CONNECTED_TO", object_type="IPAddress",
                  object_id=f"{rec.get('DestAddress', '?')}:{rec.get('DestPort', '?')}")
    elif eid == 4624:
        user = _s(rec.get("TargetUserName")).lower()
        if not user or user.endswith("$") or user in ("system", "anonymous logon", "-"):
            raise Skip("machine/system logon")
        ev.update(layer="identity", actor_type="User", actor_id=f"{_s(rec.get('TargetDomainName')).lower()}\\{user}",
                  action="LOGGED_ON", object_type="Host", object_id=host,
                  attributes={"object.logon_type": rec.get("LogonType"), "actor.source_ip": rec.get("IpAddress")})
    else:
        raise Skip(f"security {eid} not modelled")
    ev["attributes"] = _trim(ev.get("attributes", {}))
    return ev


def map_windows(rec: dict[str, Any]) -> dict[str, Any]:
    ch = channel(rec)
    if ch == SYSMON:
        return map_sysmon(rec)
    if ch == SECURITY:
        return map_security(rec)
    raise Skip(f"channel {ch or '?'} not modelled")
