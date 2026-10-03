"""Correlation: many alerts -> few incidents (one incident = one graph cluster).

Reads only the graph. Every process carrying a technique claim (from any
engine) or an alert is a *signal*. Signals are grouped by their **story
root**: walk ``SPAWNED`` predecessors until the parent is a session/service
boundary process (services.exe, explorer.exe, wmiprvse.exe, ...). Everything a
user or service launched under one boundary child is one incident; this is the
same notion of "story" REVENANT and ROOTLINE use, applied across engines.

Each incident gets

* ``<process> PART_OF Incident:<host>/<root>`` for every signal and every
  process on the path from the root down to it (source ``correlation``),
* ``Incident EXHIBITS Technique`` roll-ups: the best claim of each independent
  engine across all members, combined by noisy-OR (the member claims are cited
  in ``evidence_ref``, not re-counted), so intel engines read "what this
  incident did" in one hop and cross-engine agreement raises confidence, and
* display attributes: ``score`` (its most confident technique), ``breadth``,
  ``pivot`` (the strongest member), alert/technique counts.

Cross-host stitching (:func:`stitch`) joins incidents on *different* hosts into
one ``cluster`` through two kinds of evidence:

* **shared rare destination** - members of both incidents contacted the same
  remote endpoint (``CONNECTED_TO`` an ``IPAddress`` or ``RESOLVED`` a ``Domain``),
  so a beacon to one C2 from several hosts reads as one intrusion. Only
  connections made by non-system processes count (``lsass.exe`` talking to the
  domain controller is not evidence), non-routable addresses (loopback,
  link-local, multicast) and ``localhost`` are ignored, as are Windows
  infrastructure ports (DNS, Kerberos, LDAP, RPC endpoint mapper and the dynamic
  RPC range, NetBIOS, SMB). A destination is *rare* if at most ``max_fanout``
  incidents share it and at most half of the hosts (minimum 2) contacted it at
  all, counted over every process's traffic, not just incidents.
* **lateral movement** - a member on host A connected to host B on a remote
  administration port (SMB, RPC, WinRM, RDP, SSH), and an incident on B starts
  under a remote-execution service (``wsmprovhost.exe``, ``psexesvc.exe``,
  ``wmiprvse.exe``, ``winrshost.exe``) within an hour of that connection.
  Addresses are mapped to hosts from the local address of each host's own
  outbound connections.

Each link is a proposal with its evidence (``cluster_via``), not a proven edge.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from ..contracts import Claim
from ..graph import KnowledgeGraph
from .calibration import default_map

SOURCE = "correlation"
# processes that sit above user/service activity: a story root is a child of one
BOUNDARY = frozenset({
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "userinit.exe", "wmiprvse.exe", "taskhostw.exe", "taskeng.exe",
    "runtimebroker.exe", "sihost.exe", "dllhost.exe", "?",
})
# engines whose technique claims are annotations of an incident, not signals
NON_SIGNAL_SOURCES = frozenset({SOURCE, "dragnet", "occam", "vantage"})


def image(key: str) -> str:
    """Lower-case image name of a ``Process:`` key (empty for other nodes)."""
    return key.rsplit("/", 1)[-1].lower() if key.startswith("Process:") else ""


def story_root(kg: KnowledgeGraph, key: str, max_hops: int = 64) -> tuple[str, list[str]]:
    """(root, path root->key) following SPAWNED parents up to a boundary process."""
    path = [key]
    cur = key
    seen = {key}
    for _ in range(max_hops):
        parents = [p for p, _, k in kg.g.in_edges(cur, keys=True) if k == "SPAWNED" and p not in seen]
        if not parents:
            break
        parent = min(parents, key=lambda p: kg.g.nodes[p]["first_seen"])
        if image(parent) in BOUNDARY:
            break
        seen.add(parent)
        path.append(parent)
        cur = parent
    return cur, list(reversed(path))


def signal_techniques(kg: KnowledgeGraph, key: str) -> dict[str, dict[str, float]]:
    """technique -> {source: best base confidence} over the signal claims on one node."""
    out: dict[str, dict[str, float]] = {}
    for _, t, k, d in kg.g.out_edges(key, keys=True, data=True):
        if k != "EXHIBITS":
            continue
        tid = t.split(":", 1)[1]
        for cid in d.get("claims", []):
            c = kg.claims[cid]
            if c.source in NON_SIGNAL_SOURCES:
                continue
            best = out.setdefault(tid, {})
            best[c.source] = max(best.get(c.source, 0.0), c.base_confidence)
    return out


NET_PREDICATES = frozenset({"CONNECTED_TO", "RESOLVED"})
# processes whose network traffic is the operating system's own (authentication, RPC, telemetry)
SYSTEM_NET_IMAGES = frozenset({
    "system", "lsass.exe", "svchost.exe", "services.exe", "wininit.exe", "smss.exe", "csrss.exe",
    "winlogon.exe", "backgroundtaskhost.exe", "taskhostw.exe", "runtimebroker.exe", "searchui.exe",
    "searchapp.exe", "searchindexer.exe", "msmpeng.exe", "mpcmdrun.exe", "smartscreen.exe", "dns.exe",
    "dfsrs.exe", "ismserv.exe", "spoolsv.exe", "wuauclt.exe", "usocoreworker.exe", "compattelrunner.exe",
    "sihost.exe", "ctfmon.exe", "audiodg.exe", "wmiprvse.exe", "splunkd.exe", "winlogbeat.exe", "sysmon.exe",
    "sysmon64.exe", "?",
})
# Windows infrastructure services: every domain member talks to them, so sharing one is not evidence
INFRA_PORTS = frozenset({53, 67, 68, 88, 123, 135, 137, 138, 139, 389, 445, 464, 636, 1900, 3268, 3269,
                         5353, 5355})
DYNAMIC_RPC = 49152
REMOTE_ADMIN_PORTS = frozenset({22, 135, 445, 3389, 5985, 5986})
REMOTE_EXEC_IMAGES = frozenset({"wsmprovhost.exe", "psexesvc.exe", "wmiprvse.exe", "winrshost.exe"})
LATERAL_WINDOW_S = 3600
LATERAL_SKEW_S = 120


def split_endpoint(key: str) -> tuple[str, int | None]:
    """``IPAddress:10.0.0.4:88`` -> ("10.0.0.4", 88); IPv6 keeps its colons; ``Domain:x`` -> ("x", None)."""
    if key.startswith("Domain:"):
        return key.split(":", 1)[1], None
    rest = key.split(":", 1)[1]
    host, _, port = rest.rpartition(":")
    try:
        return (host or rest).strip("[]"), int(port)
    except ValueError:
        return rest, None


def routable(addr: str) -> bool:
    """False for loopback, link-local, multicast, unspecified and broadcast addresses and ``localhost``."""
    import ipaddress

    a = addr.lower()
    if a in ("localhost", "?", "") or a.endswith(".localhost"):
        return False
    try:
        ip = ipaddress.ip_address(a.split("%", 1)[0])
    except ValueError:
        return True  # a domain name
    return not (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
                or a == "255.255.255.255")


def evidence_destination(key: str) -> bool:
    """Whether contacting ``key`` can count as shared-destination evidence at all."""
    addr, port = split_endpoint(key)
    if not routable(addr):
        return False
    return port is None or not (port in INFRA_PORTS or port >= DYNAMIC_RPC)


def destinations(kg: KnowledgeGraph, members: Iterable[str]) -> set[str]:
    """Remote endpoints (IPAddress/Domain nodes) contacted by non-system members that can
    count as stitching evidence."""
    out = set()
    for m in members:
        if m not in kg.g or image(m) in SYSTEM_NET_IMAGES:
            continue
        for _, t, k in kg.g.out_edges(m, keys=True):
            if k in NET_PREDICATES and t.startswith(("IPAddress:", "Domain:")) and evidence_destination(t):
                out.add(t)
    return out


def host_of(key: str) -> str:
    """Host part of a ``Process:`` / ``Incident:`` key (``host/pid/image`` or ``host/...``)."""
    return key.split(":", 1)[1].split("/", 1)[0]


def host_fanout(kg: KnowledgeGraph) -> tuple[dict[str, set[str]], set[str]]:
    """destination -> hosts whose processes contacted it (all traffic), and every host seen."""
    out: dict[str, set[str]] = defaultdict(set)
    hosts = set()
    for n in kg.g:
        if not n.startswith("Process:"):
            continue
        h = host_of(n)
        hosts.add(h)
        for _, t, k in kg.g.out_edges(n, keys=True):
            if k in NET_PREDICATES and t.startswith(("IPAddress:", "Domain:")):
                out[t].add(h)
    return out, hosts


def host_addresses(kg: KnowledgeGraph) -> dict[str, str]:
    """local address -> host, from the ``local_ip`` of each host's outbound connections
    (an address seen on two hosts, e.g. a NAT or VPN address, is dropped)."""
    seen: dict[str, set[str]] = defaultdict(set)
    for n in kg.g:
        if n.startswith("Process:"):
            ip = kg.g.nodes[n]["attrs"].get("local_ip")
            if ip and routable(str(ip)):
                seen[str(ip).lower()].add(host_of(n))
    return {ip: next(iter(hs)) for ip, hs in seen.items() if len(hs) == 1}


def _edge_ts(kg: KnowledgeGraph, s: str, k: str, o: str) -> str:
    cids = [c for _, oo, kk, d in kg.g.out_edges(s, keys=True, data=True) if kk == k and oo == o
            for c in d.get("claims", [])]
    return min((kg.claims[c].timestamp for c in cids), default=kg.g.nodes[s]["first_seen"])


def _epoch(ts: str) -> float | None:
    from datetime import datetime

    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError, TypeError):
        return None


def remote_entry(kg: KnowledgeGraph, root: str) -> bool:
    """The story root is (or was spawned by) a remote-execution service."""
    if image(root) in REMOTE_EXEC_IMAGES:
        return True
    return any(image(p) in REMOTE_EXEC_IMAGES for p, _, k in kg.g.in_edges(root, keys=True) if k == "SPAWNED")


def lateral_links(kg: KnowledgeGraph, incidents: list[dict],
                  members: dict[str, set[str]]) -> list[tuple[str, str, str]]:
    """(incident on A, incident on B, evidence) for every admin-port connection A -> B that is
    followed by an incident on B rooted under a remote-execution service."""
    addr = host_addresses(kg)
    targets: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for i in incidents:
        if remote_entry(kg, i["root"]):
            t = _epoch(min(kg.g.nodes[m]["first_seen"] for m in members[i["incident"]]))
            if t is not None:
                targets[host_of(i["root"])].append((i["incident"], t))
    links = set()
    for i in incidents:
        a = host_of(i["root"])
        for m in members[i["incident"]]:
            if m not in kg.g or image(m) in SYSTEM_NET_IMAGES:
                continue
            for _, t, k in kg.g.out_edges(m, keys=True):
                if k != "CONNECTED_TO" or not t.startswith("IPAddress:"):
                    continue
                ip, port = split_endpoint(t)
                b = addr.get(ip.lower())
                if port not in REMOTE_ADMIN_PORTS or not b or b == a:
                    continue
                when = _epoch(_edge_ts(kg, m, k, t))
                if when is None:
                    continue
                for inc_b, start in targets.get(b, []):
                    if when - LATERAL_SKEW_S <= start <= when + LATERAL_WINDOW_S:
                        links.add((i["incident"], inc_b, f"lateral {a}->{b} {image(m)} {ip}:{port}"))
    return sorted(links)


def stitch(incidents: list[dict], dests: dict[str, set[str]], max_fanout: int = 3,
           host_fanout_of: dict[str, set[str]] | None = None, n_hosts: int = 0,
           links: list[tuple[str, str, str]] | None = None) -> dict[str, dict]:
    """Union incidents on different hosts that share a rare destination or a lateral link.

    ``dests`` maps incident key -> destination node keys. A destination joins incidents only
    if at most ``max_fanout`` incidents share it and (when ``host_fanout_of`` is given) at most
    ``max(2, n_hosts // 2)`` hosts contacted it in all. ``links`` are extra (incident, incident,
    evidence) joins. Returns incident key -> ``{"cluster": id, "hosts": [...], "via": [...]}``.
    """
    host = {i["incident"]: host_of(i["incident"]) for i in incidents}
    users: dict[str, set[str]] = defaultdict(set)
    for inc, ds in dests.items():
        for d in ds:
            users[d].add(inc)
    parent = {i: i for i in host}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    host_cap = max(2, n_hosts // 2)
    via: dict[str, set[str]] = defaultdict(set)
    for d, incs in sorted(users.items()):
        if len(incs) < 2 or len(incs) > max_fanout or len({host[i] for i in incs}) < 2:
            continue
        if host_fanout_of is not None and len(host_fanout_of.get(d, ())) > host_cap:
            continue
        incs = sorted(incs)
        for other in incs[1:]:
            union(incs[0], other)
        for i in incs:
            via[i].add(d)
    for a, b, why in links or []:
        if a in parent and b in parent and host[a] != host[b]:
            union(a, b)
            via[a].add(why)
            via[b].add(why)
    groups: dict[str, list[str]] = defaultdict(list)
    for i in host:
        groups[find(i)].append(i)
    out = {}
    for root, members in groups.items():
        hosts = sorted({host[m] for m in members})
        shared = sorted(set().union(*(via[m] for m in members)))
        for m in members:
            out[m] = {"cluster": root, "hosts": hosts, "via": shared}
    return out


def noisy_or(values: Iterable[float]) -> float:
    """``1 - prod(1 - v)`` over the values, capped at 0.99."""
    miss = 1.0
    for v in values:
        miss *= 1.0 - v
    return min(1.0 - miss, 0.99)


class CorrelationEngine:
    """Groups signal processes into incidents by story root, fuses each incident's technique
    claims across independent engines and stitches incidents across hosts (see module docs).
    """
    name = "correlation"
    project = "THROUGHLINE"
    reads = ("EXHIBITS", "ALERTED_ON", "SPAWNED")
    writes = ("PART_OF", "EXHIBITS")

    def __init__(self, min_confidence: float = 0.0, max_fanout: int = 3):
        self.min_confidence = min_confidence
        self.max_fanout = max_fanout
        self.incidents: list[dict] = []

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Write ``PART_OF`` and incident ``EXHIBITS`` claims; put incidents and clusters in ``context``."""
        signals: dict[str, dict[str, dict[str, float]]] = {}
        alerts: dict[str, int] = defaultdict(int)
        for n in list(kg.g.nodes):
            if not n.startswith("Process:"):
                continue
            techs = {t: srcs for t, srcs in signal_techniques(kg, n).items()
                     if noisy_or(srcs.values()) >= self.min_confidence}
            n_alerts = sum(len(d.get("claims", [])) for _, _, k, d in kg.g.in_edges(n, keys=True, data=True)
                           if k == "ALERTED_ON")
            if techs or n_alerts:
                signals[n] = techs
                alerts[n] = n_alerts
        groups: dict[str, dict] = {}
        for n, techs in signals.items():
            root, path = story_root(kg, n)
            host = n.split(":", 1)[1].split("/", 1)[0]
            g = groups.setdefault(root, {"host": host, "root": root, "members": set(), "signals": {},
                                         "sources": defaultdict(dict), "alerts": 0})
            g["members"].update(path)
            g["signals"][n] = techs
            g["alerts"] += alerts[n]
            for t, srcs in techs.items():
                best = g["sources"][t]
                for src, v in srcs.items():
                    best[src] = max(best.get(src, 0.0), v)
        out: list[Claim] = []
        self.incidents = []
        platt = default_map()
        for root, g in groups.items():
            inc_id = f"{g['host']}/{root.split('/', 1)[1] if '/' in root else root}"
            inc_key = f"Incident:{inc_id}"
            ts = min(kg.g.nodes[m]["first_seen"] for m in g["members"])
            for m in sorted(g["members"]):
                mt, mid = m.split(":", 1)
                techs = g["signals"].get(m, {})
                conf = max((noisy_or(s.values()) for s in techs.values()), default=0.5)
                out.append(kg.add_claim(mt, mid, "PART_OF", "Incident", inc_id, source=SOURCE, method="inferred",
                                        reliability="B" if m in g["signals"] else "C", timestamp=ts,
                                        score=conf))
            tconf: dict[str, float] = {}
            for t, best in sorted(g["sources"].items()):
                # incident-level fusion: best claim per independent engine across all members,
                # combined by noisy-OR. The member claims are cited, not re-counted.
                tconf[t] = noisy_or(best.values())
                support = [cid for m, techs in g["signals"].items() if t in techs
                           for _, o, k, d in kg.g.out_edges(m, keys=True, data=True)
                           if k == "EXHIBITS" and o == f"Technique:{t}" for cid in d.get("claims", [])]
                c = kg.tag_technique(inc_key, t, "", source=SOURCE, ts=ts, score=tconf[t], reliability="A")
                c.evidence_ref = f"fused from {len(best)} engine(s) {sorted(best)}: " + ",".join(support[:20])
                out.append(c)
            pivot = max(g["signals"], key=lambda m: (max((noisy_or(s.values()) for s in g["signals"][m].values()),
                                                          default=0.0), alerts[m], m))
            info = {"engine": "THROUGHLINE", "root": root, "score": round(max(tconf.values(), default=0.0), 4),
                    "breadth": len(tconf),
                    "pivot": pivot, "alerts": g["alerts"], "signals": len(g["signals"]),
                    "members": len(g["members"]), "techniques": ",".join(sorted(tconf))[:1000]}
            kg.set_attrs(inc_key, info)
            if platt:
                kg.set_attrs(inc_key, {"calibrated_score": round(platt(info["score"]), 4)})
            self.incidents.append({"incident": inc_key, **info, "technique_conf": dict(sorted(tconf.items())),
                                   "technique_prob": {t: round(platt(c), 4) for t, c in sorted(tconf.items())}
                                   if platt else {},
                                   "technique_sources": {t: dict(b) for t, b in sorted(g["sources"].items())}})
        members = {i["incident"]: groups[i["root"]]["members"] for i in self.incidents}
        dests = {inc: destinations(kg, ms) for inc, ms in members.items()}
        fan, hosts = host_fanout(kg)
        clusters = stitch(self.incidents, dests, self.max_fanout, fan, len(hosts),
                          lateral_links(kg, self.incidents, members))
        for i in self.incidents:
            c = clusters[i["incident"]]
            i.update(cluster=c["cluster"], cluster_hosts=c["hosts"], cluster_via=c["via"])
            kg.set_attrs(i["incident"], {"cluster": c["cluster"], "cluster_hosts": ",".join(c["hosts"])[:1000]})
        self.incidents.sort(key=lambda i: (-i["score"], -i["breadth"], -i["alerts"], i["incident"]))
        context["incidents"] = self.incidents
        context["clusters"] = sorted({c["cluster"] for c in clusters.values()})
        return out
