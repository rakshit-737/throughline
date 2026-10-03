"""Provenance engines: REVENANT (causal stories) and ROOTLINE (IOC-seeded reconstruction).

REVENANT reads the same raw Windows records, builds its own provenance graph
(process lineage, cross-artefact fusion, causal rules, anti-forensics scan)
and scores every event with ATT&CK heuristics. Its conclusions come back as
claims from an independent source (``revenant``):

* ``<process> EXHIBITS Technique`` for each heuristic hit, with the
  heuristic's weight as the engine-reported score, and
* ``<process> PART_OF Incident:rev-<story>`` for the members of each
  suspicious causal story, scored by REVENANT's story confidence.

Process identity is mapped from REVENANT's ``process:<pid>:<image>`` refs to
THROUGHLINE's ``host/pid/image`` keys, so both engines talk about the same nodes.
"""
from __future__ import annotations

from collections import Counter

from ..connectors.windows import basename, proc_id
from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require

SOURCE = "revenant"
GRADE_RELIABILITY = {"high": "B", "medium": "C", "low": "D"}


def _proc_key(host: str, ref: str, guid: str = "") -> str | None:
    from revenant.entities import split_process_ref

    parts = split_process_ref(ref)
    if not parts:
        return None
    pid, image = parts
    return "Process:" + proc_id(host, pid or None, image, guid or None)


def event_process(ev) -> str | None:
    """THROUGHLINE key of the process a REVENANT event is about."""
    a = ev.attributes
    host = a.get("host", "") or "unknown-host"
    if ev.event_type.value == "process_start":
        return _proc_key(host, ev.object, a.get("object_guid", ""))
    return _proc_key(host, ev.actor, a.get("actor_guid", ""))


class RevenantProvenanceEngine:
    """REVENANT causal stories and ATT&CK heuristics over the raw Windows events."""
    name = "provenance:revenant"
    project = "REVENANT"
    reads = ("events",)
    writes = ("EXHIBITS", "PART_OF")

    def __init__(self, min_story_suspicion: float = 0.5, max_stories: int = 50):
        self.min_story_suspicion = min_story_suspicion
        self.max_stories = max_stories
        self.stats: Counter = Counter()
        self.analysis = None

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Analyse the run's records with REVENANT; write technique tags and story membership."""
        require("REVENANT")
        from revenant.attack import HEURISTICS
        from revenant.parsers.otrf import events_from_rows
        from revenant.pipeline import analyze_events

        rows = [r[1] for r in context.get("records", []) if r[0] == "windows"]
        if not rows:
            return []
        events = events_from_rows([dict(r) for r in rows])
        an = analyze_events(events, chains=False)
        self.analysis = an
        weight = {}
        for h in HEURISTICS:
            weight[h.technique] = max(weight.get(h.technique, 0.0), h.weight)
        by_id = {e.event_id: e for e in an.events}
        out: list[Claim] = []
        for eid, tag in an.tags.items():
            if not tag.techniques:
                continue
            ev = by_id.get(eid)
            subj = event_process(ev) if ev else None
            if not subj:
                continue
            ts = ev.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            for tech, _tactic, hname in tag.techniques:
                self.stats["technique_tags"] += 1
                out.append(kg.tag_technique(subj, tech, f"revenant heuristic: {hname}", source=SOURCE, ts=ts,
                                            reliability="C", score=weight.get(tech, 0.5)))
        for story in an.stories[: self.max_stories]:
            if story.suspicion < self.min_story_suspicion:
                continue
            self.stats["stories"] += 1
            inc = f"rev-{story.story_id.removeprefix('story-')}"
            members = {p for i in story.event_ids if (e := by_id.get(i)) and (p := event_process(e))}
            ts = by_id[story.event_ids[0]].timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if story.event_ids \
                and story.event_ids[0] in by_id else "1970-01-01T00:00:00Z"
            for p in sorted(members):
                ptype, pid = p.split(":", 1)
                out.append(kg.add_claim(ptype, pid, "PART_OF", "Incident", inc, source=SOURCE, method="inferred",
                                        reliability=GRADE_RELIABILITY.get(story.grade.value.lower(), "C"),
                                        timestamp=ts, score=story.confidence_score))
            kg.set_attrs(f"Incident:{inc}", {"engine": "REVENANT", "suspicion": story.suspicion,
                                             "grade": story.grade.value, "techniques": ",".join(story.techniques),
                                             "events": len(story.event_ids)})
        return out


class RootlineProvenanceEngine:
    """ROOTLINE's alert-pivoted reconstruction, seeded from THROUGHLINE's incidents.

    ROOTLINE backtracks from a pivot to its root cause(s) and forward to the impact.
    THROUGHLINE pivots it on the strongest member of each correlated incident and
    records every process of the reconstruction as ``PART_OF`` the incident, from an
    independent source (``rootline``): agreement with the lineage-based correlation
    raises membership confidence, and processes only ROOTLINE reaches (e.g. through a
    dropped file that was later executed) enlarge the incident. Sysmon records only.
    """

    name = "provenance:rootline"
    project = "ROOTLINE"
    reads = ("events", "PART_OF")
    writes = ("PART_OF",)

    def __init__(self, max_incidents: int = 25, max_members: int = 200):
        self.max_incidents = max_incidents
        self.max_members = max_members
        self.stats: Counter = Counter()

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Reconstruct each top incident from its pivot and record ROOTLINE's members as claims."""
        require("ROOTLINE")
        from rootline.loaders.sysmon import to_records
        from rootline.models import Alert, NodeType, Severity
        from rootline.pipeline import build_graph
        from rootline.reconstruct import reconstruct

        from ..connectors.windows import SYSMON, channel, short_host

        recs: list[dict] = []
        for r in context.get("records", []):
            raw = r[1]
            if r[0] != "windows" or channel(raw) != SYSMON:
                continue
            ev = dict(raw)
            try:
                ev["EventID"] = int(ev.get("EventID"))
            except (TypeError, ValueError):
                continue
            recs.extend(to_records(ev, host=short_host(raw)))
        if not recs:
            return []
        recs.sort(key=lambda x: x["ts"])
        g, _ = build_graph(recs)
        by_key: dict[str, list[str]] = {}
        for nid, n in g.nodes.items():
            if n.type is NodeType.PROCESS:
                k = f"Process:{n.attrs.get('host')}/{n.attrs.get('pid')}/{basename(n.attrs.get('comm') or n.attrs.get('exe'))}"
                by_key.setdefault(k, []).append(nid)
        out: list[Claim] = []
        incidents = sorted((n for n in kg.g if n.startswith("Incident:")
                            and kg.g.nodes[n]["attrs"].get("engine") == "THROUGHLINE"),
                           key=lambda n: -float(kg.g.nodes[n]["attrs"].get("score", 0)))
        for inc in incidents[: self.max_incidents]:
            pivot = kg.g.nodes[inc]["attrs"].get("pivot")
            vids = by_key.get(pivot or "", [])
            if not vids:
                self.stats["pivot_not_found"] += 1
                continue
            vid = vids[-1]
            ts = max((e.ts for e in g.in_edges.get(vid, []) + g.out_edges.get(vid, [])),
                     default=g.nodes[vid].first_ts)
            rec = reconstruct(g, Alert("THROUGHLINE", vid, ts, Severity.HIGH, "incident pivot"))
            self.stats["reconstructions"] += 1
            procs = [x for x in rec.nodes if g.nodes[x].type is NodeType.PROCESS][: self.max_members]
            roots = [x for x in rec.root_causes if x in g.nodes]
            inc_id = inc.split(":", 1)[1]
            for x in procs:
                a = g.nodes[x].attrs
                pid = f"{a.get('host')}/{a.get('pid')}/{basename(a.get('comm') or a.get('exe'))}"
                out.append(kg.add_claim("Process", pid, "PART_OF", "Incident", inc_id, source="rootline",
                                        method="inferred", reliability="C",
                                        timestamp=kg.g.nodes[inc]["first_seen"]))
            kg.set_attrs(inc, {"rootline_root_causes": ", ".join(g.nodes[r].label for r in roots)[:1000],
                               "rootline_nodes": len(rec.nodes)})
        return out
