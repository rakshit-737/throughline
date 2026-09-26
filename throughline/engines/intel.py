"""Intel engines: DRAGNET and OCCAM attribute incidents to ATT&CK groups.

Both read an incident's techniques (``Incident EXHIBITS Technique`` roll-ups
written by correlation) and the ATT&CK software ids of the Sigma rules that
alerted on its members, and each writes **one** claim:

    Incident ATTRIBUTED_TO Actor:<group name>   (source dragnet / occam)

with the engine's own probability as the score and its confidence grade as the
source-reliability grade. An engine that concludes *unknown* or *false flag*
writes ``ATTRIBUTED_TO Actor:UNKNOWN`` instead, which competes with named
actors: ``ATTRIBUTED_TO`` is an exclusive predicate, so the graph's confidence
engine discounts every hypothesis by its strongest competitor (ADR-0003).
Agreement between the two independent engines raises confidence (noisy-OR);
disagreement lowers both. That fusion is the point of running two.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require

UNKNOWN_ACTOR = "UNKNOWN"


@dataclass
class Verdict:
    engine: str
    leading: str | None          # ATT&CK group name, None = unknown / false flag / insufficient
    probability: float           # engine's stated probability that `leading` is right
    grade: str                   # engine's own confidence grade
    ranked: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    """Engine-neutral attribution evidence."""
    techniques: list[str]
    software: list[str] = field(default_factory=list)       # ATT&CK S-ids
    planted: list[str] = field(default_factory=list)         # group names forgeable markers point at


def incident_evidence(kg: KnowledgeGraph, incident: str, min_conf: float = 0.0) -> Evidence:
    techs = sorted({o.split(":", 1)[1] for _, o, k, d in kg.g.out_edges(incident, keys=True, data=True)
                    if k == "EXHIBITS" and d.get("confidence", 0.0) >= min_conf})
    software: set[str] = set()
    members = [m for m, _, k in kg.g.in_edges(incident, keys=True) if k == "PART_OF"]
    for m in members:
        for det, _, k in kg.g.in_edges(m, keys=True):
            if k == "ALERTED_ON":
                software.update(x for x in str(kg.g.nodes[det]["attrs"].get("software", "")).split(",") if x)
    return Evidence(techs, sorted(software))


GRADE_RELIABILITY = {"HIGH": "B", "MEDIUM": "C", "LOW": "D", "INSUFFICIENT": "E",
                     "high": "B", "moderate": "C", "low": "D"}


class _IntelBase:
    reads = ("EXHIBITS", "PART_OF", "ALERTED_ON")
    writes = ("ATTRIBUTED_TO",)
    source = ""

    def __init__(self, min_techniques: int = 3, max_incidents: int = 10, min_technique_conf: float = 0.0):
        self.min_techniques = min_techniques
        self.max_incidents = max_incidents
        self.min_technique_conf = min_technique_conf
        self.verdicts: dict[str, Verdict] = {}

    def attribute(self, ev: Evidence) -> Verdict:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        incidents = [i["incident"] for i in context.get("incidents", [])] or sorted(
            n for n in kg.g if n.startswith("Incident:"))
        out: list[Claim] = []
        for inc in incidents[: self.max_incidents]:
            ev = incident_evidence(kg, inc, self.min_technique_conf)
            if len(ev.techniques) < self.min_techniques:
                continue
            v = self.attribute(ev)
            self.verdicts[inc] = v
            out.append(record_verdict(kg, inc, v, self.source))
        return out


def record_verdict(kg: KnowledgeGraph, incident: str, v: Verdict, source: str) -> Claim:
    actor = v.leading or UNKNOWN_ACTOR
    itype, iid = incident.split(":", 1)
    c = kg.add_claim(itype, iid, "ATTRIBUTED_TO", "Actor", actor, source=source, method="inferred",
                     reliability=GRADE_RELIABILITY.get(v.grade, "D"), timestamp=kg.g.nodes[incident]["first_seen"],
                     score=v.probability)
    kg.set_attrs(f"Actor:{actor}", {"kind": "unknown" if not v.leading else "group"})
    kg.set_attrs(incident, {f"{source}_verdict": f"{actor} ({v.grade}, p={v.probability:.2f})",
                            f"{source}_flags": "; ".join(v.flags)[:1000]})
    return c


class DragnetIntelEngine(_IntelBase):
    name = "intel:dragnet"
    project = "DRAGNET"
    source = "dragnet"

    def __init__(self, attack_path: str | Path, misp_path: str | Path | None = None, **kw):
        super().__init__(**kw)
        require("DRAGNET")
        from dragnet.kg_build import build_from_attack
        from dragnet.sources.attack import load_attack

        self.attack = load_attack(attack_path)
        misp = None
        if misp_path and Path(misp_path).exists():
            from dragnet.sources.misp import load_threat_actors
            misp = load_threat_actors(misp_path)
        self.kg = build_from_attack(self.attack, misp=misp)
        self._sw = {o.attack_id: o for o in self.attack.software.values()}

    def signals(self, ev: Evidence):
        from dragnet.models import Signal, SignalKind

        sigs = [Signal(SignalKind.TTP, t, "incident") for t in ev.techniques]
        for sid in ev.software:
            sw = self._sw.get(sid)
            if sw:
                sigs.append(Signal(SignalKind.FAMILY if sw.type == "malware" else SignalKind.TOOL, sw.name,
                                   "incident"))
        return sigs

    def attribute(self, ev: Evidence, extra_signals: list | None = None) -> Verdict:
        from dragnet.ach import FALSE_FLAG, UNKNOWN, assess

        a = assess("throughline", self.signals(ev) + list(extra_signals or []), self.kg)
        ranked = [h.hypothesis for h in a.hypotheses if h.hypothesis not in (FALSE_FLAG, UNKNOWN) and h.score > 0]
        top = next((h for h in a.hypotheses if h.hypothesis == (a.leading or "")), None)
        if a.leading and top is not None:
            return Verdict("dragnet", a.leading, float(top.score), a.confidence.value, ranked,
                           list(a.false_flag_indicators))
        best = ranked[0] if ranked else None
        p_unknown = next((h.score for h in a.hypotheses if h.hypothesis in (UNKNOWN, FALSE_FLAG)), 0.5)
        return Verdict("dragnet", None, float(p_unknown), a.confidence.value, ranked,
                       list(a.false_flag_indicators) + ([f"withheld; best named {best}"] if best else []))


class OccamIntelEngine(_IntelBase):
    name = "intel:occam"
    project = "OCCAM"
    source = "occam"

    def __init__(self, attack_path: str | Path, shortlist: int = 25, **kw):
        super().__init__(**kw)
        require("OCCAM")
        from occam.attribution import ACHAttributor
        from occam.knowledge import AttackData

        self.data = AttackData.load(attack_path)
        self.kb = self.data.to_kb()
        self.profiles = self.data.actor_profiles()
        self.names = {g: e.name for g, e in self.data.groups.items()}
        self.ids = {e.name: g for g, e in self.data.groups.items()}
        self.attributor = ACHAttributor(self.profiles, self.kb, shortlist=shortlist)

    def evidence(self, ev: Evidence):
        from occam.attribution import evidence_from_items, planted_markers

        items = [x for x in ev.techniques + ev.software if self.kb.get(x)]
        out = evidence_from_items(items, self.kb)
        for name in ev.planted:
            gid = self.ids.get(name)
            if gid:
                out += planted_markers(gid, n=1, prefix=f"FF{len(out)}-")
        return out

    def attribute(self, ev: Evidence) -> Verdict:
        r = self.attributor.attribute(self.evidence(ev))
        ranked = [self.names.get(a, a) for a in r.ranked_actors]
        flags = [f"false flag suspected: framing {self.names.get(r.flagged, r.flagged)}"] if r.flagged else []
        if r.leading_kind == "actor" and r.leading:
            return Verdict("occam", self.names.get(r.leading, r.leading), float(r.probability), r.confidence,
                           ranked, flags)
        return Verdict("occam", None, float(r.probability), r.confidence, ranked, flags)
