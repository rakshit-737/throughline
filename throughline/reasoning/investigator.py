"""Bounded, read-only investigator: an agent over a *tool set of graph queries*.

Spec section 4: "retrieve the neighbourhood -> generate hypotheses -> decide
which graph query would confirm/deny -> execute read-only queries -> update
confidence -> stop at threshold -> emit an investigation with its full
reasoning trace." This implementation is deterministic (no LLM): hypotheses
come from the graph, the next tool is the one addressing the *most uncertain*
open hypothesis (closest to 0.5), and every finding cites claim ids. The trace
is replayable: same graph in, same steps out.

What it is **not** allowed to do (the integrity boundary): write to the graph,
assert a link without a path, or state an attribution the ACH engines and the
confidence engine did not produce.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..graph import KnowledgeGraph
from ..pipeline import resolve


@dataclass
class Hypothesis:
    """A competing explanation the investigator keeps open, with its belief and citations."""
    id: str
    statement: str
    belief: float
    cites: list[str] = field(default_factory=list)
    open: bool = True


@dataclass
class Step:
    """One investigator step: the read-only tool used, its finding and the claims it cites."""
    n: int
    tool: str
    target: str
    finding: str
    cites: list[str]
    beliefs: dict[str, float]


def _edge_claims(kg: KnowledgeGraph, s: str, o: str, k: str) -> list[str]:
    return list(kg.g.edges[s, o, k].get("claims", []))


class Investigator:
    """Bounded, deterministic, read-only investigation over graph queries.

    It runs a fixed sequence of tools (incident, techniques, root cause, corroboration,
    attribution, posture, blast radius); every finding cites claim ids, and nothing is
    written to the graph.
    """
    TOOLS = ("incident", "techniques", "root_cause", "corroboration", "attribution", "posture", "blast_radius")

    def __init__(self, kg: KnowledgeGraph, budget: int = 10, stop_at: float = 0.9):
        self.kg = kg
        self.budget = budget
        self.stop_at = stop_at

    # ------------------------------------------------------------------ tools (read-only)
    def _incident_of(self, key: str) -> str | None:
        if key.startswith("Incident:"):
            return key
        best, conf = None, -1.0
        for _, o, k, d in self.kg.g.out_edges(key, keys=True, data=True):
            if k == "PART_OF" and d.get("confidence", 0) > conf and \
                    self.kg.g.nodes[o]["attrs"].get("engine") == "THROUGHLINE":
                best, conf = o, d.get("confidence", 0)
        if best is None:  # alert -> the process it fired on
            for _, o, k in self.kg.g.out_edges(key, keys=True):
                if k == "ALERTED_ON":
                    return self._incident_of(o)
        return best

    def t_incident(self, inc: str) -> tuple[str, list[str], dict]:
        """Incident membership: how many processes, from which engines, under which story root."""
        members = [(m, d.get("confidence", 0.0)) for m, _, k, d in self.kg.g.in_edges(inc, keys=True, data=True)
                   if k == "PART_OF"]
        members.sort(key=lambda x: -x[1])
        a = self.kg.g.nodes[inc]["attrs"]
        cites = [c for m, _ in members[:5] for c in _edge_claims(self.kg, m, inc, "PART_OF")[:1]]
        lineage = sum(1 for m, _ in members
                      if any(self.kg.claims[c].source == "correlation" for c in _edge_claims(self.kg, m, inc, "PART_OF")))
        txt = (f"{len(members)} processes ({lineage} by process lineage, {len(members) - lineage} added by other "
               f"engines) grouped under story root {a.get('root', '?')}; "
               f"{a.get('alerts', 0)} alerts; strongest member {members[0][0] if members else '-'}")
        return txt, cites, {"members": [m for m, _ in members]}

    def t_techniques(self, inc: str) -> tuple[str, list[str], dict]:
        """The incident's strongest fused technique claims."""
        techs = sorted(((o, d.get("confidence", 0.0), d.get("claims", []))
                        for _, o, k, d in self.kg.g.out_edges(inc, keys=True, data=True) if k == "EXHIBITS"),
                       key=lambda x: -x[1])
        if not techs:
            return "no technique claims", [], {"top": []}
        top = [f"{o.split(':', 1)[1]} {self.kg.g.nodes[o].get('name', '')} ({c:.2f})" for o, c, _ in techs[:5]]
        return "; ".join(top), [cl[0] for _, _, cl in techs[:5] if cl], {"top": techs}

    def t_root_cause(self, key: str) -> tuple[str, list[str], dict]:
        """The causal chain back to the root cause, with the command lines along it."""
        chain = self.kg.root_cause_chain(key)
        cites = []
        for a, b in zip(chain, chain[1:]):
            for k in self.kg.g[a][b]:
                cites += _edge_claims(self.kg, a, b, k)[:1]
        imgs = [self.kg.g.nodes[n].get("attrs", {}).get("cmdline") or n for n in chain]
        return " -> ".join(str(x)[:80] for x in imgs), cites, {"chain": chain}

    def t_corroboration(self, inc: str) -> tuple[str, list[str], dict]:
        """Which independent engines back the incident's strongest technique (read from the
        member claims the roll-up was fused from)."""
        techs = [(o, d) for _, o, k, d in self.kg.g.out_edges(inc, keys=True, data=True) if k == "EXHIBITS"]
        if not techs:
            return "nothing to corroborate", [], {"sources": []}
        o, _ = max(techs, key=lambda x: x[1].get("confidence", 0))
        sources: dict[str, str] = {}
        for m, _, k in self.kg.g.in_edges(inc, keys=True):
            if k != "PART_OF" or not self.kg.g.has_edge(m, o, "EXHIBITS"):
                continue
            for cid in self.kg.g.edges[m, o, "EXHIBITS"].get("claims", []):
                c = self.kg.claims[cid]
                if c.source not in sources or c.base_confidence > self.kg.claims[sources[c.source]].base_confidence:
                    sources[c.source] = cid
        return (f"{o.split(':', 1)[1]} is supported by {len(sources)} independent engine(s): "
                f"{', '.join(sorted(sources)) or 'none'}"), sorted(sources.values()), {"sources": sorted(sources)}

    def t_attribution(self, inc: str) -> tuple[str, list[str], dict]:
        """Competing ``ATTRIBUTED_TO`` hypotheses (``UNKNOWN`` included) and their confidence."""
        rows = sorted(((o, d.get("confidence", 0.0), d.get("claims", []))
                       for _, o, k, d in self.kg.g.out_edges(inc, keys=True, data=True) if k == "ATTRIBUTED_TO"),
                      key=lambda x: -x[1])
        if not rows:
            return "no attribution claims (too few techniques, or intel engines not installed)", [], {"rows": []}
        parts = []
        for o, c, cl in rows:
            srcs = sorted({self.kg.claims[x].source for x in cl})
            parts.append(f"{o.split(':', 1)[1]} {c:.2f} [{'+'.join(srcs)}]")
        return "; ".join(parts), [cl[0] for _, _, cl in rows if cl], {"rows": rows}

    def t_posture(self, inc: str) -> tuple[str, list[str], dict]:
        """What should have detected the observed techniques and what was missed."""
        out, cites = [], []
        for _, o, k in self.kg.g.out_edges(inc, keys=True):
            if k != "EXHIBITS":
                continue
            st = self.kg.g.nodes[o].get("attrs", {}).get("posture")
            if st in ("missed", "blind", "paper-only"):
                out.append(f"{o.split(':', 1)[1]}={st}")
        return ("coverage gaps: " + ", ".join(out)) if out else "every observed technique had a detection fire", \
            cites, {"gaps": out}

    def t_blast_radius(self, key: str) -> tuple[str, list[str], dict]:
        """Everything reachable from the entity through causal edges."""
        br = self.kg.blast_radius(key)
        kinds: dict[str, int] = {}
        for n in br:
            kinds[n.split(":", 1)[0]] = kinds.get(n.split(":", 1)[0], 0) + 1
        return (f"{len(br)} downstream entities: " + ", ".join(f"{v} {k}" for k, v in sorted(kinds.items()))), \
            [], {"nodes": sorted(br)[:200]}

    # ------------------------------------------------------------------ loop
    def investigate(self, query: str) -> dict:
        """Run every tool on an entity or incident and return the cited report and the trace.

        Args:
            query: a node key, an id or a key suffix.

        Returns:
            ``{"target", "incident", "steps", "hypotheses", "report"}``; every step cites claim ids.
        """
        key = resolve(self.kg, query)
        inc = self._incident_of(key)
        steps: list[Step] = []
        hyps: dict[str, Hypothesis] = {}

        def record(tool: str, tgt: str, res):
            txt, cites, _ = res
            steps.append(Step(len(steps) + 1, tool, tgt, txt, cites, {h.id: round(h.belief, 3)
                                                                      for h in hyps.values()}))

        if inc is None:
            res = self.t_root_cause(key)
            record("root_cause", key, res)
            return self._report(query, key, None, hyps, steps)
        score = float(self.kg.g.nodes[inc]["attrs"].get("score", 0.0))
        hyps["malicious"] = Hypothesis("malicious", f"{inc} is attacker activity", score)
        res = self.t_incident(inc)
        record("incident", inc, res)
        pivot = self.kg.g.nodes[inc]["attrs"].get("pivot") or key
        res = self.t_techniques(inc)
        hyps["malicious"].cites = res[1]
        record("techniques", inc, res)
        hyps["root_cause"] = Hypothesis("root_cause", f"root cause of {pivot} is identifiable", 0.5)
        hyps["attribution"] = Hypothesis("attribution", "a named actor is responsible", 0.5)
        hyps["coverage"] = Hypothesis("coverage", "existing detections covered every step", 0.5)
        done: set[str] = {"incident", "techniques"}
        plan = {"malicious": "corroboration", "root_cause": "root_cause", "attribution": "attribution",
                "coverage": "posture"}
        while len(steps) < self.budget:
            open_h = [h for h in hyps.values() if h.open and plan[h.id] not in done]
            if not open_h:
                break
            h = min(open_h, key=lambda x: (abs(x.belief - 0.5), x.id))  # most uncertain first
            tool = plan[h.id]
            tgt = pivot if tool == "root_cause" else inc
            res = getattr(self, f"t_{tool}")(tgt)
            done.add(tool)
            _, cites, data = res
            if tool == "corroboration":
                n = len(data["sources"])
                h.belief = min(0.99, h.belief + 0.05 * max(0, n - 1))
            elif tool == "root_cause":
                h.belief = 0.9 if len(data["chain"]) > 1 else 0.2
            elif tool == "attribution":
                h.belief = data["rows"][0][1] if data["rows"] else 0.0
                h.statement = (f"{data['rows'][0][0]} is responsible" if data["rows"]
                               else "no actor can be named")
            elif tool == "posture":
                h.belief = 0.1 if data["gaps"] else 0.9
            h.cites = cites
            h.open = False
            record(tool, tgt, res)
            if all(not x.open or x.belief >= self.stop_at for x in hyps.values()):
                break
        if len(steps) < self.budget:
            record("blast_radius", pivot, self.t_blast_radius(self.kg.root_cause_chain(pivot)[0]))
        return self._report(query, key, inc, hyps, steps)

    def _report(self, query, key, inc, hyps, steps) -> dict:
        lines = [f"Investigation of {query} ({key})."]
        for s in steps:
            cite = f" [{', '.join(s.cites[:3])}]" if s.cites else ""
            lines.append(f"{s.n}. {s.tool}: {s.finding}{cite}")
        return {"query": query, "entity": key, "incident": inc,
                "hypotheses": [asdict(h) for h in hyps.values()],
                "trace": [asdict(s) for s in steps], "report": "\n".join(lines),
                "note": "Read-only; every finding cites the claims it rests on."}
