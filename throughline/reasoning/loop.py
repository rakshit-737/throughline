"""The feedback loop: undetected step -> drafted detection -> tested -> coverage delta.

Spec section 6 ("Learn -> Improve -> Validate"). For a replayed, labelled
emulation (an OTRF capture) whose technique no deployed detection caught:

1. **Learn** - mine the capture's process tree for the *novel* behaviour:
   command lines / PowerShell script blocks that do not occur in unrelated
   captures (those are background noise every lab host produces).
2. **Improve** - hand them to ANVIL's drafter (deterministic heuristic backend;
   the LLM backend is optional), which keeps behavioural tokens and drops IOCs.
3. **Validate** - a draft is *accepted* only if it compiles, fires on the capture
   it came from, and fires on **zero** events of every unrelated capture (the
   false-positive gate). Accepted drafts stay ``status: experimental`` and
   ``reviewed: false``: a human still approves deployment (ANVIL lint A114).

Nothing self-updates silently; every improvement is a measured artefact.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ..connectors.windows import SECURITY, SYSMON, channel, event_id
from ..engines import require

PS_CHANNELS = ("microsoft-windows-powershell/operational", "windows powershell")
_WS = re.compile(r"\s+")
_NUM = re.compile(r"\b\d{3,}\b|0x[0-9a-f]+|\{?[0-9a-f]{8}-[0-9a-f-]{27,}\}?", re.I)


def behaviour_text(rec: dict[str, Any]) -> str | None:
    """The command line / script block of a process-creation or PowerShell record."""
    ch, eid = channel(rec), event_id(rec)
    if (ch == SYSMON and eid == 1) or (ch == SECURITY and eid == 4688):
        return str(rec.get("CommandLine") or "") or None
    if ch in PS_CHANNELS and eid == 4104:
        return str(rec.get("ScriptBlockText") or "")[:2000] or None
    return None


def norm_cmd(s: str) -> str:
    """Normalise away pids, GUIDs and whitespace so the same behaviour matches across captures."""
    return _NUM.sub("#", _WS.sub(" ", s.strip().lower()))


@dataclass
class CaptureView:
    """The slice of a capture the loop needs: labelled techniques + behaviour records."""
    id: str
    techniques: list[str]
    behaviour: list[dict[str, Any]]       # raw process-creation / 4104 records

    @property
    def commands(self) -> set[str]:
        """Normalised command lines and script blocks of the capture."""
        return {norm_cmd(t) for r in self.behaviour if (t := behaviour_text(r))}


def view(capture_id: str, techniques: list[str], records: Iterable[dict[str, Any]]) -> CaptureView:
    """Keep the behaviour records (process creations, script blocks) of one capture."""
    return CaptureView(capture_id, list(techniques), [r for r in records if behaviour_text(r)])


def related(a: list[str], b: list[str]) -> bool:
    """Whether two technique lists share a parent technique."""
    pa, pb = {t.split(".")[0] for t in a}, {t.split(".")[0] for t in b}
    return bool(pa & pb)


@dataclass
class LoopResult:
    """Outcome of closing one detection gap: drafts, accepted and rejected rules with their hits."""
    capture: str
    technique: str
    novel_commands: int
    drafted: int
    accepted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    generalises_to: list[str] = field(default_factory=list)   # other captures of the technique it fires on


def _library(drafts):
    require("ANVIL")
    from anvil.models import Rule
    from anvil.runner import Library

    rules = []
    for d in drafts:
        try:
            rules.append(Rule.from_dict(d.rule))
        except (TypeError, ValueError, KeyError):
            continue
    return Library.build(rules)


def _hits(lib, records) -> dict[str, int]:
    from anvil.telemetry import normalise

    out: dict[str, int] = {}
    for r in records:
        for rid in lib.match_event(normalise(dict(r))):
            out[rid] = out.get(rid, 0) + 1
    return out


def close_gap(target: CaptureView, others: list[CaptureView], backend: str = "heuristic",
              max_rules: int = 4, max_commands: int = 40) -> LoopResult:
    """Run learn -> improve -> validate for one undetected capture."""
    require("ANVIL")
    from anvil.draft import draft

    unrelated = [o for o in others if not related(o.techniques, target.techniques)]
    same = [o for o in others if related(o.techniques, target.techniques)]
    population: dict[str, int] = {}
    for o in unrelated:
        for c in o.commands:
            population[c] = population.get(c, 0) + 1
    novel, seen = [], set()
    for r in target.behaviour:
        t = behaviour_text(r)
        n = norm_cmd(t) if t else ""
        if t and n not in population and n not in seen:
            seen.add(n)
            novel.append(t)
    tech = target.techniques[0] if target.techniques else ""
    res = LoopResult(target.id, tech, len(novel), 0)
    if not novel:
        return res
    text = "\n".join([f"Emulated technique {' '.join(target.techniques)}"] + novel[:max_commands])
    drafts = draft(text, title=f"THROUGHLINE gap {target.id}", source=f"throughline:{target.id}", backend=backend)
    drafts = drafts[:max_rules]
    res.drafted = len(drafts)
    if not drafts:
        return res
    lib = _library(drafts)
    own = _hits(lib, target.behaviour)
    fp: dict[str, int] = {}
    for o in unrelated:
        for rid, n in _hits(lib, o.behaviour).items():
            fp[rid] = fp.get(rid, 0) + n
    for d in drafts:
        rid = str(d.rule.get("id"))
        row = {"id": rid, "title": d.rule.get("title"), "own_hits": own.get(rid, 0), "fp_hits": fp.get(rid, 0),
               "compiled": rid in lib.compiled, "rationale": d.rationale, "yaml": d.to_yaml()}
        if row["compiled"] and row["own_hits"] > 0 and row["fp_hits"] == 0:
            res.accepted.append(row)
        else:
            res.rejected.append(row)
    if res.accepted and same:
        acc = _library([d for d in drafts if str(d.rule.get("id")) in {a["id"] for a in res.accepted}])
        res.generalises_to = [o.id for o in same if _hits(acc, o.behaviour)]
    return res
