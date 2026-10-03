"""Detection engine: ANVIL's Sigma engine over the raw endpoint events.

Reads the raw Windows records kept in the run context (the event store), not
the graph: Sigma rules need every EventData field, the graph keeps only the
entities. Each rule hit becomes

* ``Detection:<rule id> ALERTED_ON <acting process>``   (the alert), and
* ``<process> EXHIBITS Technique:<tag>`` for each ATT&CK tag of the rule,
  corroborated by the alert claim, and ``Detection DETECTS Technique``.

Sigma ``level`` becomes the Admiralty source-reliability grade of the claim
(critical=A ... informational=E): a critical rule is a more reliable source
than an informational one. All Sigma rules count as ONE source ("anvil"), so
twenty overlapping rules cannot inflate confidence by noisy-OR (ADR-0003).
"""
from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from ..connectors.windows import acting_process, event_ts, short_host
from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require

LEVEL_RELIABILITY = {"critical": "A", "high": "B", "medium": "C", "low": "D", "informational": "E"}
SOURCE = "anvil"
_SOFTWARE_TAG = re.compile(r"^attack\.s\d{4}$")


def rule_software(rule) -> list[str]:
    """ATT&CK software ids (S0002 = Mimikatz, ...) a Sigma rule is tagged with."""
    return sorted({t.split(".", 1)[1].upper() for t in rule.tags if _SOFTWARE_TAG.match(t)})


def load_library(rule_dirs: list[str | Path], include_deprecated: bool = False):
    """Compile a routed ANVIL rule library from Sigma rule directories."""
    require("ANVIL")
    from anvil.runner import Library, load_rule_dir

    rules, _report = load_rule_dir([str(d) for d in rule_dirs])
    return Library.build(rules, include_deprecated=include_deprecated)


def sigma_dirs(sigma_root: str | Path, subset: str = "core") -> list[Path]:
    """SigmaHQ rule folders: ``core`` = rules/windows; ``all`` adds hunting + emerging threats."""
    root = Path(sigma_root)
    dirs = [root / "rules" / "windows"]
    if subset == "all":
        dirs += [root / "rules-threat-hunting" / "windows", root / "rules-emerging-threats"]
    return [d for d in dirs if d.exists()]


class AnvilDetectionEngine:
    """ANVIL's compiled Sigma library over the raw Windows events in the run context."""
    name = "detection:anvil"
    project = "ANVIL"
    reads = ("events",)
    writes = ("ALERTED_ON", "DETECTS", "EXHIBITS")

    def __init__(self, library, min_level: str = "informational"):
        self.library = library
        levels = list(LEVEL_RELIABILITY)
        self.min_rank = levels.index(min_level) if min_level in levels else len(levels) - 1
        self.stats: Counter = Counter()

    @classmethod
    def from_sigma(cls, sigma_root: str | Path, subset: str = "core", **kw) -> AnvilDetectionEngine:
        """Compile a SigmaHQ checkout (``core`` = rules/windows, ``all`` adds hunting rules)."""
        return cls(load_library(sigma_dirs(sigma_root, subset)), **kw)

    def _level_ok(self, level: str) -> bool:
        levels = list(LEVEL_RELIABILITY)
        return levels.index(level) <= self.min_rank if level in levels else True

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        """Match every Windows record; write alerts, technique claims and DETECTS edges."""
        require("ANVIL")
        from anvil.telemetry import normalise

        out: list[Claim] = []
        detects: set[tuple[str, str]] = set()
        keys: set[tuple[str, int]] = set()
        for rec in context.get("records", []):
            connector, raw = rec[0], rec[1]
            if connector != "windows":
                continue
            self.stats["events"] += 1
            try:
                keys.add((str(raw.get("Channel") or "").lower(), int(raw.get("EventID") or 0)))
            except (TypeError, ValueError):
                pass
            try:
                hits = self.library.match_event(normalise(dict(raw)))
            except (TypeError, ValueError, AttributeError):
                self.stats["engine_errors"] += 1
                continue
            if not hits:
                continue
            subj = acting_process(raw) or f"Host:{short_host(raw)}"
            stype, sid = subj.split(":", 1)
            ts = event_ts(raw)
            ref = rec[3] if len(rec) > 3 else None
            for rid in hits:
                rule = self.library.rules[rid]
                level = (rule.level or "medium").lower()
                if not self._level_ok(level):
                    continue
                rel = LEVEL_RELIABILITY.get(level, "C")
                self.stats["alerts"] += 1
                alert = kg.add_claim("Detection", rid, "ALERTED_ON", stype, sid, source=SOURCE,
                                     method="inferred", reliability=rel, timestamp=ts,
                                     evidence_ref=ref)
                kg.set_attrs(f"Detection:{rid}", {"title": rule.title, "level": level,
                                                   "status": rule.status, "engine": "ANVIL",
                                                   "software": ",".join(rule_software(rule))})
                out.append(alert)
                for t in rule.techniques:
                    out.append(kg.tag_technique(subj, t, f"sigma: {rule.title}", source=SOURCE, ts=ts,
                                                reliability=rel, corroboration=[alert.claim_id]))
                    if (rid, t) not in detects:
                        detects.add((rid, t))
                        out.append(kg.add_claim("Detection", rid, "DETECTS", "Technique", t, source=SOURCE,
                                                method="stated", reliability="B", timestamp=ts))
        context["log_sources"] = self.log_sources(keys)
        return out

    def log_sources(self, keys: set[tuple[str, int]]) -> set[str]:
        """Sigma log sources (VANTAGE ids, ``product/category/service``) the telemetry
        actually contains: a rule's source counts as collected if any (channel, event id)
        its route needs was observed."""
        out: set[str] = set()
        for rid, rt in self.library.routes.items():
            if not rt.routable:
                continue
            ok = any((c == "*" and keys) or any(k[0] == c and (not ids or k[1] in ids) for k in keys)
                     for c, ids in rt.channels)
            if ok:
                ls = self.library.rules[rid].logsource
                out.add("/".join(x.strip().lower() for x in (ls.product, ls.category, ls.service) if x))
        return out
