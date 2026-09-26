"""Posture engine (VANTAGE): which controls and detections *should* have covered what happened.

VANTAGE's catalog joins ATT&CK techniques, CIS v8 safeguards (official
mapping) and SigmaHQ detections with their log-source requirements. For every
technique the investigation observed, THROUGHLINE asks VANTAGE:

* which CIS safeguards claim to mitigate it  -> ``Control MITIGATES Technique``
* which catalogued detections target it      -> ``Detection SHOULD_DETECT Technique``
* did any of those actually fire here?        -> technique attribute ``posture``:
  ``detected`` (a detection for it alerted), ``missed`` (detections exist and
  their log source was present, none fired), ``blind`` (no detection needs a
  log source we collect), ``paper-only`` (a control claims it, nothing detects it).

That turns "we have CIS control X" into a checkable statement per incident.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require

SOURCE = "vantage"


def build_catalog(attack_path: str | Path, sigma_rules: str | Path, cis_xlsx: str | Path | None = None):
    """A VANTAGE catalog from ATT&CK STIX + SigmaHQ rules (+ the CIS mapping when available)."""
    require("VANTAGE")
    from vantage.catalog import catalog_from_dict
    from vantage.ingest.attack import load_attack
    from vantage.ingest.build import build_catalog as vbuild
    from vantage.ingest.sigma import load_rules

    attack = load_attack(attack_path)
    safeguards = {}
    if cis_xlsx and Path(cis_xlsx).exists():
        try:
            from vantage.ingest.cis import load_cis
            safeguards = load_cis(cis_xlsx)
        except ImportError:  # openpyxl missing: posture without CIS controls
            safeguards = {}
    return catalog_from_dict(vbuild(attack, safeguards, load_rules(sigma_rules)))


class VantagePostureEngine:
    name = "posture:vantage"
    project = "VANTAGE"
    reads = ("EXHIBITS", "DETECTS", "ALERTED_ON")
    writes = ("MITIGATES", "SHOULD_DETECT")

    def __init__(self, catalog, ingested: set[str] | None = None, max_detections: int = 5):
        self.catalog = catalog
        # log sources present in the investigated telemetry (VANTAGE ids, e.g. "windows/sysmon")
        self.ingested = ingested
        self.max_detections = max_detections
        self.report: dict[str, dict] = {}
        self.stats: Counter = Counter()

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        cat = self.catalog
        fired_rules = {n.split(":", 1)[1] for n in kg.g if n.startswith("Detection:")
                       and any(k == "ALERTED_ON" for _, _, k in kg.g.out_edges(n, keys=True))}
        observed = sorted({o for _, o, k in kg.g.edges(keys=True) if k == "EXHIBITS" and o.startswith("Technique:")})
        ingested = self.ingested if self.ingested is not None else set(context.get("log_sources", ()))
        out: list[Claim] = []
        ts = "1970-01-01T00:00:00Z"
        for tkey in observed:
            tid = tkey.split(":", 1)[1]
            base = tid.split(".")[0]
            dets = [d for d in cat.detections.values() if tid in d.techniques or base in d.techniques]
            controls = [c for c in cat.controls.values() if tid in c.mitigates or base in c.mitigates]
            fired = [d for d in dets if d.id in fired_rules]
            live = [d for d in dets if not ingested or d.requires <= ingested]
            if fired:
                status = "detected"
            elif live:
                status = "missed"
            elif controls:
                status = "paper-only"
            else:
                status = "blind"
            self.stats[status] += 1
            for c in controls:
                out.append(kg.add_claim("Control", c.id, "MITIGATES", "Technique", tid, source=SOURCE,
                                        method="stated", reliability="B", timestamp=ts))
                kg.set_attrs(f"Control:{c.id}", {"title": c.title, "framework": c.framework})
            for d in (fired + [x for x in live if x not in fired])[: self.max_detections]:
                out.append(kg.add_claim("Detection", d.id, "SHOULD_DETECT", "Technique", tid, source=SOURCE,
                                        method="stated", reliability="B", timestamp=ts))
                kg.set_attrs(f"Detection:{d.id}", {"title": d.title, "level": d.level})
            self.report[tid] = {"status": status, "detections": len(dets), "live": len(live), "fired": len(fired),
                                "controls": sorted(c.id for c in controls)}
            kg.set_attrs(tkey, {"posture": status, "posture_detections": len(dets), "posture_fired": len(fired),
                                "posture_controls": ",".join(sorted(c.id for c in controls))[:1000]})
        context["posture"] = self.report
        return out
