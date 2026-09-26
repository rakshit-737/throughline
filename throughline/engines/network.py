"""Network detection engine (FEINT): an adversarially-hardened flow classifier.

FEINT scores network flows (CIC-IDS2017 / UNSW-NB15 feature schema) with an
ensemble trained to survive constrained evasion. For each flow scored above
the threshold THROUGHLINE records

    Host:<src ip> CONNECTED_TO IPAddress:<dst ip>:<port>   (observed, from the flow)
    Host:<src ip> EXHIBITS Technique:<mapped>              (predicted, score = P(attack))

The class -> technique map is coarse on purpose (CIC labels are traffic
classes, not techniques) and documented in :data:`LABEL_TECHNIQUE`.
"""
from __future__ import annotations

from ..contracts import Claim
from ..graph import KnowledgeGraph
from . import require

LABEL_TECHNIQUE = {
    "portscan": "T1046", "ddos": "T1498", "dos": "T1499", "bot": "T1071", "ftp-patator": "T1110",
    "ssh-patator": "T1110", "brute force": "T1110", "web attack": "T1190", "infiltration": "T1105",
    "heartbleed": "T1190", "exploits": "T1190", "reconnaissance": "T1595", "backdoor": "T1071",
    "shellcode": "T1203", "worms": "T1210", "fuzzers": "T1595", "generic": "T1071", "analysis": "T1595",
    "attack": "T1071",
}


def flow_claims(kg: KnowledgeGraph, flows: list[dict], probs, threshold: float = 0.5,
                source: str = "feint") -> list[Claim]:
    """``flows``: dicts with src_ip, dst_ip, dst_port, ts and optional label; ``probs``: P(attack)."""
    out: list[Claim] = []
    for f, p in zip(flows, probs):
        p = float(p)
        if p < threshold:
            continue
        ts = str(f.get("ts", "1970-01-01T00:00:00Z"))
        src, dst = str(f["src_ip"]), f"{f['dst_ip']}:{f.get('dst_port', '?')}"
        out.append(kg.add_claim("Host", src, "CONNECTED_TO", "IPAddress", dst, source=source, method="observed",
                                reliability="B", timestamp=ts))
        label = str(f.get("label", "attack")).lower()
        tech = next((t for k, t in LABEL_TECHNIQUE.items() if k in label), "T1071")
        out.append(kg.tag_technique(f"Host:{src}", tech, f"feint flow score {p:.2f} ({label})", source=source,
                                    ts=ts, method="predicted", reliability="C", score=p))
    return out


class FeintNetworkEngine:
    name = "detection:feint"
    project = "FEINT"
    reads = ("flows",)
    writes = ("CONNECTED_TO", "EXHIBITS")

    def __init__(self, detector=None, threshold: float = 0.5):
        self.detector = detector
        self.threshold = threshold

    def run(self, kg: KnowledgeGraph, context: dict) -> list[Claim]:
        require("FEINT")
        flows = context.get("flows")
        if not flows:
            return []
        X, meta = flows["X"], flows["meta"]
        det = self.detector or context.get("feint_detector")
        if det is None:
            return []
        return flow_claims(kg, meta, det.predict_proba(X), self.threshold)
