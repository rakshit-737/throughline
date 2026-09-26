"""Frozen contracts: canonical event schema, graph schema, claim model.

Everything else in THROUGHLINE is pluggable; these types are the only
inter-component API (see docs/adr/0001-frozen-contracts.md).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum

SCHEMA_VERSION = "0.2.0"  # additive over 0.1.0, see docs/adr/0004-schema-0.2.md


class Method(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"      # inferred-by-rule
    STATED = "stated"          # stated-in-report
    PREDICTED = "predicted"    # predicted-by-model


class Reliability(str, Enum):
    """Admiralty-style source reliability (CTI A-F)."""
    A = "A"  # completely reliable
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"  # cannot be judged


class Layer(str, Enum):
    CODE = "code"
    INFRA = "infra"
    IDENTITY = "identity"
    RUNTIME = "runtime"
    NETWORK = "network"
    THREAT = "threat"
    GOVERNANCE = "governance"


NODE_TYPES = frozenset({
    # code/build
    "Commit", "Author", "Dependency", "Build", "Artifact", "ImageLayer",
    # infrastructure
    "Host", "Container", "Pod", "CloudResource", "NetworkSegment",
    # identity
    "User", "ServiceAccount", "Credential", "Privilege", "Role",
    # runtime
    "Process", "File", "Socket", "RegistryKey", "ModuleLoad",
    # threat
    "Sample", "MalwareFamily", "IOC", "Technique", "Campaign", "Actor",
    # governance
    "Control", "Detection", "Policy", "Vulnerability",
    # network endpoint (remote address)
    "IPAddress",
    # 0.2.0 (ADR-0004): DNS names and derived incident clusters
    "Domain", "Incident",
})

EDGE_TYPES = frozenset({
    "INTRODUCED", "BUILT_INTO", "RUNS", "SPAWNED", "WROTE", "CONNECTED_TO",
    "EXHIBITS", "ATTRIBUTED_TO", "SHOULD_DETECT", "MITIGATES", "EXPLOITS",
    "DEPENDS_ON", "DEPLOYED_AS", "AUTHORED", "LOADED", "READ",
    # 0.2.0 (ADR-0004): richer endpoint telemetry, detections, incidents, intel, posture
    "MODIFIED", "ACCESSED", "INJECTED_INTO", "DELETED", "RESOLVED", "LOGGED_ON",
    "ALERTED_ON", "DETECTS", "PART_OF", "USES", "AFFECTS", "CAN_REACH",
})

#: Display metadata a connector may attach to an event (process image, command
#: line, hashes...). Bounded so an untrusted connector cannot bloat the graph.
MAX_ATTRIBUTES = 16
MAX_ATTRIBUTE_LEN = 1024


class ContractError(ValueError):
    pass


def canonical_hash(obj) -> str:
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    ts: str
    layer: str
    actor_type: str
    actor_id: str
    action: str
    object_type: str
    object_id: str
    source: str
    method: str
    confidence: float
    raw_ref: str
    hash: str
    reliability: str = "C"
    attributes: dict = field(default_factory=dict)  # 0.2.0: optional display metadata

    def validate(self) -> CanonicalEvent:
        if self.layer not in {x.value for x in Layer}:
            raise ContractError(f"bad layer {self.layer!r}")
        for t in (self.actor_type, self.object_type):
            if t not in NODE_TYPES:
                raise ContractError(f"unknown node type {t!r}")
        if self.action not in EDGE_TYPES:
            raise ContractError(f"unknown edge type {self.action!r}")
        if self.method not in {m.value for m in Method}:
            raise ContractError(f"bad method {self.method!r}")
        if self.reliability not in {r.value for r in Reliability}:
            raise ContractError(f"bad reliability {self.reliability!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ContractError("confidence out of [0,1]")
        if not self.actor_id or not self.object_id:
            raise ContractError("actor_id/object_id required")
        if not isinstance(self.attributes, dict) or len(self.attributes) > MAX_ATTRIBUTES:
            raise ContractError("attributes must be a mapping of at most "
                                f"{MAX_ATTRIBUTES} entries")
        for k, v in self.attributes.items():
            if not isinstance(k, str) or not isinstance(v, (str, int, float, bool)):
                raise ContractError("attribute keys must be str and values scalar")
            if isinstance(v, str) and len(v) > MAX_ATTRIBUTE_LEN:
                raise ContractError(f"attribute {k!r} too long")
        return self

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Claim:
    """claim = (assertion, source, method, timestamp, confidence, corroboration[])"""
    claim_id: str
    assertion: str               # e.g. "Process:p1 SPAWNED Process:p2"
    subject: str                 # node key
    predicate: str               # edge type or "EXISTS"
    obj: str | None              # node key or None for node claims
    source: str
    method: str
    timestamp: str
    reliability: str = "C"
    base_confidence: float = 0.5
    confidence: float = 0.5      # after corroboration / conflict
    corroboration: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    evidence_ref: str | None = None  # raw_ref / hash of source event

    def to_dict(self) -> dict:
        return asdict(self)


def node_key(node_type: str, node_id: str) -> str:
    return f"{node_type}:{node_id}"
