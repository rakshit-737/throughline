# ADR-0004: Schema 0.2.0 - additive vocabulary for real endpoint telemetry and engine outputs

**Status:** Accepted (extends ADR-0001)

## Context
Real Windows telemetry (Sysmon, the Security log) and the sibling engines produce facts the 0.1.0 vocabulary could not express: process access and injection, registry writes, DNS resolution, logons, Sigma alerts, incident membership, attack-path reachability and vulnerability-to-asset links. Connectors also need to carry display metadata (image path, command line, hashes) that analysts read but that is not itself a claim.

## Decision
`SCHEMA_VERSION = 0.2.0`, strictly additive:

- Node types: `Domain`, `Incident`.
- Edge types: `MODIFIED`, `ACCESSED`, `INJECTED_INTO`, `DELETED`, `RESOLVED`, `LOGGED_ON` (telemetry); `ALERTED_ON`, `DETECTS` (detections); `PART_OF` (incident membership); `USES`, `AFFECTS`, `CAN_REACH` (malware, vulnerabilities, attack paths).
- `CanonicalEvent.attributes`: an optional mapping of at most 16 scalar entries, values truncated to 1,024 characters and stripped of non-printables. Keys are prefixed `actor.` or `object.` and land on the node as `attrs`, never as claims.
- Predicates are split into *causal* (`AUTHORED`, `INTRODUCED`, `BUILT_INTO`, `DEPLOYED_AS`, `RUNS`, `SPAWNED`, `INJECTED_INTO`, `DEPENDS_ON`) and *annotation* (`EXHIBITS`, `ATTRIBUTED_TO`, `PART_OF`, `DETECTS`, `SHOULD_DETECT`, `MITIGATES`, `ALERTED_ON`, `USES`). Root cause walks causal edges backwards; blast radius does not follow annotation edges.

## Consequences
- Every 0.1.0 event is still valid, and the synthetic demo is unchanged.
- An alert that fired before the process it names no longer becomes that process's "root cause". In 0.1.0 it did, because root cause followed every predecessor.
- Attributes are unverified display data. They are bounded so an untrusted connector cannot bloat the graph, and they must never be used as evidence.
