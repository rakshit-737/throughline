# Architecture decision records

- [ADR-0001: Freeze contracts first; engines communicate only via the graph](0001-frozen-contracts.md)
- [ADR-0002: In-memory networkx graph first; Neo4j as an optional mirror](0002-networkx-first-neo4j-optional.md)
- [ADR-0003: Transparent rule-based confidence model](0003-confidence-model.md)
- [ADR-0004: Schema 0.2.0 - additive vocabulary for real endpoint telemetry and engine outputs](0004-schema-0.2.md)
- [ADR-0005: Windows process identity is host/pid/image, with the Sysmon GUID as a fallback](0005-windows-process-identity.md)
- [ADR-0006: Engines may report their own probability; calibration is a separate, fitted map](0006-engine-scores-and-calibration.md)
- [ADR-0007: Sibling projects plug in as pinned optional extras, not vendored code](0007-siblings-as-pinned-extras.md)
- [ADR-0008: Two ACH engines each write one competing attribution claim; UNKNOWN is a hypothesis](0008-attribution-fusion.md)
