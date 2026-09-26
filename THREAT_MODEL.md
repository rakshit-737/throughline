# Threat model: THROUGHLINE spine

## Assets
- **The knowledge graph.** It maps the whole organization (topology, identities, weaknesses), so it is highly sensitive.
- **Evidence integrity.** Raw-event hashes and claim provenance.
- **Confidence scores and attributions.** These drive analyst decisions.
- **Future:** the detection library and signing keys.

## Trust boundaries
1. **Connectors -> normalizer.** All connector input is *untrusted*.
2. **API clients -> API.** The MVP has no authentication and binds to localhost only.
3. **Engines -> graph.** Engines are semi-trusted plugins. They can only add claims, and they cannot overwrite existing claims.
4. **Simulation range -> platform.** Not present in this MVP. When added, it must have no egress.

## Threats and mitigations (STRIDE-ish)

| Threat | Example | Mitigation in MVP | Gap / TODO |
| --- | --- | --- | --- |
| Spoofed / false telemetry | Adversary injects events to frame a benign host | Every event becomes a *claim* that carries its source reliability. Confidence comes from independent corroboration, and contradictions lower it. Nothing is absolute. | Connector authentication, signed events |
| Tampering with evidence | Raw event edited after ingest | SHA-256 over canonical raw JSON; `normalizer.verify()` detects edits | Append-only store + custody ledger |
| Attribution poisoning / false flag | Planted indicator points at another actor | `ATTRIBUTED_TO` is exclusive, so competing claims contradict each other and both lose confidence (tested) | ACH engine (OCCAM) |
| Injection into graph DB | Malicious IDs in Cypher | Labels are allow-listed and regex-checked; all values are parameterized (tested) | - |
| Schema abuse / DoS | Huge fields or batches | Field length cap (512), non-printables stripped, API batch cap of 1000 | Rate limiting |
| Unknown types | `action="DROP TABLE"` | Closed enums for node and edge types; the event is rejected | - |
| Information disclosure | Graph exfiltrated via API | Binds to localhost by default | AuthN/Z, TLS, audit log |
| Insider poisons detections | Rogue engine writes bogus EXHIBITS | Engine claims are `method=inferred` with a lower prior and a named source | Human approval for detection deploys |
| AI overreach | Model asserts causality with no path | No ML/LLM in the MVP; investigation reports only graph facts with claim ids | Enforce the same rule in the future agentic layer |
