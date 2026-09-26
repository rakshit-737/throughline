# Threat model: THROUGHLINE

## Assets
- **The knowledge graph.** It maps the whole organization (topology, identities, weaknesses), so it is highly sensitive.
- **Evidence integrity.** Raw-event hashes and claim provenance.
- **Confidence scores and attributions.** These drive analyst decisions.
- **Future:** the detection library and signing keys.

## Trust boundaries
1. **Connectors -> normalizer.** All connector input is *untrusted*.
2. **API clients -> API.** The MVP has no authentication and binds to localhost only.
3. **Engines -> graph.** Engines are semi-trusted plugins. They can only add claims, and they cannot overwrite existing claims.
4. **Sibling engines -> graph.** Installed from pinned commits (ADR-0007). They run in-process, so a compromised sibling release is a supply-chain risk; pins are reviewed like any dependency bump.
5. **Simulation range -> platform.** Only a dry-run plan is produced. A real range, when added, must have no egress.

## Threats and mitigations (STRIDE-ish)

| Threat | Example | Mitigation in MVP | Gap / TODO |
| --- | --- | --- | --- |
| Spoofed / false telemetry | Adversary injects events to frame a benign host | Every event becomes a *claim* that carries its source reliability. Confidence comes from independent corroboration, and contradictions lower it. Nothing is absolute. | Connector authentication, signed events |
| Tampering with evidence | Raw event edited after ingest | SHA-256 over canonical raw JSON; `normalizer.verify()`; append-only event store with a hash-chained ledger (`store verify`, tested) | Off-host ledger copy, signing |
| Attribution poisoning / false flag | Planted indicator points at another actor | Two ACH engines (DRAGNET, OCCAM) each write one competing claim; UNKNOWN competes too; the platform commits only at fused confidence >= 0.5 (measured in results/attribution.json) | Planted *exclusive malware families* still mislead DRAGNET and, at the "name anyone" point, the fused verdict |
| Injection into graph DB | Malicious IDs in Cypher | Labels are allow-listed and regex-checked; all values are parameterized (tested) | - |
| Schema abuse / DoS | Huge fields or batches | Field length cap (512), non-printables stripped, API batch cap of 1000 | Rate limiting |
| Unknown types | `action="DROP TABLE"` | Closed enums for node and edge types; the event is rejected | - |
| Information disclosure | Graph exfiltrated via API | Binds to localhost by default | AuthN/Z, TLS, audit log |
| Insider poisons detections | Rogue engine writes bogus EXHIBITS | Engine claims are `method=inferred` with a lower prior and a named source | Human approval for detection deploys |
| AI overreach | Model asserts causality with no path | The investigator is deterministic and read-only; every finding cites claim ids (tested). Drafted detections must pass a false-positive gate and stay unreviewed drafts | An LLM hypothesis layer would need the same citation rule |
