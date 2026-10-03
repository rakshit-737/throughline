# Limitations and roadmap

## Limitations

- **Labels are coarse.** OTRF captures carry one technique label, so incidental but genuine techniques count as errors. Calibration is fitted on emulated attacks where every capture contains an attack; it will over-state probabilities on ordinary production telemetry.
- **Attribution evidence is ATT&CK's, not telemetry's.** The 448 leave-report-out cases are curated technique lists from public reports; false flags are simulated, following DRAGNET's protocol. The temporal campaign set is small (17), and its 41% vs 24% gain is not significant on its own.
- **Lateral-movement ground truth is tiny.** Three host pairs over two days; the stitching result is a correctness check, not a precision estimate. Logon (4624) edges are not yet used for stitching.
- **Process identity** merges two processes that reuse a pid with the same image inside one capture ([ADR-0005](adr/0005-windows-process-identity.md)); ROOTLINE cannot run on captures whose Sysmon export dropped the pid.
- **Cross-layer joins on real data are partial.** The endpoint slice (OTRF) and the supply-chain slice (healthchecks) are real but unrelated datasets; the full code-to-runtime story is shown on STRATUM's and the built-in synthetic scenarios. LINCHPIN, VITRINE, SPECIMEN and FEINT are exercised on their own synthetic data or pure mappings, not on real inputs here.
- **In-memory graph.** networkx holds APT29 day 1 (152k claims) in 2.7 GB and day 2 (419k claims) in 8.1 GB, most of it the sibling engines' own copies of the events; every API ingest rebuilds the graph. A persistent store is the Neo4j mirror, which is not the primary backend yet ([ADR-0002](adr/0002-networkx-first-neo4j-optional.md)).
- **Authentication is a single bearer token**; no users, roles or TLS. Keep the API on localhost or behind a TLS proxy.
- **Not built** (spec items out of scope for this release): GraphQL (REST covers every query the console needs), a relational case and audit store, an LLM hypothesis step, a reflexive posture run of VANTAGE on THROUGHLINE's own deployment, an in-code egress guard for a live emulation range (the simulation slot only emits a dry-run plan and nothing executes it), and a time-to-detect measure on APT29 (the plan has no per-step timestamps to measure from).

## Roadmap

- Logon (4624) and SMB/RDP edges between story roots for stitching, scored on more multi-host captures.
- An LLM hypothesis step inside the investigator, under the same "every sentence cites a claim" rule, evaluated against the deterministic trace.
- Real inputs for the remaining adapters: STRATUM's public manifests, LINCHPIN's DefectDojo/BloodHound case study, SPECIMEN on CAPE reports, FEINT on CIC-IDS2017 flows.
- Persistent graph backend and incremental ingest.
