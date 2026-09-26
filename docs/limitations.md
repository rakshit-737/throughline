# Limitations and roadmap

## Limitations

- **Labels are coarse.** OTRF captures carry one technique label, so incidental but genuine techniques count as errors. Calibration is fitted on emulated attacks where every capture contains an attack; it will over-state probabilities on ordinary production telemetry.
- **Small attribution sample.** 17 temporal and 25 retrospective campaigns; rates move 4-6 points per case. False flags are simulated, following DRAGNET's protocol.
- **Cross-host correlation is shallow.** Incidents are built per host and process lineage; since 1.0.0 incidents on different hosts that contacted the same rare network destination (`CONNECTED_TO` an IP:port or `RESOLVED` a domain, shared by at most 3 incidents) are stitched into one `cluster`. That is a proposal with its shared destination as evidence, not a proven lateral-movement edge: logon (4624) and SMB/WinRM edges are not yet used, and the effect on APT29 day 1 (60 per-host incidents) has not been re-measured for this release (it needs the 13-minute full-engine run).
- **Process identity** merges two processes that reuse a pid with the same image inside one capture ([ADR-0005](adr/0005-windows-process-identity.md)); ROOTLINE cannot run on captures whose Sysmon export dropped the pid.
- **Cross-layer joins on real data are partial.** The endpoint slice (OTRF) and the supply-chain slice (healthchecks) are real but unrelated datasets; the full code-to-runtime story is shown on STRATUM's and the built-in synthetic scenarios. LINCHPIN, VITRINE, SPECIMEN and FEINT are exercised on their own synthetic data or pure mappings, not on real inputs here.
- **In-memory graph.** networkx is fine to ~150k claims on a laptop (the APT29 run peaks at ~2.6 GB resident, most of it the sibling engines' own copies of the events); a persistent store is the Neo4j mirror, which is not the primary backend yet ([ADR-0002](adr/0002-networkx-first-neo4j-optional.md)).
- **Authentication is a single optional bearer token** (`THROUGHLINE_API_TOKEN`); no users, roles or TLS. Keep the API on localhost or behind a TLS proxy.

## Roadmap

- Cross-host stitching beyond shared destinations (logon + SMB/WinRM edges between story roots) and a lateral-movement benchmark on APT29 day 2.
- An LLM hypothesis step inside the investigator, under the same "every sentence cites a claim" rule, evaluated against the deterministic trace.
- Real inputs for the remaining adapters: STRATUM's public manifests, LINCHPIN's DefectDojo/BloodHound case study, SPECIMEN on CAPE reports, FEINT on CIC-IDS2017 flows.
- Persistent graph backend and incremental ingest.
