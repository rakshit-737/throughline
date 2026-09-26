# Security policy

## Scope and safety (non-negotiable)
- THROUGHLINE **reasons about** attacks. It does not perform them. This repository contains no exploit, emulation or malware code.
- `throughline.synth` produces **data records only**. Nothing is executed and nothing is contacted. All IPs come from RFC 5737 documentation ranges.
- The simulation slot (GAUNTLET) only emits a **dry-run** Atomic Red Team manifest (test names and GUIDs). Nothing is executed. An operator may run it inside an isolated, no-egress lab range only.
- Real attack data is replayed from public **logs** (OTRF Security-Datasets). Malware engines (VITRINE, SPECIMEN) analyse bytes statically or replay existing sandbox *reports*; no sample is ever run. Some antivirus products quarantine OTRF log archives because they contain attack command lines: they are data, not malware.
- Detections drafted by the feedback loop are written `status: experimental` and `reviewed: false`. They are never deployed automatically.
- Do not point connectors at systems you do not own or are not authorized to monitor.

## Deployment guidance
- The API has **optional single-token authentication**: set `THROUGHLINE_API_TOKEN` and every endpoint except `/health` and `/ui` requires `Authorization: Bearer <token>` (constant-time compare). There are no users, roles or TLS, so keep it on `127.0.0.1` (the default; docker-compose publishes it on localhost only) or behind a TLS reverse proxy. Never expose it unauthenticated.
- The raw event store (`throughline store`) is append-only with a hash-chained ledger; `store verify` detects edited records or ledger lines. It does not stop an attacker with write access from deleting the whole store, so keep a copy off-host.
- Treat exported graphs (`export`) as sensitive: they map an organization's attack surface.
- The Neo4j adapter expects a local instance. Change the default credentials.

## Reporting a vulnerability
Please report privately through GitHub Security Advisories on this repository, or email the maintainer. Do not open a public issue. Expect an acknowledgement within 7 days.
