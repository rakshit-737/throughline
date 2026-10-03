# Security policy

## Scope and safety (non-negotiable)
- THROUGHLINE **reasons about** attacks. It does not perform them. This repository contains no exploit, emulation or malware code.
- `throughline.synth` produces **data records only**. Nothing is executed and nothing is contacted. All IPs come from RFC 5737 documentation ranges.
- The simulation slot (GAUNTLET) only emits a **dry-run** Atomic Red Team manifest (test names and GUIDs). Nothing is executed. An operator may run it inside an isolated, no-egress lab range only.
- Real attack data is replayed from public **logs** (OTRF Security-Datasets). Malware engines (VITRINE, SPECIMEN) analyse bytes statically or replay existing sandbox *reports*; no sample is ever run. Some antivirus products quarantine OTRF log archives because they contain attack command lines: they are data, not malware.
- Detections drafted by the feedback loop are written `status: experimental` and `reviewed: false`. They are never deployed automatically.
- Do not point connectors at systems you do not own or are not authorized to monitor.

## Deployment guidance
- **Network exposure.** `throughline serve` binds to `127.0.0.1` by default and serves only loopback `Host` headers (add names with `THROUGHLINE_ALLOWED_HOSTS`), which blocks DNS-rebinding pages from reading the graph through a browser. State-changing requests from another origin (`Origin` / `Sec-Fetch-Site`) are refused, and `/ingest` accepts `application/json` only.
- **Authentication** is a single bearer token: with `THROUGHLINE_API_TOKEN` set, every endpoint except `/health` and `/ui` requires `Authorization: Bearer <token>` (constant-time compare; open the console as `/ui#token=<token>`). Serving on a non-loopback address without a token makes `serve` generate a random one and print the console URL, so the container image never exposes an open API. There are no users, roles or TLS: keep it on localhost or behind a TLS reverse proxy. Generate tokens with `python -c "import secrets; print(secrets.token_urlsafe(24))"`.
- **Input limits.** Request bodies over 10 MB (413), batches over 1,000 records, raw records over 64 KB (422) and more than 250,000 retained records (413) are refused; malformed records get 422, not 500.
- **Evidence integrity.** The raw event store (`throughline store`) is append-only with a hash-chained ledger. `store verify` detects edited records, ledger gaps, overlaps and records outside the ledger; `--expect-head` (a head hash kept off-host) detects a truncated or extended tail, and `THROUGHLINE_LEDGER_KEY` adds per-record HMACs. None of this stops an attacker with write access from deleting the store: keep a copy off-host.
- Treat exported graphs (`export`) and the Neo4j mirror as sensitive: they map an organization's attack surface.
- **Neo4j** (`docker-compose.neo4j.yml`) has no default password: Compose refuses to start until `NEO4J_PASSWORD` is set. Its ports are published on `127.0.0.1` only.

## Supply chain
- Sibling engines are installed from pinned release tags; `scripts/check_sibling_tags.py` fails when a pinned tag was moved to another commit, and CI checks that every installed sibling is exactly the pinned commit.
- Datasets are downloaded from pinned commits and checked against `scripts/checksums.sha256` (OTRF files also against the pinned commit's git blob ids); an unpinned file is refused.
- CI runs `pip-audit` on every installed PyPI dependency, `gitleaks` over the full history, Trivy on the built image, and ruff's flake8-bandit (`S`) rules on all code (the per-file exceptions in `pyproject.toml` are reviewed false positives). GitHub Actions are pinned to commit SHAs and the base images to digests; Dependabot proposes updates weekly. Secret scanning with push protection and Dependabot alerts are enabled on the repository.

## Reporting a vulnerability
Please report privately through GitHub's private vulnerability reporting: <https://github.com/rakshit-737/throughline-security-knowledge-graph/security/advisories/new>. Do not open a public issue. Expect an acknowledgement within 7 days and a fix or a documented decision within 30.
