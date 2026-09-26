# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [1.0.0] - 2026-09-26

First stable release: documentation site, container image and closed gaps from 0.2.0.

### Added
- **Cross-host stitching:** incidents on different hosts that contacted the same rare network destination (shared by at most 3 incidents) are joined into one `cluster` (`/incidents`, incident node attributes). A proposal with its shared destination as evidence, not a proven lateral-movement edge.
- **Optional API authentication:** `THROUGHLINE_API_TOKEN` requires `Authorization: Bearer <token>` on every endpoint except `/health` and `/ui` (constant-time compare); the console reads `#token=` from its URL.
- **Docs site** (MkDocs Material) at <https://rakshit-737.github.io/throughline/> with a static, pre-rendered investigation console at `/demo/` (`scripts/build_static_demo.py`).
- **Release pipeline:** on `v*` tags, wheel + sdist, a GitHub Release with these notes, and `ghcr.io/rakshit-737/throughline`. Docker image runs as a non-root user with a health check.

### Changed
- SPECIMEN pin moved to `e3dc7de` (docs-only change upstream); all other sibling pins are unchanged and still equal their current `main`.
- `throughline.__version__` and the API version now match the package version (they still said 0.1.0 / 0.2.0).

## [0.2.0] - 2026-09-26

The spine becomes a platform: the sibling projects run as engines on real public data, and every headline claim is benchmarked against a single-engine baseline.

### Added
- **Sibling engines** (`throughline/engines/`), installed as pinned optional extras: ANVIL (Sigma detection), REVENANT and ROOTLINE (provenance), DRAGNET and OCCAM (ACH attribution), VANTAGE (posture), GAUNTLET (dry-run emulation plans), TRACEGATE and STRATUM (supply chain), LINCHPIN (attack paths), VITRINE and SPECIMEN (malware), FEINT (network). `throughline engines` shows what is installed.
- **Real-data stack** (`throughline.stack.Stack`) that runs every installed engine in dependency order and reports skipped ones.
- **Connectors:** Windows Sysmon + Security (OTRF, Winlogbeat, NXLog JSON), OCSF 1.x, OTRF capture catalog with ATT&CK labels.
- **Full MITRE ATT&CK STIX loader** (techniques, groups, software, campaigns, mitigations, revoked-id forwarding).
- **Correlation** into incidents by process-lineage story root, with incident-level noisy-OR fusion across independent engines.
- **Investigator:** bounded, deterministic, read-only agent over graph queries; every finding cites claim ids.
- **Calibration:** Brier, ECE, AUC, reliability curves, Platt scaling; the map fitted on 95 OTRF captures ships in the package.
- **Feedback loop:** mines novel behaviour of an undetected capture, drafts rules with ANVIL's drafter, and accepts them only if they fire on their capture and nowhere in unrelated captures.
- **Append-only event store** with a hash-chained custody ledger (`throughline store ingest|verify`).
- **API and console:** capture mode, `/incidents`, `/investigator`, `/graph`, `/engines`, and a single-page UI at `/ui`. Dockerfile and docker-compose (localhost only, optional Neo4j).
- **Datasets:** checksummed downloader for ATT&CK v19.2/v10.1, SigmaHQ, OTRF (atomic + APT29), CIS v8 mapping, MISP galaxy, OSV PyPI and a pinned public repository.
- **Benchmarks** with committed results: B1 technique identification (95 captures), B2 alert compression, B3 attribution under false flags (temporal hold-out), B4 APT29 end to end, B5 feedback loop, and the supply-chain slice. Figures in `results/figures/`.
- ADRs 0004-0008, CONTRIBUTING, MIT licence.

### Changed
- Schema 0.2.0 (additive): `Domain`/`Incident` nodes, telemetry, detection, incident, intel and posture edges, and bounded event `attributes`.
- Confidence recomputation is indexed by (subject, predicate) and can be deferred during bulk loads; ingest of large captures is linear instead of quadratic.
- Engines may report their own probability (`score`); base confidence is then `score x reliability`.
- Root cause follows causal predicates only; blast radius ignores annotation edges.
- CI: a core job on Python 3.11-3.13 with ruff, and an engines job that runs the whole stack on committed real fixture captures.

### Fixed
- Platt fitting uses backtracking Newton steps and can no longer diverge.

## [0.1.0] - 2026-09-26

### Added
- Frozen contracts (canonical event, node/edge schema, claim model), normalizer with integrity hashing, networkx knowledge graph, rule-based confidence engine, ATT&CK mapping stub, synthetic supply-chain intrusion, engine registry with declared sibling slots, one-query investigation, FastAPI, CLI and an optional Neo4j mirror.
