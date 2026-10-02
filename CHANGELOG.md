# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Changed
- **Sibling engines pinned to their v1.1.0 release tags** (ANVIL, REVENANT, ROOTLINE, DRAGNET, OCCAM,
  VANTAGE, GAUNTLET, TRACEGATE, STRATUM, LINCHPIN, VITRINE, SPECIMEN); FEINT stays at `v1.0.0`, its newest
  published release. Three siblings renamed their distributions at v1.1.0, so the `engines` extra now
  installs `dragnet-attribution`, `gauntlet-coverage` and `linchpin-attackpath` (import names unchanged;
  the direct URLs stay because unrelated PyPI projects own the bare names). REVENANT is pinned by tag,
  not by commit. `throughline.engines.SIBLINGS` records each tag's commit, and a test checks that the
  `engines`/`network` extras and the table are one pin set. No adapter changes were needed.
- **Python 3.11 or newer** (GAUNTLET v1.1.0 requires it); CI tests 3.11-3.14 on Linux and 3.12 on Windows,
  and runs the engines job on 3.11 and 3.14 with every extra, checking that each installed sibling is
  exactly the pinned commit. Licence metadata uses the SPDX `license = "MIT"` form.
- `throughline engines` and `GET /engines` report the pinned tag *and* the installed version and commit.

### Added
- `scripts/check_sibling_tags.py`: lists every sibling's tags (`git ls-remote`) and newest published
  release (one GraphQL call), fails when a pin is behind or a pinned tag was moved, reads the newer
  release's `pyproject.toml` to catch renamed distributions, and `--write` updates both pin records.
- Release workflow gating: a preflight job (tag equals the package version, CHANGELOG section present,
  sibling pins current, repository hygiene) and the whole CI suite must pass before anything is built;
  the wheel is smoke-tested in a fresh venv and the image with `docker run` before publishing; build
  provenance is attested; only the publish job holds write permissions; actions are pinned by commit.
- `scripts/release_notes.py` extracts the release body from CHANGELOG and fails on a missing section
  (the old awk pattern never matched, so the v1.0.0 release body was just "See CHANGELOG.md").
- `scripts/repo_lint.py` (CI): no tracked file over 1,000,000 bytes, no Unicode bidi control characters.
- Temporal views (`throughline.temporal`): `as_of(kg, ts)` keeps the first-order claims known at `ts`
  and recomputes confidence; `replay()` re-derives incidents on that view. `as_of=` on `/incidents`,
  `/investigate`, `/investigator` and `throughline investigate --as-of`.
- Neo4j mirror includes the claim layer: `(:Claim {source, method, reliability, confidence, ts})` nodes
  with `SUBJECT`/`OBJECT`/`CORROBORATED_BY` links, so provenance is one Cypher query.
- Event store: `store head`, `verify --expect-head` (detects a truncated or extended ledger tail), an
  optional HMAC key for ledger records (`THROUGHLINE_LEDGER_KEY`).

### Security
- The API serves only loopback Host headers (plus `THROUGHLINE_ALLOWED_HOSTS`), which blocks DNS
  rebinding; refuses cross-site state-changing requests (`Origin` / `Sec-Fetch-Site`, 403); requires
  `application/json` on `/ingest` (415); caps request bodies (10 MB, 413), raw records (64 KB, 422) and
  retained records (250,000, 413); returns 422 instead of 500 for malformed records; and holds a lock
  around ingest and rebuild. FastAPI floor raised to 0.132.
- `throughline serve` on a non-loopback address generates a bearer token when none is set and prints
  the console URL; the Docker image therefore no longer serves an open API on `0.0.0.0`.
- Neo4j moved to `docker-compose.neo4j.yml` with no default password (Compose refuses to start
  without `NEO4J_PASSWORD`); image pinned by digest. The Dockerfile is multi-stage (git only in the
  builder) on a digest-pinned base image.
- CI: pip-audit of every installed PyPI dependency, a gitleaks scan of the full history, a Trivy scan of
  the built image, and the compose end-to-end job runs with a bearer token and checks the Host and
  cross-site defences.

### Fixed
- `store verify` no longer creates a missing directory or reports an empty store as ok; it flags
  records outside the ledger's ranges, gaps and duplicates; `get()` checks the reference digest.
- CLI: every subcommand and option has help text; unknown entities or claims, missing datasets and a
  missing `api` extra end with a one-line error (exit 2) instead of a traceback.
- The console's incidents and claim ids are buttons (keyboard reachable); the static demo opens on an
  investigation, links back to the docs, and also shows the real fixture capture through every engine.
- README and docs no longer contain a raw U+202E (right-to-left override) character, which mirrored
  the rest of the APT29 bullets on GitHub and the docs site.

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
