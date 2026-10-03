# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.1.3] - 2026-10-03

### Changed
- The GitHub repository was renamed to `throughline-security-knowledge-graph`; docs moved to <https://rakshit-737.github.io/throughline-security-knowledge-graph/> and the image to `ghcr.io/rakshit-737/throughline-security-knowledge-graph`. Links in older entries below point at the old names, which GitHub redirects (Pages URLs do not).
- Sibling engines are pinned through their renamed repositories (`throughline.engines.REPO_NAMES`) and moved to their newest releases: ANVIL, ROOTLINE, VANTAGE, GAUNTLET, TRACEGATE, FEINT v1.1.2; REVENANT, DRAGNET, OCCAM, STRATUM, LINCHPIN, VITRINE v1.1.3; SPECIMEN v1.1.4.
- Every benchmark re-run in CI with the newly pinned engines (bench run 37136774950). Only runtimes changed; no accuracy, calibration, attribution or supply-chain metric changed.

## [1.1.2] - 2026-10-03

The first published release since 1.0.0; it contains everything listed under 1.1.1 and 1.1.0. Neither of those tags published anything: `v1.1.0`'s release preflight refused results produced by the previous engine commits, and `v1.1.1`'s preflight could not run its repository lint because PyYAML was not installed.

### Fixed
- Release workflow: install PyYAML before the repository-hygiene preflight step.

## [1.1.1] - 2026-10-03 (tagged, not released)

### Changed
- Every benchmark re-run in CI with the newly pinned engines (bench run 37106795062). No accuracy, calibration, attribution or supply-chain metric changed. APT29 pipeline time on the CI runner rose from 68 s to 84 s (day 1) and from 228 s to 269 s (days 1 + 2); peak memory is unchanged.

## [1.1.0] - 2026-10-03 (tagged, not released) - 2026-10-03

Sibling engines are pinned to their newest releases (FEINT v1.1.0, VITRINE and SPECIMEN v1.1.2, the other ten v1.1.1; STRATUM's distribution is now `stratum-cnapp`, and the TRACEGATE adapter accepts its v1.1.1 pair-list lineage). The benchmarks below were measured in CI with the v1.1.0 engines. Every sibling engine moved to its v1.1.0 release, every benchmark is re-run in CI with them, and the evaluation is rebuilt so each headline comes with an interval, an ablation and a like-for-like baseline. Several published numbers got worse when re-measured this way; they are listed under **Changed results**.

### Changed results (re-measured with the v1.1.0 engines, 97 captures, in CI)
- **B1 hit@1 and MRR are now scored with ties in expectation** (Sigma's confidence takes five values; the old alphabetical tie-break favoured whatever sorted first). Fused hit@1 0.400 -> **0.372** [0.288, 0.462], MRR 0.511 -> **0.497**; Sigma alone 0.337 -> **0.259**, MRR 0.457 -> 0.413 (on the same data the alphabetical tie-break gives 0.392 and 0.330). The fused advantage grows: +0.114 [0.047, 0.178] hit@1 over Sigma alone (was +0.063), +0.088 over the unfused union.
- **Calibration is compared on one shared claim set**: fused + Platt Brier 0.111 vs **0.123** for Sigma alone (difference -0.013 [-0.020, -0.006], capture-clustered); the old 0.110 vs 0.130 compared different claim sets.
- **Alert compression against de-duplicated alerts**: 6,056 alerts -> 384 incidents is 15.8x, but against 838 distinct (rule, host) alerts it is **2.2x**.
- **Attribution headline replaced**: the 41% vs 24% confident-and-right gain on 17 temporal campaigns (7 vs 4 cases) is not significant (exact McNemar p = 0.25). On the new leave-report-out set (448 cases) the gain is 19.2% vs 13.0% (p = 0.0003).
- The "group drift" and "group retrospective" sets added in round 3 were degenerate (evidence disjoint from the culprit's profile by construction) or in-sample; they are replaced (below) and their 1 MB of per-row data left git.

### Added
- **Ablation of the evidence model** (B1): Sigma by rule level, unfused union, noisy-OR without the independence rule, per-process fusion without incidents, THROUGHLINE, without reliability grades, and risk-based alerting, with paired bootstrap CIs. Fusing *independent engines* carries the gain; incident grouping adds nothing to ranking (+0.003 [-0.016, 0.023]); the independence rule and grades are not significant.
- B1 also reports the corroboration curve (claims both engines agree on: precision 0.51 vs 0.15), incident prioritisation AUROC (fused 0.795 vs Sigma severity 0.796: no gain), and analyst effort (incidents opened and lines read vs alert queues: no fewer items read).
- **Attribution case sets** (B3): leave-report-out per-report cases (448 cases, 149 groups; the fold's report-only relationships removed from the STIX both engines load), 79 malware families first published after ATT&CK v10.1 (no method attributes them: top-1 0-4%), and behaviour drift as a dose-response curve; Wilson and group-clustered intervals, exact McNemar tests, risk-coverage (AURC).
- **APT29 ground truth** (B4): the CTID APT29 emulation plan (new `apt29plan` download source, Apache-2.0, pinned) scores each day's technique ranking (fused precision@10 0.40 / 0.33 vs Sigma 0.33 / 0.22); a cited lateral-movement truth file scores stitching; an attribution oracle runs both intel engines on the plan's own techniques (APT29 still not named: only 34% of the plan is in its ATT&CK profile). **APT29 day 2** is measured for the first time (587,286 records, 84 incidents, 8.1 GB peak).
- **Compound captures**: APT3 (Empire, CALDERA round 1) and the seven LSASS credential-dumping campaigns run through the whole stack, with per-analyst recall of each campaign's documented techniques.
- **Lateral-movement stitching**: an admin-port connection from host A followed by an incident on B under a remote-execution service joins the two; hosts are mapped to addresses from their own outbound connections.
- **Feedback-loop re-validation in CI** (`loop-revalidation`): on a fresh Windows runner with process-creation auditing, the accepted drafts must fire on a benign re-run of the discovery command they were mined from (`net localgroup Administrators`) and stay silent on a baseline of ordinary administration.
- Every result file records the sibling versions and commits, THROUGHLINE commit, platform and data pins; result files are strict JSON and refused near 1 MB; per-case rows go to a CI artefact. The bench workflow has a choice input, runs every benchmark, and `benchmarks/check_results.py` fails on stale, oversized, degenerate or wrongly-pinned results; the release preflight runs it too.
- Temporal views (`throughline.temporal`): `as_of(kg, ts)` keeps the claims known at `ts` and recomputes confidence; `replay()` re-derives incidents; `as_of=` on `/incidents`, `/investigate`, `/investigator`, and `throughline investigate --as-of`.
- Neo4j mirror includes the claim layer (`(:Claim {source, method, reliability, confidence, ts})` with `SUBJECT`/`OBJECT`/`CORROBORATED_BY`), queried by the compose end-to-end job.
- Event store: `store head`, `verify --expect-head` (detects a truncated or extended tail), an optional HMAC key for ledger records (`THROUGHLINE_LEDGER_KEY`).
- `scripts/check_sibling_tags.py` (newest published release of every sibling, moved tags, renamed distributions; `--write` updates both pin records), `scripts/release_notes.py`, `scripts/repo_lint.py` (no file over 1 MB, no bidi controls, workflow YAML parses), `scripts/screenshot.py`, `scripts/revalidate_loop.py`.
- Documentation: How it works (one real capture end to end), Evaluation (methodology, every result with intervals, comparison with published work), Reproduce (commands, expected numbers, runtimes), a console screenshot, references to verified prior work.
- Repository: CITATION.cff, issue forms, PR checklist, CODEOWNERS, Dependabot; secret scanning with push protection, Dependabot alerts and private vulnerability reporting are enabled.

### Changed
- **Sibling engines pinned to their v1.1.0 release tags** (ANVIL, REVENANT, ROOTLINE, DRAGNET, OCCAM, VANTAGE, GAUNTLET, TRACEGATE, STRATUM, LINCHPIN, VITRINE, SPECIMEN); FEINT stays at `v1.0.0`, its newest published release. DRAGNET, GAUNTLET and LINCHPIN renamed their distributions (`dragnet-attribution`, `gauntlet-coverage`, `linchpin-attackpath`; import names unchanged); the direct URLs stay because unrelated PyPI projects own the bare names. REVENANT is pinned by tag. No adapter changes were needed.
- **Python 3.11 or newer** (GAUNTLET v1.1.0 requires it); CI tests 3.11-3.14 on Linux and 3.12 on Windows, and the engines job runs on 3.11 and 3.14 with every extra, checking each installed sibling is exactly the pinned commit.
- **Cross-host stitching ignores shared infrastructure**: connections of operating-system processes, non-routable addresses, `localhost` and Windows infrastructure ports no longer join hosts, and rarity is counted over all traffic. On APT29 days 1 + 2 the joined host pairs go from 3 true of 6 to **3 true of 3**.
- Inbound Sysmon network connections (whose Destination is the local end) are skipped like inbound WFP events, so `CONNECTED_TO` always points at the remote end; the local address of outbound connections is kept on the process.
- The shipped Platt map is refitted on 97 captures with the v1.1.0 engines (a = 1.513, b = -2.264).
- The investigator says how many incident members come from process lineage and how many other engines added.
- `throughline engines` and `GET /engines` report the pinned tag and the installed version and commit.

### Fixed
- **Raw Winlogbeat exports are flattened** (6.x `event_data`, 7.x `winlog.*`, with the computer name instead of the collector's): the APT3 compound captures produced 0 incidents, and two atomic T1112 captures (registry modification) produced no alerts at all; they now produce 21 and 26, which moves B1 recall from 0.691 to 0.711.
- `bench_compound.py` read the wrong LSASS metadata file, so no campaign had expected techniques.
- The release workflow's YAML did not parse (a plain scalar containing `: `) after the preflight edits; repo_lint now parses every workflow.
- `results/attribution.json` was 1,032,968 bytes, over the 1 MB limit.
- `store verify` no longer creates a missing directory or reports an empty store as ok, and flags records outside the ledger's ranges, gaps and duplicates; `get()` checks the reference digest.
- CLI: help on every subcommand and option, one-line errors (exit 2) for unknown entities and claims, missing datasets and a missing extra; an installed wheel keeps data in `~/.throughline/data`, not site-packages.
- The sdist now ships `tests/conftest.py` and the fixtures, so its test suite runs.
- The console's incidents and claim ids are buttons (keyboard reachable); the static demo opens on a real capture investigation and links back to the docs.
- README and docs no longer contain a raw U+202E (right-to-left override), which mirrored the APT29 bullets on GitHub and the docs site; the release-notes extraction no longer falls back to "See CHANGELOG.md".
- Fixture Sigma rule paths are shorter, so deep Windows checkouts stay under 260 characters.

### Security
- The API serves only loopback Host headers (plus `THROUGHLINE_ALLOWED_HOSTS`), which blocks DNS rebinding; refuses cross-site state-changing requests (403); requires `application/json` on `/ingest` (415); caps request bodies (10 MB), raw records (64 KB) and retained records (250,000); returns 422 instead of 500 for malformed records; FastAPI >= 0.132.
- `throughline serve` on a non-loopback address generates a bearer token when none is set, so the image never serves an open API.
- Neo4j has no default password (Compose refuses to start without `NEO4J_PASSWORD`); base and Neo4j images pinned by digest; multi-stage Dockerfile without git at runtime.
- Downloads fail closed on a file without a pinned checksum (OTRF files are also checked against the pinned commit's git blob ids); every file, including the 18 compound and atomic captures that were unpinned, is now pinned. The GitHub token is never forwarded on redirects, and `gh auth token` is used only with `--use-gh-token`; zip extraction cannot write outside its directory.
- CI: pip-audit, gitleaks over the full history, Trivy on the image; actions pinned by commit; least-privilege workflow permissions; the release is gated on a preflight (version, CHANGELOG, CITATION, sibling pins, committed results produced by the pinned engines) and the full CI suite, smoke-tests the wheel and the image, and attests build provenance.

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
