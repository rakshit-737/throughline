# Contributing

Thanks for looking. THROUGHLINE is small on purpose: one graph, frozen contracts, and engines that talk only through the graph. Contributions that keep it that way are very welcome.

## Setup

Python 3.11 or newer.

```bash
git clone https://github.com/rakshit-737/throughline && cd throughline
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,api]"                          # core: no sibling engines needed
pip install -e ".[dev,api,engines]"                  # + the sibling projects at their pinned release tags
python scripts/download_data.py all                  # optional: ~330 MB of real data, every file checksummed
```

On Windows, a checkout in a deep directory can hit the 260-character path limit; `git config --global core.longpaths true` avoids it.

## Before you open a PR

```bash
ruff check .
python -m pytest -q                # engine tests skip without the siblings, real-data tests skip without the data
python scripts/repo_lint.py        # no file over 1 MB, no bidi control characters, workflow YAML parses
```

CI runs: `core` (no siblings; Python 3.11-3.14 on Linux, 3.12 on Windows), `engines` (every sibling at its pinned commit, Python 3.11 and 3.14, the full stack on the committed fixture captures), `compose-e2e` (API + Neo4j through docker compose, an investigation over HTTP), `loop-revalidation` (the feedback loop's accepted detections against a benign re-emulation on a fresh Windows runner) and `security` (pip-audit, gitleaks). The long real-data benchmarks run only on demand: `gh workflow run bench.yml -f which=all` (see [docs/reproduce.md](docs/reproduce.md)).

## Documentation

```bash
pip install -e ".[api,engines,docs]"
python scripts/build_docs.py       # copies the result figures, pre-renders the static console, mkdocs build --strict
python scripts/screenshot.py       # optional: docs/assets/console.png (needs `pip install playwright` + Chromium)
```

## Ground rules

- **Contracts are frozen.** Changing `throughline/contracts.py` (node types, edge types, the canonical event, the claim model) needs a new ADR in `docs/adr/` and a `SCHEMA_VERSION` bump. Additive changes are preferred.
- **Engines talk through the graph only.** A new engine implements `name`, `reads`, `writes` and `run(kg, context) -> list[Claim]`. It must not call another engine. Put the mapping from the sibling's output into claims in a pure function so it can be tested without the sibling installed.
- **Every conclusion is a claim** with a source, a method and a reliability grade. Do not write confidence values directly; let the confidence engine compute them.
- **No new data in git** above ~1 MB. Add a pinned, checksummed source to `scripts/download_data.py` and a tiny fixture under `tests/fixtures/` with its licence in the fixtures README.
- **Benchmarks report what happened**, including where THROUGHLINE loses to a baseline. Keep the baseline and the method on identical inputs, give every rate an interval, and regenerate published numbers with `bench.yml` (each result file records the engine versions that produced it).
- **Sibling pins** move only to published release tags: `python scripts/check_sibling_tags.py --write`, then let the `engines` job and a bench run confirm them.
- **Safety:** no exploit code, no live malware, no scanning. Emulation stays a dry-run plan; the only commands CI ever runs are read-only administration commands on its own throwaway runner (see SECURITY.md).

## Commit messages

Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `refactor:`, `ci:`, `build:`), small and logical.
