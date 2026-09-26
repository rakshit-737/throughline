# Contributing

Thanks for looking. THROUGHLINE is small on purpose: one graph, frozen contracts, and engines that talk only through the graph. Contributions that keep it that way are very welcome.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,api]"                          # core: no sibling engines needed
pip install -e ".[dev,api,engines]"                  # + the sibling projects at pinned release tags
python scripts/download_data.py all                  # optional: ~290 MB of real data, checksummed
```

## Before you open a PR

```bash
ruff check .
python -m pytest -q          # engine tests skip without the siblings, real-data tests skip without the data
```

Both CI jobs must be green: `core` (no siblings, Python 3.11-3.13) and `engines` (all siblings, full stack on the committed fixture captures).

## Ground rules

- **Contracts are frozen.** Changing `throughline/contracts.py` (node types, edge types, the canonical event, the claim model) needs a new ADR in `docs/adr/` and a `SCHEMA_VERSION` bump. Additive changes are preferred.
- **Engines talk through the graph only.** A new engine implements `name`, `reads`, `writes` and `run(kg, context) -> list[Claim]`. It must not call another engine. Put the mapping from the sibling's output into claims in a pure function so it can be tested without the sibling installed.
- **Every conclusion is a claim** with a source, a method and a reliability grade. Do not write confidence values directly; let the confidence engine compute them.
- **No new data in git** above ~1 MB. Add a pinned, checksummed source to `scripts/download_data.py` and a tiny fixture under `tests/fixtures/` with its licence in the fixtures README.
- **Benchmarks report what happened**, including where THROUGHLINE loses to a baseline. Keep the baseline and the method on identical inputs.
- **Safety:** no exploit code, no live malware, no scanning. Emulation stays a dry-run plan (see SECURITY.md).

## Commit messages

Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `refactor:`, `ci:`, `build:`), small and logical.
