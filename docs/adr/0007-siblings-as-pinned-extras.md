# ADR-0007: Sibling projects plug in as pinned optional extras, not vendored code

**Status:** Accepted

## Context
Thirteen sibling projects fill the eight engine slots. The options were to vendor their code, to depend on them unconditionally, or to depend on them optionally.

## Decision
- Each sibling is a pip distribution installed from `git+https://github.com/rakshit-737/<repo>@<commit>` through the `engines` extra. FEINT, which pulls in xgboost and pandas, has its own `network` extra. `throughline.engines.SIBLINGS` is the single table of project, slot, package and validated commit.
- Adapters import their sibling lazily inside `run()`. A missing package raises `EngineUnavailable`; `Stack.registry()` records the engine as skipped and the rest of the stack runs.
- The mapping from a sibling's native output to claims is a pure function where possible (`lineage_claims`, `path_claims`, `flow_claims`, `claims_from_report`), so it can be tested without the sibling installed.
- Sibling repositories are never modified from here.

## Consequences
- `pip install throughline` stays at two dependencies (networkx, PyYAML). CI runs a core job without siblings and an `engines` job with all of them on the committed fixture captures.
- Bumping a sibling is an explicit commit-hash change in two places (the pyproject extra and `SIBLINGS`), reviewed like any dependency bump.
- Git-URL dependencies cannot be published to PyPI as they are. That is acceptable for a portfolio platform.
