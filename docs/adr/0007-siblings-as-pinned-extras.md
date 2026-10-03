# ADR-0007: Sibling projects plug in as pinned optional extras, not vendored code

**Status:** Accepted (amended in 1.1.0: release tags instead of commits)

## Context
Thirteen sibling projects fill the eight engine slots. The options were to vendor their code, to depend on them unconditionally, or to depend on them optionally.

## Decision
- Each sibling is a pip distribution installed from `<dist> @ git+https://github.com/rakshit-737/<repo>@<release tag>` through the `engines` extra (direct URLs, because unrelated PyPI projects own several of the bare names). FEINT, which pulls in xgboost and pandas, has its own `network` extra. `throughline.engines.SIBLINGS` is the single table of project, slot, package, distribution, pinned release tag and the commit that tag pointed to when it was validated; a test checks that the pyproject extras list exactly these pins.
- Adapters import their sibling lazily inside `run()`. A missing package raises `EngineUnavailable`; `Stack.registry()` records the engine as skipped and the rest of the stack runs.
- The mapping from a sibling's native output to claims is a pure function where possible (`lineage_claims`, `path_claims`, `flow_claims`, `claims_from_report`), so it can be tested without the sibling installed.
- Sibling repositories are never modified from here.

## Consequences
- Installing THROUGHLINE without extras (`pip install -e .` in a checkout, or the release wheel; the bare PyPI name `throughline` is an unrelated project) stays at two dependencies (networkx, PyYAML). CI runs a core job without siblings and an `engines` job with all of them on the committed fixture captures.
- Bumping a sibling is an explicit change of release tag (and recorded commit) in two places, the pyproject extra and `SIBLINGS`; `scripts/check_sibling_tags.py --write` makes it, and fails when a newer published release exists, a pinned tag was moved, or a release renamed its distribution (DRAGNET, GAUNTLET and LINCHPIN did at v1.1.0). CI checks that every installed sibling is exactly the recorded commit, and the release workflow re-runs the tag check before anything is built.
- Git-URL dependencies cannot be published to PyPI as they are. That is acceptable for a portfolio platform.
