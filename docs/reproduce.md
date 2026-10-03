# Reproduce

Every published number comes from one run of the manual **bench** workflow; the same scripts run locally. The expected values below are what the committed `results/*.json` contain; the scripts are deterministic (bootstrap seed 0, DRAGNET's decoy seed 7, drift seeds 0-2, triage tie-break seed 0), so a rerun with the same engine pins and data gives the same numbers. Only timings differ.

## Environment

- Python 3.11-3.14 (CI uses 3.12 on `ubuntu-24.04`). Every sibling engine at its pinned release: `pip install -e ".[dev,api,engines,bench]"`.
- About 330 MB of data (`$THROUGHLINE_DATA`, default `../../datasets/throughline` next to the checkout).
- Memory: everything fits in 3 GB except APT29 day 2, which peaks at **8.1 GB** resident (day 1: 2.7 GB). On a small machine, run that one in CI.

## In CI (the published numbers)

```bash
gh workflow run bench.yml -f which=all          # or: otrf | attribution | apt29 | compound | loop | supplychain
gh run watch <run-id>
gh run download <run-id> -n bench-results      # results/*.json, figures, checksums.sha256, download.log
gh run download <run-id> -n bench-raw           # per-case rows (never committed)
```

A `which=all` run takes about 25 minutes on a GitHub-hosted runner. Its last step (`benchmarks/check_results.py --since <start> --pins`) fails if any result is stale, over 1 MB, not strict JSON, degenerate, or was produced by sibling commits other than the pins.

## Locally, step by step

| step | command | CI runner time | output | expected key numbers |
| --- | --- | ---: | --- | --- |
| data | `python scripts/download_data.py all` | 15 s (minutes on a home connection) | `$THROUGHLINE_DATA` | 246 files pinned by sha256; "done." with no `failed:` |
| B1/B2 | `python benchmarks/bench_otrf.py` (`--from-cache` re-scores) | 4.5 min | `results/otrf_core.json` | captures 97; fused hit@1 0.372, MRR 0.497; Sigma hit@1 0.259; fused - Sigma hit@1 +0.114 [0.047, 0.178]; shared-set Brier 0.111 vs 0.123; 6,056 alerts, 838 de-duplicated, 384 incidents |
| B3 | `python benchmarks/bench_attribution.py` (`--quick` smoke test) | 1 min | `results/attribution.json` | report_lro: 448 cases, fused confident-and-right 0.192, DRAGNET 0.130; McNemar fused vs DRAGNET 43/15, p = 0.0003; temporal: 17 + 79 cases |
| B4 | `python benchmarks/demo_apt29.py --day 1` and `--day 2` | 1.5 + 4.5 min | `results/apt29_day1.json`, `apt29_day2.json` | day 1: 60 incidents, stitching pair precision 1.0, recall 1.0; fused precision@10 0.40 vs Sigma 0.33. Day 2: 84 incidents, 2 of 2 pairs; 0.33 vs 0.22 |
| compound | `python benchmarks/bench_compound.py` | 5 min | `results/compound*.json` | all 9 captures with incidents; APT3 Empire 18 incidents, 1 cross-host cluster; LSASS pooled recall Sigma 30/59, union 32/59, fused 31/59 |
| B5 | `python benchmarks/bench_loop.py` | 3.5 min | `results/feedback_loop.json` | 31 gaps; heuristic: 27 drafts, 20 rejected by the gate, 6 accepted |
| supply chain | `python scripts/download_data.py osv repos` then `python benchmarks/demo_supplychain.py` | 1 min | `results/supplychain_healthchecks.json` | 236 commits, 311 versions, blame agreement 15/15 (OSV is a rolling feed: advisory counts drift) |
| figures | `python benchmarks/figures.py` | 1 s | `results/figures/*.png` | five PNGs |
| check | `python benchmarks/check_results.py --which all --pins` | 1 s | - | every line `ok` |

On a Windows laptop the same steps take roughly three times as long, and endpoint antivirus may quarantine two OTRF archives (they contain attack command lines); the loaders then skip and report them, so B1 scores 95 captures instead of 97.

## Re-emulation of the feedback loop (CI only)

The `loop-revalidation` job in `ci.yml` needs administrator rights on a throwaway Windows host: it turns on process-creation auditing, records a baseline, re-runs `net localgroup Administrators`, exports the 4688 events and runs `python scripts/revalidate_loop.py --events events.jsonl --windows windows.json`. Do not run those steps on a machine you care about; the script itself can be run on any exported events.

## Documentation and screenshot

```bash
pip install -e ".[api,engines,docs]"
python scripts/build_docs.py                    # static console + mkdocs build --strict -> site/
pip install playwright && python -m playwright install chromium
python scripts/screenshot.py                    # docs/assets/console.png
```
