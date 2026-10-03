# Convenience targets. Every target is a plain command you can run without make.
PY ?= python

.PHONY: install engines data test lint demo demo-real bench docs serve

install:
	$(PY) -m pip install -e ".[dev,api]"

engines:            ## sibling projects as capability engines (pinned release tags)
	$(PY) -m pip install -e ".[dev,api,engines]"

data:               ## ~330 MB into ../../datasets/throughline (or $$THROUGHLINE_DATA), every file checksummed
	$(PY) scripts/download_data.py all

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
	$(PY) scripts/repo_lint.py

demo:               ## synthetic, no downloads
	$(PY) -m throughline demo
	$(PY) -m throughline --false-flag demo

demo-real:          ## real OTRF capture through every engine
	$(PY) -m throughline capture SDWIN-201018195009
	$(PY) benchmarks/demo_apt29.py --day 1

bench:              ## every benchmark on real data (~25 min in CI; APT29 day 2 needs ~8 GB): gh workflow run bench.yml
	$(PY) benchmarks/bench_otrf.py
	$(PY) benchmarks/bench_attribution.py
	$(PY) benchmarks/demo_apt29.py --day 1
	$(PY) benchmarks/demo_apt29.py --day 2
	$(PY) benchmarks/bench_compound.py
	$(PY) benchmarks/bench_loop.py
	$(PY) benchmarks/demo_supplychain.py
	$(PY) benchmarks/figures.py
	$(PY) benchmarks/check_results.py --which all --pins

docs:               ## the documentation site exactly as CI builds it (needs the docs extra)
	$(PY) scripts/build_docs.py

serve:
	$(PY) -m throughline serve
