# Convenience targets. Every target is a plain command you can run without make.
PY ?= python

.PHONY: install engines data test lint demo demo-real bench serve

install:
	$(PY) -m pip install -e ".[dev,api]"

engines:            ## sibling projects as capability engines (pinned git commits)
	$(PY) -m pip install -e ".[dev,api,engines]"

data:               ## ~290 MB into ../../datasets/throughline (or $$THROUGHLINE_DATA)
	$(PY) scripts/download_data.py all

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

demo:               ## synthetic, no downloads
	$(PY) -m throughline demo
	$(PY) -m throughline --false-flag demo

demo-real:          ## real OTRF capture through every engine
	$(PY) -m throughline capture SDWIN-201018195009
	$(PY) benchmarks/demo_apt29.py --day 1

bench:              ## all benchmarks on real data (~45 min)
	$(PY) benchmarks/bench_otrf.py
	$(PY) benchmarks/bench_attribution.py
	$(PY) benchmarks/bench_loop.py
	$(PY) benchmarks/demo_apt29.py --day 1
	$(PY) benchmarks/demo_supplychain.py
	$(PY) benchmarks/figures.py

serve:
	$(PY) -m throughline serve
