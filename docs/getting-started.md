# Getting started

Python 3.11 or newer. The core depends only on `networkx` and `PyYAML`.

```bash
git clone https://github.com/rakshit-737/throughline-security-knowledge-graph && cd throughline
pip install -e ".[dev,api]"
python -m pytest -q                       # engine and real-data tests skip without siblings/data
python -m throughline demo                # synthetic supply-chain intrusion, no downloads
python -m throughline --false-flag demo   # conflicting CTI lowers attribution confidence
```

Without a checkout: `pip install "throughline @ git+https://github.com/rakshit-737/throughline-security-knowledge-graph"` (the name `throughline` on PyPI belongs to an unrelated project). An installed package keeps datasets in `~/.throughline/data` unless `THROUGHLINE_DATA` or `--data` says otherwise.

## Sibling engines

```bash
pip install -e ".[dev,api,engines]"       # the sibling projects at their pinned release tags
python -m throughline engines             # pinned tag, installed version and commit of each engine
python -m throughline capture SDWIN-201018195009 --data tests/fixtures/data
```

FEINT is in its own extra (`.[network]`) because it pulls in xgboost and pandas.

## Real data

```bash
python scripts/download_data.py all       # ~330 MB, every file checksummed, outside the repo
python -m throughline captures
python -m throughline capture SDWIN-190301174830
```

The benchmarks and their expected numbers are on [Reproduce](reproduce.md).

## API and console

```bash
python -m throughline serve --capture SDWIN-201018195009   # http://127.0.0.1:8000/ui
export THROUGHLINE_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(24))")
python -m throughline serve                                  # then open /ui#token=<the token>
```

## Docker

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/throughline-security-knowledge-graph:latest   # open the console link it logs
docker compose up                                                              # the same, built locally
NEO4J_PASSWORD=$(python -c "import secrets; print(secrets.token_urlsafe(24))") \
  docker compose -f docker-compose.yml -f docker-compose.neo4j.yml up          # plus a local Neo4j mirror
```

The image runs as a non-root user and includes the `api`, `engines` and `neo4j` extras. Inside the container the server listens on all interfaces, so it generates a bearer token unless `THROUGHLINE_API_TOKEN` is set; the port is published on 127.0.0.1 only. `POST /neo4j/sync` mirrors the graph, claims included, into Neo4j.
