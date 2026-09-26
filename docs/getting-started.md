# Getting started

Python 3.10+ is required. The core depends only on `networkx` and `PyYAML`.

```bash
git clone https://github.com/rakshit-737/throughline && cd throughline
pip install -e ".[dev,api]"
python -m pytest -q                       # engine and real-data tests skip without siblings/data
python -m throughline demo                # synthetic supply-chain intrusion, no downloads
python -m throughline --false-flag demo   # conflicting CTI lowers attribution confidence
```

## Sibling engines

```bash
pip install -e ".[dev,api,engines]"       # the sibling projects at their pinned commits
python -m throughline engines             # which engines are installed
python -m throughline capture SDWIN-201018195009 --data tests/fixtures/data
```

## Real data

```bash
python scripts/download_data.py all       # ~290 MB, checksummed, outside the repo
python -m throughline captures
python -m throughline capture SDWIN-190301174830
```

## API and console

```bash
python -m throughline serve --capture SDWIN-201018195009   # http://127.0.0.1:8000/ui
THROUGHLINE_API_TOKEN=change-me python -m throughline serve # then open /ui#token=change-me
```

## Docker

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/throughline:latest
docker compose up                          # add --profile neo4j for a local Neo4j mirror
```

The image runs as a non-root user and includes the `api` and `engines` extras.
