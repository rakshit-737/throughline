# syntax=docker/dockerfile:1
# python:3.12-slim (Debian trixie), pinned by digest; Dependabot proposes bumps.
ARG PYTHON_IMAGE=python:3.12-slim-trixie@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

# ---- builder: git is needed only to fetch the sibling engines at their pinned release tags
FROM ${PYTHON_IMAGE} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY throughline ./throughline
RUN pip install --no-cache-dir ".[api,engines,neo4j]"

# ---- runtime: the same base image without git; the virtualenv is copied over unchanged
FROM ${PYTHON_IMAGE}
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH THROUGHLINE_DATA=/data PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 tl
USER tl
WORKDIR /home/tl
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
# Binds 0.0.0.0 *inside* the container (publish it on 127.0.0.1 only). Without
# THROUGHLINE_API_TOKEN the server generates a random token and logs the console URL.
CMD ["python", "-m", "throughline", "serve", "--host", "0.0.0.0"]
