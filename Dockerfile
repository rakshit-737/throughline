FROM python:3.12-slim
# git is needed only to install the sibling engines from their pinned release tags
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY throughline ./throughline
RUN pip install --no-cache-dir ".[api,engines,neo4j]" && useradd --create-home --uid 10001 tl
USER tl
ENV THROUGHLINE_DATA=/data PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"
# binds 0.0.0.0 *inside* the container; docker-compose publishes it on 127.0.0.1 only
CMD ["python", "-m", "throughline", "serve", "--host", "0.0.0.0"]
