FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY throughline ./throughline
RUN pip install --no-cache-dir ".[api,engines]"
RUN useradd -m tl
USER tl
ENV THROUGHLINE_DATA=/data
EXPOSE 8000
# binds 0.0.0.0 *inside* the container; docker-compose publishes it on 127.0.0.1 only
CMD ["python", "-m", "throughline", "serve", "--host", "0.0.0.0"]
