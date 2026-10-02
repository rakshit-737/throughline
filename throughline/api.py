"""Read-mostly REST API (FastAPI) + the investigation console. Binds to localhost by default.

    create_app()                                 # synthetic demo world
    create_app(capture="SDWIN-201018195009")     # a real OTRF capture through every engine

Defences (see THREAT_MODEL.md):

* **Host allow-list** (``TrustedHostMiddleware``): only ``localhost``/``127.0.0.1``/``[::1]``
  plus ``THROUGHLINE_ALLOWED_HOSTS`` are served, so a DNS-rebinding page cannot read the graph
  through a victim's browser.
* **Cross-site writes are refused**: a state-changing request whose ``Origin`` is not an
  allowed host, or whose ``Sec-Fetch-Site`` is ``cross-site``/``same-site``, gets 403;
  ``/ingest`` accepts ``application/json`` only (415 otherwise).
* **Size limits**: request bodies over :data:`MAX_BODY_BYTES` (413), batches over
  :data:`MAX_BATCH` records, raw records over :data:`MAX_RAW_BYTES` (422), and at most
  :data:`MAX_RECORDS` retained records (413). Ingest and rebuild hold a lock.
* **Optional bearer token**: with ``THROUGHLINE_API_TOKEN`` (or ``token=``) every endpoint
  except ``/health`` and ``/ui`` requires ``Authorization: Bearer <token>`` (the console reads
  it from ``/ui#token=...``). ``throughline serve`` on a non-loopback address generates one when
  none is set.

Every read endpoint that takes ``as_of`` (ISO-8601) answers from the claims known at that time
(:mod:`throughline.temporal`).
"""
from __future__ import annotations

import hmac
import json
import os
import threading
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__, synth
from .contracts import ContractError
from .graph import KnowledgeGraph
from .normalizer import connectors, normalize
from .pipeline import build, investigate
from .reasoning.investigator import Investigator

MAX_BATCH = 1000
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_RAW_BYTES = 64 * 1024
MAX_RECORDS = 250_000
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1", "[::1]")
UI = Path(__file__).resolve().parent / "ui" / "index.html"
OPEN_PATHS = frozenset({"/health", "/ui"})
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class Record(BaseModel):
    """One raw connector record (``connector`` names a registered mapper)."""

    connector: str = Field(max_length=64)
    raw: dict
    reliability: str = Field(default="C", max_length=1)


class Batch(BaseModel):
    """An ``/ingest`` request body."""

    records: list[Record] = Field(max_length=MAX_BATCH)


def allowed_hosts(extra: list[str] | None = None) -> list[str]:
    """Loopback names plus ``THROUGHLINE_ALLOWED_HOSTS`` (comma separated) and ``extra``."""
    env = [h.strip() for h in os.environ.get("THROUGHLINE_ALLOWED_HOSTS", "").split(",") if h.strip()]
    return list(dict.fromkeys([*LOOPBACK_HOSTS, *env, *(extra or [])]))


class _TooLarge(Exception):
    pass


class BodySizeLimit:
    """ASGI middleware: 413 for a declared or streamed request body over ``max_bytes``."""

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > self.max_bytes):
            await JSONResponse({"detail": "request body too large"}, status_code=413)(scope, receive, send)
            return
        seen = 0

        async def limited():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_bytes:
                    raise _TooLarge
            return msg

        try:
            await self.app(scope, limited, send)
        except _TooLarge:
            await JSONResponse({"detail": "request body too large"}, status_code=413)(scope, receive, send)


def _hostname(origin: str) -> str:
    try:
        return (urlsplit(origin).hostname or "").lower()
    except ValueError:
        return ""


def create_app(seed_demo: bool = True, capture: str | None = None, data: str | None = None,
               token: str | None = None, hosts: list[str] | None = None) -> FastAPI:
    """Build the API app.

    Args:
        seed_demo: start from the synthetic supply-chain intrusion (ignored with ``capture``).
        capture: an OTRF capture id or path to serve through every installed engine.
        data: dataset root for ``capture`` (default ``$THROUGHLINE_DATA``).
        token: bearer token (default ``$THROUGHLINE_API_TOKEN``; ``None``/empty disables auth).
        hosts: extra Host header names to accept (besides loopback and ``THROUGHLINE_ALLOWED_HOSTS``).
    """
    app = FastAPI(title="THROUGHLINE", version=__version__)
    token = token if token is not None else os.environ.get("THROUGHLINE_API_TOKEN") or None
    allowed = allowed_hosts(hosts)
    allowed_names = {h.strip("[]").lower() for h in allowed}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.method not in SAFE_METHODS:
            origin = request.headers.get("origin")
            if origin is not None and _hostname(origin) not in allowed_names:
                return JSONResponse({"detail": "cross-origin write refused"}, status_code=403)
            if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
                return JSONResponse({"detail": "cross-site write refused"}, status_code=403)
            if request.url.path == "/ingest":
                ctype = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if ctype != "application/json":
                    return JSONResponse({"detail": "Content-Type must be application/json"}, status_code=415)
        if token and request.url.path not in OPEN_PATHS:
            got = request.headers.get("authorization", "")
            if not hmac.compare_digest(got.encode(), f"Bearer {token}".encode()):
                return JSONResponse({"detail": "missing or invalid bearer token"}, status_code=401)
        return await call_next(request)

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed)
    app.add_middleware(BodySizeLimit, max_bytes=MAX_BODY_BYTES)

    state: dict = {"incidents": [], "mode": "synthetic", "views": OrderedDict()}
    lock = threading.Lock()

    if capture:
        from .cli import capture_records_for
        from .stack import Stack
        stack = Stack.from_data_dir(data)
        title, truth, records = capture_records_for(capture, stack)
        state.update(mode=f"capture {title}", truth=truth, stack=stack)

        def rebuild() -> None:
            kg, summary, ctx = stack.run(state["records"])
            state.update(kg=kg, summary=summary, incidents=ctx.get("incidents", []))
    else:
        records = list(synth.generate()["records"]) if seed_demo else []

        def rebuild() -> None:
            ctx: dict = {}
            state["kg"], state["summary"] = build(state["records"], context=ctx)
            state["incidents"] = ctx.get("incidents", [])
    state["records"] = records
    rebuild()

    def view(as_of: str | None) -> tuple[KnowledgeGraph, list[dict]]:
        """The live graph, or the graph as known at ``as_of`` (cached, a few views)."""
        if not as_of:
            return state["kg"], state["incidents"]
        from .temporal import replay
        cache: OrderedDict = state["views"]
        if as_of not in cache:
            try:
                kg, ctx = replay(state["kg"], as_of)
            except ValueError as e:
                raise HTTPException(422, str(e)) from None
            cache[as_of] = (kg, ctx.get("incidents", []))
            while len(cache) > 8:
                cache.popitem(last=False)
        return cache[as_of]

    @app.get("/health")
    def health() -> dict:
        """Liveness, serving mode and graph size (no authentication)."""
        return {"status": "ok", "mode": state["mode"], "version": __version__, **state["kg"].stats()}

    @app.get("/connectors")
    def list_connectors() -> list[str]:
        """Registered connector names accepted by ``/ingest``."""
        return connectors()

    @app.get("/engines")
    def engines() -> dict:
        """Sibling engines: pinned release, installed version, and the last run's claim counts."""
        from .engines import status
        return {"siblings": status(), "last_run": state["summary"].get("engines", {}),
                "timings_s": state["summary"].get("timings_s", {})}

    @app.post("/ingest")
    def ingest(batch: Batch) -> dict:
        """Validate, append and re-derive. Rejects the whole batch if any record is invalid."""
        errors = []
        for i, r in enumerate(batch.records):
            try:
                if len(json.dumps(r.raw, default=str)) > MAX_RAW_BYTES:
                    raise ContractError(f"raw record larger than {MAX_RAW_BYTES} bytes")
                normalize(r.raw, r.connector, reliability=r.reliability)
            except (ContractError, KeyError, ValueError, TypeError, OverflowError) as e:
                errors.append({"index": i, "error": f"{type(e).__name__}: {str(e)[:200]}"})
        if errors:
            raise HTTPException(422, detail=errors)
        with lock:
            if len(state["records"]) + len(batch.records) > MAX_RECORDS:
                raise HTTPException(413, f"the in-memory store holds at most {MAX_RECORDS} records")
            state["records"] += [(r.connector, r.raw, r.reliability) for r in batch.records]
            rebuild()
            state["views"].clear()
            return {"accepted": len(batch.records), **state["kg"].stats()}

    @app.get("/incidents")
    def incidents(as_of: str | None = None) -> list[dict]:
        """Correlated incidents, most confident first (optionally as known at ``as_of``)."""
        _, incs = view(as_of)
        return [{k: i.get(k) for k in ("incident", "score", "breadth", "alerts", "members", "technique_conf",
                                       "cluster", "cluster_hosts")} for i in incs]

    @app.get("/investigate/{query:path}")
    def inv(query: str, min_conf: float = 0.0, as_of: str | None = None) -> dict:
        """One-query investigation: root cause, techniques, attribution, cited facts."""
        kg, _ = view(as_of)
        try:
            return investigate(kg, query, min_conf)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None

    @app.get("/investigator/{query:path}")
    def agent(query: str, budget: int = 10, as_of: str | None = None) -> dict:
        """The bounded read-only investigator's trace and report."""
        kg, _ = view(as_of)
        try:
            return Investigator(kg, budget=min(max(budget, 1), 20)).investigate(query)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None

    @app.get("/graph/{key:path}")
    def neighbourhood(key: str, radius: int = 1) -> dict:
        """Nodes and edges within ``radius`` (1-2) of a node key."""
        g = state["kg"]
        if key not in g.g:
            raise HTTPException(404, "no such node")
        sub = g.neighborhood(key, radius=min(max(radius, 1), 2))
        return {"nodes": [{"key": n, "type": d["type"], "attrs": d.get("attrs", {})}
                          for n, d in sub.nodes(data=True)][:400],
                "edges": [{"src": s, "dst": o, "predicate": k, "confidence": d.get("confidence", 0.0),
                           "claims": d.get("claims", [])[:5]} for s, o, k, d in sub.edges(keys=True, data=True)][:800]}

    @app.get("/claims/{cid}/explain")
    def explain(cid: str) -> dict:
        """How one claim's confidence was computed (sources, corroboration, contradiction)."""
        if cid not in state["kg"].claims:
            raise HTTPException(404, "no such claim")
        return state["kg"].explain_claim(cid)

    @app.post("/neo4j/sync")
    def neo4j_sync() -> dict:
        """Mirror the current graph, claims included, into Neo4j (``THROUGHLINE_NEO4J_URI``,
        ``..._USER``, ``..._PASSWORD``). 404 when no server is configured, 503 when it is unreachable."""
        uri = os.environ.get("THROUGHLINE_NEO4J_URI")
        if not uri:
            raise HTTPException(404, "THROUGHLINE_NEO4J_URI not set")
        from .neo4j_adapter import push
        auth = (os.environ.get("THROUGHLINE_NEO4J_USER", "neo4j"), os.environ.get("THROUGHLINE_NEO4J_PASSWORD", ""))
        with lock:
            kg = state["kg"]
            try:
                got = push(kg, uri, auth)
            except Exception as e:  # driver/connection errors surface as 503, not 500
                raise HTTPException(503, f"neo4j: {type(e).__name__}") from None
            return {**got, "expected_nodes": kg.g.number_of_nodes(), "expected_edges": kg.g.number_of_edges(),
                    "expected_claims": len(kg.claims)}

    @app.get("/ui", response_class=HTMLResponse)
    def ui() -> str:
        """The single-page investigation console."""
        return UI.read_text(encoding="utf-8")

    return app
