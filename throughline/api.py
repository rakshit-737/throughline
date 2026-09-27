"""Read-mostly REST API (FastAPI) + the investigation console. Binds to localhost by default.

Ingest accepts connector records only and enforces a batch limit. Optional
bearer-token auth: set ``THROUGHLINE_API_TOKEN`` (or pass ``token=``) and every
endpoint except ``/health`` and ``/ui`` requires ``Authorization: Bearer <token>``
(the console reads the token from ``/ui#token=...``). Even with a token, keep it
on localhost or behind TLS (see SECURITY.md).

    create_app()                                 # synthetic demo world
    create_app(capture="SDWIN-201018195009")     # a real OTRF capture through every engine
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from . import synth
from .contracts import ContractError
from .normalizer import connectors, normalize
from .pipeline import build, investigate
from .reasoning.investigator import Investigator

MAX_BATCH = 1000
UI = Path(__file__).resolve().parent / "ui" / "index.html"


class Record(BaseModel):
    connector: str
    raw: dict
    reliability: str = "C"


class Batch(BaseModel):
    records: list[Record] = Field(max_length=MAX_BATCH)


OPEN_PATHS = frozenset({"/health", "/ui"})


def create_app(seed_demo: bool = True, capture: str | None = None, data: str | None = None,
               token: str | None = None) -> FastAPI:
    app = FastAPI(title="THROUGHLINE", version="1.0.0")
    token = token if token is not None else os.environ.get("THROUGHLINE_API_TOKEN") or None

    if token:
        @app.middleware("http")
        async def bearer(request: Request, call_next):
            if request.url.path not in OPEN_PATHS:
                got = request.headers.get("authorization", "")
                if not hmac.compare_digest(got.encode(), f"Bearer {token}".encode()):
                    return JSONResponse({"detail": "missing or invalid bearer token"}, status_code=401)
            return await call_next(request)
    state: dict = {"incidents": [], "mode": "synthetic"}

    if capture:
        from .cli import _capture_records
        from .stack import Stack
        stack = Stack.from_data_dir(data)
        title, truth, records = _capture_records(capture, stack)
        state.update(mode=f"capture {title}", truth=truth, stack=stack)

        def rebuild():
            kg, summary, ctx = stack.run(state["records"])
            state.update(kg=kg, summary=summary, incidents=ctx.get("incidents", []))
    else:
        records = list(synth.generate()["records"]) if seed_demo else []

        def rebuild():
            state["kg"], state["summary"] = build(state["records"])
    state["records"] = records
    rebuild()

    def kg():
        return state["kg"]

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": state["mode"], **kg().stats()}

    @app.get("/connectors")
    def list_connectors():
        return connectors()

    @app.get("/engines")
    def engines():
        from .engines import status
        return {"siblings": status(), "last_run": state["summary"].get("engines", {}),
                "timings_s": state["summary"].get("timings_s", {})}

    @app.post("/ingest")
    def ingest(batch: Batch):
        errors = []
        for i, r in enumerate(batch.records):
            try:
                normalize(r.raw, r.connector, reliability=r.reliability)
            except (ContractError, KeyError) as e:
                errors.append({"index": i, "error": str(e)})
        if errors:
            raise HTTPException(422, detail=errors)
        state["records"] += [(r.connector, r.raw, r.reliability) for r in batch.records]
        rebuild()
        return {"accepted": len(batch.records), **kg().stats()}

    @app.get("/incidents")
    def incidents():
        return [{k: i.get(k) for k in ("incident", "score", "breadth", "alerts", "members", "technique_conf",
                                       "cluster", "cluster_hosts")}
                for i in state["incidents"]]

    @app.get("/investigate/{query:path}")
    def inv(query: str, min_conf: float = 0.0):
        try:
            return investigate(kg(), query, min_conf)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None

    @app.get("/investigator/{query:path}")
    def agent(query: str, budget: int = 10):
        try:
            return Investigator(kg(), budget=min(max(budget, 1), 20)).investigate(query)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None

    @app.get("/graph/{key:path}")
    def neighbourhood(key: str, radius: int = 1):
        g = kg()
        if key not in g.g:
            raise HTTPException(404, "no such node")
        sub = g.neighborhood(key, radius=min(max(radius, 1), 2))
        return {"nodes": [{"key": n, "type": d["type"], "attrs": d.get("attrs", {})} for n, d in sub.nodes(data=True)][:400],
                "edges": [{"src": s, "dst": o, "predicate": k, "confidence": d.get("confidence", 0.0),
                           "claims": d.get("claims", [])[:5]} for s, o, k, d in sub.edges(keys=True, data=True)][:800]}

    @app.get("/claims/{cid}/explain")
    def explain(cid: str):
        if cid not in kg().claims:
            raise HTTPException(404, "no such claim")
        return kg().explain_claim(cid)

    @app.post("/neo4j/sync")
    def neo4j_sync():
        """Mirror the current graph into Neo4j (``THROUGHLINE_NEO4J_URI``, ``..._USER``,
        ``..._PASSWORD``). 404 when no server is configured."""
        uri = os.environ.get("THROUGHLINE_NEO4J_URI")
        if not uri:
            raise HTTPException(404, "THROUGHLINE_NEO4J_URI not set")
        from .neo4j_adapter import push
        auth = (os.environ.get("THROUGHLINE_NEO4J_USER", "neo4j"), os.environ.get("THROUGHLINE_NEO4J_PASSWORD", ""))
        try:
            got = push(kg(), uri, auth)
        except Exception as e:  # driver/connection errors surface as 503, not 500
            raise HTTPException(503, f"neo4j: {type(e).__name__}") from None
        return {**got, "expected_nodes": kg().g.number_of_nodes(), "expected_edges": kg().g.number_of_edges()}

    @app.get("/ui", response_class=HTMLResponse)
    def ui():
        return UI.read_text(encoding="utf-8")

    return app
