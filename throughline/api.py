"""Read-mostly REST API (FastAPI) + the investigation console. Binds to localhost by default.

Ingest accepts connector records only and enforces a batch limit. There is no
auth (see SECURITY.md), so never expose it beyond localhost.

    create_app()                                 # synthetic demo world
    create_app(capture="SDWIN-201018195009")     # a real OTRF capture through every engine
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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


def create_app(seed_demo: bool = True, capture: str | None = None, data: str | None = None) -> FastAPI:
    app = FastAPI(title="THROUGHLINE", version="0.2.0")
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
        return [{k: i[k] for k in ("incident", "score", "breadth", "alerts", "members", "technique_conf")}
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

    @app.get("/ui", response_class=HTMLResponse)
    def ui():
        return UI.read_text(encoding="utf-8")

    return app
