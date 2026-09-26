"""Small read-mostly REST API (FastAPI). Binds to localhost by default.

Ingest accepts canonical-connector records only and enforces a size limit;
there is no auth in the MVP (TODO in SECURITY.md) so never expose it publicly.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import synth
from .contracts import ContractError
from .normalizer import connectors, normalize
from .pipeline import build, investigate

MAX_BATCH = 1000


class Record(BaseModel):
    connector: str
    raw: dict
    reliability: str = "C"


class Batch(BaseModel):
    records: list[Record] = Field(max_length=MAX_BATCH)


def create_app(seed_demo: bool = True) -> FastAPI:
    app = FastAPI(title="THROUGHLINE", version="0.1.0")
    state = {"records": list(synth.generate()["records"]) if seed_demo else []}
    state["kg"], state["summary"] = build(state["records"])

    @app.get("/health")
    def health():
        return {"status": "ok", **state["kg"].stats()}

    @app.get("/connectors")
    def list_connectors():
        return connectors()

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
        state["kg"], state["summary"] = build(state["records"])
        return {"accepted": len(batch.records), **state["kg"].stats()}

    @app.get("/investigate/{query}")
    def inv(query: str, min_conf: float = 0.0):
        try:
            return investigate(state["kg"], query, min_conf)
        except KeyError as e:
            raise HTTPException(404, str(e))

    @app.get("/claims/{cid}/explain")
    def explain(cid: str):
        if cid not in state["kg"].claims:
            raise HTTPException(404, "no such claim")
        return state["kg"].explain_claim(cid)

    return app
