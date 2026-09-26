"""API (synthetic and capture mode), console UI and the real-data CLI commands."""
from __future__ import annotations

import json

from conftest import FIX, needs
from fastapi.testclient import TestClient

from throughline.api import create_app
from throughline.cli import main

ENGINES = ("anvil", "revenant", "rootline", "dragnet", "occam", "vantage", "gauntlet")


def test_synthetic_api_new_endpoints():
    c = TestClient(create_app())
    assert c.get("/health").json()["mode"] == "synthetic"
    assert "siblings" in c.get("/engines").json()
    a = c.get("/investigator/checkout-7").json()
    assert a["entity"] == "Pod:checkout-7" and a["trace"]
    g = c.get("/graph/Pod:checkout-7").json()
    assert any(e["predicate"] == "RUNS" for e in g["edges"])
    assert c.get("/graph/Nope:x").status_code == 404
    assert "THROUGHLINE" in c.get("/ui").text


@needs(*ENGINES)
def test_capture_mode_api_on_real_fixture():
    c = TestClient(create_app(capture="SDWIN-201018195009", data=str(FIX)))
    incs = c.get("/incidents").json()
    assert incs and max(incs[0]["technique_conf"], key=incs[0]["technique_conf"].get) == "T1003.001"
    a = c.get(f"/investigator/{incs[0]['incident']}").json()
    assert a["incident"] == incs[0]["incident"]
    cid = next(s["cites"][0] for s in a["trace"] if s["cites"])
    assert c.get(f"/claims/{cid}/explain").json()["claim"] == cid


@needs(*ENGINES)
def test_cli_capture_json(capsys):
    assert main(["capture", "SDWIN-201018195009", "--data", str(FIX), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["labelled_techniques"] == ["T1003.001"] and out["incidents"]
    assert out["investigation"]["trace"]


def test_cli_captures_and_store(tmp_path, capsys):
    assert main(["captures", "--data", str(FIX)]) == 0
    assert "SDWIN-201021232814" in capsys.readouterr().out
    cap = FIX / "otrf/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry.zip"
    assert main(["store", "ingest", str(tmp_path / "s"), str(cap)]) == 0
    assert json.loads(capsys.readouterr().out)["appended"] == 68
    assert main(["store", "verify", str(tmp_path / "s")]) == 0
    assert main(["engines"]) == 0


def test_api_bearer_token():
    c = TestClient(create_app(token="s3cret"))
    assert c.get("/health").status_code == 200
    assert c.get("/incidents").status_code == 401
    assert c.get("/incidents", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = c.get("/incidents", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and isinstance(r.json(), list)
