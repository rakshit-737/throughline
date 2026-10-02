"""API (synthetic and capture mode), console UI and the real-data CLI commands."""
from __future__ import annotations

import json

from conftest import FIX, local_client, needs

from throughline.api import create_app
from throughline.cli import main

ENGINES = ("anvil", "revenant", "rootline", "dragnet", "occam", "vantage", "gauntlet")


def test_synthetic_api_new_endpoints():
    c = local_client(create_app())
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
    c = local_client(create_app(capture="SDWIN-201018195009", data=str(FIX)))
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
    c = local_client(create_app(token="s3cret"))
    assert c.get("/health").status_code == 200
    assert c.get("/incidents").status_code == 401
    assert c.get("/incidents", headers={"Authorization": "Bearer wrong"}).status_code == 401
    r = c.get("/incidents", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and isinstance(r.json(), list)


# ---------- API defences ----------
def test_api_refuses_foreign_host_headers():
    """DNS rebinding: a page on attacker.example resolving to 127.0.0.1 sends Host: attacker.example."""
    c = local_client(create_app())
    assert c.get("/incidents").status_code == 200
    assert c.get("/incidents", headers={"Host": "attacker.example:8000"}).status_code == 400
    assert c.get("/investigate/checkout-7", headers={"Host": "rebind.attacker.example"}).status_code == 400
    assert local_client(create_app(hosts=["tl.internal"])).get(
        "/health", headers={"Host": "tl.internal"}).status_code == 200


def test_api_refuses_cross_site_writes_and_non_json_ingest():
    c = local_client(create_app())
    body = {"records": [{"connector": "cicd", "reliability": "A",
                         "raw": {"kind": "commit", "author": "dave", "sha": "f00", "ts": "t"}}]}
    assert c.post("/ingest", json=body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/ingest", json=body, headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert c.post("/neo4j/sync", headers={"Origin": "https://evil.example"}).status_code == 403
    no_ctype = c.post("/ingest", content=json.dumps(body).encode(), headers={"Content-Type": "text/plain"})
    assert no_ctype.status_code == 415
    assert c.post("/ingest", json=body, headers={"Origin": "http://localhost:8000"}).status_code == 200


def test_api_input_limits_and_malformed_records():
    c = local_client(create_app())
    big = {"records": [{"connector": "cicd", "raw": {"kind": "commit", "author": "a", "sha": "b",
                                                      "blob": "x" * 70_000}}]}
    assert c.post("/ingest", json=big).status_code == 422
    bad_ocsf = {"records": [{"connector": "ocsf", "raw": {"class_uid": "abc"}}]}
    r = c.post("/ingest", json=bad_ocsf)
    assert r.status_code == 422 and "ValueError" in r.text


def test_body_size_limit_middleware():
    from fastapi import FastAPI

    from throughline.api import BodySizeLimit
    app = FastAPI()

    @app.post("/echo")
    async def echo(payload: dict) -> dict:
        return {"n": len(payload)}

    app.add_middleware(BodySizeLimit, max_bytes=100)
    c = local_client(app)
    assert c.post("/echo", json={"a": 1}).status_code == 200
    assert c.post("/echo", json={"a": "x" * 200}).status_code == 413


def test_api_as_of_answers_from_the_claims_known_then():
    c = local_client(create_app())
    before = c.get("/investigate/checkout-7", params={"as_of": "2026-01-05T09:30:00Z"})
    assert before.status_code == 404                     # the malicious pod was deployed at 10:03
    after = c.get("/investigate/checkout-7", params={"as_of": "2026-01-05T10:10:00Z"})
    assert after.status_code == 200 and after.json()["origin"] == "Author:mallory"
    assert c.get("/incidents", params={"as_of": "not-a-time"}).status_code == 422


def test_cli_errors_are_messages_not_tracebacks(tmp_path, capsys):
    assert main(["explain", "c99999"]) == 2
    assert "no claim 'c99999'" in capsys.readouterr().err
    assert main(["investigate", "no-such-thing"]) == 2
    assert "no entity matches" in capsys.readouterr().err
    assert main(["captures", "--data", str(tmp_path)]) == 2
    assert "no datasets under" in capsys.readouterr().err
    assert main(["store", "verify", str(tmp_path / "nonexistent")]) == 2
    assert not (tmp_path / "nonexistent").exists()


def test_cli_help_documents_every_option(capsys):
    import contextlib

    from throughline.cli import parser
    p = parser()
    subs = next(a for a in p._actions if a.dest == "cmd").choices
    for name, sp in subs.items():
        for act in sp._actions:
            if act.dest != "help":
                assert act.help, f"{name} {act.dest} has no help text"
    with contextlib.suppress(SystemExit):
        main(["--help"])
    assert "capture" in capsys.readouterr().out
