import pytest
from conftest import local_client

from throughline import confidence as conf
from throughline import synth
from throughline.api import create_app
from throughline.cli import main
from throughline.contracts import Claim, ContractError
from throughline.graph import KnowledgeGraph
from throughline.modules import SIBLING_SLOTS, EngineRegistry, default_registry
from throughline.neo4j_adapter import batches, statements
from throughline.normalizer import normalize, verify
from throughline.pipeline import build, investigate


# ---------- normalizer / contracts ----------
def test_normalize_endpoint_process_create():
    raw = {"kind": "process_create", "host": "h", "ppid": 1, "pid": 2, "ts": "2026-01-01T00:00:00Z"}
    ev = normalize(raw, "endpoint")
    assert (ev.actor_id, ev.action, ev.object_id) == ("h/1", "SPAWNED", "h/2")
    assert ev.method == "observed" and 0 < ev.confidence <= 1
    assert verify(ev, raw)
    assert not verify(ev, {**raw, "pid": 3})  # tamper detected


def test_normalize_is_deterministic():
    raw = {"kind": "commit", "author": "a", "sha": "abc", "ts": "t"}
    assert normalize(raw, "cicd").event_id == normalize(dict(raw), "cicd").event_id


@pytest.mark.parametrize("raw,connector", [
    ({"kind": "nope"}, "endpoint"),
    ({"kind": "commit", "author": "a", "sha": "x"}, "unknown-connector"),
    ({"layer": "runtime", "actor_type": "Evil", "actor_id": "1", "action": "SPAWNED",
      "object_type": "Process", "object_id": "2"}, "canonical"),
    ({"layer": "runtime", "actor_type": "Process", "actor_id": "1", "action": "DROP TABLE",
      "object_type": "Process", "object_id": "2"}, "canonical"),
    ({"kind": "file_write", "host": "h", "pid": 1, "path": "A" * 5000}, "endpoint"),
])
def test_normalizer_rejects_bad_input(raw, connector):
    with pytest.raises(ContractError):
        normalize(raw, connector)


# ---------- confidence ----------
def _c(cid, src, method="observed", rel="B"):
    return Claim(cid, "x", "s", "P", "o", src, method, "t", rel, conf.base_confidence(method, rel))


def test_method_ordering():
    assert conf.base_confidence("observed", "B") > conf.base_confidence("inferred", "B") \
        > conf.base_confidence("predicted", "B")


def test_independent_corroboration_raises_but_same_source_does_not():
    a = _c("1", "s1")
    assert conf.combine(a, [_c("2", "s2")], []) > conf.combine(a, [], [])
    assert conf.combine(a, [_c("3", "s1")], []) == conf.combine(a, [], [])


def test_contradiction_lowers_confidence():
    a = _c("1", "s1")
    assert conf.combine(a, [], [_c("2", "s2")]) < conf.combine(a, [], [])


def test_brier():
    assert conf.brier([(1.0, True), (0.0, False)]) == 0.0
    assert conf.brier([(0.5, True)]) == 0.25


# ---------- graph ----------
def test_graph_rejects_unknown_types():
    kg = KnowledgeGraph()
    with pytest.raises(ContractError):
        kg.add_claim("Process", "1", "HACKS", "Process", "2", source="s", method="observed",
                      reliability="A", timestamp="t")


def test_exclusive_attribution_conflict():
    kg = KnowledgeGraph()
    kw = dict(method="stated", reliability="B", timestamp="t")
    c1 = kg.add_claim("IPAddress", "1.2.3.4:443", "ATTRIBUTED_TO", "Actor", "A", source="f1", **kw)
    before = c1.confidence
    kg.add_claim("IPAddress", "1.2.3.4:443", "ATTRIBUTED_TO", "Actor", "B", source="f2", **kw)
    assert c1.confidence < before and c1.contradicts
    assert kg.explain_claim(c1.claim_id)["contradicting"]


# ---------- end-to-end on synthetic enterprise ----------
@pytest.fixture(scope="module")
def world():
    data = synth.generate()
    kg, summary = build(data["records"])
    return kg, summary, data["truth"]


def test_build_has_no_rejections(world):
    _, summary, _ = world
    assert summary["rejected"] == [] and summary["claims"] > summary["events"]


def test_one_query_investigation_recovers_ground_truth(world):
    kg, _, truth = world
    r = investigate(kg, "checkout-7")
    assert r["origin"] == "Author:mallory"
    assert "Commit:deadbeef01" in r["root_cause_chain"]
    assert truth["malicious_nodes"] <= set(r["nodes"])
    assert set(r["techniques"]) == truth["techniques"]
    assert list(r["attribution"])[0] == truth["attacker"]
    assert all(f["claims"] for f in r["facts"])  # every fact cites claims


def test_benign_pods_not_implicated(world):
    kg, _, _ = world
    r = investigate(kg, "cart-1")
    assert "Commit:deadbeef01" not in r["root_cause_chain"]
    assert r["techniques"] == []


def test_false_flag_lowers_attribution_confidence():
    clean, _ = build(synth.generate()["records"])
    ff, _ = build(synth.generate(false_flag=True)["records"])
    a = investigate(clean, "checkout-7")["attribution"]["Actor:APT-Example"]
    b = investigate(ff, "checkout-7")["attribution"]
    assert b["Actor:APT-Example"] < a and "Actor:APT-Decoy" in b


def test_blast_radius(world):
    kg, _, _ = world
    br = kg.blast_radius("Dependency:colorama-utils==0.0.9")
    assert "Pod:checkout-7" in br and "IPAddress:203.0.113.66:443" in br


# ---------- modules ----------
def test_registry_and_sibling_slots():
    reg = default_registry()
    names = {e.name for e in reg.engines}
    assert {"attack-mapping", "attack-path", "intel", "simulation"} <= names
    assert {s.project for s in SIBLING_SLOTS} >= {"LINCHPIN", "VANTAGE", "TRACEGATE"}
    with pytest.raises(TypeError):
        EngineRegistry().register(object())


# ---------- neo4j adapter ----------
def test_cypher_is_parameterized(world):
    kg, _, _ = world
    stmts = statements(kg)
    assert stmts and all("$" in q for q, _ in stmts)
    assert not any("deadbeef01" in q for q, _ in stmts)


def test_neo4j_batches_cover_graph(world):
    kg, _, _ = world
    b = batches(kg, size=7)
    assert all("$rows" in q for q, _ in b)
    rows = [r for q, p in b for r in p["rows"]]
    assert sum(1 for q, p in b if "MERGE (n:" in q for _ in p["rows"]) == kg.g.number_of_nodes()
    entity_rows = [r for q, p in batches(kg, size=7, claims=False) for r in p["rows"]]
    assert len(entity_rows) == kg.g.number_of_nodes() + kg.g.number_of_edges()
    # the claim layer: one row per claim, linked to its subject (and object), values parameterised
    claim_rows = [r for q, p in b if "MERGE (c:TLClaim" in q for r in p["rows"]]
    assert len(claim_rows) == len(kg.claims) and len(rows) > len(entity_rows)
    assert {r["source"] for r in claim_rows} >= {"cicd", "attack-mapping"}
    assert not any("deadbeef01" in q for q, _ in b)


def test_neo4j_sync_needs_config(monkeypatch):
    monkeypatch.delenv("THROUGHLINE_NEO4J_URI", raising=False)
    assert local_client(create_app()).post("/neo4j/sync").status_code == 404


# ---------- API ----------
def test_api():
    client = local_client(create_app())
    assert client.get("/health").json()["status"] == "ok"
    r = client.get("/investigate/checkout-7").json()
    assert r["origin"] == "Author:mallory"
    cid = r["facts"][0]["claims"][0]
    assert client.get(f"/claims/{cid}/explain").json()["claim"] == cid
    assert client.get("/investigate/nope-404").status_code == 404
    bad = client.post("/ingest", json={"records": [{"connector": "endpoint", "raw": {"kind": "x"}}]})
    assert bad.status_code == 422
    ok = client.post("/ingest", json={"records": [{"connector": "cicd", "reliability": "A",
                     "raw": {"kind": "commit", "author": "dave", "sha": "f00", "ts": "t"}}]})
    assert ok.status_code == 200


def test_cli(capsys):
    assert main(["demo"]) == 0
    assert "Author:mallory" in capsys.readouterr().out
    assert main(["engines"]) == 0
