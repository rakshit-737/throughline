"""Graph mechanics, correlation, the investigator, calibration and the event store."""
from __future__ import annotations

import json
import random

import pytest

from throughline import synth
from throughline.eventstore import EventStore
from throughline.graph import KnowledgeGraph
from throughline.pipeline import build
from throughline.reasoning import calibration as cal
from throughline.reasoning.correlation import CorrelationEngine, noisy_or, story_root
from throughline.reasoning.investigator import Investigator

TS = "2020-01-01T00:00:00Z"


def _proc(kg, parent, child, src="sysmon"):
    pt, pid = parent.split(":", 1)
    ct, cid = child.split(":", 1)
    return kg.add_claim(pt, pid, "SPAWNED", ct, cid, source=src, method="observed", reliability="B", timestamp=TS)


def test_deferred_confidence_equals_eager():
    recs = synth.generate(false_flag=True)["records"]
    eager, _ = build(recs)
    kg = KnowledgeGraph()
    kg.defer_confidence = True
    from throughline.normalizer import normalize
    for c, raw, rel in recs:
        kg.ingest(normalize(raw, c, reliability=rel))
    kg.finalize()
    # same assertions, same confidences (engines are not run on the deferred copy)
    for cid, c in kg.claims.items():
        assert eager.claims[cid].confidence == pytest.approx(c.confidence) or c.predicate == "EXHIBITS"


def test_engine_score_sets_base_confidence():
    kg = KnowledgeGraph()
    c = kg.add_claim("Incident", "i", "ATTRIBUTED_TO", "Actor", "X", source="e", method="inferred",
                     reliability="A", timestamp=TS, score=0.8)
    assert c.base_confidence == 0.8


def test_root_cause_ignores_annotation_edges():
    kg = KnowledgeGraph()
    _proc(kg, "Process:h/1/explorer.exe", "Process:h/2/cmd.exe")
    kg.add_claim("Detection", "r1", "ALERTED_ON", "Process", "h/2/cmd.exe", source="anvil", method="inferred",
                 reliability="B", timestamp="2019-01-01T00:00:00Z")  # earlier, but not a cause
    assert kg.root_cause_chain("Process:h/2/cmd.exe") == ["Process:h/1/explorer.exe", "Process:h/2/cmd.exe"]
    assert "Detection:r1" not in kg.blast_radius("Process:h/1/explorer.exe")


def _two_engine_world():
    kg = KnowledgeGraph()
    _proc(kg, "Process:h/1/explorer.exe", "Process:h/2/powershell.exe")
    _proc(kg, "Process:h/2/powershell.exe", "Process:h/3/rundll32.exe")
    _proc(kg, "Process:h/9/services.exe", "Process:h/10/svchost.exe")
    kg.tag_technique("Process:h/3/rundll32.exe", "T1003.001", "sigma", source="anvil", ts=TS, reliability="B")
    kg.tag_technique("Process:h/2/powershell.exe", "T1003.001", "heuristic", source="revenant", ts=TS,
                     reliability="C", score=0.85)
    kg.tag_technique("Process:h/10/svchost.exe", "T1053", "sigma", source="anvil", ts=TS, reliability="D")
    return kg


def test_story_root_stops_at_boundary_processes():
    kg = _two_engine_world()
    root, path = story_root(kg, "Process:h/3/rundll32.exe")
    assert root == "Process:h/2/powershell.exe" and path[-1] == "Process:h/3/rundll32.exe"


def test_correlation_fuses_independent_engines_per_incident():
    kg = _two_engine_world()
    ctx: dict = {}
    CorrelationEngine().run(kg, ctx)
    incs = {i["incident"]: i for i in ctx["incidents"]}
    assert len(incs) == 2                                        # the svchost signal is its own incident
    top = ctx["incidents"][0]
    a, r = 0.9 * 0.7, 0.85 * 0.75
    assert top["technique_conf"]["T1003.001"] == pytest.approx(noisy_or([a, r]), abs=1e-3)
    assert top["technique_conf"]["T1003.001"] > max(a, r)       # agreement raises confidence
    assert set(top["technique_sources"]["T1003.001"]) == {"anvil", "revenant"}
    edge = kg.g.edges[top["incident"], "Technique:T1003.001", "EXHIBITS"]
    assert edge["confidence"] == pytest.approx(top["technique_conf"]["T1003.001"], abs=1e-3)  # not re-counted


def test_investigator_is_deterministic_and_cites_claims():
    kg = _two_engine_world()
    CorrelationEngine().run(kg, {})
    a = Investigator(kg).investigate("rundll32.exe")
    b = Investigator(kg).investigate("rundll32.exe")
    assert a["trace"] == b["trace"]
    assert a["incident"].startswith("Incident:h/2/")
    tools = [s["tool"] for s in a["trace"]]
    assert tools[:2] == ["incident", "techniques"] and "root_cause" in tools
    assert any(s["cites"] for s in a["trace"])
    before = kg.stats()
    Investigator(kg).investigate("rundll32.exe")
    assert kg.stats() == before                                 # read-only


def test_calibration_metrics_and_platt():
    assert cal.brier([(1.0, True), (0.0, False)]) == 0.0
    assert cal.ece([(0.9, True)] * 9 + [(0.9, False)]) == pytest.approx(0.0)
    assert cal.auc([(0.9, True), (0.1, False)]) == 1.0
    rng = random.Random(0)
    # over-confident scores: true rate is ~half the stated confidence
    pairs = [(p, rng.random() < p / 2) for p in (rng.uniform(0.5, 1.0) for _ in range(600))]
    pl = cal.Platt.fit(pairs)
    fitted = [(pl(p), y) for p, y in pairs]
    assert cal.brier(fitted) < cal.brier(pairs)
    assert cal.ece(fitted) < cal.ece(pairs)


def test_event_store_detects_tampering(tmp_path):
    st = EventStore(tmp_path / "store")
    refs = st.append([("windows", {"EventID": 1, "Image": "a.exe"}), ("windows", {"EventID": 3})], note="batch1")
    st.append([("windows", {"EventID": 11})])
    assert st.verify()["ok"] and len(st) == 3
    assert st.get(refs[1])["raw"] == {"EventID": 3}
    assert len(EventStore(tmp_path / "store")) == 3            # reopen keeps the sequence
    shard = next((tmp_path / "store").glob("events-*.jsonl"))
    lines = shard.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["raw"]["Image"] = "evil.exe"
    lines[0] = json.dumps(rec, sort_keys=True)
    shard.write_text("\n".join(lines) + "\n")
    rep = EventStore(tmp_path / "store").verify()
    assert not rep["ok"] and rep["tampered_records"] == [0] and rep["broken_ledger_entries"] == [0]


def test_event_store_detects_unledgered_and_truncated_tails(tmp_path):
    from throughline.contracts import canonical_hash
    from throughline.eventstore import StoreError
    st = EventStore(tmp_path / "s")
    st.append([("windows", {"EventID": 1}), ("windows", {"EventID": 3})])
    head = st.head
    assert st.verify(expect_head=head)["ok"]
    # a well-formed record appended without a ledger entry is flagged
    raw = {"EventID": 99}
    with open(next((tmp_path / "s").glob("events-*.jsonl")), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"seq": 2, "connector": "windows", "sha256": canonical_hash(raw), "raw": raw},
                            sort_keys=True) + chr(10))
    rep = EventStore(tmp_path / "s").verify()
    assert not rep["ok"] and rep["unledgered_records"] == [2]
    # a ledger extended by someone else no longer matches the head recorded off-host
    st2 = EventStore(tmp_path / "s2")
    st2.append([("windows", {"EventID": 1})])
    anchored = st2.head
    st2.append([("windows", {"EventID": 2})])
    assert st2.verify()["ok"] and not st2.verify(expect_head=anchored)["ok"]
    # empty or missing stores are not "ok"; opening for verify never creates a directory
    assert not EventStore(tmp_path / "empty").verify()["ok"]
    assert EventStore(tmp_path / "empty").verify(allow_empty=True)["ok"]
    with pytest.raises(StoreError):
        EventStore(tmp_path / "missing", create=False)
    assert not (tmp_path / "missing").exists()
    # get() checks the digest in the reference
    ref = st2.append([("windows", {"EventID": 5})])[0]
    assert st2.get(ref)["raw"] == {"EventID": 5}
    with pytest.raises(KeyError):
        st2.get(ref.split("#")[0] + "#" + "0" * 64)


def test_event_store_ledger_hmac(tmp_path):
    st = EventStore(tmp_path / "k", key="secret-key")
    st.append([("windows", {"EventID": 1})])
    assert st.verify()["ok"] and st.verify()["keyed"]
    assert not EventStore(tmp_path / "k", key="other-key").verify()["ok"]


def test_stitch_joins_hosts_sharing_a_rare_destination():
    from throughline.reasoning.correlation import stitch
    incs = [{"incident": f"Incident:{h}/{n}"} for h, n in (("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5"))]
    dests = {"Incident:a/1": {"IPAddress:6.6.6.6:443"}, "Incident:b/2": {"IPAddress:6.6.6.6:443"},
             "Incident:c/3": {"IPAddress:10.0.0.1:389"}, "Incident:d/4": {"IPAddress:10.0.0.1:389"},
             "Incident:e/5": {"IPAddress:10.0.0.1:389"}}
    out = stitch(incs, dests, max_fanout=2)
    assert out["Incident:a/1"]["cluster"] == out["Incident:b/2"]["cluster"]
    assert out["Incident:a/1"]["hosts"] == ["a", "b"] and out["Incident:a/1"]["via"] == ["IPAddress:6.6.6.6:443"]
    # a destination shared by more than max_fanout incidents is common infrastructure
    assert len({out[i]["cluster"] for i in ("Incident:c/3", "Incident:d/4", "Incident:e/5")}) == 3


def test_correlation_stitches_cross_host_incidents():
    kg = KnowledgeGraph()
    for h in ("h1", "h2"):
        _proc(kg, f"Process:{h}/1/explorer.exe", f"Process:{h}/2/beacon.exe")
        kg.add_claim("Process", f"{h}/2/beacon.exe", "CONNECTED_TO", "IPAddress", "6.6.6.6:443",
                     source="sysmon", method="observed", reliability="B", timestamp=TS)
        kg.tag_technique(f"Process:{h}/2/beacon.exe", "T1071", "sigma", source="anvil", ts=TS, reliability="B")
    ctx: dict = {}
    CorrelationEngine().run(kg, ctx)
    assert len(ctx["incidents"]) == 2 and len(ctx["clusters"]) == 1
    assert ctx["incidents"][0]["cluster_hosts"] == ["h1", "h2"]


def _net(kg, proc, dest, ts=TS, local_ip=None):
    kg.add_claim("Process", proc.split(":", 1)[1], "CONNECTED_TO", "IPAddress", dest.split(":", 1)[1],
                 source="sysmon", method="observed", reliability="B", timestamp=ts)
    if local_ip:
        kg.set_attrs(proc, {"local_ip": local_ip})


def test_stitching_ignores_loopback_infrastructure_and_system_traffic():
    from throughline.reasoning.correlation import evidence_destination, routable

    assert not routable("127.0.0.1") and not routable("::1") and not routable("fe80::1") and not routable("localhost")
    assert routable("192.168.0.5") and routable("evil.example")
    assert not evidence_destination("IPAddress:10.0.0.4:88")       # Kerberos on the DC
    assert not evidence_destination("IPAddress:10.0.0.4:49667")    # dynamic RPC
    assert not evidence_destination("Domain:localhost")
    assert evidence_destination("IPAddress:192.168.0.5:443")
    kg = KnowledgeGraph()
    for h in ("h1", "h2"):
        _proc(kg, f"Process:{h}/1/explorer.exe", f"Process:{h}/2/tool.exe")
        kg.tag_technique(f"Process:{h}/2/tool.exe", "T1003", "sigma", source="anvil", ts=TS, reliability="B")
        _net(kg, f"Process:{h}/2/tool.exe", "IPAddress:10.0.0.4:88")       # every host talks to the DC
        _net(kg, f"Process:{h}/2/tool.exe", "IPAddress:127.0.0.1:8080")    # loopback
        # an OS process inside the incident talks to a shared cloud endpoint: not evidence either
        _proc(kg, f"Process:{h}/2/tool.exe", f"Process:{h}/3/backgroundtaskhost.exe")
        kg.tag_technique(f"Process:{h}/3/backgroundtaskhost.exe", "T1105", "sigma", source="anvil", ts=TS,
                         reliability="C")
        _net(kg, f"Process:{h}/3/backgroundtaskhost.exe", "IPAddress:52.167.250.154:443")
    ctx: dict = {}
    CorrelationEngine().run(kg, ctx)
    assert len(ctx["clusters"]) == 2


def test_stitching_host_fanout_and_lateral_link():
    from throughline.reasoning.correlation import stitch

    incs = [{"incident": "Incident:a/1"}, {"incident": "Incident:b/2"}]
    dests = {"Incident:a/1": {"IPAddress:6.6.6.6:443"}, "Incident:b/2": {"IPAddress:6.6.6.6:443"}}
    # contacted by 3 of 4 hosts in all (> max(2, 4 // 2)): common infrastructure, not joined
    fan = {"IPAddress:6.6.6.6:443": {"a", "b", "c"}}
    assert stitch(incs, dests, 3, fan, 4)["Incident:a/1"]["cluster"] != stitch(incs, dests, 3, fan, 4)[
        "Incident:b/2"]["cluster"]
    # PsExec-style lateral movement: a member on h1 connects to h2's SMB port, and an incident on h2
    # starts under psexesvc.exe a minute later -> one cluster, with the lateral evidence
    kg = KnowledgeGraph()
    _proc(kg, "Process:h1/1/explorer.exe", "Process:h1/2/psexec64.exe")
    kg.tag_technique("Process:h1/2/psexec64.exe", "T1570", "sigma", source="anvil", ts=TS, reliability="B")
    _net(kg, "Process:h1/2/psexec64.exe", "IPAddress:10.0.1.6:445", local_ip="10.0.1.4")
    _net(kg, "Process:h2/9/updater.exe", "IPAddress:93.184.216.34:443", local_ip="10.0.1.6")
    later = "2020-01-01T00:01:00Z"
    kg.add_claim("Process", "h2/5/psexesvc.exe", "SPAWNED", "Process", "h2/6/python.exe", source="sysmon",
                 method="observed", reliability="B", timestamp=later)
    kg.tag_technique("Process:h2/6/python.exe", "T1059", "sigma", source="anvil", ts=later, reliability="B")
    ctx: dict = {}
    CorrelationEngine().run(kg, ctx)
    assert len(ctx["clusters"]) == 1
    via = ctx["incidents"][0]["cluster_via"]
    assert any(v.startswith("lateral h1->h2 psexec64.exe 10.0.1.6:445") for v in via)
