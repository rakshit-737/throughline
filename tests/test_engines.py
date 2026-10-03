"""Sibling engines wired through the graph, on the real fixture captures.

Skipped when the sibling packages are not installed (``pip install -e .[engines]``);
the pure mapping functions are tested without them.
"""
from __future__ import annotations

import importlib.util
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
from conftest import FIX, needs

from throughline.connectors.otrf import load_catalog
from throughline.engines import SIBLINGS, status
from throughline.engines.malware import SpecimenMalwareEngine
from throughline.engines.network import flow_claims
from throughline.engines.supplychain import lineage_claims, osv_claims
from throughline.graph import KnowledgeGraph
from throughline.stack import Stack, capture_records

ALL = ("anvil", "revenant", "rootline", "dragnet", "occam", "vantage", "gauntlet")


def test_sibling_table_is_pinned_and_complete():
    projects = {s.project for s in SIBLINGS}
    assert projects == {"ANVIL", "FEINT", "REVENANT", "ROOTLINE", "DRAGNET", "OCCAM", "VANTAGE", "GAUNTLET",
                        "TRACEGATE", "STRATUM", "LINCHPIN", "VITRINE", "SPECIMEN"}
    for s in SIBLINGS:
        assert re.fullmatch(r"v\d+\.\d+\.\d+", s.tag), s
        assert re.fullmatch(r"[0-9a-f]{40}", s.sha), s
        assert s.pip_spec.startswith(f"{s.dist} @ git+https://github.com/rakshit-737/")
        assert importlib.util.find_spec(f"throughline.engines.{s.module}") is not None, s.module
    assert len(status()) == len(SIBLINGS)


def test_pyproject_extras_match_the_sibling_table():
    """The ``engines``/``network`` extras and SIBLINGS are one pin set: same dist, repo and tag."""
    data = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(encoding="utf-8"))
    extras = data["project"]["optional-dependencies"]
    git_reqs = {r for name in ("engines", "network") for r in extras[name] if " @ git+" in r}
    assert git_reqs == {s.pip_spec for s in SIBLINGS}
    for s in SIBLINGS:
        assert s.pip_spec in extras[s.extra], (s.project, s.extra)


@pytest.fixture(scope="module")
def comsvcs_run():
    st = Stack.from_data_dir(FIX)
    caps = {c.id: c for c in load_catalog(st.paths.otrf)}
    kg, summary, ctx = st.run(capture_records(caps["SDWIN-201018195009"]))
    return kg, summary, ctx


@needs("anvil", "revenant", "rootline", "dragnet", "occam", "vantage", "gauntlet")
def test_full_stack_on_real_lsass_dump_capture(comsvcs_run):
    kg, summary, ctx = comsvcs_run
    assert summary["rejected_total"] == 0 and not summary["skipped_engines"]
    assert all(summary["engines"][n] >= 0 for n in summary["engines"])
    top = ctx["incidents"][0]
    # the labelled technique is the incident's most confident claim ...
    assert max(top["technique_conf"], key=top["technique_conf"].get) == "T1003.001"
    # ... and Sigma (ANVIL) and provenance (REVENANT) corroborate it
    srcs = top["technique_sources"]["T1003.001"]
    assert set(srcs) == {"anvil", "revenant"}
    assert top["technique_conf"]["T1003.001"] > max(srcs.values())
    # ROOTLINE re-derived membership from its own provenance graph
    assert any(kg.claims[c].source == "rootline" for _, _, k, d in kg.g.in_edges(top["incident"], keys=True, data=True)
               if k == "PART_OF" for c in d["claims"])
    # both intel engines were consulted; posture saw the detections fire
    attrs = kg.g.nodes[top["incident"]]["attrs"]
    assert "dragnet_verdict" in attrs and "occam_verdict" in attrs
    assert ctx["posture"]["T1003.001"]["status"] == "detected"


@needs("anvil")
def test_sigma_alerts_carry_level_as_reliability(comsvcs_run):
    kg, _, _ = comsvcs_run
    alerts = [kg.claims[c] for _, _, k, d in kg.g.edges(keys=True, data=True) if k == "ALERTED_ON" for c in d["claims"]]
    assert alerts and {a.source for a in alerts} == {"anvil"}
    levels = {kg.g.nodes[a.subject]["attrs"]["level"]: a.reliability for a in alerts}
    assert levels.get("high") == "B" and levels.get("medium") == "C"


@needs("anvil")
def test_feedback_loop_drafts_a_gated_rule_from_real_capture():
    from throughline.reasoning.loop import close_gap, view
    caps = load_catalog(FIX / "otrf")
    views = {c.id: view(c.id, c.techniques, c.records()) for c in caps}
    target = views["SDWIN-201018195009"]
    r = close_gap(target, [v for k, v in views.items() if k != target.id])
    assert r.drafted >= 1 and r.accepted
    acc = r.accepted[0]
    assert acc["own_hits"] > 0 and acc["fp_hits"] == 0
    assert "reviewed: false" in acc["yaml"] and "status: experimental" in acc["yaml"]


@needs("tracegate")
def test_tracegate_lineage_on_a_real_git_history(tmp_path):
    from throughline.engines.supplychain import TracegateSupplyChainEngine
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*a):
        subprocess.run(["git", "-c", "user.email=dev@example.org", "-c", "user.name=dev", *a], cwd=repo,
                       check=True, capture_output=True)
    git("init", "-q")
    (repo / "requirements.txt").write_text("requests==2.19.0\n")
    git("add", ".")
    git("commit", "-qm", "add requests")
    (repo / "requirements.txt").write_text("requests==2.19.0\nurllib3==1.23\n")
    git("commit", "-qam", "pin urllib3")
    kg = KnowledgeGraph()
    eng = TracegateSupplyChainEngine(repo, osv_cache=None)
    eng.run(kg, {})
    dep = "Dependency:urllib3==1.23"
    chain = kg.root_cause_chain(dep)
    assert chain[0] == "Author:dev@example.org" and chain[1].startswith("Commit:") and chain[-1] == dep
    assert kg.g.nodes[chain[1]]["attrs"]["subject"] == "pin urllib3"


def test_lineage_and_osv_mapping_without_siblings():
    class MC:
        sha, author, timestamp, subject, added, removed = "a" * 40, "eve", 1_600_000_000, "bump", {"django": "2.0"}, {}
    kg = KnowledgeGraph()
    lineage_claims(kg, [MC()])
    osv_claims(kg, {"django==2.0": ["GHSA-xxxx"]}, "2020-09-13T12:26:40Z")
    assert kg.root_cause_chain("Dependency:django==2.0")[0] == "Author:eve"
    assert "Vulnerability:GHSA-xxxx" in {s for s, _ in kg.g.in_edges("Dependency:django==2.0")}


@needs("stratum")
def test_stratum_lifecycle_incident_reaches_commit_and_author():
    from throughline.engines.supplychain import StratumEngine
    kg = KnowledgeGraph()
    eng = StratumEngine()
    eng.run(kg, {})
    incs = [n for n in kg.g if n.startswith("Incident:stratum-")]
    assert incs
    attrs = kg.g.nodes[incs[0]]["attrs"]
    assert attrs["engine"] == "STRATUM" and attrs["commit"] and attrs["failed_controls"]
    pods = [n for n in kg.g if n.startswith("Pod:")]
    assert any(kg.root_cause_chain(p)[0].startswith(("Commit:", "Author:", "ImageLayer:")) for p in pods)


@needs("linchpin")
def test_linchpin_attack_paths_become_can_reach_claims():
    from throughline.engines.attackpath import LinchpinAttackPathEngine
    kg = KnowledgeGraph()
    eng = LinchpinAttackPathEngine(k=5, budget=2, synth_hosts=12)
    out = eng.run(kg, {})
    assert out and eng.paths
    assert any(c.predicate == "CAN_REACH" for c in out)
    assert any(d["attrs"].get("linchpin_fix_rank") == 1 for _, d in kg.g.nodes(data=True))


@needs("vitrine")
def test_vitrine_static_triage_on_inert_synthetic_samples():
    from vitrine.synth import corpus

    from throughline.engines.malware import VitrineMalwareEngine
    data = [b for _, b in corpus(2, 1)][:4]
    kg = KnowledgeGraph()
    eng = VitrineMalwareEngine(samples=data)
    eng.run(kg, {})
    assert len(eng.results) == 4
    assert all(f"Sample:{r.sha256.lower()}" in kg.g for r in eng.results)


def test_specimen_report_mapping_links_to_process_by_hash():
    kg = KnowledgeGraph()
    kg.add_claim("Process", "h/1/a.exe", "EXISTS", None, None, source="sysmon", method="observed",
                 reliability="B", timestamp="2020-01-01T00:00:00Z")
    kg.set_attrs("Process:h/1/a.exe", {"sha256": "ABC123"})
    rep = {"sample": {"sha256": "abc123"}, "verdict": {"label": "malicious", "score": 0.93},
           "behavior": {"family": "emotet", "family_similarity": 0.81}, "techniques": ["T1055", "T1547.001"]}
    SpecimenMalwareEngine.claims_from_report(kg, rep)
    assert kg.g.has_edge("Process:h/1/a.exe", "Sample:abc123", "USES")
    assert kg.g.has_edge("Sample:abc123", "MalwareFamily:emotet", "ATTRIBUTED_TO")
    assert kg.g.has_edge("Sample:abc123", "Technique:T1055", "EXHIBITS")


def test_feint_flow_mapping():
    kg = KnowledgeGraph()
    out = flow_claims(kg, [{"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 22, "label": "SSH-Patator"},
                           {"src_ip": "10.0.0.6", "dst_ip": "198.51.100.1", "dst_port": 443}], [0.97, 0.2])
    assert len(out) == 2
    assert kg.g.has_edge("Host:10.0.0.5", "Technique:T1110", "EXHIBITS")
    assert "Host:10.0.0.6" not in kg.g


@needs("specimen")
def test_specimen_run_on_a_benign_synthetic_cape_report():
    # the real run path (specimen.pipeline.run_report) on a tiny, benign, reduced CAPE-style report
    rep = FIX.parent / "cape_benign_summary.json"
    eng = SpecimenMalwareEngine([rep])
    kg = KnowledgeGraph()
    eng.run(kg, {})
    assert len(eng.results) == 1
    sha = "0f343b0931126a20f133d67c2b018a3b5e5e1d6c3f1a6b1f2a41d7b8a5e2c9d1"
    assert f"Sample:{sha}" in kg.g


@needs("feint")
def test_feint_engine_run_path_with_a_detector():
    import feint  # noqa: F401  (the pinned FEINT installs and imports)

    from throughline.engines.network import FeintNetworkEngine

    class Detector:  # stands in for a trained FEINT model: P(attack) per flow
        def predict_proba(self, X):
            return [0.91 if row[0] else 0.05 for row in X]

    flows = {"X": [[1], [0]], "meta": [{"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 22,
                                         "label": "SSH-Patator"},
                                        {"src_ip": "10.0.0.6", "dst_ip": "198.51.100.1", "dst_port": 443}]}
    kg = KnowledgeGraph()
    out = FeintNetworkEngine(detector=Detector()).run(kg, {"flows": flows})
    assert len(out) == 2 and kg.g.has_edge("Host:10.0.0.5", "Technique:T1110", "EXHIBITS")
    assert "Host:10.0.0.6" not in kg.g
