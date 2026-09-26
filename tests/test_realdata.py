"""Checks against the full downloaded datasets; skipped when they are absent (CI)."""
from __future__ import annotations

import pytest
from conftest import needs, real_data_root

from throughline.attack import AttackCatalog
from throughline.connectors.otrf import load_catalog

ROOT = real_data_root()
pytestmark = [pytest.mark.realdata,
              pytest.mark.skipif(ROOT is None, reason="real data not downloaded (scripts/download_data.py all)")]


def test_attack_bundle_v19_2():
    cat = AttackCatalog.load(ROOT / "attack" / "enterprise-attack-19.2.json")
    s = cat.summary()
    assert s["version"] == "19.2" and s["techniques"] == 697 and s["groups"] == 176 and s["attributed_campaigns"] == 25


def test_otrf_catalog_has_the_labelled_captures():
    caps = [c for c in load_catalog(ROOT / "otrf") if c.techniques]
    assert len(caps) >= 95
    assert sum(c.available for c in caps) >= 90   # a few logs may be quarantined by local antivirus


@needs("anvil", "revenant")
def test_one_real_capture_end_to_end():
    from throughline.stack import Stack, capture_records
    st = Stack.from_data_dir(ROOT, engines=("anvil", "revenant", "correlation"))
    cap = next(c for c in load_catalog(st.paths.otrf) if c.id == "SDWIN-201018195009")
    kg, summary, ctx = st.run(capture_records(cap))
    assert summary["rejected_total"] == 0
    assert "T1003.001" in ctx["incidents"][0]["technique_conf"]
