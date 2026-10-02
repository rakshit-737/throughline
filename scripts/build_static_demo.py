"""Pre-render the investigation console as a static page for the docs site.

Runs demo worlds through the real API (in-process, no server), saves every
response the console needs, and writes ``<out>/index.html`` in static mode:

* ``capture`` - the committed real OTRF fixture (an LSASS dump through
  ``comsvcs.dll``) through every installed sibling engine: incidents, fused
  technique confidence, two-engine corroboration and the UNKNOWN attribution.
  Skipped (with a message) when the engines extra is not installed.
* ``synthetic`` - the built-in supply-chain intrusion (``checkout-7``).

Nothing here contacts a network.

    python scripts/build_static_demo.py docs/demo
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from throughline.api import UI, create_app  # noqa: E402
from throughline.engines import sibling  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "data"
CAPTURE = "SDWIN-201018195009"
ENGINES = ("anvil", "revenant", "rootline", "dragnet", "occam", "vantage", "gauntlet")


def skey(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)


def render(app, out: Path, queries: list[str]) -> tuple[int, int]:
    """Save every response the console needs for ``queries`` plus every incident."""
    out.mkdir(parents=True, exist_ok=True)
    c = TestClient(app, base_url="http://localhost")

    def save(url: str) -> dict | list:
        r = c.get(url)
        r.raise_for_status()
        (out / f"{skey(url)}.json").write_text(json.dumps(r.json()), encoding="utf-8")
        return r.json()

    save("/health")
    qs = list(dict.fromkeys(queries + [i["incident"] for i in save("/incidents")]))
    claims: set[str] = set()
    for q in qs:
        a = save(f"/investigator/{q}")
        claims.update(re.findall(r"\bc\d{5}\b", a.get("report", "")))
        f = save(f"/investigate/{a.get('incident') or a.get('entity')}")
        for fact in f.get("facts", [])[:80]:
            claims.update(fact.get("claims", [])[:4])
    for cid in sorted(claims):
        save(f"/claims/{quote(cid)}/explain")
    return len(qs), len(claims)


def main(out: str = "docs/demo") -> int:
    root = Path(out)
    api = root / "api"
    worlds = []
    if all(sibling(e).installed for e in ENGINES):
        n = render(create_app(capture=CAPTURE, data=str(FIXTURE)), api / "capture", [])
        worlds.append({"id": "capture", "title": f"Real OTRF capture {CAPTURE}: LSASS dump via comsvcs.dll",
                       "queries": n[0], "claims": n[1]})
    else:
        print("engines extra not installed: the static demo has the synthetic world only", file=sys.stderr)
    n = render(create_app(), api / "synthetic", ["checkout-7"])
    worlds.append({"id": "synthetic", "title": "Synthetic supply-chain intrusion (checkout-7)",
                   "queries": n[0], "claims": n[1]})
    (api / "worlds.json").write_text(json.dumps(worlds, indent=1), encoding="utf-8")
    html = UI.read_text(encoding="utf-8").replace("<html", '<html data-static="api/"', 1)
    (root / "index.html").write_text(html, encoding="utf-8")
    for w in worlds:
        print(f"static demo world {w['id']}: {w['queries']} queries, {w['claims']} claims -> {api / w['id']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
