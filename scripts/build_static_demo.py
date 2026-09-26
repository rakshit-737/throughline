"""Pre-render the investigation console as a static page for the docs site.

Runs the synthetic demo world through the real API (in-process, no server),
saves every response the console needs for the pre-selected queries, and
writes ``<out>/index.html`` in static mode. Nothing here contacts a network.

    python scripts/build_static_demo.py docs/demo
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

from fastapi.testclient import TestClient

from throughline.api import UI, create_app

QUERIES = ["checkout-7"]


def skey(url: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", url)


def main(out: str = "docs/demo") -> int:
    root = Path(out)
    api = root / "api"
    api.mkdir(parents=True, exist_ok=True)
    c = TestClient(create_app())

    def save(url: str) -> dict | list:
        r = c.get(url)
        r.raise_for_status()
        (api / f"{skey(url)}.json").write_text(json.dumps(r.json()), encoding="utf-8")
        return r.json()

    save("/health")
    queries = QUERIES + [i["incident"] for i in save("/incidents")]
    claims: set[str] = set()
    for q in queries:
        a = save(f"/investigator/{q}")
        claims.update(re.findall(r"\bc\d{5}\b", a.get("report", "")))
        f = save(f"/investigate/{a.get('incident') or a.get('entity')}")
        for fact in f.get("facts", [])[:80]:
            claims.update(fact.get("claims", [])[:4])
    for cid in sorted(claims):
        save(f"/claims/{quote(cid)}/explain")
    html = UI.read_text(encoding="utf-8").replace("<html", '<html data-static="api/"', 1)
    (root / "index.html").write_text(html, encoding="utf-8")
    print(f"static demo: {len(queries)} queries, {len(claims)} claims -> {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
