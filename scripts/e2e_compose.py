#!/usr/bin/env python3
"""End-to-end check against a running docker-compose stack (API + Neo4j).

Waits for the API, runs an investigation over HTTP exactly as an analyst's
client would, mirrors the graph into Neo4j, reads the counts back, asserts on
all of it and writes a JSON artefact.

    python scripts/e2e_compose.py --api http://127.0.0.1:8000 --out e2e.json
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def call(base: str, path: str, method: str = "GET"):
    req = urllib.request.Request(base + path, method=method, data=b"" if method == "POST" else None)
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--out", default="e2e.json")
    ap.add_argument("--wait", type=int, default=900, help="seconds to wait for the API")
    a = ap.parse_args(argv)
    t0 = time.time()
    while True:
        try:
            health = call(a.api, "/health")
            break
        except (urllib.error.URLError, ConnectionError, OSError):
            if time.time() - t0 > a.wait:
                print("API did not come up", file=sys.stderr)
                return 2
            time.sleep(5)
    res: dict = {"health": health, "startup_s": round(time.time() - t0, 1)}
    res["engines"] = call(a.api, "/engines")
    incs = call(a.api, "/incidents")
    res["incidents"] = incs[:5]
    top = incs[0]["incident"] if incs else None
    checks = {"capture_mode": health["mode"].startswith("capture"),
              "graph_nonempty": health.get("nodes", 0) > 0,
              "engines_ran": len(res["engines"]["last_run"]) >= 3,
              "incidents": bool(incs)}
    if top:
        q = urllib.parse.quote(top, safe="")
        inv = call(a.api, f"/investigator/{q}")
        res["investigation"] = {k: inv.get(k) for k in ("query", "entity", "incident", "hypotheses", "report")}
        checks["investigation_has_trace"] = len(inv.get("trace", [])) >= 2
        checks["investigation_cites_claims"] = any(s.get("cites") for s in inv.get("trace", []))
        pivot = call(a.api, f"/graph/{q}")
        checks["graph_neighbourhood"] = len(pivot["nodes"]) > 1
    sync = call(a.api, "/neo4j/sync", "POST")
    res["neo4j"] = sync
    checks["neo4j_nodes_match"] = sync["nodes"] == sync["expected_nodes"]
    checks["neo4j_edges_match"] = sync["edges"] == sync["expected_edges"]
    again = call(a.api, "/neo4j/sync", "POST")
    checks["neo4j_sync_idempotent"] = again["nodes"] == sync["nodes"] and again["edges"] == sync["edges"]
    res["checks"] = checks
    res["ok"] = all(checks.values())
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1, default=str)
    print(json.dumps({"checks": checks, "neo4j": sync, "health": health}, indent=1))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
