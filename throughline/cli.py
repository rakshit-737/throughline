"""THROUGHLINE CLI.

Synthetic spine (no downloads):   demo, investigate, explain, export, engines, serve
Real data (scripts/download_data.py, sibling engines installed):
    capture <SDWIN-id | path.zip|.json>   run every engine on an OTRF capture and investigate
    captures                              list the labelled OTRF captures available locally
    store ingest|verify                   append-only raw event store with a hash-chained ledger
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import synth
from .neo4j_adapter import statements
from .pipeline import build, investigate


def _kg(args):
    return build(synth.generate(seed=args.seed, false_flag=args.false_flag)["records"])


def cmd_demo(args) -> int:
    kg, summary = _kg(args)
    print("== THROUGHLINE demo: synthetic supply-chain intrusion (data only) ==")
    print(json.dumps({k: v for k, v in summary.items() if k not in ("rejected", "skipped")}, indent=2))
    r = investigate(kg, args.query)
    print(f"\nQ: What happened with {args.query}?")
    print("Root-cause chain:")
    for i, n in enumerate(r["root_cause_chain"]):
        print(f"  {'  ' * i}-> {n}")
    print("Techniques:", ", ".join(r["techniques"]) or "none")
    print("Attribution (confidence):")
    for a, c in r["attribution"].items():
        print(f"  {a}: {c:.2f}")
    print(f"Facts cited: {len(r['facts'])} (each with claim ids)")
    for f in r["facts"][:8]:
        print(f"  [{f['confidence']:.2f}] {f['subject']} -{f['predicate']}-> {f['object']}  {f['claims']}")
    return 0


def cmd_investigate(args) -> int:
    kg, _ = _kg(args)
    print(json.dumps(investigate(kg, args.query, args.min_conf), indent=2))
    return 0


def cmd_explain(args) -> int:
    kg, _ = _kg(args)
    print(json.dumps(kg.explain_claim(args.claim_id), indent=2))
    return 0


def cmd_export(args) -> int:
    kg, _ = _kg(args)
    if args.format == "cypher":
        for q, p in statements(kg):
            print(q, json.dumps(p))
    else:
        print(json.dumps(kg.to_json(), indent=2, default=str))
    return 0


def cmd_engines(args) -> int:
    from .engines import status
    from .modules import default_registry
    print("built-in / synthetic-demo registry:")
    for e in default_registry().engines:
        proj = getattr(e, "project", "built-in")
        print(f"  {e.name:15} {proj:22} reads={','.join(e.reads)} writes={','.join(e.writes)}")
    print("\nsibling engines (pip install -e .[engines]):")
    for s in status():
        mark = "installed" if s["installed"] else "missing"
        print(f"  {s['project']:10} {s['slot']:13} {mark:10} @{s['commit']}  {s['adapter']:38} {s['note']}")
    return 0


def _capture_records(spec: str, stack):
    from .connectors.otrf import iter_records, load_catalog
    p = Path(spec)
    if p.exists():
        return p.name, [], [("windows", r, "B") for r in iter_records(p)]
    for c in load_catalog(stack.paths.otrf):
        if c.id == spec:
            return f"{c.id} {c.title}", c.techniques, [("windows", r, "B") for r in c.records()]
    raise SystemExit(f"no capture {spec!r}: pass an SDWIN id (see `throughline captures`) or a file path")


def cmd_capture(args) -> int:
    from .reasoning.investigator import Investigator
    from .stack import ALL_ENGINES, Stack
    engines = tuple(args.engines.split(",")) if args.engines else ALL_ENGINES
    st = Stack.from_data_dir(args.data, engines=engines, sigma_subset=args.sigma)
    missing = st.paths.missing()
    if missing:
        raise SystemExit(f"missing data {missing} under {st.paths.root}: run python scripts/download_data.py all")
    title, truth, records = _capture_records(args.capture, st)
    kg, summary, ctx = st.run(records)
    incs = ctx.get("incidents", [])
    out = {"capture": title, "labelled_techniques": truth, "records": len(records),
           "graph": {k: summary[k] for k in ("nodes", "edges", "claims", "events")},
           "engine_claims": summary["engines"], "skipped_engines": summary["skipped_engines"],
           "incidents": [{k: i[k] for k in ("incident", "score", "breadth", "alerts", "technique_conf")}
                         for i in incs[: args.top]]}
    if args.json:
        if incs:
            out["investigation"] = Investigator(kg).investigate(incs[0]["incident"])
        print(json.dumps(out, indent=2, default=str))
        return 0
    print(f"== {title}  ({len(records)} records; labelled: {', '.join(truth) or 'n/a'})")
    print(f"graph: {out['graph']}  engines: {out['engine_claims']}")
    if summary["skipped_engines"]:
        print("skipped engines:", summary["skipped_engines"])
    for i in out["incidents"]:
        techs = ", ".join(f"{t} {c:.2f}" for t, c in sorted(i["technique_conf"].items(), key=lambda x: -x[1])[:6])
        print(f"  {i['incident']}  score={i['score']:.2f}  alerts={i['alerts']}  [{techs}]")
    if incs:
        print()
        print(Investigator(kg).investigate(incs[0]["incident"])["report"])
    return 0


def cmd_captures(args) -> int:
    from .connectors.otrf import load_catalog
    from .stack import DataPaths, data_dir
    p = DataPaths(Path(args.data) if args.data else data_dir())
    for c in load_catalog(p.otrf):
        print(f"{c.id}  {'ok ' if c.available else '-- '} {','.join(c.techniques):22} {c.title}")
    return 0


def cmd_store(args) -> int:
    from .connectors.otrf import iter_records
    from .eventstore import EventStore
    st = EventStore(args.dir)
    if args.action == "ingest":
        n = 0
        for f in args.files:
            refs = st.append((("windows", r) for r in iter_records(f)), note=Path(f).name)
            n += len(refs)
        print(json.dumps({"appended": n, "total": len(st)}))
        return 0
    rep = st.verify()
    print(json.dumps(rep, indent=2))
    return 0 if rep["ok"] else 1


def cmd_serve(args) -> int:  # pragma: no cover
    import uvicorn

    from .api import create_app
    uvicorn.run(create_app(capture=args.capture, data=args.data), host=args.host, port=args.port)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="throughline", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--false-flag", action="store_true", help="inject conflicting attribution (synthetic demo)")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo")
    d.add_argument("--query", default="checkout-7")
    d.set_defaults(fn=cmd_demo)
    i = sub.add_parser("investigate")
    i.add_argument("query")
    i.add_argument("--min-conf", type=float, default=0.0)
    i.set_defaults(fn=cmd_investigate)
    e = sub.add_parser("explain")
    e.add_argument("claim_id")
    e.set_defaults(fn=cmd_explain)
    x = sub.add_parser("export")
    x.add_argument("--format", choices=["json", "cypher"], default="json")
    x.set_defaults(fn=cmd_export)
    sub.add_parser("engines").set_defaults(fn=cmd_engines)
    c = sub.add_parser("capture", help="run all engines on a real OTRF capture")
    c.add_argument("capture", help="SDWIN-... id or path to a .zip/.json capture")
    c.add_argument("--data", default=None, help="dataset root (default: $THROUGHLINE_DATA)")
    c.add_argument("--engines", default="", help="comma list, default: all installed")
    c.add_argument("--sigma", default="core", choices=["core", "all"])
    c.add_argument("--top", type=int, default=5)
    c.add_argument("--json", action="store_true")
    c.set_defaults(fn=cmd_capture)
    cl = sub.add_parser("captures", help="list labelled OTRF captures")
    cl.add_argument("--data", default=None)
    cl.set_defaults(fn=cmd_captures)
    s = sub.add_parser("store", help="append-only raw event store")
    s.add_argument("action", choices=["ingest", "verify"])
    s.add_argument("dir")
    s.add_argument("files", nargs="*")
    s.set_defaults(fn=cmd_store)
    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--capture", default=None, help="serve a real capture instead of the synthetic demo")
    sv.add_argument("--data", default=None)
    sv.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
