"""THROUGHLINE CLI: demo, investigate, explain, export, serve, engines."""
from __future__ import annotations

import argparse
import json
import sys

from . import synth
from .neo4j_adapter import statements
from .pipeline import build, investigate


def _kg(args):
    return build(synth.generate(seed=args.seed, false_flag=args.false_flag)["records"])


def cmd_demo(args) -> int:
    kg, summary = _kg(args)
    print("== THROUGHLINE demo: synthetic supply-chain intrusion (data only) ==")
    print(json.dumps({k: v for k, v in summary.items() if k != "rejected"}, indent=2))
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
    from .modules import default_registry
    for e in default_registry().engines:
        proj = getattr(e, "project", "built-in")
        print(f"{e.name:15} {proj:22} reads={','.join(e.reads)} writes={','.join(e.writes)}")
    return 0


def cmd_serve(args) -> int:  # pragma: no cover
    import uvicorn
    from .api import create_app
    uvicorn.run(create_app(), host=args.host, port=args.port)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="throughline")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--false-flag", action="store_true", help="inject conflicting attribution")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--query", default="checkout-7"); d.set_defaults(fn=cmd_demo)
    i = sub.add_parser("investigate"); i.add_argument("query"); i.add_argument("--min-conf", type=float, default=0.0)
    i.set_defaults(fn=cmd_investigate)
    e = sub.add_parser("explain"); e.add_argument("claim_id"); e.set_defaults(fn=cmd_explain)
    x = sub.add_parser("export"); x.add_argument("--format", choices=["json", "cypher"], default="json")
    x.set_defaults(fn=cmd_export)
    sub.add_parser("engines").set_defaults(fn=cmd_engines)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    s.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
