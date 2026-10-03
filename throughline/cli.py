"""THROUGHLINE command line.

Synthetic spine (no downloads; ``serve`` needs the ``api`` extra):
    demo, investigate, explain, export, engines, serve
Real data (scripts/download_data.py in a checkout, sibling engines installed):
    capture <SDWIN-id | path.zip|.json>   run every engine on an OTRF capture and investigate
    captures                              list the labelled OTRF captures available locally
    store ingest|verify|head              append-only raw event store with a hash-chained ledger
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from . import __version__, synth
from .neo4j_adapter import statements
from .pipeline import build, investigate

if TYPE_CHECKING:
    from .stack import Stack

LOOPBACK = ("127.0.0.1", "localhost", "::1")


class CliError(Exception):
    """A user-facing error: printed without a traceback, exit status 2."""


def _kg(args):
    return build(synth.generate(seed=args.seed, false_flag=args.false_flag)["records"])


def cmd_demo(args: argparse.Namespace) -> int:
    """Synthetic supply-chain intrusion, investigated end to end."""
    kg, summary = _kg(args)
    print("== THROUGHLINE demo: synthetic supply-chain intrusion (data only) ==")
    print(json.dumps({k: v for k, v in summary.items() if k not in ("rejected", "skipped")}, indent=2))
    r = _investigate(kg, args.query)
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


def _investigate(kg, query: str, min_conf: float = 0.0) -> dict:
    try:
        return investigate(kg, query, min_conf)
    except KeyError as e:
        raise CliError(f"{e.args[0] if e.args else e} (try a node key such as Pod:checkout-7, or "
                       "`throughline export` to list entities)") from None


def cmd_investigate(args: argparse.Namespace) -> int:
    """One-query investigation of an entity, as JSON."""
    kg, _ = _kg(args)
    if args.as_of:
        from .temporal import replay
        try:
            kg, _ = replay(kg, args.as_of)
        except ValueError as e:
            raise CliError(str(e)) from None
    print(json.dumps(_investigate(kg, args.query, args.min_conf), indent=2))
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    """How one claim's confidence was computed."""
    kg, _ = _kg(args)
    if args.claim_id not in kg.claims:
        raise CliError(f"no claim {args.claim_id!r} in the demo graph (ids run c00001-c{len(kg.claims):05d})")
    print(json.dumps(kg.explain_claim(args.claim_id), indent=2))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """The demo graph as JSON or parameterised Cypher."""
    kg, _ = _kg(args)
    if args.format == "cypher":
        for q, p in statements(kg):
            print(q, json.dumps(p))
    else:
        print(json.dumps(kg.to_json(), indent=2, default=str))
    return 0


def cmd_engines(args: argparse.Namespace) -> int:
    """Built-in engines and the sibling engines: pinned release, installed version."""
    from .engines import status
    from .modules import default_registry
    print("built-in / synthetic-demo registry:")
    for e in default_registry().engines:
        proj = getattr(e, "project", "built-in")
        print(f"  {e.name:15} {proj:22} reads={','.join(e.reads)} writes={','.join(e.writes)}")
    print("\nsibling engines (pinned release tags; pip install -e .[engines], FEINT: .[network]):")
    for s in status():
        if s["installed"]:
            got = f"installed {s['installed_version'] or '?'}"
            if s["matches_pin"] is False:
                got += f" @{s['installed_commit']} (not the pin)"
        else:
            got = "missing"
        print(f"  {s['project']:10} {s['slot']:13} pin {s['pinned']:7} {got:34} {s['adapter']:38} {s['note']}")
    return 0


def capture_records_for(spec: str, stack: Stack) -> tuple[str, list[str], list[tuple[str, dict, str]]]:
    """``(title, labelled techniques, records)`` for an SDWIN id or a capture file path."""
    from .connectors.otrf import iter_records, load_catalog
    p = Path(spec)
    if p.exists():
        return p.name, [], [("windows", r, "B") for r in iter_records(p)]
    for c in load_catalog(stack.paths.otrf):
        if c.id == spec:
            return f"{c.id} {c.title}", c.techniques, [("windows", r, "B") for r in c.records()]
    raise CliError(f"no capture {spec!r} under {stack.paths.otrf}: pass an SDWIN id (see `throughline captures`) "
                   "or a .zip/.json/.tar.gz path")


def _no_data_hint(root: Path) -> str:
    return (f"no datasets under {root}. Set --data or THROUGHLINE_DATA to a dataset root; in a checkout, "
            "`python scripts/download_data.py all` fetches one (the committed fixtures are in tests/fixtures/data)")


def cmd_capture(args: argparse.Namespace) -> int:
    """Run every installed engine on one real capture and investigate the top incident."""
    from .reasoning.investigator import Investigator
    from .stack import ALL_ENGINES, Stack
    engines = tuple(args.engines.split(",")) if args.engines else ALL_ENGINES
    st = Stack.from_data_dir(args.data, engines=engines, sigma_subset=args.sigma)
    missing = st.paths.missing()
    if missing and not Path(args.capture).exists():
        raise CliError(f"missing {missing}: " + _no_data_hint(st.paths.root))
    title, truth, records = capture_records_for(args.capture, st)
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


def cmd_captures(args: argparse.Namespace) -> int:
    """List the labelled OTRF captures under the dataset root."""
    from .connectors.otrf import load_catalog
    from .stack import DataPaths, data_dir
    p = DataPaths(Path(args.data) if args.data else data_dir())
    caps = load_catalog(p.otrf)
    if not caps:
        raise CliError(_no_data_hint(p.root))
    for c in caps:
        print(f"{c.id}  {'ok ' if c.available else '-- '} {','.join(c.techniques):22} {c.title}")
    return 0


def cmd_store(args: argparse.Namespace) -> int:
    """Append to, verify, or print the head of an append-only event store."""
    from .connectors.otrf import iter_records
    from .eventstore import EventStore, StoreError
    try:
        if args.action == "ingest":
            st = EventStore(args.dir, create=True)
            n = 0
            for f in args.files:
                refs = st.append((("windows", r) for r in iter_records(f)), note=Path(f).name)
                n += len(refs)
            print(json.dumps({"appended": n, "total": len(st), "head": st.head}))
            return 0
        st = EventStore(args.dir, create=False)
    except StoreError as e:
        raise CliError(str(e)) from None
    if args.action == "head":
        print(json.dumps({"records": len(st), "head": st.head}))
        return 0
    rep = st.verify(allow_empty=args.allow_empty, expect_head=args.expect_head)
    print(json.dumps(rep, indent=2))
    return 0 if rep["ok"] else 1


def cmd_serve(args: argparse.Namespace) -> int:  # pragma: no cover - starts a server
    """Serve the API and console (localhost by default)."""
    try:
        import uvicorn

        from .api import create_app
    except ImportError as e:
        raise CliError(f"`serve` needs the api extra ({e.name} is missing): pip install "
                       "\"throughline[api] @ git+https://github.com/rakshit-737/throughline\" "
                       "or, in a checkout, pip install -e .[api] (the bare name 'throughline' on PyPI is an "
                       "unrelated project)") from None
    import os
    token = os.environ.get("THROUGHLINE_API_TOKEN") or None
    if args.host not in LOOPBACK and not token:
        token = secrets.token_urlsafe(24)
        print(f"binding {args.host} without THROUGHLINE_API_TOKEN: generated a token for this run.\n"
              f"open http://127.0.0.1:{args.port}/ui#token={token}", flush=True)
    else:
        print(f"open http://127.0.0.1:{args.port}/ui" + (f"#token={token}" if token else ""), flush=True)
    uvicorn.run(create_app(capture=args.capture, data=args.data, token=token or ""), host=args.host,
                port=args.port)
    return 0


def parser() -> argparse.ArgumentParser:
    """The argument parser (also used to render docs/reference.md)."""
    p = argparse.ArgumentParser(prog="throughline", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"throughline {__version__}")
    p.add_argument("--seed", type=int, default=7, help="seed of the synthetic world (default 7)")
    p.add_argument("--false-flag", action="store_true", help="inject conflicting attribution (synthetic demo)")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")
    d = sub.add_parser("demo", help="investigate the synthetic supply-chain intrusion (no downloads)")
    d.add_argument("--query", default="checkout-7", help="entity to investigate (default checkout-7)")
    d.set_defaults(fn=cmd_demo)
    i = sub.add_parser("investigate", help="one-query investigation of a synthetic-world entity, as JSON")
    i.add_argument("query", help="entity id or node key, e.g. checkout-7 or Pod:checkout-7")
    i.add_argument("--min-conf", type=float, default=0.0, help="drop facts below this confidence")
    i.add_argument("--as-of", default=None, help="ISO-8601 time: answer from the claims known then")
    i.set_defaults(fn=cmd_investigate)
    e = sub.add_parser("explain", help="explain one claim's confidence (sources, corroboration, conflict)")
    e.add_argument("claim_id", help="claim id such as c00012")
    e.set_defaults(fn=cmd_explain)
    x = sub.add_parser("export", help="export the synthetic graph as JSON or Cypher")
    x.add_argument("--format", choices=["json", "cypher"], default="json", help="output format (default json)")
    x.set_defaults(fn=cmd_export)
    sub.add_parser("engines", help="list engines: pinned sibling releases and what is installed"
                   ).set_defaults(fn=cmd_engines)
    c = sub.add_parser("capture", help="run all engines on a real OTRF capture and investigate it")
    c.add_argument("capture", help="SDWIN-... id or path to a .zip/.json/.tar.gz capture")
    c.add_argument("--data", default=None, help="dataset root (default: $THROUGHLINE_DATA)")
    c.add_argument("--engines", default="", help="comma list of engines (default: all installed)")
    c.add_argument("--sigma", default="core", choices=["core", "all"], help="SigmaHQ rule subset (default core)")
    c.add_argument("--top", type=int, default=5, help="incidents to list (default 5)")
    c.add_argument("--json", action="store_true", help="print the result and the top investigation as JSON")
    c.set_defaults(fn=cmd_capture)
    cl = sub.add_parser("captures", help="list the labelled OTRF captures under the dataset root")
    cl.add_argument("--data", default=None, help="dataset root (default: $THROUGHLINE_DATA)")
    cl.set_defaults(fn=cmd_captures)
    s = sub.add_parser("store", help="append-only raw event store with a hash-chained ledger")
    s.add_argument("action", choices=["ingest", "verify", "head"],
                   help="ingest FILES, verify every record and the ledger, or print the head hash")
    s.add_argument("dir", help="store directory (created by ingest only)")
    s.add_argument("files", nargs="*", help="capture files to ingest (.zip/.json/.tar.gz)")
    s.add_argument("--allow-empty", action="store_true", help="verify: an empty store counts as ok")
    s.add_argument("--expect-head", default=None,
                   help="verify: ledger head hash recorded elsewhere (detects a truncated or extended tail)")
    s.set_defaults(fn=cmd_store)
    sv = sub.add_parser("serve", help="serve the REST API and console (needs the api extra)")
    sv.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; any other address requires a token)")
    sv.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    sv.add_argument("--capture", default=None, help="serve a real capture instead of the synthetic demo")
    sv.add_argument("--data", default=None, help="dataset root for --capture (default: $THROUGHLINE_DATA)")
    sv.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point of the ``throughline`` console script."""
    args = parser().parse_args(argv)
    try:
        return args.fn(args)
    except CliError as e:
        print(f"throughline: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
