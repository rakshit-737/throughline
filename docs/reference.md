# CLI and API reference

## CLI

`throughline --help` (or `python -m throughline --help`); every subcommand has its own `--help`.

```text
throughline [--seed SEED] [--false-flag] [--version] COMMAND

demo                                   investigate the synthetic supply-chain intrusion (no downloads)
investigate QUERY [--min-conf X] [--as-of TIME]
                                       one-query investigation of a synthetic-world entity, as JSON
explain CLAIM_ID                       explain one claim's confidence (sources, corroboration, conflict)
export [--format json|cypher]          export the synthetic graph as JSON or Cypher
engines                                pinned sibling releases and what is installed (version, commit)
capture ID_OR_PATH [--data DIR] [--engines LIST] [--sigma core|all] [--top N] [--json]
                                       run every engine on a real OTRF capture and investigate it
captures [--data DIR]                  list the labelled OTRF captures under the dataset root
store {ingest,verify,head} DIR [FILES] [--allow-empty] [--expect-head HASH]
                                       append-only raw event store with a hash-chained ledger
serve [--host H] [--port P] [--capture ID] [--data DIR]
                                       REST API and console (needs the api extra)
```

Errors (an unknown entity or claim, missing datasets, a missing extra) end with a one-line message and exit code 2. `serve` binds to `127.0.0.1`; on any other address without `THROUGHLINE_API_TOKEN` it generates a token and prints the console URL.

## REST API

| method | path | parameters | returns |
| --- | --- | --- | --- |
| GET | `/health` | | mode and graph size (never needs a token) |
| GET | `/connectors` | | registered connectors |
| GET | `/engines` | | pinned and installed siblings, timings of the last run |
| POST | `/ingest` | JSON body `{"records": [{"connector", "raw", "reliability"}]}` | normalise and rebuild; at most 1,000 records per batch, 10 MB per body (413), 64 KB per raw record (422), 250,000 retained records (413); `application/json` only (415) |
| GET | `/incidents` | `as_of` | correlated incidents with fused technique confidence and cross-host `cluster` |
| GET | `/investigator/{entity}` | `budget` (1-20), `as_of` | the bounded, deterministic investigation: trace and cited report |
| GET | `/investigate/{entity}` | `min_conf`, `as_of` | facts about an entity or incident, each citing claims |
| GET | `/graph/{key}` | `radius` (1-2) | neighbourhood subgraph |
| GET | `/claims/{id}/explain` | | how one claim's confidence was computed |
| POST | `/neo4j/sync` | | mirror the graph, claims included, into Neo4j (`THROUGHLINE_NEO4J_URI`, `THROUGHLINE_NEO4J_USER`, `THROUGHLINE_NEO4J_PASSWORD`); 404 when no URI is set, 503 when the server is unreachable |
| GET | `/ui` | | the investigation console (never needs a token) |

`as_of` (ISO-8601) answers from the claims known at that time. With `THROUGHLINE_API_TOKEN` set, every path except `/health` and `/ui` requires `Authorization: Bearer <token>` (the console reads `#token=` from its URL). Only loopback `Host` headers are served (add names with `THROUGHLINE_ALLOWED_HOSTS`), and state-changing requests from another origin get 403.

## Python API

::: throughline.contracts
    options:
      show_root_heading: true
      members_order: source

::: throughline.graph.KnowledgeGraph
    options:
      show_root_heading: true

::: throughline.confidence
    options:
      show_root_heading: true

::: throughline.reasoning.correlation
    options:
      show_root_heading: true

::: throughline.reasoning.investigator.Investigator
    options:
      show_root_heading: true

::: throughline.reasoning.calibration
    options:
      show_root_heading: true

::: throughline.temporal
    options:
      show_root_heading: true

::: throughline.stack
    options:
      show_root_heading: true

::: throughline.engines
    options:
      show_root_heading: true

::: throughline.eventstore.EventStore
    options:
      show_root_heading: true

::: throughline.api.create_app
    options:
      show_root_heading: true
