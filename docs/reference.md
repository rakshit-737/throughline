# CLI and API reference

## CLI

```text
throughline [--seed SEED] [--false-flag] {demo,investigate,explain,export,engines,capture,captures,store,serve}

demo                          synthetic supply-chain intrusion, one-query investigation
investigate <entity>          facts about an entity, each citing claims
explain <claim-id>            decompose the confidence of a claim
export --format cypher|json   dump the graph
engines                       installed sibling engines
capture <SDWIN-id|path>       run every engine on an OTRF capture and investigate
captures                      labelled OTRF captures available locally
store ingest|verify DIR FILES append-only raw event store with a hash-chained ledger
serve [--capture ID]          REST API + console on 127.0.0.1:8000
```

## REST API

| method | path | returns |
| --- | --- | --- |
| GET | `/health` | mode and graph size (never needs a token) |
| GET | `/connectors` | available connectors |
| GET | `/engines` | installed siblings and the timings of the last run |
| POST | `/ingest` | normalize up to 1,000 connector records and rebuild |
| GET | `/incidents` | correlated incidents with fused technique confidence and cross-host `cluster` |
| GET | `/investigator/{entity}` | bounded, deterministic investigation with a cited report |
| GET | `/investigate/{entity}` | facts about an entity or incident |
| GET | `/graph/{key}?radius=1` | neighbourhood subgraph |
| GET | `/claims/{id}/explain` | how the confidence of a claim was computed |
| GET | `/ui` | the investigation console |

Set `THROUGHLINE_API_TOKEN` to require `Authorization: Bearer <token>` on every path except `/health` and `/ui`.

## Python API

::: throughline.contracts
    options:
      show_root_heading: true
      members_order: source

::: throughline.graph.KnowledgeGraph
    options:
      show_root_heading: true

::: throughline.reasoning.correlation
    options:
      show_root_heading: true

::: throughline.reasoning.investigator.Investigator
    options:
      show_root_heading: true

::: throughline.api.create_app
    options:
      show_root_heading: true
