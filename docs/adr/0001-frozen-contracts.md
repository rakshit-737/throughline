# ADR-0001: Freeze contracts first; engines communicate only via the graph

**Status:** Accepted

## Context
Eight sibling projects will become engines. If they call each other directly, the result is a tightly coupled monolith that nobody can build incrementally.

## Decision
The canonical event schema, the node and edge type sets, and the claim model (`throughline/contracts.py`) are frozen at `SCHEMA_VERSION = 0.1.0`. Engines implement the `Engine` protocol (`name`, `reads`, `writes`, `run`) and interact **only** by reading and writing claims in the graph. Unknown types are rejected.

## Consequences
- Engines can be added or removed independently, and each can be built in its own session.
- Any schema change requires a new ADR and a version bump.
- Closed type sets reduce flexibility, but they block schema-abuse input.
