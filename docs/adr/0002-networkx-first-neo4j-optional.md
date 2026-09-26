# ADR-0002: In-memory networkx graph first; Neo4j as an optional mirror

**Status:** Accepted

## Context
The spec targets Neo4j. However, requiring a database server makes tests, CI and demos heavier, and at MVP scale (thousands of nodes) Neo4j is not needed.

## Decision
The reference store is a `networkx.MultiDiGraph`, where the edge key is the predicate. `neo4j_adapter` generates parameterized Cypher and can push to a local Neo4j when the driver is installed.

## Consequences
- Zero-infrastructure `make test` and `make demo`, and CI needs no services.
- The graph is not persistent and does not scale past memory. Moving to Neo4j as the primary store is a Stage 2+ decision.
- Traversals (root cause, blast radius) are written in Python for now. They will need Cypher equivalents later.
