# Loading the dataset into Neo4j

Turns the five preprocessed source folders under `data-preprocessing/` into a single
Neo4j graph: **1,107,176 nodes across 33 labels** and **1,135,867 relationships across
94 types**.

```
py generate_load_cypher.py          # validates the data, writes load.cypher
```

Then, with the five source folders reachable from Neo4j's import directory:

```
cypher-shell -u neo4j -p <password> -f load.cypher
```

`load.cypher` is generated — regenerate it rather than editing it. Optional flags:
`--input`, `--output`, `--url-prefix`, `--batch-size`.

## Prerequisites

- **APOC** installed, and `apoc.import.file.enabled=true` in `neo4j.conf`.
- The five source folders visible to the server at the URL prefix baked into
  `load.cypher` (default `file:///`, i.e. `$NEO4J_HOME/import/CVE/…`,
  `$NEO4J_HOME/import/CWE/…`, and so on). Copy or symlink them there, or regenerate
  with a different `--url-prefix`.
- **An empty database.** Nodes are `CREATE`d, not `MERGE`d, because the generator has
  already proven every id is unique — so a re-run against a populated database would
  duplicate everything. Use `CREATE OR REPLACE DATABASE` (or drop and recreate) first.

## Why JSON instead of CSV

`apoc.load.json` reads the preprocessed files as they are. The alternative,
`neo4j-admin database import` from CSV, is faster but would mean escaping every
embedded newline and quote out of ~950 MB of description text and then re-declaring
each property's type in a CSV header — only to reconstruct what JSON already encodes.
At ~1.1M nodes this dataset is small enough that the simpler path is the better trade.
If load time ever becomes the bottleneck, the CSV route is the thing to reach for.

The load leans on one property of the preprocessed data: **nothing nests**. Neo4j
properties hold scalars and scalar arrays, never maps, so `SET n = value` maps a whole
record to properties in a single step with no per-field handling. Both sources that
used to nest (ATT&CK's log sources and mutable elements, CAPEC's consequences and
skill levels) were unpacked upstream precisely so this holds.

## Naming: `type` -> label, `relationship_type` -> type

The preprocessed JSON keeps each catalog's own vocabulary (`x-mitre-analytic`,
`course-of-action`, `cvss-v3-score`) so the files stay faithful to their sources and
usable outside a graph. `graph_schema.py` maps that vocabulary to Cypher-friendly
names at load time. Two reasons this is not cosmetic:

- **19 of the 33 `type` values contain a hyphen**, which is not a valid bare Cypher
  identifier. `MATCH (t:attack-technique)` is a syntax error; without the mapping,
  every query against most of the graph would need backticks forever. Labels become
  PascalCase (`AttackTechnique`, `CvssV3Score`, `LogSource`).
- **4 of the 94 relationship types** have the same problem (`related-to`,
  `revoked-by`, `attributed-to`, `subtechnique-of`). All 94 become `UPPER_SNAKE`
  mechanically (`RELATED_TO`, `HAS_CVSS_V3_SCORE`).

Two mappings are deliberately not mechanical. D3FEND's bare `technique`/`tactic`
become `DefensiveTechnique`/`DefensiveTactic` — they're already distinct from ATT&CK's
`attack-technique`/`x-mitre-tactic` in the data, but plain `Technique`/`Tactic` as
labels read as the generic concept and invite querying the wrong one. And every
`x-mitre-` prefix is dropped: it marks a STIX custom extension, which is a fact about
the source format, not the entity.

`type` is dropped from node properties (it has become the label).
`type`/`relationship_type`/`source_ref`/`target_ref` are dropped from relationship
properties (all encoded in the edge itself); the relationship's own `id` is kept,
since it's a deterministic uuid5.

## The shared `:Entity` label

Every node gets `:Entity` in addition to its specific label, with a uniqueness
constraint on `:Entity(id)`.

This exists because an edge row names its endpoints by bare id — `source_ref:
"CVE-1999-0001"` — and says nothing about what kind of thing that is. Without one
label spanning every entity, resolving an endpoint would mean either trying all 33
labels or threading endpoint types through the preprocessors. With it, each of the
1.1M edges resolves in one indexed lookup.

It's only sound because **entity ids are unique across all five sources** — the
generator re-proves that on every run and refuses to emit Cypher otherwise, since a
duplicate id under a shared label would silently merge two unrelated entities.

**The constraints must be created before any relationship statement runs.** Without
the index backing `:Entity(id)`, each edge's endpoint lookup is a full scan of 1.1M
nodes, which turns a minutes-long load into an hours-long one. `load.cypher` orders
this correctly and calls `db.awaitIndexes()` before loading nodes.

## Validation is a hard gate

`generate_load_cypher.py` refuses to write Cypher if:

- any entity id is claimed by more than one record (would silently merge nodes),
- any record lacks an `id` or a `type`,
- any `type` has no label in `graph_schema.NODE_LABELS` (fails loudly rather than
  inventing a label).

Dangling edge endpoints are reported but not fatal — they're skipped by the `MATCH` in
each edge statement rather than creating phantom nodes, and the count is written into
`load.cypher`'s header. Currently **4** of 1,135,867 endpoints dangle, all in
`CWE/external_relationships.json`: CWE cites four CVEs as observed examples that the
CVE side of this project doesn't contain — one (`CVE-2019-1135`) because NVD marks it
`Rejected` and the CVE preprocessor drops all 17,655 rejected records, the rest
because they aren't in the NVD snapshot at all. Nothing to fix on this side; the load
correctly declines to invent them.

## After loading

`load.cypher` ends with verification queries — node counts per label, relationship
counts per type, and checks for nodes missing `:Entity`, missing `id`, or left
orphaned. Compare the first two against the expected counts in the file's header.

## Known modelling choices left open

Two things worth revisiting once you've queried the graph a little; neither blocks a
load:

- **`RELATED_TO` is 328,887 edges — 29% of the graph — and is semantically vague.** It
  bundles CVE→CWE, CWE→CVE, CAPEC→CWE, and CAPEC→ATT&CK, distinguished only by a
  `source_name` property. Splitting it into typed edges would make the main
  cross-source bridge far more direct to traverse.
- **63 of the 94 relationship types come from D3FEND's artifact verbs** (`analyzes`,
  `filters`, `may_modify`, …), many with a single edge. They could stay distinct or
  collapse into one `ACTS_ON` with the verb as a property.
