# data-loading: file-by-file

44 files, ~2,800 lines of Python. This is the map; the *why* behind each modelling
decision is in [README.md](README.md), and every module's own docstring explains
its reason for existing.

## The one rule

```
catalog/  ──imports──▶  graphload/
catalog/  ◀──never───   graphload/
```

`graphload/` is a general-purpose property-graph loader. It contains no mention of
CVE, CWE, CAPEC, ATT&CK, D3FEND, STIX or cybersecurity anywhere. It knows two
shapes: **entity records** (an id and a type) and **edge rows** (a type and two
endpoint ids).

`catalog/` is everything about *this* dataset, expressed as declarations rather
than logic.

`py main.py --self-check` greps the engine for `import catalog` and fails if it
finds one. If the engine ever needs to know something about CTI, the abstraction
has sprung a leak — that's the signal to fix the abstraction, not to add the
import.

---

## Data flow

```
                       catalog/sources/*.py   ← which files exist
                                │
                                ▼
   graphload/readers/  ──▶  graphload/reading.py  ──▶  graphload/transform.py
   stream records            find id + type            build properties
                                │                       (strip prefixes)
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
  registry.py             stages/nodes.py         stages/edges.py
  id → (label, source)    write nodes             stages/bridges.py
        │                                                │
        └────────────▶ router.py ────────────────────────┘
                    local? bridge? dangling?
                                │
                                ▼
                          dedupe.py  ← catalog/bridges.py rules
                       canonical direction + id
                                │
                                ▼
                          batch.py  ──▶  Neo4j (Bolt)
                     UNWIND $rows, grouped, batched
```

---

## `graphload/` — the engine (29 files)

### Describing input

| File | Lines | Job |
|---|---|---|
| `spec.py` | 99 | `SourceSpec`, `EntityFile`, `EdgeFile`, `RecordShape`, `EdgeShape`. **Field names are declared, not assumed** — the defaults match `data-preprocessing/`, but data calling them `uuid`/`kind`/`from`/`to` just passes a different shape. |
| `readers/__init__.py` | 31 | Plugin registry: name → `(Path) -> Iterator[dict]`. |
| `readers/json_array.py` | 26 | Streams `[{...}, {...}]` via `ijson`. **The reason the loader fits in memory** — `json.load` on the CVE folder peaks near 4 GB. |
| `readers/jsonl.py` | 19 | One object per line. |
| `readers/csv_rows.py` | 19 | CSV with a header. |
| `reading.py` | 80 | Opens a file, finds each record's id and type, resolves its label. Records *what it did* in `Findings` rather than deciding policy. |

### Naming and shaping

| File | Lines | Job |
|---|---|---|
| `naming.py` | 67 | `attack-technique` → `AttackTechnique`, `subtechnique-of` → `SUBTECHNIQUE_OF`, `x_mitre_platforms` → `platforms`. Plus `assert_identifier`, the guard on anything interpolated into Cypher. |
| `transform.py` | 105 | Record → properties. Lifts out id/type, strips prefixes, and **rejects nested values** — Neo4j holds scalars and flat arrays only, so a map fails here with the offending record named rather than as a driver error 300,000 records later. |

### Talking to Neo4j

| File | Lines | Job |
|---|---|---|
| `config.py` | 76 | Settings from the repo-root `.env`; real env vars win. `repo_root()` walks up from the file, so the loader runs from any directory. |
| `driver.py` | 62 | Connect, and `check()` — answers "is it reachable, with these credentials, and what's already in it" in a second, before anyone streams a gigabyte at a server that isn't listening. |
| `schema.py` | 57 | Uniqueness constraints + `db.awaitIndexes()`. **The most consequential file here** — see below. |
| `batch.py` | 172 | `UNWIND $rows` writers, and `GroupedWriter`, which buffers edges per `(source label, type, target label)` and flushes when a group fills or total buffering crosses a ceiling. One pass, bounded memory. |

### Resolving and routing

| File | Lines | Job |
|---|---|---|
| `registry.py` | 161 | `id → (label, source)` for all 1.1M ids, with labels interned so each id costs one integer. Cached **per source**, fingerprinted by file size+mtime — which is why adding a sixth source doesn't re-stream the first five. |
| `router.py` | 70 | Local / bridge / dangling, **decided by endpoints, not filenames**. Only 1,310 of D3FEND's 6,471 edges stay inside D3FEND; nothing in the filename says so. |
| `dedupe.py` | 150 | `CanonicalRule` + `Canonicalizer`. Rewrites matching rows to a canonical direction and a deterministic id, so one fact lands on one arrow however many catalogs assert it. |

### Checking and reporting

| File | Lines | Job |
|---|---|---|
| `validate.py` | 107 | The hard gates: duplicate ids, missing id/type, unmapped types, property collisions, leftover `related-to`. Dangling endpoints are the deliberate exception — reported, never fatal. |
| `report.py` | 40 | Writes `.cache/load_report.json`. |
| `context.py` | 56 | Everything a stage needs, assembled once. Holds both `all_specs` and `selected_specs` — bridges need every source even when `--only` is used. |
| `enrichment.py` | 18 | `EnrichmentStep`: a named post-load Cypher pass. |

### The six stages

| File | Lines | Job |
|---|---|---|
| `stages/constraints.py` | 29 | One uniqueness constraint per declared label, then wait for the indexes. |
| `stages/nodes.py` | 88 | Entity records → nodes. One pass that also feeds the registry and writes its cache, because streaming a gigabyte twice would dominate the load. |
| `stages/edges.py` | 20 | Same-source edges. |
| `stages/bridges.py` | 33 | Cross-source edges. Always reads **every** source regardless of `--only`. |
| `stages/_edges.py` | 159 | What both edge stages share — resolve, canonicalise, name, build properties, hand to the writer. They differ only in which `Route` they accept. |
| `stages/_registry.py` | 40 | Fills in the registry for sources this run didn't load, from cache. |
| `stages/enrich.py` | 36 | Runs `catalog/enrichments.py`'s Cypher passes. |
| `stages/verify.py` | 81 | Read-only counts, orphan check, and the actual five-catalog traversal. |

---

## `catalog/` — this dataset, declared (11 files)

| File | Lines | Contains |
|---|---|---|
| `sources/cve.py` | 38 | 7 files — 940,892 nodes, 916,972 edge rows |
| `sources/cwe.py` | 35 | 10 files — 5,056 nodes, 18,339 edge rows |
| `sources/mitre_attack.py` | 47 | 17 files — 6,052 nodes, 36,346 edge rows |
| `sources/capec.py` | 27 | 6 files — 1,538 nodes, 4,930 edge rows |
| `sources/mitre_defend.py` | 34 | 4 files — 1,193 nodes, 6,471 edge rows |
| `labels.py` | 77 | 32 `type` → label mappings, and the declared label set constraints are built from |
| `properties.py` | 56 | Prefixes to strip, fields to drop, and why provenance is called `catalog` not `source` |
| `bridges.py` | 153 | 8 `CanonicalRule`s — the three `related-to` bridges, `CLASSIFIED_AS`, and three same-fact collapses |
| `enrichments.py` | 87 | 8 CVSS summary passes, in preference order |

## Top level

| File | Lines | Job |
|---|---|---|
| `main.py` | 230 | Orchestrator. `--stage`, `--only`, `--skip`, `--dry-run`, `--limit`, `--batch-size`, `--no-cache`, `--allow-new-labels`, `--check`, `--self-check`. Streams progress, prints a pass/fail/timing summary, gates on validation after `nodes` and `bridges`. |
| `docker-compose.yml` | 47 | Neo4j 5.26 LTS, 1536 MB heap / 768 MB page cache, persistent volumes |
| `queries.cypher` | 184 | ~20 starter queries in 7 groups |
| `requirements.txt` | 2 | `neo4j`, `ijson` |

---

## Three things that carry most of the weight

**1. Constraints before data.** Each of the 1.13M edges looks its two endpoints up
by id. Backed by the index a uniqueness constraint creates, that's an instant seek;
unbacked, it's a scan of a million-node label, 2.27M times. Minutes versus hours.
`stages/constraints.py` also waits for `db.awaitIndexes()`, because an index still
POPULATING isn't used by the planner — skipping the wait silently buys the slow
version anyway.

**2. Streaming plus grouped flushing.** `readers/json_array.py` keeps node loading
flat in memory. Edges can't be streamed quite so naively because they must be
*grouped* before writing — that triple fixes the Cypher statement — so
`batch.GroupedWriter` flushes each group as it fills instead of collecting all
1.13M rows first.

**3. Union-on-write, not merge-in-Python.** When two catalogs assert the same fact,
the second write must not erase the first's provenance. Rather than holding 334,000
cross-source edges in a dict to merge them, the Cypher itself unions:

```cypher
SET r.asserted_by = [x IN coalesce(r.asserted_by, []) WHERE NOT x IN row.u['asserted_by']]
                    + row.u['asserted_by']
```

That keeps `stages/bridges.py` streaming, and the `WHERE NOT x IN` guard is also
what makes a re-run idempotent instead of appending the same provenance again.

---

## Extending it

Adding a data source touches only `catalog/`. The checklist is in
[README.md](README.md#adding-a-new-data-source). Things already declared rather
than assumed, so they need no engine change:

| Need | Where |
|---|---|
| Different field names for id/type/endpoints | `RecordShape`/`EdgeShape` on the file |
| Input isn't a JSON array | `reader="jsonl"` / `reader="csv"` on the file |
| A brand-new input format | one function in `graphload/readers/`, registered in `REGISTRY` |
| A new property prefix to strip | one entry in `catalog/properties.py` |
| New cross-catalog duplication to collapse | one `CanonicalRule` in `catalog/bridges.py` |
| A new post-load computation | one `EnrichmentStep` in `catalog/enrichments.py` |
| A label name the automatic transform gets wrong | one entry in `catalog/labels.py` |
