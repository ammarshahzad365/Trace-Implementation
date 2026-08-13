# Project Context: Trace Implementation

Paste this whole file as context before your own instructions in a new session
(with Claude Code or otherwise) to pick this project up with no other background
needed. It describes what exists, why it's built the way it is, what's verified,
and what's next.

For how to *run* things, see [`README.md`](README.md). This file is the history
and the reasoning.

## 1. What this project is

This repo ("Trace-Implementation", part of a "Literature Review / Trace Paper"
research project) builds a four-stage pipeline that pulls raw
cyber-threat-intelligence data from five public MITRE/NIST sources — CVE, CWE,
CAPEC, MITRE ATT&CK, and MITRE D3FEND — lands it locally in a consistent,
diffable format, flattens it into graph-ready entity/relationship files, and
loads it into Neo4j as a single "Trace" knowledge graph connecting
vulnerabilities → weaknesses → attack patterns → techniques → defensive
countermeasures.

**All four stages are built and the graph is loaded.** The headline traversal
works end to end:

```cypher
MATCH path = (v:Vulnerability {id: "CVE-2021-44228"})
             -[:HAS_WEAKNESS]->(:Weakness)
             <-[:EXPLOITS]-(:AttackPattern)
             -[:MAPS_TO_TECHNIQUE]->(:AttackTechnique)
             <-[:COUNTERS]-(:DefensiveTechnique)
RETURN path
```

There's also a `Prompts/` folder (`ie.txt`/`et.txt`/`link.txt`/
`input_source_url.txt`) with LLM prompt templates for a **later, not-yet-started**
information-extraction stage — for pulling entities/relationships out of free text
(CVE/ATT&CK/CAPEC descriptions), complementary to the structured-field extraction
the pipeline already does. See §7.

## 2. Stage 1 — `data-acquisition/`: five crawlers, one per source

Every source folder follows the same shape: `client.py` (fetch, retry/backoff, and
state-diff helpers), `full_crawler.py` (re-sync everything, overwrite the local
snapshot), `incremental_crawler.py` (fetch/merge only what changed, write a delta
file), `run.ps1` (interactive menu), and a `README.md` (that source's specific
design, plus a "what the data looks like" section with real sample records).

| Source | Folder | Upstream | Local format | Notable design point |
|---|---|---|---|---|
| CVE | `data-acquisition/CVE/` | NVD REST API 2.0 | STIX 2.1 `vulnerability` objects, sharded by year (1999–2026) | Converts raw NVD JSON to STIX; sliding-window rate limiter matching NVD's quota (5/30s, 50/30s with an API key in the repo-root `.env`); 120-day incremental fetch windowing (NVD's own limit) |
| CWE | `data-acquisition/CWE/` | MITRE's versioned XML catalog (no bulk REST API exists) | Generic XML→JSON (`weakness`/`category`/`view` records, flat array) | No native timestamp field — `created`/`modified` synthesized per entry from its own embedded `Content_History` |
| CAPEC | `data-acquisition/CAPEC/` | MITRE's pre-built STIX 2.1 bundle (mitre/cti GitHub repo) | STIX 2.1, used as-is | No conversion needed; corpus version read from `x_capec_version` (no separate version endpoint) |
| MITRE ATT&CK | `data-acquisition/mitre-attack/` | MITRE's TAXII 2.1 server | STIX 2.1, per domain (enterprise/mobile/ics), each with a full version-history archive (`history/<version>.json`, seeded once via `historical_loader.py` from a vendored `mitre/attack-stix-data` clone) | The only source with a genuine date-filtered upstream API (`added_after` TAXII cursor) — incremental runs actually fetch less, not just diff less |
| MITRE D3FEND | `data-acquisition/mitre-defend/` | D3FEND's own "alpha" REST JSON API, 6 endpoints | JSON-LD entities (5 domains: technique/tactic/artifact/weakness/offensive-technique) + a SPARQL-bindings-shaped relationship export (`mappings`, ~14k rows, ~45MB) | **Built this project** (not pre-existing). No native timestamps at all — change detection is content-hash based (`_content_hash`/`_first_seen_at` stamped by the crawler itself), unlike the timestamp-ordering model the other four use. A real bug was found+fixed here during verification (unstable content-hash keys for the `mappings` domain across save/reload). |

**Top-level orchestrator**: `data-acquisition/full_crawler.py` /
`incremental_crawler.py` / `run.ps1` / `client.py` (also built this project) run
every source's own crawler in turn (or a `--sources` subset), streaming each one's
own progress through and finishing with a per-source ok/failed line plus an
aggregate JSON summary. This is what you should generally run rather than `cd`-ing
into each folder individually:

```
py -m full_crawler            # from data-acquisition/
py -m incremental_crawler
```

`--dry-run` fetches and diffs without writing anything — useful for checking sync
status against live upstream without touching local state.

`data-acquisition/README.md` is the top-level index; each source's own `README.md`
has the full detail. `DATA_STORAGE_REPORT.md` documents what the raw data looks
like across all five.

## 3. Stage 2 — `data-preprocessing/`: five preprocessors → 44 flat JSON files

One independent script per source (`<source>_preprocessing.py`) plus `main.py`
which runs them all in subprocesses (`--only`/`--skip`). Each reads its own
source's raw output from `data-acquisition/` and writes trimmed, flattened JSON
into its own subfolder. No shared state between them — a deliberate choice that
costs a little duplication and buys total independence.

The design target for all five: **output that a graph can load directly.**

- **Entities and relationships are separate files.** Every relation that started
  out embedded on an entity record (`RelatedWeaknesses`, `x_capec_child_of_refs`,
  `kill_chain_phases`, `x_nvd_weaknesses`, `rdfs:hasSubClass`, ...) is pulled out
  into its own `{id, type, relationship_type, source_ref, target_ref}` record.
- **Nothing nests.** Neo4j properties hold scalars or flat scalar arrays, never
  maps. Both fields that used to nest were unpacked upstream for exactly this
  reason (ATT&CK's log sources and mutable elements, CAPEC's consequences);
  CAPEC's `x_capec_skills_required` was dropped rather than unpacked.
- **Ids are human-readable.** `CVE-2021-44228`, `CWE-79`, `CAPEC-66`, `T1055`, with
  the original STIX id kept alongside as `stix_id`.
- **Reruns are byte-identical.** Every synthesized id is a deterministic uuid5
  seeded from its own content.

| Source | Files | Nodes | Edge rows |
|---|---|---|---|
| CVE | 7 | 940,892 | 916,972 |
| MITRE ATT&CK | 17 | 6,052 | 36,346 |
| CWE | 10 | 5,056 | 18,339 |
| CAPEC | 6 | 1,538 | 4,930 |
| MITRE D3FEND | 4 | 1,193 | 6,471 |

Each source folder's `README.md` documents **every** field decision and why —
what was kept, renamed, flattened, promoted to its own entity, or dropped. Those
are the files to read before changing anything about the shape of the data.

## 4. Stage 3 — `data-loading/`: the Neo4j loader

Two packages with a strict one-way dependency:

- **`graphload/`** — a general-purpose property-graph loader. Contains no mention
  of CVE, CWE, STIX or cybersecurity anywhere. It knows *entity records* (an id
  and a type) and *edge rows* (a type and two endpoint ids).
- **`catalog/`** — everything about this dataset, as declarations rather than
  logic: five source specs, a label map, a property policy, cross-catalog rules,
  post-load Cypher passes.

`catalog/` imports `graphload/`, never the reverse. `py main.py --self-check`
enforces it. Adding a sixth source means writing a `SourceSpec` and its label
entries — no engine change. `ARCHITECTURE.md` is the file-by-file map; `README.md`
has every modelling decision and the "adding a new data source" checklist.

Six stages, run in order or individually via `--stage`: `constraints` → `nodes` →
`edges` → `bridges` → `enrich` → `verify`.

### Design decisions worth knowing before you change anything

- **Loaded over Bolt with the Python driver**, batched `UNWIND` + `MERGE`, ~10k
  rows per transaction. No APOC, no CSV bulk import, no server-side configuration,
  and the data files never need to be visible to the server. `MERGE` on
  deterministic ids is what makes re-running after an incremental crawl update
  rather than duplicate.
- **Constraints are created before any data**, and the loader waits for
  `db.awaitIndexes()`. Each of the 1.13M edges looks up two endpoints by id;
  indexed that's an instant seek, unindexed it's a scan of a million-node label.
  Minutes versus hours.
- **JSON is streamed with `ijson`.** `CVE/vulnerabilities.json` is 249 MB
  pretty-printed and the CVE folder is ~700 MB; `json.load` would peak near 4 GB,
  on a machine whose Docker VM has 3.9 GB total and runs a 1.5 GB Neo4j heap.
- **`RELATED_TO` does not exist in the graph.** `data-preprocessing/` leaves all
  cross-source references as one vague `related-to` type (328,883 rows, 29% of all
  edges) asserted redundantly from both ends. It's retyped into four directional
  relationships — `HAS_WEAKNESS`, `CLASSIFIED_AS`, `EXPLOITS`,
  `MAPS_TO_TECHNIQUE` — with an `asserted_by` list recording which catalogs
  agreed. `validate.py` refuses to load if a `related-to` shape appears that has
  no rule.
- **Cross-source edges are routed by endpoint, not by filename.** Only 1,310 of
  D3FEND's 6,471 edges stay inside D3FEND; 3,544 point at ATT&CK ids and 1,103
  live entirely in CWE's id space. Nothing in the filename says so.
- **All 63 D3FEND artifact verbs are kept as distinct relationship types**, not
  collapsed — faithful to how D3FEND defines its ontology.
- **Property prefixes are stripped** (`x_capec_`, `x_mitre_`, `x_nvd_`) since they
  mark a STIX custom extension, a fact about the file rather than the entity. A
  collision after stripping is a hard error, not last-write-wins.
- **Provenance on nodes is called `catalog`, not `source`** — CVSS/SSVC records
  already own a `source` field holding the assessing organisation, and taking that
  name would have silently overwritten it on 593,945 nodes.
- **CVSS is reduced, then both summarised and kept.** All 593,945 score nodes
  load, *and* each `:Vulnerability` gets flat
  `cvss_base_score`/`_base_severity`/`_vector_string`/`_version` properties via a
  post-load Cypher pass (v3.1 → v3.0 → v4.0 → v2.0, NVD `Primary` before any CNA
  `Secondary`). Done after loading because the score files don't record which CVE
  they belong to — that's in `relationships.json`, so rebuilding the join in
  Python would mean holding two very large maps. `cvss_base_severity` is computed
  by that pass rather than copied, since it is a band table over `base_score`.
- **The score records were 746,387 before three preprocessing reductions.**
  `cve_preprocessing.py` now drops (1) every CVSS field that `vectorString` or
  `baseScore` already encodes — verified reconstructible with 0 mismatches across
  all 583,026 score records before removal; (2) v2 scores on a CVE that also has a
  v3 score (122,022); (3) Secondary scores asserting exactly what a Primary
  asserts (30,420). Score files fell from 476 MB to 192 MB. Rules 2 and 3 only
  drop records that have a surviving sibling, so no CVE lost its severity data,
  and a surviving `Secondary` now means the CNA genuinely disagreed with NVD.

### Two things caught by validation that the plan had wrong

Both are documented in `data-loading/README.md`; recording them here because they
were genuine near-misses, not cosmetic:

1. **`related-to` isn't only CVE→Weakness.** NVD classifies 14,272 CVEs against
   CWE *categories* and 13 against *views* — organisational groupings, not
   weaknesses. Forcing them into `HAS_WEAKNESS` would have asserted something
   false about 14,285 edges. They got their own `CLASSIFIED_AS` type.
2. **The `source` property collision above** would have destroyed real data on
   746,387 nodes.

## 5. Verified state

### Stage 1 — acquisition

Internal consistency (does what's on disk match what the manifests claim): **all 5
sources check out exactly** — no gaps, no silent truncation, manifest counts match
actual file counts everywhere, D3FEND's `mappings` join-keys resolve with 0 orphans
against the other 5 D3FEND domains.

Live upstream comparison, as of the last check:

- CWE, CAPEC, MITRE ATT&CK (all 3 domains), MITRE D3FEND (all 6 domains): **fully
  in sync**, 0 drift, verified via live `--dry-run` crawls.
- **CVE is stale**: local has 346,947 non-rejected records from a `2026-07-10`
  sync, a week behind the other sources (`2026-07-17`). This is staleness, not a
  bug — run `py -m incremental_crawler --sources cve` from `data-acquisition/` to
  catch it up, then re-run stages 2 and 3.

### Stage 3 — the loaded graph

> **These figures predate the CVSS reductions (§4) and the graph has not been
> reloaded since.** Every count below was measured against a load built from the
> old 746,387-record score files. The trace-path findings are unaffected — nothing
> in the trace touches a score node — but the node, relationship and timing totals
> will drop by roughly 152,000 nodes and 152,000 relationships on the next load.

Full load from an empty database, Neo4j 5.26.28 community in Docker:

| | |
|---|---|
| **Nodes** | **1,107,173** across 32 labels |
| **Relationships** | **1,129,919** across 96 types |
| Edge rows read | 1,135,496 (801,456 same-source + 334,040 cross-source) |
| Rows collapsed onto an existing edge | 5,573 |
| Dangling endpoints skipped | 4 |
| Nodes with no `id` / surviving `RELATED_TO` | 0 / 0 |
| CVEs with a summary CVSS score | 345,323 of 346,947 |
| **Full 5-catalog trace** | **81,625 CVEs reach 124 defensive techniques** |
| Total time | 426 s |

Confirmed by query rather than inferred:

- **`EXPLOITS` is perfectly reciprocal** — all 1,212 of CAPEC's weakness
  references are independently asserted by CWE too (2,424 rows → 1,212 edges).
- **`MAPS_TO_TECHNIQUE` is perfectly non-overlapping** — ATT&CK's 36 CAPEC
  references name pairs CAPEC itself doesn't assert, so nothing collapsed.
- **`CHILD_OF` between weaknesses is exactly 1,184** — CWE's 1,160 distinct pairs
  plus the 24 that only D3FEND publishes. 1,079 of D3FEND's 1,103 `child_of` rows
  duplicated CWE's own hierarchy and were collapsed.
- **The 4 dangling endpoints are correct citations, not bugs** — CWE names four
  CVEs that NVD either rejected (`CVE-2019-1135`, dropped with all 17,655 rejected
  records) or never published. They're reported and skipped, never invented.
- **1,860 isolated nodes, all accounted for** — 1,548 CVEs NVD hasn't analysed
  (no CWE, no score), all 42 `DataSource` nodes (`data_source_ref` doesn't exist
  anywhere in this ATT&CK release), 122 abstract parent D3FEND techniques, 55
  unmapped CAPEC patterns, 93 empty groupings and unreferenced leaves.
- **The enrich stage is idempotent** — a second run sets 0 properties.

## 6. Known limitations

1. **No affected-product data.** `x_nvd_configurations` (CPE applicability) was
   dropped in `cve_preprocessing.py` — it's a nested AND/OR boolean tree over 3.1M
   `cpeMatch` entries across 427K distinct CPE criteria strings, not a flat edge
   list, so there's no lossless `(source_ref, target_ref)` to extract. The graph
   therefore can't answer "which software versions are affected". Re-adding this is
   the single biggest available expansion.
2. **`Consequence` holds 7 duplicate node pairs.** CWE contributes 311 and CAPEC
   46; **7** `(scope, impact)` pairs are byte-identical in both but get one node
   each, because the two preprocessors run independently and can't share an id
   space. Note that `data-preprocessing/CAPEC/README.md` says 4 — measured against
   the loaded graph it is 7. Fixable with a small merge query (given in
   `data-loading/README.md`).
3. **`asserted_by` list order reflects load order**, not a sort — compare with
   `size()` or `IN`, not by index.
4. **`COUNTERS` and `USES_DATA_COMPONENT` can be parallel edges** between the same
   two nodes (3,544 `COUNTERS` over 3,234 distinct pairs). Intentional — each
   repeat is a genuinely different artifact-bridge justification, and their several
   attributes are *correlated*, so unioning each into its own list would destroy
   which value pairs with which. But a path query counting edges rather than
   distinct nodes will count those pairs more than once.
5. **Community edition, single database.** No `CREATE OR REPLACE DATABASE`; to
   start clean, `docker compose --env-file ../.env down -v && ... up -d`.
6. **Page cache (768 MB) is smaller than the store**, so loading and querying are
   disk-bound. Sized for this machine's 3.9 GB Docker VM; if that limit is raised,
   raising `pagecache` to 2G is the single highest-value change.

## 7. What's next

1. **Reload the graph.** Stage 2's output has been re-generated with the CVSS
   reductions (§4) but stage 3 has not been re-run, so the live database still
   holds the old 746,387 score nodes and every score node in it still carries the
   now-dropped derived properties. Re-run `data-loading/` against an empty
   database before trusting any count queried from it.
2. **Catch up the stale CVE data** (§5), then re-run stages 2 and 3.
3. **Query the graph and validate it against the research questions.** Start from
   `data-loading/queries.cypher` — particularly the coverage queries ("which
   weaknesses have no route to any defence?"), which are the ones a table-shaped
   database is worst at and the likeliest source of paper findings.
4. **The text-IE pass is still not started.** `Prompts/` has templates for it. The
   scoped target: ~175 CVE mentions found in ATT&CK free text and ~59 in CAPEC free
   text, which the structured fields don't capture. If built, tag these as a
   separate, lower-confidence relationship type (e.g. `MENTIONS`) — never silently
   merged with the structured edges, since their provenance and reliability differ.
5. **Optional modelling cleanups**, none blocking: merge the 4 duplicate
   `Consequence` pairs (§6.2); reconsider the CPE/configurations gap (§6.1).
