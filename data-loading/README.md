# Loading the dataset into Neo4j

Turns the five preprocessed folders under `data-preprocessing/` into one Neo4j
graph. Two packages, and the split between them is the design:

- **`graphload/`** is a general-purpose property-graph loader. It knows about
  *entity records* (each has an id and a type) and *edge rows* (each has a type
  and two endpoint ids). It contains no mention of CVE, CWE, STIX or
  cybersecurity anywhere.
- **`catalog/`** is everything about *this* dataset, expressed as declarations
  rather than logic: five source specs, a label map, a property policy, a set of
  cross-catalog rules, and a list of post-load Cypher passes.

`catalog/` imports `graphload/`; `graphload/` never imports `catalog/`. That's
enforced -- `py main.py --self-check` fails if it ever does. Pointing this at a
different dataset means writing a new `catalog/`, not editing the engine.

## Quick start

```bash
# 1. one-time: dependencies
py -m pip install -r requirements.txt

# 2. start the database (reads NEO4J_PASSWORD from the repo-root .env)
docker compose --env-file ../.env up -d

# 3. confirm Python can reach it
py main.py --check

# 4. load
py main.py
```

Then open <http://localhost:7474>, log in as `neo4j`, and work through
[`queries.cypher`](queries.cypher) -- it starts with `CALL db.schema.visualization()`,
which draws the whole graph's shape, and then the CVE -> CWE -> CAPEC -> ATT&CK ->
D3FEND trace this project exists for.

## Usage

```
py main.py                                   # everything, in order
py main.py --check                           # connectivity + what's in the DB
py main.py --self-check                      # assert the engine/catalog split
py main.py --dry-run                         # validate + report, write nothing
py main.py --stage nodes edges --only capec cwe
py main.py --stage bridges                   # after editing catalog/bridges.py
py main.py --stage verify                    # read-only counts
py main.py --limit 500 --dry-run             # fast trial on unfamiliar data
```

Also: `--skip`, `--batch-size`, `--no-cache`, `--allow-new-labels`.

Every run writes `.cache/load_report.json` -- per-stage counts, timings, warnings.
Diff it after a re-crawl to see what actually changed.

### Re-running is safe

Nodes and relationships are `MERGE`d on their ids, so a second run updates what
changed and adds what's new rather than duplicating anything. That's what makes
this the thing to run after `data-acquisition/incremental_crawler.py` picks up new
CVEs. The enrich stage is idempotent too, since each of its passes only touches
nodes that don't have the property yet.

## The six stages

Order is a dependency chain, not a preference.

| Stage | What it does | Needs first |
|---|---|---|
| **1. constraints** | one uniqueness constraint (and so, one index) per label | -- |
| **2. nodes** | entity records become nodes; honours `--only`/`--skip` | constraints |
| **3. edges** | edges whose both endpoints are in the same source | that source's nodes |
| **4. bridges** | edges crossing between sources, retyped and deduplicated | **all** sources' nodes |
| **5. enrich** | CVSS summary properties onto `:Vulnerability` | CVE nodes + edges |
| **6. verify** | read-only counts and checks | -- |

Stage 1 existing before stage 2 is the single most consequential thing in the
loader. Each of the 1.13M edges looks its two endpoints up by id; backed by an
index that's an instant seek, unbacked it's a scan of a million-node label. The
same load goes from minutes to hours. `stages/constraints.py` also waits for
`db.awaitIndexes()`, because an index that's still POPULATING isn't used by the
planner -- skipping the wait silently buys you the slow version anyway.

Stage 4 is separate because the data forces it, not for tidiness. Cross-source
edges can't resolve until every source's nodes exist, and they're the ones
needing dedupe rules. Keeping them apart means you can iterate on the ~334,000
hardest edges in the graph without reloading the other 1.1 million.

## Reading 1 GB of JSON without 4 GB of RAM

`CVE/vulnerabilities.json` is 249 MB and `CVE/relationships.json` 196 MB, both
pretty-printed. Parsed with `json.load`, the CVE folder alone peaks around 4 GB of
Python objects -- on a machine whose Docker VM has 3.9 GB total and is already
running a 1.5 GB Neo4j heap. So every file is streamed record-by-record through
`ijson` (`graphload/readers/json_array.py`), and memory stays flat regardless of
file size.

Edges can't be streamed quite so naively, because they have to be *grouped* by
`(source label, type, target label)` before writing -- that triple is what fixes
the Cypher statement. Collecting all of them first would cost more memory than the
whole Neo4j heap, so `batch.GroupedWriter` flushes a group as soon as it fills a
batch, and flushes the largest group early if total buffering crosses a ceiling.
One pass, bounded memory, any number of groups.

## The model

### 32 node labels

A source's `type` value becomes the label. This isn't cosmetic: 18 of the 32 type
values contain a hyphen, and `MATCH (t:attack-technique)` is a Cypher syntax
error -- without the mapping, every query against most of the graph would need
backticks forever.

| Source | Labels |
|---|---|
| CVE | `Vulnerability` `CvssV2Score` `CvssV3Score` `CvssV4Score` `SsvcAssessment` |
| CWE | `Weakness` `Category` `View` `Platform` `Introduction` `Mitigation` `DetectionMethod` `Consequence` |
| CAPEC | `AttackPattern` `CourseOfAction` (+ shares `Consequence`) |
| ATT&CK | `AttackTechnique` `AttackMitigation` `AttackTactic` `AttackMatrix` `Analytic` `DetectionStrategy` `DataComponent` `DataSource` `Asset` `LogSource` `Malware` `Tool` `IntrusionSet` `Campaign` |
| D3FEND | `DefensiveTechnique` `DefensiveTactic` `Artifact` |

Three of those are judgement calls rather than translations, and
`catalog/labels.py` explains each: D3FEND's bare `technique`/`tactic` become
`DefensiveTechnique`/`DefensiveTactic` so nobody queries ATT&CK's by accident; the
`x-mitre-` prefix is dropped because it describes the file format, not the entity;
and `Consequence` is deliberately shared by CWE and CAPEC, which mean the same
thing by it.

### Relationship types

`UPPER_SNAKE`, derived mechanically (`subtechnique-of` -> `SUBTECHNIQUE_OF`). All
**63 of D3FEND's artifact verbs are kept as distinct types** rather than collapsed
into one -- faithful to how D3FEND defines its ontology.

### The cross-catalog bridges

`data-preprocessing/` leaves every cross-source reference as one vague
`related-to` type disambiguated by a property -- 328,883 rows, 29% of all edges,
and exactly the path this project traverses. Worse, catalogs assert the same fact
from both ends: NVD says `CVE-2021-44228 related-to CWE-502` and CWE says the
reverse. Loaded literally that's two vague arrows for one fact.

`RELATED_TO` therefore does not exist in the graph. In its place:

| Arrow | Direction | Forward | Reverse folded in |
|---|---|---|---|
| `HAS_WEAKNESS` | Vulnerability -> Weakness | 308,742 (NVD) | 3,125 (CWE's ObservedExamples) |
| `CLASSIFIED_AS` | Vulnerability -> Category/View | 14,285 (NVD) | none exist |
| `EXPLOITS` | AttackPattern -> Weakness | 1,212 (CAPEC) | 1,212 (CWE) |
| `MAPS_TO_TECHNIQUE` | AttackPattern -> AttackTechnique | 271 (CAPEC) | 36 (ATT&CK) |

Two of those names were chosen carefully. `MAPS_TO_TECHNIQUE` is a taxonomy
*correspondence* -- MITRE publishes CAPEC's ATT&CK references as "this pattern is
the same idea as this technique", so `USES` would misdescribe it. And
`CLASSIFIED_AS` exists because NVD doesn't only classify CVEs against weaknesses:
**14,272 of its references point at a CWE *category* and 13 at a *view***, which
are organisational groupings, not weaknesses. Calling those `HAS_WEAKNESS` would
assert something false about 14,285 edges. A CVE classified only at category level
can still reach weaknesses in two hops, via the category's own `HAS_MEMBER` edges.

Those eight shapes are every direction/label-pair combination `related-to` appears
in, checked exhaustively. `validate.py` refuses to load if a ninth appears, rather
than letting an untyped `RELATED_TO` through.

### One fact, one arrow

Three more relationships repeat their endpoint pair under different ids, which
would load as parallel arrows and double-count in any traversal:

- **`CHILD_OF` between weaknesses.** CWE and D3FEND *both* publish the CWE
  hierarchy: **1,079 of D3FEND's 1,103** `child_of` rows exactly duplicate CWE's,
  with 24 genuinely new. Separately CWE records the same parent/child fact once
  per view (1,318 rows over 1,160 pairs), so `view_id`/`ordinal` become lists.
  Checked: only 2 of the 1,160 pairs have an `ordinal` that differs between views.
- **`HAS_LOG_SOURCE`** -- 3,165 rows over 1,001 distinct pairs; the 351 pairs that
  repeat differ only in `channel`.
- **`INTRODUCED_IN`** -- 1,398 rows over 1,373 pairs, the 25 repeats differing only
  in `note`.

Each varies in a single attribute, so unioning it into a list is lossless.
`asserted_by` records which catalogs claimed the fact, on **every** edge, so the
graph always answers "where did this come from".

Deliberately **not** collapsed: `counters` (293 repeated pairs) and
`uses_data_component` (57). Both carry several *correlated* attributes -- a
`counters` edge explains itself with which artifact each side acts on and how --
and unioning each field separately would destroy which value pairs with which.
There, a repeated pair is a genuinely second justification, so it stays a second
arrow.

### Property names

Source-format prefixes are stripped: the `x_` marks a STIX custom extension, which
is a fact about the file rather than about the thing.

| Was | Becomes | On |
|---|---|---|
| `x_nvd_vuln_status`, `x_nvd_source_identifier` | `vuln_status`, `source_identifier` | Vulnerability |
| `x_capec_abstraction`, `_domains`, `_prerequisites`, `_typical_severity`, `_likelihood_of_attack`, `_resources_required`, `_example_instances` | prefix dropped | AttackPattern |
| `x_mitre_platforms`, `_domains`, `_deprecated`, `_is_subtechnique`, `_tactic_type`, `_impact_type`, `_remote_support`, `_sectors`, `_collection_layers`, `_mutable_element_fields`, `_mutable_element_notes` | prefix dropped | various ATT&CK labels |

A collision after stripping is a **hard error**, not last-write-wins -- otherwise a
field would silently vanish. (Verified: none collide.)

Dropped: `type` from nodes (it became the label), and
`type`/`relationship_type`/`source_ref`/`target_ref`/`source_name` from edges (all
encoded in the relationship itself). Each edge keeps its own `id`, which is the
deterministic uuid5 that makes a reload update it rather than add a second one.

Every node gets a `catalog` property naming its source. It's deliberately **not**
called `source`: CVSS and SSVC records already have a `source` field holding the
assessing organisation (`nvd@nist.gov`, or a CNA uuid), and taking that name would
silently overwrite it on 746,387 nodes. `stages/nodes.py` refuses to load if a
record already has a field by that name.

### CVSS: both summarised and kept

Severity is 746,387 score/assessment nodes -- more than half the graph -- and
nothing in the trace path traverses them. They're loaded in full, *and* each
`:Vulnerability` gets flat `cvss_base_score` / `cvss_base_severity` /
`cvss_vector_string` / `cvss_version` properties, so "the critical CVEs with a
full trace to a defence" costs no extra hop.

That runs as a post-load Cypher pass (`catalog/enrichments.py`) rather than in
Python, because the score files don't record which CVE they belong to -- that's in
`relationships.json` -- so rebuilding the join in memory would mean holding two
~700,000-entry maps. After loading it's a traversal the indexes already serve.
Preference order: v3.1 -> v3.0 -> v4.0 -> v2.0, NVD's `Primary` assessment before
any CNA `Secondary`. v4.0 sits below v3 on purpose: only 29,426 CVEs have one.

## Validation is a hard gate

The load stops before writing if any record lacks an id or a type, if any `type`
has no label in `catalog/labels.py`, if any **id is claimed by two records** (they
would `MERGE` into one node whose properties blend two unrelated things, and
nothing downstream would ever look wrong), if a property collision appears, or if
a `related-to` shape has no bridge rule.

**Dangling endpoints are the deliberate exception** -- reported, counted, and
skipped, never fatal. There are exactly **4**, and they aren't a bug: CWE cites
four CVEs as observed examples that NVD either rejected (`CVE-2019-1135`, dropped
along with all 17,655 rejected records) or never published. The correct behaviour
is to name them and decline to invent them.

```
CWE-345  -> CVE-2022-30267      CWE-362  -> CVE-2014-8273
CWE-1233 -> CVE-2014-8273       CWE-1421 -> CVE-2019-1135
```

## Verified results of a full load

Measured on this machine (Neo4j 5.26.28 community, 1536 MB heap / 768 MB page
cache in Docker), from an empty database:

| | |
|---|---|
| **Nodes** | **1,107,173** across 32 labels |
| **Relationships** | **1,129,919** across 96 types |
| Edge rows read | 1,135,496 (801,456 same-source + 334,040 cross-source) |
| Rows collapsed onto an existing edge | 5,573 |
| Dangling endpoints skipped | 4 |
| Nodes with no `id` | 0 |
| Surviving `RELATED_TO` | 0 |
| CVEs with a summary CVSS score | 345,323 of 346,947 |
| **Full CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND trace** | **81,625 CVEs reach 124 defensive techniques** |
| Total time | **426 s** (nodes 182 s, edges 94 s, bridges 50 s, enrich 89 s, verify 10 s) |

The 1,624 CVEs with no summary score genuinely have no CVSS assessment at all
(NVD `Awaiting Analysis`/`Deferred`) -- verified separately that **0** CVEs have a
score node without the summary property.

### The bridge and dedupe rules, as loaded

| Type | Edges | Rows in | Asserted by 2 catalogs |
|---|---|---|---|
| `HAS_WEAKNESS` | 310,924 | 311,863 | 931 |
| `CLASSIFIED_AS` | 14,285 | 14,285 | 0 (no reverse exists) |
| `COUNTERS` | 3,544 | 3,544 | 0 (parallel edges kept on purpose) |
| `CHILD_OF` (Weakness->Weakness) | 1,184 | 2,421 | 1,079 |
| `INTRODUCED_IN` | 1,373 | 1,398 | 0 |
| `EXPLOITS` | 1,212 | 2,424 | **1,212 -- all of them** |
| `HAS_LOG_SOURCE` | 1,001 | 3,165 | 0 |
| `MAPS_TO_TECHNIQUE` | 307 | 307 | 0 |

Three things worth reading off that table:

- **`EXPLOITS` is perfectly reciprocal** -- every one of CAPEC's 1,212 weakness
  references is matched by the identical claim from CWE's side. Loaded literally
  that would have been 2,424 arrows for 1,212 facts.
- **`MAPS_TO_TECHNIQUE` is perfectly *non*-overlapping** -- ATT&CK's 36 CAPEC
  references name pairs CAPEC itself doesn't assert, so nothing collapsed. The
  two catalogs disagree about what to cross-reference rather than duplicating.
- **`CHILD_OF` between weaknesses lands on exactly 1,184** -- CWE's 1,160 distinct
  parent/child pairs plus the **24** that only D3FEND publishes. Confirmed by
  query, not inferred.

### Isolated nodes: 1,860, all accounted for

Not a defect, but worth knowing before the number alarms you:

| Label | Isolated | Why |
|---|---|---|
| `Vulnerability` | 1,548 | NVD hasn't analysed them: no CWE classification and no CVSS score |
| `DefensiveTechnique` | 122 | abstract parents in D3FEND's ontology, with no `counters`/`enables` of their own |
| `AttackPattern` | 55 | CAPEC patterns with no CWE/ATT&CK mapping and no mitigation |
| `DataSource` | 42 | **all of them** -- `data_source_ref` does not exist anywhere in this ATT&CK release, so the type is effectively orphaned upstream |
| `Category`/`View`/`Weakness`/others | 93 | groupings with no members, and leaf records nothing references |

A sudden jump in this number is the cheapest signal that an edge file failed to
load, which is why `stages/verify.py` prints it every run.

## Adding a new data source

If this takes more than these steps, the abstraction is wrong -- that's the point
of the `graphload`/`catalog` split.

1. **Write `catalog/sources/<name>.py`** -- one `SourceSpec` listing the folder and
   its files, each an `EntityFile` or an `EdgeFile`.
2. **Add its `type` values to `catalog/labels.py`.** Or run
   `py main.py --dry-run --allow-new-labels --only <name>` and let it report every
   label it derived, then paste them in. Unknown types stop the load by default,
   deliberately: an invented label is how half a future ATT&CK release ends up
   filed under the wrong name.
3. **Add bridge rules** to `catalog/bridges.py` *only if* the new data
   cross-references your existing sources.
4. **`py main.py --only <name>`** -- additive, nothing else in the graph is touched.

Things you should not have to change, because they're already declared rather than
assumed:

- **Different field names?** Pass a `RecordShape`/`EdgeShape` on the file
  (`RecordShape(id="uuid", type="kind")`). The defaults just happen to match what
  `data-preprocessing/` emits.
- **Not JSON?** Set `reader="jsonl"` or `reader="csv"` on the file. Adding another
  format means one function in `graphload/readers/`, registered in its `REGISTRY`.
- **New property prefix to strip?** One entry in `catalog/properties.py`.
- **New post-load computation?** One `EnrichmentStep` in `catalog/enrichments.py`.

The per-source registry cache means adding a sixth source rescans only that
source; the other five load their id maps from `.cache/registry-*.pickle` in a
couple of seconds instead of re-streaming ~700 MB of CVE JSON.

## Prerequisites and configuration

- **Docker**, or any reachable Neo4j 5.x. No APOC, no plugins, no server-side
  configuration, and the data files never need to be visible to the server --
  everything travels over Bolt as query parameters.
- **`.env` at the repo root** (already gitignored):
  `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE`. A real
  environment variable overrides the file, so `NEO4J_URI=... py main.py` works for
  a one-off.
- **Memory.** `docker-compose.yml` sets a 1536 MB heap and a 768 MB page cache to
  fit this machine's 3.9 GB Docker VM. The store is larger than 768 MB, so loading
  is disk-bound rather than memory-bound; if you ever raise Docker's memory limit,
  raising `pagecache` to 2G is the single change that helps most.

To throw the graph away and start clean:

```bash
docker compose --env-file ../.env down -v
docker compose --env-file ../.env up -d
```

## Known limitations

1. **`Consequence` holds 7 duplicate node pairs across catalogs.** CWE contributes
   311 and CAPEC 46, and **7** `(scope, impact)` pairs are byte-identical in both
   but get one node each, because the two preprocessors run independently and can't
   share an id space. (CAPEC's own preprocessing README says 4 -- measured against
   the loaded graph it's 7: `Access Control/Bypass Protection Mechanism`,
   `Accountability/Hide Activities`, `Confidentiality/Alter Execution Logic`,
   `Confidentiality/Bypass Protection Mechanism`, `Integrity/Alter Execution Logic`,
   `Integrity/Bypass Protection Mechanism`, and `Other/Other`.) Fixable with:

   ```cypher
   MATCH (a:Consequence {catalog:'cwe'}), (b:Consequence {catalog:'capec'})
   WHERE a.scope = b.scope AND a.impact = b.impact
   RETURN a.scope, a.impact, a.id, b.id      // inspect first, then merge
   ```
2. **No affected-product data.** `x_nvd_configurations` (CPE applicability) was
   dropped upstream in `cve_preprocessing.py`, because it's a nested AND/OR tree
   over 3.1M `cpeMatch` entries rather than a flat edge list. So the graph can't
   answer "which software versions are affected".
3. **`asserted_by` list order reflects load order**, not a sort. Compare with
   `size()` or `IN`, not by index.
4. **`COUNTERS` and `USES_DATA_COMPONENT` can be parallel edges** between the same
   two nodes (3,544 `COUNTERS` over 3,234 distinct pairs). This is intentional --
   see "One fact, one arrow" -- but a path query counting edges rather than
   distinct nodes will count those pairs more than once.
