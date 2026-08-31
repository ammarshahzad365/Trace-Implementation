# Loading the dataset into Neo4j (stage 3)

Turns the ten files under [`../data-preprocessing/`](../data-preprocessing/) into
one Neo4j graph. It is the last stage: [`data-acquisition/`](../data-acquisition/)
downloads, [`data-preprocessing/`](../data-preprocessing/) cleans, this loads.

## The one rule

**This loader does not preprocess.** It moves records into Neo4j; it does not
change what they mean. No field is renamed, no value is derived, no link is
retyped, no duplicate is merged, no provenance is stamped on. A property in the
graph can always be traced to a field documented in a source's
`data-preprocessing/<SOURCE>/README.md`, spelled the same way.

There are exactly two exceptions, both about Cypher rather than about meaning,
both mechanical and reversible, and both listed per type in
[`catalog/labels.py`](catalog/labels.py):

| | Example | Why |
|---|---|---|
| Node labels PascalCase | `attack-technique` → `AttackTechnique` | `MATCH (t:attack-technique)` is a Cypher **syntax error**. 12 of the 25 type values contain a hyphen. |
| Relationship types UPPER_SNAKE | `child_of` → `CHILD_OF` | Neo4j convention. Not strictly required — the current values are all legal as-is. |

If you want `related_to` on a CVE→CWE edge to say `HAS_WEAKNESS` instead, that
is a modelling decision that needs domain knowledge, and it belongs in
`data-preprocessing/` where it can be documented next to the raw field it came
from. Putting it here would make the graph disagree with the docs that describe
its own inputs.

## Two packages

- **[`graphload/`](graphload/)** is a general-purpose property-graph loader. It
  knows about *entity records* (each has an id and a type) and *edge rows* (each
  has a type and two endpoint ids). It contains no mention of CVE, CWE, STIX or
  cybersecurity anywhere.
- **[`catalog/`](catalog/)** is everything about *this* dataset, as declarations
  rather than logic: five source specs and two name maps.

`catalog/` imports `graphload/`; `graphload/` never imports `catalog/`. That is
enforced — `py main.py --self-check` fails if it ever does. Pointing this at a
different dataset means writing a new `catalog/`, not editing the engine.

## Quick start

```bash
# 1. one-time: dependencies
py -m pip install -r requirements.txt

# 2. check the data before you need a database at all
py main.py --dry-run

# 3. start a database (see below), then confirm Python can reach it
py main.py --check

# 4. load
py main.py
```

Then open <http://localhost:7474>, log in as `neo4j`, and try
[`queries.cypher`](queries.cypher).

## Starting a database

**Locally, with Docker** — [`docker-compose.yml`](docker-compose.yml) reads the
password from the repo-root `.env`:

```bash
docker compose --env-file ../.env up -d      # start
docker compose --env-file ../.env down       # stop, keep the data
docker volume rm data-loading_neo4j-data     # throw the graph away
```

Two things that bite:

- **`NEO4J_AUTH` only applies to a database being created for the first time.**
  Point a container at an existing data volume and it keeps that volume's
  original password, whatever `.env` now says. If you have lost it, remove the
  volume — that is the only way back.
- **Neo4j refuses to start if `heap.max + pagecache` exceeds physical memory.**
  On a default Windows Docker VM (~3.9 GB) that ceiling arrives fast; the
  symptom is a container that restarts forever with `Invalid memory
  configuration` in `docker logs trace-neo4j`. The compose file is sized to fit.

**On a server with no Docker and no root** — a shared university host, say —
use the unix tarball, which installs entirely inside `$HOME`:

```bash
mkdir -p ~/opt && cd ~/opt
curl -LO https://dist.neo4j.org/neo4j-community-5.26.20-unix.tar.gz
tar -xzf neo4j-community-5.26.20-unix.tar.gz && mv neo4j-community-5.26.20 neo4j
~/opt/neo4j/bin/neo4j-admin dbms set-initial-password 'your-password'

ulimit -n 40000            # Neo4j wants 40000; the usual soft limit is 1024
~/opt/neo4j/bin/neo4j start
```

Needs Java 17 or 21. Put the `ulimit` line in `~/.bashrc` — raising it needs no
root as long as the *hard* limit is already high (`ulimit -Hn` to check). Leave
`server.default_listen_address=127.0.0.1` in `conf/neo4j.conf` and reach it
through an SSH tunnel rather than exposing a database on a shared host:

```bash
ssh -L 7474:localhost:7474 -L 7687:localhost:7687 you@the-server
```

**Credentials** come from the repo-root `.env`, and a real environment variable
always beats it — so loading somewhere else for one run needs no file edit:

```ini
NEO4J_PASSWORD=...                    # required
NEO4J_URI=bolt://localhost:7687       # optional, this is the default
NEO4J_USER=neo4j                      # optional
NEO4J_DATABASE=neo4j                  # optional
```

## Usage

```
py main.py                                   # everything, in order
py main.py --check                           # connectivity + what is in the DB
py main.py --self-check                      # assert the engine/catalog split
py main.py --dry-run                         # validate + report, write nothing
py main.py --stage nodes edges --only capec cwe
py main.py --stage bridges                   # after adding a source
py main.py --stage verify                    # read-only counts
py main.py --limit 500 --dry-run             # fast trial on unfamiliar data
```

Also: `--skip`, `--batch-size`, `--no-cache`, `--allow-new-labels`.

`--dry-run` needs no database — that is the point of it, so `verify` is dropped
from the default stage list when it is on. Every run writes
`.cache/load_report.json` with per-stage counts, timings and warnings. Diff it
after a re-crawl to see what actually changed.

Note that `--limit` produces alarming dangling-endpoint warnings, and they are
an artefact: edges past the limit point at entities that were never read. It is
for checking that a new source parses, not for checking that it connects.

### What a full load looks like

Measured 2026-08-31 against Neo4j 5.26 in Docker (1.5 GB heap, 1 GB page cache):

| Stage | Time | Result |
|---|---|---|
| constraints | 1.8s | 25 constraints, indexes online |
| nodes | 72.0s | 372,739 nodes across 25 labels |
| edges | 12.7s | 48,701 rows, 26 types |
| bridges | 29.5s | 344,717 rows, 8 types |
| verify | 4.1s | 372,739 nodes / 393,418 relationships, 0 without an id |
| **total** | **120.1s** | |

The counts reconcile exactly against the input: 372,739 entity records in, all
loaded; 393,422 edge rows in, 4 skipped as dangling, 393,418 loaded. Those four
are CWE citing CVE ids NVD rejected or never published (`CWE-345`, `CWE-362`,
`CWE-1233`, `CWE-1421`), and they are the only ones in the whole dataset.

56,973 nodes end up isolated, 56,702 of them CVEs with no CWE mapping at all.
That is the data, not the load — worth knowing before reading anything into
coverage numbers.

### Re-running is safe

Nodes and relationships are `MERGE`d on their ids, so a second run updates what
changed and adds what is new rather than duplicating anything. That is what
makes this the thing to run after `data-acquisition/incremental_crawler.py`
picks up new CVEs.

Verified rather than assumed: an immediate second full load produced the same
372,739 nodes and 393,418 relationships, and took 70s instead of 120s — the
registry resolves from its per-source cache instead of re-streaming 402 MB of
CVE JSON.

Properties are written with `SET n = row.props`, not `+=`, which makes the graph
an exact mirror of the files: a field dropped upstream disappears on reload
instead of leaving a stale value behind. The trade is that anything you set by
hand in the Browser does not survive the next load. This graph is a projection
of `data-preprocessing/`, not a place to keep work.

## The five stages

Order is a dependency chain, not a preference.

| Stage | What it does | Needs first |
|---|---|---|
| **1. constraints** | one uniqueness constraint (and so, one index) per label | — |
| **2. nodes** | entity records become nodes; honours `--only`/`--skip` | constraints |
| **3. edges** | edges whose endpoints are both in the source that declared them | that source's nodes |
| **4. bridges** | edges crossing between sources | **all** sources' nodes |
| **5. verify** | read-only counts and checks | — |

**Stage 1 existing before stage 2 is the single most consequential thing in the
loader.** Each of the 393,418 edges looks its two endpoints up by id — 786,836
lookups. Backed by an index that is an instant seek; unbacked it is a scan of a
several-hundred-thousand-node label. The same load goes from minutes to hours.
`stages/constraints.py` also waits for `db.awaitIndexes()`, because an index
still POPULATING is not used by the planner — skipping the wait silently buys
you the slow version anyway.

**Stage 4 is separate because the data forces it.** Cross-source edges cannot
resolve until every source's nodes exist. Keeping them apart is what makes
`--only cwe` work: you can reload one source and its internal links without
CVE's 336,339 cross-catalog rows failing to find their targets, then run
`--stage bridges` once at the end.

Which edges those are is decided by **endpoints, not filenames**, and this is
not a detail. `mitre-defend/relationships.json` sounds internal and mostly is
not — only 1,310 of its 5,056 rows are D3FEND-to-D3FEND, while thousands point
at ATT&CK ids and over a thousand live entirely in CWE's id space. Conversely
`CVE/relationships.json` sounds internal and is entirely cross-source: all
336,339 rows point from a CVE at a CWE. See
[`graphload/router.py`](graphload/router.py).

## The model

**Labels** come from each record's own `type`, PascalCased, per
[`catalog/labels.py`](catalog/labels.py) — 25 entity types across 25 labels.
Two groups are judgement calls rather than translations: D3FEND's
`technique`/`tactic` become `DefensiveTechnique`/`DefensiveTactic` so they
cannot be confused with ATT&CK's, and the `x-mitre-` prefix is dropped from
labels because it marks a STIX custom extension — a fact about the file format,
not about the entity. The records' own fields keep their prefixes verbatim:
`x_mitre_platforms` stays `x_mitre_platforms`.

**Relationship types** come from each row's own `relationship_type`,
uppercased. No overrides are currently needed.

**Properties** are every remaining field, under its own name. The only fields
that do not become properties are the ones that became structure: a record's
`type`, and an edge row's `type`/`relationship_type`/`source_ref`/`target_ref`.
`id` stays a property, because it is how every edge finds the node and how a
reload updates rather than duplicates. `null` values are skipped, because
`SET n.x = null` deletes a property in Cypher and there is no way to store one.

## Reading 500 MB of JSON without 5 GB of RAM

`CVE/entities.json` is 402 MB and `CVE/relationships.json` 95 MB, both
pretty-printed. Parsed with `json.load`, the CVE folder alone peaks at several
GB of Python objects — on a machine that may also be running the Neo4j heap. So
every file is streamed record-by-record through `ijson`
([`graphload/readers/json_array.py`](graphload/readers/json_array.py)) and
memory stays flat regardless of file size.

Edges cannot be streamed quite so naively, because they have to be *grouped* by
`(source label, type, target label)` before writing — that triple is what fixes
the Cypher statement. Collecting all of them first would cost more than the
whole load's memory budget, so `batch.GroupedWriter` flushes a group as soon as
it fills a batch, and flushes the largest group early if total buffering crosses
a ceiling. One pass, bounded memory, any number of groups.

## What stops a bad load

[`graphload/validate.py`](graphload/validate.py) is the gate. Fatal:

- **A duplicate entity id** — the worst failure mode available, because it does
  not error. Two records sharing an id `MERGE` into one node whose properties
  are a blend of two unrelated things, and nothing downstream ever looks wrong.
- **A type with no entry in `catalog/labels.py`** — an invented label is how
  half of a future ATT&CK release quietly ends up somewhere nobody queries.
  `--allow-new-labels` downgrades this to a warning *and reports every name it
  derived*, for when you are deliberately loading something new.
- **A record with no id or no type**, which cannot become a node at all.

Reported but never fatal:

- **A dangling endpoint** — an edge naming an id no entity claims. Not always a
  bug: a catalog can legitimately cite an id another catalog rejected or never
  published. The edge is skipped and counted; the missing node is never
  invented, which is the only behaviour consistent with not preprocessing.

A value Neo4j cannot store (a map, a nested list) stops the load with the
record and field named. It is *rejected*, not flattened — flattening would be
preprocessing.

The gates run after each stage that reads records, which is after that stage's
writes. Catching a duplicate id without reading every record first is
impossible, and reading everything twice would double the slowest part of the
load. `--dry-run` is the pass that catches it with nothing written at all — run
it first on unfamiliar data.

## Adding a new data source

Nothing in `graphload/` changes. The whole job is a new module in
`catalog/sources/` plus two edits.

### 1. Make `data-preprocessing/` emit it

The loader reads what that stage produces, so the source has to exist there
first, following its
[output rules](../data-preprocessing/README.md): two files, nothing nested, ids
readable, entities and links separate, every record carrying its own `type`.

The minimum an entity record needs:

```json
{ "id": "SOMETHING-1", "type": "some-kind", "name": "...", "description": "..." }
```

and an edge row:

```json
{ "id": "relationship--<uuid5>", "type": "relationship",
  "relationship_type": "some_link", "source_ref": "SOMETHING-1", "target_ref": "CWE-79" }
```

Two things matter more than they look:

- **`id` must be unique across the whole graph**, not just within the new
  source. It is the node key, and a collision with an existing id silently
  merges two unrelated records. The loader will catch it, but upstream is where
  it gets fixed.
- **To link into an existing catalog, use that catalog's ids verbatim**
  (`CWE-79`, `T1055`, `CVE-2021-44228`). That is the entire mechanism —
  there is no mapping table to register a cross-source link in. The router
  resolves both endpoints through the registry and classifies the edge as a
  bridge on its own.

### 2. Declare it

Create `catalog/sources/<yourname>.py`:

```python
from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="atlas",                          # what --only/--skip match on
    label="ATLAS",                        # display name in run output
    root="data-preprocessing/ATLAS",      # relative to the repo root
    files=(
        EntityFile("entities.json"),
        EdgeFile("relationships.json"),
    ),
)
```

Write a module docstring saying what the source contributes and anything
surprising about its shape — every existing one does, and it is where the next
person looks first.

### 3. Register it

In [`catalog/sources/__init__.py`](catalog/sources/__init__.py), import the
module and add `SPEC` to `SOURCES`. Order affects only the readability of a
run's output, but put big sources last so a mistake in a small one surfaces
before 402 MB of JSON has streamed.

### 4. Map its types

In [`catalog/labels.py`](catalog/labels.py), add one `LABELS` entry per `type`
value the new source emits. Most are mechanical — `graphload/naming.py` would
derive `AttackPattern` from `attack-pattern` unaided — but list them anyway:
the map doubles as the declared label set that stage 1 builds indexes from, and
as the gate that stops an unrecognised type instead of inventing a label for it.

Skip this and the load stops with the list of types to add. That is the gate
working, not a bug.

Reuse an existing label deliberately if the new source's records really are the
same kind of thing; the ids stay distinct, so they stay distinct nodes.

### 5. Load it

```bash
py main.py --dry-run --limit 500 --only atlas   # does it parse?
py main.py --dry-run --only atlas               # do the types map, ids collide?
py main.py --stage nodes edges --only atlas     # load it alone
py main.py --stage bridges                      # then wire it to everything else
```

That last step is not optional and is easy to forget: `--only atlas` loads only
the edges that stay inside ATLAS. Every link into CWE or ATT&CK is a bridge, and
bridges are all-sources by definition.

### If the shape differs

Neither of these is common, and neither needs an engine change:

- **Different field names.** Pass a shape:
  `EntityFile("nodes.json", shape=RecordShape(id="uuid", type="kind"))`, or
  `EdgeFile("links.json", shape=EdgeShape(type="rel", source="from", target="to"))`.
  The shape's fields are also exactly the ones that become structure instead of
  properties.
- **A different file format.** `EntityFile("data.jsonl", reader="jsonl")`.
  `json_array`, `jsonl` and `csv` ship; a new format is a new function in
  [`graphload/readers/`](graphload/readers/) registered in its `REGISTRY`. Note
  that CSV delivers every value as a string and the loader will not guess types
  from text — that is preprocessing.

### What not to add

There is deliberately no place in `catalog/` to put a field rename, a derived
value, a retyped link or a merge rule, and adding one would be a category
error. If the new source needs any of that to be useful, it needs it in
`data-preprocessing/`, where the decision can be documented beside the raw field
it came from and re-run independently of the database.

## Known limitations

- **`RELATED_TO` is the largest relationship type in the graph** (336,339 of
  them, all CVE→CWE), because that is what the data says. It is NVD's weakness
  classification and a better name would be `HAS_WEAKNESS` — but knowing that
  requires knowing what NVD means by the field, so it is a
  `data-preprocessing/` change, not one to make here.
- **`USES` conflates several relationships** for the same reason: ATT&CK states
  `uses` for a group using malware, malware using a technique and a tool used in
  a campaign. Distinguish them by endpoint labels in a query, or upstream.
- **Community edition means one database.** `NEO4J_DATABASE` exists, but on
  Community there is nowhere else to point it. Loading a second copy side by
  side means a second server.
- **No node carries which catalog it came from.** Mostly the label implies it.
  If you want it explicit, have `data-preprocessing/` emit the field and the
  loader will carry it across like any other.

## Where to read what

Docs sit next to the code they describe and explain **why**, not what.

| Question | Read |
|---|---|
| How do I run it? | this file |
| How do I add a source? | this file, "Adding a new data source" |
| Why is the engine split from the catalog? | [`graphload/__init__.py`](graphload/__init__.py) |
| Why does the loader not rename anything? | [`graphload/properties.py`](graphload/properties.py) |
| Why is there a separate bridges stage? | [`graphload/router.py`](graphload/router.py) |
| Why do constraints come first? | [`graphload/schema.py`](graphload/schema.py) |
| Why `SET n =` and not `SET n +=`? | [`graphload/batch.py`](graphload/batch.py) |
| What do the input files look like? | [`../data-preprocessing/README.md`](../data-preprocessing/README.md) |
