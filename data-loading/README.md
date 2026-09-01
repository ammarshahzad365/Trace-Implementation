# Loading the dataset into Neo4j (stage 3)

Turns the ten files under [`../data-preprocessing/`](../data-preprocessing/)
into one Neo4j graph: 372,739 nodes and 393,418 relationships, in about two
minutes.

## The one rule

**This loader does not preprocess.** No field is renamed, no value derived, no
link retyped, no duplicate merged. Every property in the graph traces back to a
field documented in a source's preprocessing README, spelled the same way.

Two exceptions, both about Cypher syntax rather than meaning, both declared per
type in [`catalog/labels.py`](catalog/labels.py):

| Rename | Example | Why |
|---|---|---|
| Labels → PascalCase | `attack-technique` → `AttackTechnique` | `MATCH (t:attack-technique)` is a **syntax error**; 12 of 25 types have hyphens |
| Relationship types → UPPER_SNAKE | `child_of` → `CHILD_OF` | Neo4j convention |

Wanting `related_to` to say `HAS_WEAKNESS` is a modelling decision needing
domain knowledge, so it belongs in `data-preprocessing/`. See
[`graphload/properties.py`](graphload/properties.py).

## Two packages

- **[`graphload/`](graphload/)** — a general-purpose property-graph loader.
  Knows about entity records and edge rows; mentions CVE, CWE and STIX nowhere.
- **[`catalog/`](catalog/)** — this dataset, as declarations: five source specs
  and two name maps. No logic.

`catalog/` imports `graphload/`, never the reverse. `py main.py --self-check`
enforces it. Retargeting at another dataset means a new `catalog/`.

## Quick start

```bash
py -m pip install -r requirements.txt
py main.py --dry-run      # validate the files; needs no database
py main.py --check        # confirm Python can reach the database
py main.py                # load
```

**You run this once.** Neo4j writes the graph to disk, so it survives restarts,
reboots and crashes on its own — there is nothing to re-run and nothing to keep
alive to hold the data. Load again only when the source data changes, i.e. after
`data-acquisition/incremental_crawler.py` and `data-preprocessing/main.py` have
produced new files.

Then open the graph — see [Connecting to the graph](#connecting-to-the-graph).

## Starting a database

**Locally, with Docker:**

```bash
docker compose --env-file ../.env up -d      # start
docker compose --env-file ../.env down       # stop, keep data
docker volume rm data-loading_neo4j-data     # discard the graph
```

Two things bite. `NEO4J_AUTH` applies only to a database being created for the
first time — pointed at an existing volume, a container keeps that volume's old
password whatever `.env` says. And Neo4j refuses to start if
`heap.max + pagecache` exceeds physical memory; on a ~3.9 GB Docker VM that
arrives fast, and the symptom is a container restarting forever with `Invalid
memory configuration`.

**On a server with no Docker and no root**, use the tarball — it installs
entirely inside `$HOME`:

```bash
mkdir -p ~/opt && cd ~/opt
curl -LO https://dist.neo4j.org/neo4j-community-5.26.20-unix.tar.gz
tar -xzf neo4j-community-5.26.20-unix.tar.gz && mv neo4j-community-5.26.20 neo4j
~/opt/neo4j/bin/neo4j-admin dbms set-initial-password 'your-password'
```

Needs Java 17 or 21. Add to `conf/neo4j.conf` (the loaded store is ~514 MB, so
4 GB of page cache holds it resident):

```
server.default_listen_address=127.0.0.1
server.memory.heap.initial_size=4g
server.memory.heap.max_size=4g
server.memory.pagecache.size=4g
db.transaction.timeout=60m
```

**Credentials** come from the repo-root `.env`; a real environment variable
beats it, so loading elsewhere for one run needs no file edit.

```ini
NEO4J_PASSWORD=...                    # required
NEO4J_URI=bolt://localhost:7687       # optional, the default
NEO4J_USER=neo4j                      # optional
NEO4J_DATABASE=neo4j                  # optional
```

## Running it on the server

Three commands:

```bash
~/opt/neo4j/bin/neo4j start
~/opt/neo4j/bin/neo4j stop
~/opt/neo4j/bin/neo4j status      # "Neo4j is running at pid NNNN"
```

`start` puts it in the background and it keeps running after you log out.

The one thing to know: **after the server reboots, SSH in and run `start`
again.** Nothing is lost when it is down -- the graph is on disk, so starting it
brings everything back exactly as it was.

`~/.bashrc` carries one line, `ulimit -n 40000`, because Neo4j wants more open
files than a login shell grants by default.

The [ingest API](ingest/README.md) is a second process alongside Neo4j, started
and stopped the same way. It is optional — the graph is fully usable without it.

## Connecting to the graph

The database is bound to `127.0.0.1`, so it is unreachable over the network by
design. Reach it by forwarding its two ports to your own machine.

**1. Open the tunnel** and leave that terminal open — the tunnel *is* the
connection:

```bash
ssh -L 7474:localhost:7474 -L 7687:localhost:7687 -L 8000:localhost:8000 you@the-server
```

7474 is the Browser, 7687 is Bolt, 8000 is the [ingest API](ingest/README.md).
Drop the third if you only want to look.

**2. Browse to <http://localhost:7474>** and log in:

| Connect URL | `bolt://localhost:7687` |
|---|---|
| Username | `neo4j` |
| Password | from the server's `.env` |

Both ports are forwarded because the Browser is a web page on 7474 that itself
speaks Bolt on 7687. Forward only the first and the page loads but cannot
connect.

Closing the tunnel stops nothing — it closes your view, not the database.

**If the tunnel will not bind**, something local holds those ports: a Docker
Neo4j, or an older tunnel of your own. Identify it before assuming — `netstat
-ano | findstr "7474 7687"` on Windows, `ss -ltnp | grep -E ':(7474|7687)'`
elsewhere. Then either stop it, or use different local ports:

```bash
ssh -L 7475:localhost:7474 -L 7688:localhost:7687 you@the-server
# http://localhost:7475, connect URL bolt://localhost:7688
```

`py main.py --check` confirms which database you actually reached — the version
and node count tell you whether it is the server's or a local one.

## Visualising it

In the Neo4j Browser, type a query into the bar at the top and press Ctrl+Enter.
**What you get back depends on what the query returns**, which is the one thing
worth knowing up front:

- Return **nodes, relationships or a `path`** and you get a drawn graph.
- Return **scalars** (`count(*)`, a property, a string) and you get a table.
  There is nothing to draw, so no amount of clicking will produce a picture.

Start with the shape of the whole model — 25 labels and how they connect:

```cypher
CALL db.schema.visualization();
```

Then a real subgraph. This is the chain the project exists for, for one CVE:

```cypher
MATCH path = (v:Vulnerability {id: 'CVE-2021-44228'})-[:RELATED_TO]->(:Weakness)
      -[:RELATED_TO]->(:AttackPattern)-[:RELATED_TO]->(:AttackTechnique)
      <-[:COUNTERS]-(:DefensiveTechnique)
RETURN path LIMIT 25;
```

Once a graph is drawn:

- **Click a node** to select it; its properties appear in a panel below.
- **Double-click a node** to expand its neighbours and grow the picture.
- **Click a label chip** at the top of the result pane, then pick a property, to
  change what the circles are captioned with — `id` or `name` is usually far
  more useful than the default.
- **Drag** to rearrange, scroll to zoom, and use the pane's expand icon for
  fullscreen.
- The Browser caps how many nodes it draws (`:config initialNodeDisplay`), so a
  `LIMIT` on exploratory queries keeps things legible rather than a hairball.

Beware the tempting `MATCH (n) RETURN n` — with 372,739 nodes it will not draw
anything useful. Always anchor on something specific and `LIMIT`.

[`queries.cypher`](queries.cypher) has a starter set, every query in it run
against the loaded graph: the schema, the full traversal, the defences answering
the most critical CVEs, and the sanity checks worth repeating after a reload.

## Usage

```
py main.py                                   # everything, in order
py main.py --check                           # connectivity + current contents
py main.py --self-check                      # assert the engine/catalog split
py main.py --dry-run                         # validate, write nothing
py main.py --stage nodes edges --only capec cwe
py main.py --stage bridges                   # after adding a source
py main.py --limit 500 --dry-run             # fast trial on unfamiliar data
```

Also `--skip`, `--batch-size`, `--no-cache`, `--allow-new-labels`.

`--dry-run` needs no database, so `verify` drops out of the default stage list
when it is on. `--limit` produces alarming dangling-endpoint warnings that are
an artefact — edges past the limit point at entities never read; it checks that
a source parses, not that it connects.

Every run writes `.cache/load_report.json` — counts, timings, warnings. Diff it
after a re-crawl to see what changed.

**Re-running is safe.** Records are `MERGE`d on their ids, so a second run
updates rather than duplicates; a verification reload produced identical totals
in 70s instead of 120s, off the registry cache. Properties are written
`SET n = row.props`, not `+=`, so the graph mirrors the files exactly — a field
dropped upstream disappears rather than lingering, and anything set by hand in
the Browser does not survive. See [`graphload/batch.py`](graphload/batch.py).

## The five stages

Order is a dependency chain, not a preference.

| Stage | Does | Needs first |
|---|---|---|
| **constraints** | one uniqueness constraint, so one index, per label | — |
| **nodes** | entity records become nodes; honours `--only`/`--skip` | constraints |
| **edges** | edges with both endpoints in the declaring source | that source's nodes |
| **bridges** | edges crossing between sources | **all** sources' nodes |
| **verify** | read-only counts and checks | — |

Constraints first is the most consequential thing here — 393,418 edges mean
786,836 endpoint lookups, indexed seeks versus full label scans, minutes versus
hours ([`schema.py`](graphload/schema.py)). Bridges are separate because a
cross-source edge cannot resolve until every source is loaded, which is what
makes `--only cwe` usable ([`router.py`](graphload/router.py)). Which edges are
which is decided by **endpoints, not filenames**: only 1,310 of D3FEND's 5,056
rows stay inside D3FEND, while all 336,339 CVE rows leave it.

Fatal on load: a duplicate entity id, a type missing from `catalog/labels.py`, a
record with no id or type, a value Neo4j cannot store. Reported but survivable:
a dangling endpoint — 4 exist, all CWE citing CVEs NVD never published. Details
in [`graphload/validate.py`](graphload/validate.py).

## Adding data after the load

The loader is for the five catalogues. To add records to a graph that is already
up — a new CVE, an internal finding, a hand-curated mapping — there is an HTTP
API in [`ingest/`](ingest/). It runs on the server beside Neo4j, and you reach it
through the same tunnel:

```bash
# on the server, from ~/trace/data-loading
setsid nohup ../.venv/bin/python -m ingest.serve </dev/null > ~/ingest.log 2>&1 &
```

Then POST to <http://localhost:8000/ingest>, or use the interactive page at
<http://localhost:8000/docs> to add records from the browser.

It writes through this same engine, so a record added that way is
indistinguishable from a loaded one. See [`ingest/README.md`](ingest/README.md).
For hundreds of thousands of records, declare a source and use the loader
instead — the next section.

## Adding a new data source

Nothing in `graphload/` changes.

**1. Have `data-preprocessing/` emit it** — two files, following its
[output rules](../data-preprocessing/README.md):

```json
{ "id": "SOMETHING-1", "type": "some-kind", "name": "..." }
{ "id": "relationship--<uuid5>", "type": "relationship",
  "relationship_type": "some_link", "source_ref": "SOMETHING-1", "target_ref": "CWE-79" }
```

Two points matter more than they look. `id` must be unique across the *whole*
graph, not just the new source — it is the node key, and a collision silently
merges unrelated records. And to link into an existing catalogue, **use that
catalogue's ids verbatim** (`CWE-79`, `T1055`). That is the entire mechanism;
there is no mapping table, because the router resolves endpoints through the
registry and classifies the edge itself.

**2. Declare it** in `catalog/sources/<name>.py`:

```python
from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="atlas",                          # what --only/--skip match on
    label="ATLAS",                        # display name in run output
    root="data-preprocessing/ATLAS",      # relative to the repo root
    files=(EntityFile("entities.json"), EdgeFile("relationships.json")),
)
```

**3. Register it** — import it in [`catalog/sources/__init__.py`](catalog/sources/__init__.py)
and add `SPEC` to `SOURCES`. Put big sources last, so a mistake in a small one
surfaces before 402 MB of JSON streams.

**4. Map its types** — one `LABELS` entry per `type` value in
[`catalog/labels.py`](catalog/labels.py). Skipping this stops the load with the
list of types to add; that is the gate working, not a bug.

**5. Load it:**

```bash
py main.py --dry-run --limit 500 --only atlas   # does it parse?
py main.py --dry-run --only atlas               # types map? ids collide?
py main.py --stage nodes edges --only atlas     # load it alone
py main.py --stage bridges                      # wire it to everything else
```

That last step is easy to forget: `--only atlas` loads only edges staying inside
ATLAS, and every link into CWE or ATT&CK is a bridge.

**If the shape differs**, pass a shape —
`EntityFile("nodes.json", shape=RecordShape(id="uuid", type="kind"))` — or name
a reader — `EntityFile("data.jsonl", reader="jsonl")`. CSV delivers every value
as a string and the loader will not guess types from text; that is preprocessing.

**What not to add:** there is deliberately nowhere in `catalog/` for a field
rename, derived value, retyped link or merge rule. If a source needs that, it
needs it in `data-preprocessing/`.

## Known limitations

- `RELATED_TO` is the largest type (336,339 CVE→CWE) because that is what the
  data says. `USES` conflates several relationships for the same reason. Constrain
  both endpoint labels when querying either.
- 56,973 nodes are isolated, 56,702 of them CVEs with no CWE mapping. That is
  the data, not the load — worth knowing before reading into coverage numbers.
- Community edition means one database; `NEO4J_DATABASE` has nowhere else to go.

## Where to read what

Docs sit next to the code and explain **why**, not what.

| Question | Read |
|---|---|
| How do I connect to the graph? | "Connecting to the graph", above |
| How do I draw it? | "Visualising it", above |
| How do I start/stop it? | "Running it on the server", above |
| How do I add a few records? | [`ingest/README.md`](ingest/README.md) |
| How do I add a whole source? | "Adding a new data source", above |
| Why rename nothing? | [`graphload/properties.py`](graphload/properties.py) |
| Why a separate bridges stage? | [`graphload/router.py`](graphload/router.py) |
| Why constraints first? | [`graphload/schema.py`](graphload/schema.py) |
| Why `SET n =` not `+=`? | [`graphload/batch.py`](graphload/batch.py) |
| Why stream the input? | [`graphload/readers/json_array.py`](graphload/readers/json_array.py) |
| What stops a bad load? | [`graphload/validate.py`](graphload/validate.py) |
| What do the input files look like? | [`../data-preprocessing/README.md`](../data-preprocessing/README.md) |
