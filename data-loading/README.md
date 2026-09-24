# Data Loading (stage 3)

Loads the 10 files from stage 2 into one Neo4j graph (372,739 nodes, 393,418
relationships, about 2 minutes), and runs an HTTP API, `ingest/`, for adding
records to the graph later.

## Run it

```bash
py -m pip install -r requirements.txt
py main.py --dry-run          # validate the files; needs no database
py main.py --check            # confirm the database is reachable, show what's in it
py main.py                    # load everything
```

**You load once.** Neo4j keeps the graph on disk through restarts and reboots.
Load again only after stages 1–2 produce new files. Re-loading is safe: records
are merged on their `id`, so nothing is duplicated.

Other options: `--only`/`--skip <source>`, `--stage <name>`, `--limit N`
(quick trial), `--self-check`. Every run writes `.cache/load_report.json` with
counts, timings and warnings.

## The one rule: the loader does not preprocess

No field is renamed, no value derived, no link retyped, no duplicate merged, so
every property in the graph traces back to a field from stage 2. The only
changes are the two Cypher needs:

| Change | Example | Why |
|---|---|---|
| Labels → PascalCase | `attack-technique` → `AttackTechnique` | A hyphen in a label is a Cypher syntax error |
| Relationship types → UPPER_SNAKE | `child_of` → `CHILD_OF` | Neo4j convention |

Any change of meaning belongs in `data-preprocessing/`.

## How it works

Two packages: **`graphload/`** is a general property-graph loader that knows
nothing about CVE or STIX; **`catalog/`** declares this dataset (five source
specs and the type → label map). `catalog/` imports `graphload/`, never the
reverse.

The load runs in five steps, in this order:

| Step | Does |
|---|---|
| constraints | One uniqueness constraint (and so one index) per label. Done first because 786,836 endpoint lookups need an index: minutes instead of hours. |
| nodes | Entity records become nodes. |
| edges | Links whose two ends are in the same source. |
| bridges | Links between sources, once every source's nodes exist. |
| verify | Read-only counts and checks. |

The load stops on a duplicate id, an unknown `type`, a record with no id, or a
value Neo4j cannot store. A link to a missing node is reported and skipped
(there are 4: CWE citing CVEs that NVD never published).

## Starting a database

Neo4j Community 5.26 from the tarball needs no root, so it works on the shared
server. It needs Java 17 or 21.

```bash
mkdir -p ~/opt && cd ~/opt
curl -LO https://dist.neo4j.org/neo4j-community-5.26.20-unix.tar.gz
tar -xzf neo4j-community-5.26.20-unix.tar.gz && mv neo4j-community-5.26.20 neo4j
~/opt/neo4j/bin/neo4j-admin dbms set-initial-password 'your-password'
```

Add to `conf/neo4j.conf`:

```
server.default_listen_address=127.0.0.1
server.memory.heap.initial_size=4g
server.memory.heap.max_size=4g
server.memory.pagecache.size=4g
db.transaction.timeout=60m
```

Then `~/opt/neo4j/bin/neo4j start | stop | status`. Put `ulimit -n 40000` in
`~/.bashrc`: Neo4j needs more open files than the default.

- `set-initial-password` only works before the first start. After that, the
  database keeps its original password whatever `.env` says.
- If heap + page cache exceed the machine's RAM, Neo4j dies at once with
  `Invalid memory configuration` in `logs/neo4j.log`.

Connection settings come from the repo-root `.env`: `NEO4J_PASSWORD` (required),
and optionally `NEO4J_URI` (default `bolt://localhost:7687`), `NEO4J_USER`,
`NEO4J_DATABASE`.

## Connecting and viewing the graph

Neo4j listens only on `127.0.0.1`, so use an SSH tunnel from your laptop:

```bash
ssh -L 7474:localhost:7474 -L 7687:localhost:7687 -L 8000:localhost:8000 <user>@10.44.83.124
```

Open http://localhost:7474 and log in with `bolt://localhost:7687`, user
`neo4j`. Both ports are needed: the Browser page is on 7474 and talks to the
database on 7687. If the ports are taken locally, use others
(`-L 7475:localhost:7474 -L 7688:localhost:7687`).

Start with `CALL db.schema.visualization();`, then try the queries in
[`queries.cypher`](queries.cypher), including the full CVE → CWE → CAPEC →
ATT&CK → D3FEND chain. Always use `LIMIT`; the root README has more tips.

## The ingest API: adding records later

For a few records after the load (a new CVE, a finding, the output of stage 4).
It writes through the same engine as the loader, so an added record looks
exactly like a loaded one.

```bash
# on the server, from ~/trace/data-loading
setsid nohup ../.venv/bin/python -m ingest.serve > ~/ingest.log 2>&1 < /dev/null &
curl -s http://127.0.0.1:8000/health          # check
pkill -f '[i]ngest.serve'                     # stop (keep the brackets)
```

The easiest way to use it is http://localhost:8000/docs through the tunnel:
expand `POST /ingest`, press **Try it out**, edit, **Execute**.

| Endpoint | Does |
|---|---|
| `GET /health` | Is it up, can it reach Neo4j, what is in the graph |
| `GET /schema` | Required fields and the types already known |
| `POST /ingest` | Add or update entities and relationships |

```json
{
  "entities": [
    { "id": "CVE-2026-99999", "type": "vulnerability", "source": "apt-report-114",
      "description": "Example." }
  ],
  "relationships": [
    { "id": "relationship--example-1", "relationship_type": "related_to",
      "source_ref": "CVE-2026-99999", "target_ref": "CWE-79", "source": "apt-report-114" }
  ]
}
```

- **Required:** entities need `id`, `type`, `source`; relationships need `id`,
  `relationship_type`, `source_ref`, `target_ref`, `source`. Every other field
  becomes a property as-is. `collected_at` is stamped if missing.
- **Send entities and their links in one request.** Entities are written first,
  so the links can attach.
- **To link to existing data, use its id** (`CWE-79`, `T1055`).
- **Re-posting replaces the record.** Send the whole record every time; a field
  left out is removed.
- **Any `type` is accepted** and gets its own label (`threat-actor` →
  `ThreatActor`), because stage 4 names new kinds of things.
- **A link to a missing node is skipped and reported**, not an error.
- Errors: `422` bad record (the message names it), `400` nothing sent, `503`
  Neo4j unreachable.
- It has no authentication, which is safe only on `127.0.0.1` behind the tunnel.
  Before binding it anywhere else, set `INGEST_API_KEY`; then `POST` needs
  `Authorization: Bearer <key>`.

For hundreds of thousands of records, add a data source instead (below).

## Adding a new data source

Nothing in `graphload/` changes.

1. Have `data-preprocessing/` write `entities.json` and `relationships.json` in
   the usual shape. Ids must be unique across the whole graph; link to other
   catalogs by their own ids (`CWE-79`).
2. Declare it in `catalog/sources/<name>.py` as a `SourceSpec`, and add it to
   `SOURCES` in `catalog/sources/__init__.py`.
3. Add one entry per new `type` to `catalog/labels.py`. The load refuses
   unknown types and lists them.
4. Load it:

```bash
py main.py --dry-run --only <name>
py main.py --stage nodes edges --only <name>
py main.py --stage bridges          # easy to forget: links into other sources
```

## Known limitations

- `RELATED_TO` means different things between different labels (CVE → CWE,
  CWE → CAPEC, CAPEC → ATT&CK), and `USES` covers several ATT&CK relations. Put
  labels on both ends when you query them.
- 56,973 nodes have no links; 56,702 are CVEs with no CWE. That is the data, not
  the load.
- Community edition allows one database.
- Labels created by the ingest API are not in `catalog/labels.py`, so rebuilding
  from the files will not bring them back.
