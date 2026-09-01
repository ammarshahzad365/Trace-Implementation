# Adding data to the knowledge graph

An HTTP API for adding records after the initial load. The batch loader
([`../main.py`](../main.py)) is for the five catalogues; this is for everything
that arrives later — a new CVE, an internal finding, a hand-curated mapping.

Both write through the same engine, so a record added here is indistinguishable
from one loaded from a file: same labels, same property names, same
MERGE-on-`id`.

## Where it runs

The API runs **on the server**, next to Neo4j. That matters: it is the API that
talks to the database, so both live on the same machine and Neo4j is a local
hop. You reach the API itself over an SSH tunnel, exactly like the Browser.

```
your laptop                      the server
───────────                      ──────────
POST :8000 ──── tunnel ────────►  ingest API :8000
                                       │ localhost
                                       ▼
                                    Neo4j :7687
```

Add a third forward to the tunnel you already use for the Browser:

```bash
ssh -L 7474:localhost:7474 -L 7687:localhost:7687 -L 8000:localhost:8000 you@the-server
```

Then <http://localhost:8000> on your machine is the API on the server.

## Starting and stopping it

On the server, from `~/trace/data-loading`:

```bash
# start (keeps running after you log out)
setsid nohup ../.venv/bin/python -m ingest.serve </dev/null > ~/ingest.log 2>&1 &

# check
curl -s http://127.0.0.1:8000/health

# stop
pkill -f '[i]ngest.serve'

# logs
tail -f ~/ingest.log
```

Like Neo4j, it needs starting again after a server reboot. The square brackets
in the `pkill` pattern are not a typo — `pkill -f 'ingest.serve'` matches its own
command line and kills the shell you typed it in before it reaches the API.

It reads `NEO4J_PASSWORD` from the repo-root `.env` like everything else.
Options: `--port`, `--allow-new-labels`, `--host`.

It binds to **127.0.0.1** on purpose. This endpoint writes to the graph with no
authentication, which is fine over loopback reached through an SSH tunnel and is
not fine on `0.0.0.0`. If you ever need other machines to POST to it, put
something that provides authentication in front rather than changing `--host`.

## The easy way: the browser

With the tunnel open, go to <http://localhost:8000/docs>. It is a live page
listing every endpoint — expand `POST /ingest`, press **Try it out**, edit the
example, press **Execute**. No client code, no curl. This is the fastest way to
add a handful of records.

## Three endpoints

| | |
|---|---|
| `GET /health` | Is it up, is Neo4j reachable, and what is in the graph |
| `GET /schema` | Which entity types are accepted, which relationship types exist |
| `POST /ingest` | Add or update records |

## Adding records

Post entities, relationships, or both. They go in one request because
**entities are written first** — a relationship can only attach to nodes that
exist, so sending them separately in the wrong order would silently skip every
relationship as dangling.

```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "entities": [
      { "id": "CVE-2026-99999", "type": "vulnerability",
        "description": "Example.", "cvss_base_score": 7.5 }
    ],
    "relationships": [
      { "id": "relationship--example-1", "relationship_type": "related_to",
        "source_ref": "CVE-2026-99999", "target_ref": "CWE-79" }
    ]
  }'
```

```json
{
  "entities":      { "written": 1, "by_label": { "Vulnerability": 1 } },
  "relationships": { "written": 1, "by_type": { "RELATED_TO": 1 },
                     "skipped_dangling": 0, "dangling": [] }
}
```

### What a record needs

An **entity** needs `id` and `type`. Everything else you send becomes a
property under that name — nothing is renamed or interpreted.

```json
{ "id": "CVE-2026-99999", "type": "vulnerability", "anything_else": "becomes a property" }
```

A **relationship** needs `id`, `relationship_type`, `source_ref` and
`target_ref`. Other fields become properties on the relationship.

```json
{ "id": "relationship--unique-1", "relationship_type": "related_to",
  "source_ref": "CVE-2026-99999", "target_ref": "CWE-79" }
```

This is the same shape `data-preprocessing/` emits, so anything valid in those
files is valid here.

### Four rules worth knowing

**`id` must be unique across the whole graph.** It is the node key. Reusing an
existing id updates that record rather than creating a new one — which is the
point when you mean it, and data loss when you do not. Prefix generated ids
distinctively (`relationship--`, or a source tag of your own).

**Linking to existing data just means using its id.** `CWE-79`, `T1055`,
`CVE-2021-44228`. There is nothing to register; the endpoints are looked up by
id and the relationship is attached.

**Re-posting replaces, it does not patch.** Properties are written with
`SET n = props`, so a field you leave out of a later post is *removed* from the
node. Always send the whole record. This is deliberate — it keeps the graph an
exact mirror of what was last asserted rather than an accumulation of every
version.

**`type` must already be known.** It is checked against
[`../catalog/labels.py`](../catalog/labels.py), and an unrecognised one is
rejected with the list of valid types. That gate is why a typo cannot silently
create a second label nobody queries. To add a genuinely new kind of thing, add
it to that file — or start with `--allow-new-labels` to derive labels on the
fly, accepting the typo risk that comes with it.

`GET /schema` lists the 25 accepted types at any time.

## When something is wrong

| Status | Means |
|---|---|
| `422` | The request is malformed: a missing field, an undeclared `type`, or a value Neo4j cannot store (a nested object or list of lists). The message names the record and field. |
| `400` | Nothing to do — both lists empty. |
| `503` | Neo4j is not reachable from the API. Check `~/opt/neo4j/bin/neo4j status` on the server. |

**Dangling relationships are not an error.** If an endpoint id does not exist,
that relationship is skipped and reported — the response tells you which ids
were missing. Nothing is invented, matching the batch loader's behaviour.

```json
{ "relationships": { "written": 0, "skipped_dangling": 1,
    "dangling": [ { "id": "relationship--x", "source_ref": "CVE-2026-99999",
                    "target_ref": "CWE-DOES-NOT-EXIST",
                    "missing": ["CWE-DOES-NOT-EXIST"] } ] } }
```

Usually that means a typo, or that you sent the relationship before the entity
it points at. Send both in one request and the ordering takes care of itself.

## Bulk data

For thousands of records, batching them into a few large requests beats sending
one per record. For hundreds of thousands, do not use this API at all — write
the records as `entities.json` and `relationships.json` under
`data-preprocessing/`, declare the source, and run the batch loader. It streams
from disk and is built for that volume; see
[the main README](../README.md#adding-a-new-data-source).

## Checking what you added

Through the tunnel at <http://localhost:7474>:

```cypher
MATCH (v {id: 'CVE-2026-99999'})-[r]-(n) RETURN v, r, n;
```

Or count what exists: `GET /health` before and after.

If the API itself does not answer, check the tunnel forwards port 8000, then
that the process is up on the server (`pgrep -f '[i]ngest.serve'`).
