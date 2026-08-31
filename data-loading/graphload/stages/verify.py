"""Stage 5 -- read-only checks on the graph that now exists.

Counts what is actually in the database, per label and per relationship type, so
they can be diffed against what the loader thought it wrote. Then two questions
worth asking every time:

- **Nodes with no `id`.** Should be zero. A non-zero count means something was
  created by an endpoint `MATCH` rather than loaded, which would be a bug here.
- **Isolated nodes.** Not necessarily wrong -- a catalog can ship entities that
  genuinely link to nothing in this release -- but a jump in this number is the
  cheapest signal that an edge file did not load.

Deliberately domain-agnostic. It does not assert that any particular traversal
works, because "the graph should connect CVE to D3FEND" is a claim about this
dataset, and the moment the loader encodes it, `--only cwe` starts reporting a
failure that is really just a partial load. Put those queries in
`queries.cypher`, where they are read by a person who knows what they loaded.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context


def run(ctx: Context, handle: Session | None) -> dict:
    if handle is None:
        ctx.log("  skipped (no database connection)")
        return {"written": False}

    nodes = handle.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    rels = handle.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
    by_label = {
        row["label"]: row["c"]
        for row in handle.run(
            "MATCH (n) UNWIND labels(n) AS label "
            "RETURN label, count(*) AS c ORDER BY c DESC, label"
        )
    }
    by_type = {
        row["type"]: row["c"]
        for row in handle.run(
            "MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS c ORDER BY c DESC, type"
        )
    }
    no_id = handle.run("MATCH (n) WHERE n.id IS NULL RETURN count(n) AS c").single()["c"]
    isolated = handle.run("MATCH (n) WHERE NOT (n)--() RETURN count(n) AS c").single()["c"]

    ctx.log(f"  {nodes:>10,} nodes across {len(by_label)} label(s)")
    ctx.log(f"  {rels:>10,} relationships across {len(by_type)} type(s)")
    ctx.log(f"  {no_id:>10,} nodes with no id   (expected 0)")
    ctx.log(f"  {isolated:>10,} isolated nodes")

    return {
        "nodes": nodes,
        "relationships": rels,
        "labels": len(by_label),
        "relationship_types": len(by_type),
        "by_label": by_label,
        "by_type": by_type,
        "nodes_without_id": no_id,
        "isolated_nodes": isolated,
        "written": False,
    }
