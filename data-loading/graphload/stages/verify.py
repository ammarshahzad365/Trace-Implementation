"""Stage 6 -- read-only checks on the graph that now exists.

Counts what's actually in the database, per label and per relationship type, so
they can be diffed against what the loader thought it wrote. Then four questions
worth asking every time:

- **Nodes with no `id`.** Should be zero; a non-zero count means something was
  created by an endpoint `MATCH` rather than loaded, which would be a bug here.
- **Isolated nodes.** Not necessarily wrong -- ATT&CK's 42 data sources have no
  edges at all in this release, by design -- but a jump in this number is the
  cheapest signal that an edge file didn't load.
- **Surviving `RELATED_TO`.** Must be zero. The bridge rules exist to eliminate
  it; one left means a cross-reference shape appeared that has no rule.
- **Whether the headline path traverses.** A graph can have every expected count
  and still not answer the question it was built for. This runs the actual
  CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND traversal and reports how many CVEs
  reach a defensive technique.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context

TRACE_QUERY = """
MATCH (v:Vulnerability)-[:HAS_WEAKNESS]->(:Weakness)<-[:EXPLOITS]-(:AttackPattern)
      -[:MAPS_TO_TECHNIQUE]->(:AttackTechnique)<-[:COUNTERS]-(d:DefensiveTechnique)
RETURN count(DISTINCT v) AS cves, count(DISTINCT d) AS defences
"""


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
    related_to = by_type.get("RELATED_TO", 0)
    trace = handle.run(TRACE_QUERY).single()

    ctx.log(f"  {nodes:>10,} nodes across {len(by_label)} label(s)")
    ctx.log(f"  {rels:>10,} relationships across {len(by_type)} type(s)")
    ctx.log(f"  {no_id:>10,} nodes with no id      (expected 0)")
    ctx.log(f"  {isolated:>10,} isolated nodes")
    ctx.log(f"  {related_to:>10,} surviving RELATED_TO  (expected 0)")
    ctx.log(
        f"  full CVE->CWE->CAPEC->ATT&CK->D3FEND trace reaches "
        f"{trace['cves']:,} CVEs and {trace['defences']:,} defensive techniques"
    )

    return {
        "nodes": nodes,
        "relationships": rels,
        "labels": len(by_label),
        "relationship_types": len(by_type),
        "by_label": by_label,
        "by_type": by_type,
        "nodes_without_id": no_id,
        "isolated_nodes": isolated,
        "surviving_related_to": related_to,
        "trace_cves": trace["cves"],
        "trace_defences": trace["defences"],
        "written": False,
    }
