"""Stage 5 -- post-load property passes, declared in `catalog/enrichments.py`.

Some properties are cheapest to compute once the graph exists. The CVSS summary
is the example this project needs: `CVE/cvss_v3_scores.json` doesn't record which
CVE each score belongs to -- that's in `CVE/relationships.json` -- so
reconstructing the join in Python would mean holding two 700,000-entry maps in
memory. After loading, it's a graph traversal the database already has indexes
for.

Each step is a named Cypher statement using `CALL { ... } IN TRANSACTIONS`, so a
pass touching 346,947 nodes commits in batches rather than in one transaction
that would exhaust a 1.5 GB heap. That form has to run as an autocommit
(implicit) transaction, which is why this stage uses `session.run` directly
rather than `execute_write`.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context


def run(ctx: Context, handle: Session | None, steps=()) -> dict:
    if ctx.dry_run or handle is None:
        for step in steps:
            ctx.log(f"  would run: {step.name} -- {step.description}")
        return {"steps": len(steps), "written": False}

    results = []
    for step in steps:
        summary = handle.run(step.cypher).consume()
        touched = summary.counters.properties_set
        ctx.log(f"  {step.name:34} {touched:>9,} properties set")
        results.append({"name": step.name, "properties_set": touched})
    return {"steps": len(steps), "details": results, "written": True}
