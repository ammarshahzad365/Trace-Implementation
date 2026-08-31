"""Stage 1 -- uniqueness constraints, and waiting for their indexes.

Runs off `catalog/labels.py`'s declared labels rather than off the data, so the
indexes exist before a single node is written. That ordering is the whole point:
see `graphload/schema.py` for why an unbacked endpoint lookup turns a
minutes-long load into an hours-long one.

Idempotent -- `IF NOT EXISTS` means re-running this stage is free.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context
from ..schema import await_indexes, create_constraints


def run(ctx: Context, handle: Session | None) -> dict:
    labels = sorted(set(ctx.declared_labels))
    if ctx.dry_run or handle is None:
        ctx.log(f"  would create {len(labels)} uniqueness constraint(s) on :Label(id)")
        return {"constraints": len(labels), "written": False}

    created = create_constraints(handle, labels)
    ctx.log(
        f"  {len(created)} uniqueness constraint(s) in place; waiting for indexes to come online"
    )
    await_indexes(handle)
    ctx.log("  indexes online")
    return {"constraints": len(created), "written": True}
