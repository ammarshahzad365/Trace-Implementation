"""Stage 4 -- edges that cross from one source into another.

Separate from stage 3 for one reason, and it is not tidiness: a cross-source
edge cannot resolve its far endpoint until *every* source's nodes exist. So this
stage ignores `--only`/`--skip` and always reads all of them.

That is also what makes partial reloads possible. `--only cwe --stage nodes
edges` reloads CWE and its internal links without CVE's 336,339 cross-catalog
rows failing to find their targets; you run `--stage bridges` once afterwards.

These edges are loaded exactly as stated, with the type the data gives them --
this stage classifies, it does not remodel. See `graphload/router.py`.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context
from ..router import Route
from . import _edges, _registry


def run(ctx: Context, handle: Session | None) -> dict:
    _registry.ensure(ctx)
    return _edges.load(ctx, handle, accept=Route.BRIDGE, stage_name="cross-source")
