"""Stage 4 -- edges that cross between two sources.

These are the ones the whole graph exists for: CVE to CWE, CAPEC to CWE, CAPEC to
ATT&CK, D3FEND to ATT&CK. They're a separate stage for two reasons, both forced
by the data rather than chosen:

- **They can't load until every source's nodes exist.** A CAPEC edge pointing at
  `T1055` is unresolvable until ATT&CK is in the graph.
- **They're the ones needing dedupe rules**, because a cross-catalog fact tends
  to be asserted from both ends under two different ids.

So this stage always reads **every** source's edge files regardless of
`--only`/`--skip` -- a subset would silently drop the bridges into the sources
left out, which are exactly the edges that matter most here. Rows that belong to
stage 3 are skipped, not reloaded.

Being separate also means you can iterate on `catalog/bridges.py` and re-run just
this stage, rather than reloading 1.1M nodes to change how ~330,000 edges are
typed.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context
from ..router import Route
from . import _edges, _registry


def run(ctx: Context, handle: Session | None) -> dict:
    _registry.ensure(ctx)
    return _edges.load(ctx, handle, accept=Route.BRIDGE, stage_name="cross-source")
