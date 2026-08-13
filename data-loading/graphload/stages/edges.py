"""Stage 3 -- edges whose both endpoints live in the same source.

The safe majority: an edge from a CVE to its own CVSS score, from a CWE category
to its member weakness, from an ATT&CK group to the technique it uses. These need
only their own source's nodes, so they honour `--only`/`--skip` and can be
reloaded per source without touching anything else.
"""

from __future__ import annotations

from neo4j import Session

from ..context import Context
from ..router import Route
from . import _edges, _registry


def run(ctx: Context, handle: Session | None) -> dict:
    _registry.ensure(ctx)
    return _edges.load(ctx, handle, accept=Route.LOCAL, stage_name="local")
