"""The six stages, each independently runnable via `main.py --stage`.

Order is a dependency chain, not a preference:

1. `constraints` -- indexes must exist before anything looks a node up by id.
2. `nodes`       -- entity records become nodes; honours `--only`/`--skip`.
3. `edges`       -- edges within one source; honours `--only`/`--skip`.
4. `bridges`     -- edges between sources; always reads every source.
5. `enrich`      -- property passes that are cheaper as graph queries.
6. `verify`      -- read-only counts and checks; safe to run any time.
"""

from __future__ import annotations

from . import bridges, constraints, edges, enrich, nodes, verify

ORDER = ("constraints", "nodes", "edges", "bridges", "enrich", "verify")

MODULES = {
    "constraints": constraints,
    "nodes": nodes,
    "edges": edges,
    "bridges": bridges,
    "enrich": enrich,
    "verify": verify,
}
