"""The five stages, each independently runnable via `main.py --stage`.

Order is a dependency chain, not a preference:

1. `constraints` -- indexes must exist before anything looks a node up by id.
2. `nodes`       -- entity records become nodes; honours `--only`/`--skip`.
3. `edges`       -- edges whose endpoints are both in one source; honours
                    `--only`/`--skip`.
4. `bridges`     -- edges between sources; always reads every source.
5. `verify`      -- read-only counts and checks; safe to run any time.

There is no transform, enrich or dedupe stage, and adding one would be a
category error: this loader moves records into Neo4j unchanged. Reshaping the
data is `data-preprocessing/`'s job, where each decision is documented next to
the raw field it came from.
"""

from __future__ import annotations

from . import bridges, constraints, edges, nodes, verify

ORDER = ("constraints", "nodes", "edges", "bridges", "verify")

MODULES = {
    "constraints": constraints,
    "nodes": nodes,
    "edges": edges,
    "bridges": bridges,
    "verify": verify,
}
