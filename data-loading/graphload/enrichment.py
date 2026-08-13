"""A named post-load Cypher pass.

Kept as data so `catalog/enrichments.py` can add one without touching a stage.
Each `cypher` should use `CALL { ... } IN TRANSACTIONS OF n ROWS` when it touches
a large number of nodes, so it commits in batches instead of building one
transaction the server's heap can't hold.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EnrichmentStep:
    name: str
    description: str
    cypher: str
