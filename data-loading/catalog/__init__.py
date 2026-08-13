"""Everything this loader knows about *this* dataset.

The split from `graphload/` is strict and one-directional: this package imports
the engine, the engine never imports this. Nothing here is logic -- it's five
source declarations, a label map, a property policy, a set of cross-catalog rules,
and a list of post-load Cypher passes. Point the engine at a different dataset by
writing a different `catalog/`.
"""

from __future__ import annotations

from .bridges import REL_TYPE_OVERRIDES, RULES
from .enrichments import STEPS as ENRICHMENTS
from .labels import LABELS, all_labels
from .properties import POLICY
from .sources import BY_KEY, SOURCES

__all__ = [
    "SOURCES",
    "BY_KEY",
    "LABELS",
    "all_labels",
    "POLICY",
    "RULES",
    "REL_TYPE_OVERRIDES",
    "ENRICHMENTS",
]
