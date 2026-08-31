"""Everything this loader knows about *this* dataset.

The split from `graphload/` is strict and one-directional: this package imports
the engine, the engine never imports this. `py main.py --self-check` fails if
that is ever violated.

Nothing here is logic. It is five source declarations and two name maps. There
is deliberately no place in this package to put a rule that changes what a
record means -- no field renames, no derived values, no retyped links, no merge
rules. That absence is the design: it is what keeps the graph a faithful
projection of `data-preprocessing/` output, so a property in Neo4j can always be
traced to a documented field in a source's README.
"""

from __future__ import annotations

from .labels import LABELS, REL_TYPE_OVERRIDES, all_labels
from .sources import BY_KEY, SOURCES

__all__ = [
    "SOURCES",
    "BY_KEY",
    "LABELS",
    "REL_TYPE_OVERRIDES",
    "all_labels",
]
