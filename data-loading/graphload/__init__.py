"""A general-purpose property-graph loader.

It knows about *entity records* (each has an id and a type) and *edge rows*
(each has a type and two endpoint ids). It contains no mention of CVE, CWE,
STIX or cybersecurity anywhere -- that all lives in `catalog/`, which imports
this package and is never imported by it. `py main.py --self-check` enforces
that direction.

It also does no preprocessing. It reads records, checks them, names them for
Cypher and writes them. Anything that changes what a record *means* -- renaming
fields, deriving values, retyping links, merging duplicates -- belongs in
`data-preprocessing/`.
"""

from __future__ import annotations

__all__ = [
    "batch",
    "config",
    "context",
    "driver",
    "naming",
    "properties",
    "readers",
    "reading",
    "registry",
    "report",
    "router",
    "schema",
    "spec",
    "stages",
    "validate",
]
