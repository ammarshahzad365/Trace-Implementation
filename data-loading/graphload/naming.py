"""Turning source vocabulary into Cypher names.

This is the **only** place the loader changes anything it reads, and it changes
names only -- never values, never structure. Two mechanical, reversible rules:

- **Node labels** PascalCase: `attack-technique` -> `AttackTechnique`. Not
  cosmetic. 12 of this dataset's 25 type values contain a hyphen, and
  `MATCH (t:attack-technique)` is a Cypher *syntax error* -- without this, every
  query against most of the graph would need backticks forever.
- **Relationship types** UPPER_SNAKE: `child_of` -> `CHILD_OF`. This one is
  convention rather than necessity (the current values are all legal as-is), but
  it is the universal Neo4j convention, and applying it uniformly is cheaper
  than remembering which catalog spelled things which way.

Both are overridable per type in `catalog/labels.py`. Neither invents, merges,
splits or renames a *field* -- if you want `related_to` to mean `HAS_WEAKNESS`,
that is a modelling decision and it belongs in `data-preprocessing/`, not here.

`assert_identifier` is the safety valve. Labels and relationship types cannot be
passed to Neo4j as query parameters -- they have to be interpolated into the
Cypher string -- so every one is checked against a strict pattern first. The
names all originate in this project's own mapping tables rather than in the
data, but a typo there should fail loudly here rather than build a query.
"""

from __future__ import annotations

import re
from typing import Mapping

_SPLIT = re.compile(r"[-_.\s]+")
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def to_label(type_value: str, overrides: Mapping[str, str] | None = None) -> str:
    """`attack-technique` -> `AttackTechnique`; `technique` -> what the override says."""
    if overrides and type_value in overrides:
        return overrides[type_value]
    parts = [p for p in _SPLIT.split(type_value.strip()) if p]
    if not parts:
        raise ValueError(f"cannot derive a label from type {type_value!r}")
    return "".join(p[:1].upper() + p[1:] for p in parts)


def to_rel_type(type_value: str, overrides: Mapping[str, str] | None = None) -> str:
    """`child_of` -> `CHILD_OF`; `uses-data-component` -> `USES_DATA_COMPONENT`."""
    if overrides and type_value in overrides:
        return overrides[type_value]
    parts = [p for p in _SPLIT.split(type_value.strip()) if p]
    if not parts:
        raise ValueError(f"cannot derive a relationship type from {type_value!r}")
    return "_".join(parts).upper()


def assert_identifier(name: str, what: str) -> str:
    """Refuse to interpolate anything that is not a bare Cypher identifier."""
    if not _IDENTIFIER.match(name):
        raise ValueError(
            f"{what} {name!r} is not a legal bare Cypher identifier -- "
            "it cannot be interpolated into a query safely"
        )
    return name
