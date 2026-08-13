"""Turning source vocabulary into Cypher-legal names.

Three jobs, all mechanical and all reversible by inspection:

- **Node labels.** A source's own type string is rarely a legal Cypher
  identifier: `attack-technique` contains a hyphen, so `MATCH (t:attack-technique)`
  is a syntax error and every query would need backticks forever. The default
  transform splits on `-`/`_`/`.` and PascalCases (`cvss-v3-score` ->
  `CvssV3Score`). Where that reads wrong, `catalog/labels.py` overrides it.
- **Relationship types.** Neo4j convention is UPPER_SNAKE, and the same hyphen
  problem applies (`subtechnique-of` -> `SUBTECHNIQUE_OF`).
- **Property names.** Source-format prefixes (`x_capec_`, `x_mitre_`, `x_nvd_`)
  mark a STIX custom extension: a fact about the file, not about the thing.
  Stripped, with the caller responsible for checking nothing collided.

`assert_identifier` is the safety valve. Labels and relationship types cannot be
passed to Neo4j as query parameters -- they have to be interpolated into the
Cypher string -- so every one is checked against a strict pattern first. The
names all originate in this project's own mapping tables rather than in the
data, but a typo there should fail loudly here rather than build a query.
"""

from __future__ import annotations

import re
from typing import Iterable, Mapping

_SPLIT = re.compile(r"[-_.\s]+")
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def to_label(type_value: str, overrides: Mapping[str, str] | None = None) -> str:
    """`cvss-v3-score` -> `CvssV3Score`; `technique` -> whatever the override says."""
    if overrides and type_value in overrides:
        return overrides[type_value]
    parts = [p for p in _SPLIT.split(type_value.strip()) if p]
    if not parts:
        raise ValueError(f"cannot derive a label from type {type_value!r}")
    return "".join(p[:1].upper() + p[1:] for p in parts)


def to_rel_type(type_value: str, overrides: Mapping[str, str] | None = None) -> str:
    """`related-to` -> `RELATED_TO`; `has_cvss_v3_score` -> `HAS_CVSS_V3_SCORE`."""
    if overrides and type_value in overrides:
        return overrides[type_value]
    parts = [p for p in _SPLIT.split(type_value.strip()) if p]
    if not parts:
        raise ValueError(f"cannot derive a relationship type from {type_value!r}")
    return "_".join(parts).upper()


def strip_prefixes(name: str, prefixes: Iterable[str]) -> str:
    """`x_mitre_platforms` -> `platforms`. Longest matching prefix wins."""
    for prefix in sorted(prefixes, key=len, reverse=True):
        if name.startswith(prefix) and len(name) > len(prefix):
            return name[len(prefix):]
    return name


def assert_identifier(name: str, what: str) -> str:
    """Refuse to interpolate anything that isn't a bare Cypher identifier."""
    if not _IDENTIFIER.match(name):
        raise ValueError(
            f"{what} {name!r} is not a legal bare Cypher identifier -- "
            "it cannot be interpolated into a query safely"
        )
    return name
