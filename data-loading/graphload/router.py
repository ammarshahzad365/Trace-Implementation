"""Deciding, per edge, whether it stays inside one source or crosses between two.

This is the one classification the loader cannot read off a filename, and getting
it wrong is what makes cross-source edges fail. Two examples from this dataset:

- `mitre-defend/relationships.json` is a single file, but only **1,310** of its
  6,471 rows are D3FEND-to-D3FEND. **3,544** point at ATT&CK technique ids,
  **1,103** live entirely in CWE's id space (`CWE-1004 -> CWE-732`), **482** come
  from ATT&CK techniques and **32** run CWE -> D3FEND artifact. Nothing about the
  file says so; only the endpoints do.
- Conversely, a file named `external_relationships.json` is not automatically
  cross-source -- it's cross-source because of what its endpoints resolve to.

So the rule is about endpoints, not paths: an edge is **local** only if both of
its endpoints belong to the same source *and* that source is the one whose file
the row came from. Everything else is a **bridge**, and bridges must wait until
every source's nodes exist. An endpoint that resolves to nothing is **dangling**
-- reported and skipped, never invented as an empty node.

`group_key` is the other half of the job: edges are written in batches sharing a
`(source label, relationship type, target label)` triple, because that triple is
what fixes the Cypher statement. Grouping also means each batch's endpoint
lookups hit exactly two indexes.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Mapping, MutableMapping

from .registry import Registry


class Route(Enum):
    LOCAL = "local"
    BRIDGE = "bridge"
    DANGLING = "dangling"


def classify(
    registry: Registry,
    *,
    file_source: str,
    source_id: str,
    target_id: str,
) -> tuple[Route, tuple[str, str] | None, tuple[str, str] | None]:
    source = registry.lookup(source_id)
    target = registry.lookup(target_id)
    if source is None or target is None:
        return (Route.DANGLING, source, target)
    if source[1] == target[1] == file_source:
        return (Route.LOCAL, source, target)
    return (Route.BRIDGE, source, target)


def group_key(source_label: str, rel_type: str, target_label: str) -> tuple[str, str, str]:
    return (source_label, rel_type, target_label)


def bucket(
    groups: MutableMapping[tuple[str, str, str], list], key: tuple[str, str, str], row: Mapping[str, object]
) -> None:
    groups.setdefault(key, []).append(row)


def summarize(groups: Mapping[tuple[str, str, str], Iterable]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for (_, rel_type, _), rows in groups.items():
        counts[rel_type] = counts.get(rel_type, 0) + len(list(rows))
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
