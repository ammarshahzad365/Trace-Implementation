"""Deciding, per edge, whether it stays inside one source or crosses between two.

This is the one classification the loader cannot read off a filename, and getting
it wrong is what makes cross-source edges fail. From this dataset:

- `mitre-defend/relationships.json` is a single file, but only **1,310** of its
  5,056 rows are D3FEND-to-D3FEND. Thousands point at ATT&CK technique ids, and
  over a thousand live entirely in CWE's id space (`CWE-1004 -> CWE-732`).
  Nothing about the file says so; only the endpoints do.
- Conversely, `CVE/relationships.json` sounds internal and is almost entirely
  cross-source: all 336,339 rows point from a CVE at a CWE.

So the rule is about endpoints, not paths: an edge is **local** only if both of
its endpoints belong to the same source *and* that source is the one whose file
the row came from. Everything else is a **bridge**, and bridges must wait until
every source's nodes exist. An endpoint that resolves to nothing is **dangling**
-- reported and skipped, never invented as an empty node.

Note what this does *not* do: it does not retype, redirect or deduplicate a
cross-source edge. A bridge is loaded exactly as the data states it, with the
type the data gives it. The split exists purely because of load *ordering*.
"""

from __future__ import annotations

from enum import Enum

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
