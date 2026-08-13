"""Turning a source record into a node's or relationship's properties.

Three things happen here, all declared by a `PropertyPolicy` rather than
hardcoded:

- **Identity fields are lifted out.** `id`/`type` become the node's key and its
  label, so they don't stay behind as properties (`type` would be a duplicate of
  the label; `id` is kept, because it's how every edge finds this node).
- **Prefixes are stripped.** `x_mitre_platforms` -> `platforms`. Collisions are
  a hard error, not a last-write-wins: if two source fields on the same label
  ever collapsed onto one name, one of them would silently vanish. `Collisions`
  accumulates them per label so all are reported at once.
- **Values are checked.** Neo4j properties hold a scalar or a flat array of
  scalars -- never a map, never a nested array. `data-preprocessing/` guarantees
  this (both sources that used to nest were unpacked upstream precisely so it
  holds), but a future dataset won't, and the failure mode without a check is a
  driver exception hundreds of thousands of records into a load. Better to name
  the offending record and field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .naming import strip_prefixes

SCALARS = (str, int, float, bool)


@dataclass(frozen=True)
class PropertyPolicy:
    """What to strip and what to drop when a record becomes properties."""

    strip_prefixes: tuple[str, ...] = ()
    drop_from_nodes: tuple[str, ...] = ()
    drop_from_edges: tuple[str, ...] = ()
    source_property: str = "source"

    def rename(self, name: str) -> str:
        return strip_prefixes(name, self.strip_prefixes)


@dataclass
class Collisions:
    """Property renames that would land two source fields on the same name."""

    hits: dict[tuple[str, str], set[str]] = field(default_factory=dict)

    def note(self, label: str, new_name: str, old_name: str) -> None:
        self.hits.setdefault((label, new_name), set()).add(old_name)

    def problems(self) -> list[str]:
        return [
            f"label {label}: {sorted(originals)} all become {new_name!r}"
            for (label, new_name), originals in sorted(self.hits.items())
            if len(originals) > 1
        ]


class ValueError_(ValueError):
    pass


def check_value(value: Any, where: str) -> Any:
    if isinstance(value, SCALARS) or value is None:
        return value
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, SCALARS):
                raise ValueError_(
                    f"{where}: list contains {type(item).__name__}, but Neo4j arrays "
                    "hold scalars only -- this field needs unpacking upstream"
                )
        return value
    raise ValueError_(
        f"{where}: value is a {type(value).__name__}, but Neo4j properties hold "
        "scalars or flat arrays only -- this field needs unpacking upstream"
    )


def properties(
    record: Mapping[str, Any],
    *,
    label: str,
    drop: tuple[str, ...],
    policy: PropertyPolicy,
    collisions: Collisions | None = None,
    record_id: str = "?",
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    seen: dict[str, str] = {}
    for key, value in record.items():
        if key in drop or value is None:
            continue
        name = policy.rename(key)
        if collisions is not None:
            collisions.note(label, name, key)
        if name in seen and seen[name] != key:
            raise ValueError_(
                f"{label} {record_id}: fields {seen[name]!r} and {key!r} both become {name!r}"
            )
        seen[name] = key
        out[name] = check_value(value, f"{label} {record_id} field {key!r}")
    return out
