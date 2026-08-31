"""Turning a record into a node's or relationship's properties.

**The loader does not preprocess.** One rule decides everything here:

    the fields declared in the record's shape become graph structure;
    every other field becomes a property, under its own name, with its own value.

Nothing is renamed, nothing is derived, nothing is stamped on, nothing is
dropped for being redundant or uninteresting. `x_nvd_vuln_status` stays
`x_nvd_vuln_status`. If a property name is wrong, the fix belongs in
`data-preprocessing/`, where it can be documented next to the raw field it came
from -- not hidden in a loader that would then quietly disagree with that
source's README.

The structural fields are the ones `spec.py` names: a record's `type` (it became
the label) and an edge row's `relationship_type`/`source_ref`/`target_ref` (they
became the relationship and its endpoints). `id` is the one identity field that
*stays* a property, because it is how every edge finds this node, and because
`data-preprocessing/` generates it as a deterministic uuid5 -- which is exactly
what makes a reload update the same record instead of adding a second one.

`check_value` is the one gate. Neo4j properties hold a scalar or a flat array of
scalars -- never a map, never a nested array. `data-preprocessing/` guarantees
this ("nothing nests" is its first output rule), but a future dataset will not,
and the failure mode without a check is a driver exception hundreds of thousands
of records into a load. Better to name the offending record and field. Note that
it *rejects*; it does not flatten. Flattening would be preprocessing.

`None` is skipped rather than written. That is not a judgement about the value --
it is what Neo4j does anyway. `SET n.foo = null` removes the property, so there
is no way to store one, and writing them would only make the batch bigger.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

SCALARS = (str, int, float, bool)


class PropertyError(ValueError):
    """A value Neo4j cannot store, named with enough context to go fix it upstream."""


def check_value(value: Any, where: str) -> Any:
    if isinstance(value, SCALARS) or value is None:
        return value
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, SCALARS):
                raise PropertyError(
                    f"{where}: list contains a {type(item).__name__}, but Neo4j arrays hold "
                    "scalars only -- this field needs unpacking in data-preprocessing/"
                )
        return value
    raise PropertyError(
        f"{where}: value is a {type(value).__name__}, but Neo4j properties hold scalars or "
        "flat arrays only -- this field needs unpacking in data-preprocessing/"
    )


def properties(
    record: Mapping[str, Any],
    *,
    structural: Iterable[str],
    what: str,
    record_id: str = "?",
) -> dict[str, Any]:
    """Every non-structural field of `record`, verbatim."""
    drop = set(structural)
    return {
        key: check_value(value, f"{what} {record_id} field {key!r}")
        for key, value in record.items()
        if key not in drop and value is not None
    }
