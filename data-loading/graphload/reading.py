"""Reading a source's records, and deciding each one's label.

Sits between `spec.py` (what the files are) and the stages (what to do with
them), so that "open the file, find the id, find the type, work out the label"
exists once rather than in every stage.

## Streaming, not `json.load`

Every `data-preprocessing/` output file is one top-level JSON array, and
streaming it is not a micro-optimisation: `CVE/entities.json` alone is 402 MB
and `CVE/relationships.json` 95 MB, both pretty-printed at indent=2. Parsed
whole, the CVE folder peaks at several GB of Python objects. Streamed one record
at a time, memory stays flat regardless of file size -- which is what lets the
loader run beside a Neo4j heap on the same machine without either of them having
to be sized around the other.

`ijson`'s C backend (yajl2) is used when available and falls back to its pure
Python one otherwise -- same output either way, roughly 10x the speed.

`use_float=True` matters for CVSS: without it ijson yields `Decimal`, which the
Neo4j driver refuses to serialise, and a base score of 9.8 would fail the write
rather than round-trip as a float.

Reading does not clean, coerce or reshape a record -- see `properties.py` for
why.

## Labels

`label_for` records what it did in `Findings` instead of deciding policy: an
override was used, or a name was derived, or the type is underivable. The stage
decides whether an unmapped type is fatal -- and by default it is, because an
invented label is how a future ATT&CK release quietly ends up with half its
techniques under one label and half under another.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Mapping

import ijson

from .naming import to_label
from .spec import ENTITY_SHAPE, EdgeFile, EntityFile, SourceSpec
from .validate import Findings


def read_json_array(path: Path) -> Iterator[Mapping[str, object]]:
    """Stream `[ {...}, {...}, ... ]` one record at a time."""
    with open(path, "rb") as handle:
        for record in ijson.items(handle, "item", use_float=True):
            yield record


def iter_records(
    spec: SourceSpec,
    source_file: EntityFile | EdgeFile,
    repo_root: Path,
    limit: int | None = None,
) -> Iterator[Mapping[str, object]]:
    path = spec.resolve(repo_root, source_file)
    for index, record in enumerate(read_json_array(path)):
        if limit is not None and index >= limit:
            return
        yield record


def label_for(
    type_value: str,
    overrides: Mapping[str, str],
    findings: Findings,
) -> str | None:
    """The mapped label, or a derived one (recorded), or None if underivable."""
    if type_value in overrides:
        return overrides[type_value]
    findings.unmapped_types[type_value] = findings.unmapped_types.get(type_value, 0) + 1
    try:
        derived = to_label(type_value)
    except ValueError:
        return None
    findings.derived_labels[type_value] = derived
    return derived


def scan_entities(
    spec: SourceSpec,
    repo_root: Path,
    overrides: Mapping[str, str],
    findings: Findings,
    *,
    limit: int | None = None,
) -> list[tuple[str, str]]:
    """(id, label) for every entity record in a source -- what the registry needs.

    Used only when the registry has to be rebuilt without loading nodes, e.g.
    `--stage bridges` on its own with a cold cache.
    """
    entries: list[tuple[str, str]] = []
    for entity_file in spec.entity_files():
        for record in iter_records(spec, entity_file, repo_root, limit):
            entity_id = record.get(ENTITY_SHAPE.id)
            type_value = record.get(ENTITY_SHAPE.type)
            if not entity_id:
                findings.missing_id.append(f"{spec.key}/{entity_file.path}")
                continue
            if not type_value:
                findings.missing_type.append(f"{spec.key}/{entity_file.path}: {entity_id}")
                continue
            label = label_for(str(type_value), overrides, findings)
            if label is None:
                continue
            entries.append((str(entity_id), label))
    return entries
