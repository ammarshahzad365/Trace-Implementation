"""Reading a source's records, and deciding each one's label.

Sits between `spec.py` (what the files are) and the stages (what to do with
them), so that "open the file, find the id, find the type, work out the label"
exists once rather than in every stage.

`label_for` records what it did in `Findings` instead of deciding policy: an
override was used, or a name was derived, or the type is underivable. The stage
decides whether an unmapped type is fatal -- and by default it is, because an
invented label is how a future ATT&CK release quietly ends up with half its
techniques under one label and half under another.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Mapping

from . import readers
from .naming import to_label
from .spec import EdgeFile, EntityFile, SourceSpec
from .validate import Findings


def iter_records(
    spec: SourceSpec,
    source_file: EntityFile | EdgeFile,
    repo_root: Path,
    limit: int | None = None,
) -> Iterator[Mapping[str, object]]:
    path = spec.resolve(repo_root, source_file)
    reader = readers.get(source_file.reader)
    for index, record in enumerate(reader(path)):
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
        shape = entity_file.shape
        for record in iter_records(spec, entity_file, repo_root, limit):
            entity_id = record.get(shape.id)
            type_value = record.get(shape.type)
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
