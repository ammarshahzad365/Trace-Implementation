"""How a data source is described to the loader.

Everything in `graphload/` is deliberately ignorant of CVE, CWE, STIX and
cybersecurity generally. What it knows is:

- an **entity file** holds records that each have an id and a type, and
- an **edge file** holds rows that each have a type and two endpoint ids.

Which fields carry those things is not assumed -- it is declared, via
`RecordShape`/`EdgeShape`. The defaults match what `data-preprocessing/` emits
(`id`, `type`, `relationship_type`, `source_ref`, `target_ref`), so `catalog/`
never has to spell them out; a future dataset that calls them
`uuid`/`kind`/`from`/`to` passes a different shape rather than needing a
different loader.

Those declared field names do double duty. They say where to *read* identity
from, and they are exactly the fields that become graph structure rather than
properties -- see `properties.py`. Nothing else about a record is interpreted.

`reader` names an entry in `graphload.readers.REGISTRY` -- streaming JSON array
by default, with JSONL and CSV also available. A new input format is a new
reader, not a change to any stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence, Union


@dataclass(frozen=True)
class RecordShape:
    """Where an entity record keeps its id and its type."""

    id: str = "id"
    type: str = "type"

    @property
    def structural(self) -> tuple[str, ...]:
        """Fields that become structure, so they do not also become properties."""
        return (self.type,)


@dataclass(frozen=True)
class EdgeShape:
    """Where an edge row keeps its id, its type, and its two endpoint ids.

    `kind` is separate from `type` because `data-preprocessing/` stamps a literal
    `"type": "relationship"` on every edge row alongside the `relationship_type`
    that actually names the link. It says what the record is, which the
    relationship itself now says, so it is structural too.
    """

    id: str = "id"
    type: str = "relationship_type"
    source: str = "source_ref"
    target: str = "target_ref"
    kind: str = "type"

    @property
    def structural(self) -> tuple[str, ...]:
        return (self.type, self.source, self.target, self.kind)


@dataclass(frozen=True)
class EntityFile:
    """One file of records that become nodes."""

    path: str
    reader: str = "json_array"
    shape: RecordShape = field(default_factory=RecordShape)


@dataclass(frozen=True)
class EdgeFile:
    """One file of rows that become relationships."""

    path: str
    reader: str = "json_array"
    shape: EdgeShape = field(default_factory=EdgeShape)


SourceFile = Union[EntityFile, EdgeFile]


@dataclass(frozen=True)
class SourceSpec:
    """One data source: a folder, and the files in it worth loading.

    `key` is what `--only`/`--skip` match on, and what the registry records as a
    node's origin -- which is how the router later tells an edge that stays
    inside one source from one that crosses between two.
    """

    key: str
    label: str
    root: str
    files: Sequence[SourceFile]

    def entity_files(self) -> list[EntityFile]:
        return [f for f in self.files if isinstance(f, EntityFile)]

    def edge_files(self) -> list[EdgeFile]:
        return [f for f in self.files if isinstance(f, EdgeFile)]

    def resolve(self, repo_root: Path, source_file: SourceFile) -> Path:
        return repo_root / self.root / source_file.path

    def missing(self, repo_root: Path) -> list[Path]:
        return [p for p in (self.resolve(repo_root, f) for f in self.files) if not p.exists()]
