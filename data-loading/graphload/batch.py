"""Writing nodes and relationships in batches.

Two extremes to avoid: one statement per record means a network round-trip per
record (hours), and one statement for everything means a single transaction
holding the entire dataset in the server's heap. The middle is
`UNWIND $rows AS row` -- one round-trip and one transaction per few thousand
records, with the rows travelling as a single parameter.

Labels and relationship types are interpolated into the query text because
Cypher cannot parameterise them; every one is run through `assert_identifier`
first. Values never are -- they always travel as parameters, so nothing in the
data can alter the query.

## Why `SET n = row.props` and not `SET n +=`

`=` replaces the property map; `+=` merges into it. This loader uses `=`, which
makes the graph an exact mirror of the preprocessed files: if a field is dropped
upstream in a later crawl, the reload removes it instead of leaving a stale value
behind that no file explains any more. The cost is that a property set by hand in
the Browser does not survive the next load -- which is the right trade for a
graph that is a projection of `data-preprocessing/` rather than a place to keep
work. `row.props` always carries the record's own `id`, so the MERGE key is never
lost.

Both writes stay idempotent either way: `MERGE` on a deterministic id means a
second run updates the same node or relationship rather than adding a second one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Mapping

from neo4j import Session

from .naming import assert_identifier


@dataclass
class WriteResult:
    batches: int = 0
    rows: int = 0

    def __iadd__(self, other: "WriteResult") -> "WriteResult":
        self.batches += other.batches
        self.rows += other.rows
        return self


def chunked(rows: Iterable[Mapping[str, object]], size: int) -> Iterator[list[Mapping[str, object]]]:
    batch: list[Mapping[str, object]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def node_query(label: str) -> str:
    assert_identifier(label, "node label")
    return (
        "UNWIND $rows AS row "
        f"MERGE (n:`{label}` {{id: row.id}}) "
        "SET n = row.props"
    )


def edge_query(source_label: str, rel_type: str, target_label: str) -> str:
    assert_identifier(source_label, "node label")
    assert_identifier(target_label, "node label")
    assert_identifier(rel_type, "relationship type")
    return (
        "UNWIND $rows AS row "
        f"MATCH (a:`{source_label}` {{id: row.s}}) "
        f"MATCH (b:`{target_label}` {{id: row.t}}) "
        f"MERGE (a)-[r:`{rel_type}` {{id: row.id}}]->(b) "
        "SET r = row.props"
    )


class GroupedWriter:
    """Buffers rows per group key and flushes them a batch at a time.

    Rows have to be grouped before writing, because the group key is what fixes
    the Cypher statement -- the label for a node, the
    `(source label, type, target label)` triple for an edge. Collecting all of
    them first is not an option: `CVE/relationships.json` is 336,339 rows, and
    holding them as Python dicts would cost more than the whole load's memory
    budget.

    So a group flushes as soon as it fills a batch, and if the total buffered
    across all groups passes `max_buffered`, the largest group flushes early.
    Memory stays bounded no matter how many groups a file turns out to have, and
    the file is still read in a single pass.

    `name_index` picks which part of the key the per-group counts are reported
    under: the label for nodes, the relationship type for edges.
    """

    def __init__(
        self,
        handle: Session | None,
        batch_size: int,
        query_for: Callable[[tuple[str, ...]], str],
        max_buffered: int = 50_000,
        dry_run: bool = False,
        name_index: int = 0,
    ) -> None:
        self._handle = handle
        self._batch_size = batch_size
        self._query_for = query_for
        self._max_buffered = max_buffered
        self._dry_run = dry_run or handle is None
        self._name_index = name_index
        self._groups: dict[tuple[str, ...], list] = {}
        self._buffered = 0
        self._queries: dict[tuple[str, ...], str] = {}
        self.result = WriteResult()
        self.per_name: dict[str, int] = {}

    def add(self, key: tuple[str, ...], row: Mapping[str, object]) -> None:
        group = self._groups.setdefault(key, [])
        group.append(row)
        self._buffered += 1
        name = key[self._name_index]
        self.per_name[name] = self.per_name.get(name, 0) + 1
        if len(group) >= self._batch_size:
            self._flush(key)
        elif self._buffered >= self._max_buffered:
            largest = max(self._groups, key=lambda k: len(self._groups[k]))
            self._flush(largest)

    def _flush(self, key: tuple[str, ...]) -> None:
        rows = self._groups.pop(key, None)
        if not rows:
            return
        self._buffered -= len(rows)
        if not self._dry_run:
            query = self._queries.get(key)
            if query is None:
                query = self._query_for(key)
                self._queries[key] = query
            self._handle.execute_write(lambda tx, q=query, b=rows: tx.run(q, rows=b).consume())
        self.result.batches += 1
        self.result.rows += len(rows)

    def close(self) -> None:
        for key in list(self._groups):
            self._flush(key)
