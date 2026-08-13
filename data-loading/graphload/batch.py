"""Writing nodes and relationships in batches.

Two extremes to avoid: one statement per record means a network round-trip per
record (hours), and one statement for everything means a single transaction
holding 1.1M nodes in the server's heap (an out-of-memory crash on a 1.5 GB
heap). The middle is `UNWIND $rows AS row` -- one round-trip and one transaction
per few thousand records, with the rows travelling as a single parameter.

Labels and relationship types are interpolated into the query text because
Cypher cannot parameterise them; every one is run through `assert_identifier`
first. Values never are -- they always travel as parameters, so nothing in the
data can alter the query.

## Union properties

`MERGE` overwrites. That's wrong for a fact two catalogs both assert: when CWE
and D3FEND both record `CWE-1004 child_of CWE-732`, the second write must not
erase the first's provenance. So designated properties are *unioned into a list*
by the write itself:

    SET r.asserted_by = [x IN coalesce(r.asserted_by, []) WHERE NOT x IN row.u['asserted_by']]
                        + row.u['asserted_by']

Doing it in Cypher rather than Python is what keeps `stages/bridges.py`
streaming -- otherwise deduplicating 334,000 cross-source edges would mean
holding all of them in a dict first. The `WHERE NOT x IN` guard is also what
makes a re-run idempotent instead of appending the same provenance again.

Every row in a group must supply every union property as a list (empty is fine);
a missing one would make `[] + null` fail at the server. `stages/` guarantees it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping, Sequence

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
        "SET n += row.props"
    )


def edge_query(
    source_label: str,
    rel_type: str,
    target_label: str,
    union_properties: Sequence[str] = (),
) -> str:
    assert_identifier(source_label, "node label")
    assert_identifier(target_label, "node label")
    assert_identifier(rel_type, "relationship type")

    parts = [
        "UNWIND $rows AS row",
        f"MATCH (a:`{source_label}` {{id: row.s}})",
        f"MATCH (b:`{target_label}` {{id: row.t}})",
        f"MERGE (a)-[r:`{rel_type}` {{id: row.id}}]->(b)",
        "SET r += row.props",
    ]
    for name in union_properties:
        assert_identifier(name, "property name")
        parts.append(
            f"SET r.`{name}` = "
            f"[x IN coalesce(r.`{name}`, []) WHERE NOT x IN row.u['{name}']] + row.u['{name}']"
        )
    return " ".join(parts)


def write(handle: Session, query: str, rows: Iterable[Mapping[str, object]], batch_size: int) -> WriteResult:
    result = WriteResult()
    for batch in chunked(rows, batch_size):
        handle.execute_write(lambda tx, b=batch: tx.run(query, rows=b).consume())
        result.batches += 1
        result.rows += len(batch)
    return result


class GroupedWriter:
    """Buffers edge rows per `(source label, type, target label)` and flushes them.

    Edges have to be grouped before writing, because that triple is what fixes
    the Cypher statement. Collecting all of them first is not an option:
    `CVE/relationships.json` alone is 593,945 rows, and holding them as Python
    dicts would cost more memory than the entire Neo4j heap this runs beside.

    So groups flush as soon as one fills a batch, and if the total buffered
    across all groups passes `max_buffered`, the largest group flushes early.
    Memory stays bounded no matter how many groups a file turns out to have,
    and the file is still read in a single pass.
    """

    def __init__(
        self,
        handle: Session,
        batch_size: int,
        query_for,
        max_buffered: int = 50_000,
        dry_run: bool = False,
        type_index: int = 1,
    ) -> None:
        self._handle = handle
        self._batch_size = batch_size
        self._query_for = query_for
        self._max_buffered = max_buffered
        self._dry_run = dry_run
        self._type_index = type_index
        self._groups: dict[tuple[str, str, str], list] = {}
        self._buffered = 0
        self._queries: dict[tuple[str, str, str], str] = {}
        self.result = WriteResult()
        self.per_type: dict[str, int] = {}

    def add(self, key: tuple[str, str, str], row: Mapping[str, object]) -> None:
        group = self._groups.setdefault(key, [])
        group.append(row)
        self._buffered += 1
        name = key[self._type_index]
        self.per_type[name] = self.per_type.get(name, 0) + 1
        if len(group) >= self._batch_size:
            self._flush(key)
        elif self._buffered >= self._max_buffered:
            largest = max(self._groups, key=lambda k: len(self._groups[k]))
            self._flush(largest)

    def _flush(self, key: tuple[str, str, str]) -> None:
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
