"""Turning posted records into Neo4j writes.

This is the API's equivalent of `graphload/stages/nodes.py` and `_edges.py`, and
it deliberately reuses the same pieces: `properties()` for the property map,
`to_label`/`to_rel_type` for naming, and `node_query`/`edge_query` for the
Cypher. Anything written through the API is therefore indistinguishable from
something written by a full load -- same labels, same property names, same
MERGE-on-id idempotency.

## Resolving endpoint labels

The batch loader knows every node's label from the registry it built while
streaming the files. The API has no such luxury: a relationship can point at a
node loaded months ago, so the label has to come from the database.

That is harder than it sounds, because `MATCH (n {id: $id})` with no label uses
no index -- Neo4j has no cross-label property index, so it would scan the whole
store for every endpoint. Instead `resolve_labels` runs one `WHERE n.id IN $ids`
query **per declared label**, each of which is an index seek over the whole
batch. 25 round trips for a batch of any size, rather than one scan per row.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from neo4j import Session

from graphload.batch import chunked, edge_query, node_query
from graphload.naming import to_label, to_rel_type
from graphload.properties import properties

# What `data-preprocessing/` calls these fields. Kept in step with
# `graphload/spec.py`'s RecordShape/EdgeShape defaults.
ENTITY_STRUCTURAL = ("type",)
EDGE_STRUCTURAL = ("type", "relationship_type", "source_ref", "target_ref")


class IngestError(ValueError):
    """A request that cannot be written, phrased for whoever sent it."""


def resolve_labels(
    handle: Session, ids: Iterable[str], declared_labels: Sequence[str]
) -> dict[str, str]:
    """id -> label, for ids that exist. Missing ids are simply absent."""
    wanted = sorted(set(ids))
    if not wanted:
        return {}
    found: dict[str, str] = {}
    for label in declared_labels:
        remaining = [i for i in wanted if i not in found]
        if not remaining:
            break
        rows = handle.run(
            f"MATCH (n:`{label}`) WHERE n.id IN $ids RETURN n.id AS id", ids=remaining
        )
        for row in rows:
            found[row["id"]] = label
    return found


def write_entities(
    handle: Session,
    records: Sequence[Mapping[str, object]],
    *,
    label_overrides: Mapping[str, str],
    declared_labels: Sequence[str],
    allow_new_labels: bool,
    batch_size: int = 1_000,
) -> dict:
    """MERGE each record as a node. Returns per-label counts."""
    grouped: dict[str, list[dict]] = {}
    for index, record in enumerate(records):
        entity_id = record.get("id")
        type_value = record.get("type")
        if not entity_id:
            raise IngestError(f"entities[{index}]: missing 'id'")
        if not type_value:
            raise IngestError(f"entities[{index}] ({entity_id}): missing 'type'")

        type_value = str(type_value)
        if type_value in label_overrides:
            label = label_overrides[type_value]
        elif allow_new_labels:
            label = to_label(type_value)
        else:
            raise IngestError(
                f"entities[{index}] ({entity_id}): type {type_value!r} is not declared in "
                f"catalog/labels.py. Known types: {', '.join(sorted(label_overrides))}. "
                "Add it there, or start the server with --allow-new-labels."
            )

        props = properties(
            record, structural=ENTITY_STRUCTURAL, what=label, record_id=str(entity_id)
        )
        grouped.setdefault(label, []).append({"id": str(entity_id), "props": props})

    written: dict[str, int] = {}
    for label, rows in grouped.items():
        if label not in declared_labels:
            # A brand-new label has no uniqueness constraint yet, and without one
            # two records could later fuse into a single node.
            handle.run(
                f"CREATE CONSTRAINT {label.lower()}_id_unique IF NOT EXISTS "
                f"FOR (n:`{label}`) REQUIRE n.id IS UNIQUE"
            ).consume()
            handle.run("CALL db.awaitIndexes($t)", t=120).consume()
        query = node_query(label)
        for batch in chunked(rows, batch_size):
            handle.execute_write(lambda tx, b=batch, q=query: tx.run(q, rows=b).consume())
        written[label] = len(rows)
    return {"written": sum(written.values()), "by_label": written}


def write_relationships(
    handle: Session,
    rows: Sequence[Mapping[str, object]],
    *,
    rel_type_overrides: Mapping[str, str],
    declared_labels: Sequence[str],
    batch_size: int = 1_000,
) -> dict:
    """MERGE each row as a relationship, skipping any whose endpoints are absent.

    Skipping rather than failing matches the loader: an edge naming an id no
    entity claims is reported, never invented. The response names every one, so
    the caller can decide whether it was a typo or a legitimate forward
    reference to something not loaded yet.
    """
    endpoint_ids: set[str] = set()
    for index, row in enumerate(rows):
        for field in ("id", "relationship_type", "source_ref", "target_ref"):
            if not row.get(field):
                raise IngestError(f"relationships[{index}]: missing {field!r}")
        endpoint_ids.add(str(row["source_ref"]))
        endpoint_ids.add(str(row["target_ref"]))

    labels = resolve_labels(handle, endpoint_ids, declared_labels)

    grouped: dict[tuple[str, str, str], list[dict]] = {}
    dangling: list[dict] = []
    for row in rows:
        source_id, target_id = str(row["source_ref"]), str(row["target_ref"])
        source_label, target_label = labels.get(source_id), labels.get(target_id)
        if source_label is None or target_label is None:
            dangling.append(
                {
                    "id": str(row["id"]),
                    "source_ref": source_id,
                    "target_ref": target_id,
                    "missing": [
                        i
                        for i, lab in ((source_id, source_label), (target_id, target_label))
                        if lab is None
                    ],
                }
            )
            continue
        rel_type = to_rel_type(str(row["relationship_type"]), rel_type_overrides)
        props = properties(
            row, structural=EDGE_STRUCTURAL, what=rel_type, record_id=str(row["id"])
        )
        grouped.setdefault((source_label, rel_type, target_label), []).append(
            {"id": str(row["id"]), "s": source_id, "t": target_id, "props": props}
        )

    written: dict[str, int] = {}
    for (source_label, rel_type, target_label), batch_rows in grouped.items():
        query = edge_query(source_label, rel_type, target_label)
        for batch in chunked(batch_rows, batch_size):
            handle.execute_write(lambda tx, b=batch, q=query: tx.run(q, rows=b).consume())
        written[rel_type] = written.get(rel_type, 0) + len(batch_rows)

    return {
        "written": sum(written.values()),
        "by_type": written,
        "skipped_dangling": len(dangling),
        "dangling": dangling[:50],
    }
