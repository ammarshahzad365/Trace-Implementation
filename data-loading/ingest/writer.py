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
query **per candidate label**, each of which is an index seek over the whole
batch. A couple of dozen round trips for a batch of any size, rather than one
scan per row.

The candidate list has to be the labels *the database actually has*, not the
labels `catalog/` declares. This endpoint mints labels the catalog has never
heard of -- that is its purpose -- so resolving against the catalog alone would
report a `ThreatActor` node posted an hour ago as a dangling endpoint. See
`api._label_candidates`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Mapping, MutableSet, Sequence

from neo4j import Session

from graphload.batch import chunked, edge_query, node_query
from graphload.naming import assert_identifier, to_label, to_rel_type
from graphload.properties import properties
from graphload.schema import await_indexes, create_constraints
from graphload.spec import EDGE_SHAPE, ENTITY_SHAPE

# Note this batches with `chunked` directly rather than through
# `graphload.batch.GroupedWriter`. The writer exists to keep memory bounded
# while streaming hundreds of megabytes, and it earns that with buffering,
# early flushes and a query cache. A request holds its records in a list
# already, so here it would be more machinery for the same two round trips.

# The fields TRACE section 3.2.4 requires on every record. `id`/`type` (or
# `relationship_type`/`source_ref`/`target_ref`) are structural -- the loader
# cannot place the record without them. `source` is not structural but is
# required anyway: it is what lets entity alignment tell two same-named nodes
# from different documents apart, which is exactly the case unstructured
# extraction produces. Everything else on a record is a plain property and is
# entirely up to the caller.
_MISSING_SOURCE = "missing 'source' -- required so this record can be told apart from others of the same id/type"


def _now() -> str:
    """Same format `data-acquisition/*/client.py` stamps: seconds precision, `Z`."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class IngestError(ValueError):
    """A request that cannot be written, phrased for whoever sent it."""


def resolve_labels(
    handle: Session, ids: Iterable[str], candidate_labels: Sequence[str]
) -> dict[str, str]:
    """id -> label, for ids that exist. Missing ids are simply absent.

    `candidate_labels` should be ordered with the likeliest first: the loop
    stops as soon as every id is placed, so the five catalogs' labels ahead of
    everything else means the common case costs a handful of seeks.
    """
    wanted = sorted(set(ids))
    if not wanted:
        return {}
    found: dict[str, str] = {}
    for label in candidate_labels:
        # Backticks are the one character that could break out of the quoting
        # below. Nothing this code writes can produce one -- write_entities
        # rejects it -- but a label created by hand in the Browser could, and
        # skipping it is better than building a broken query.
        if "`" in label:
            continue
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
    ensured_labels: MutableSet[str],
    batch_size: int = 1_000,
) -> dict:
    """MERGE each record as a node. Returns per-label counts and any new labels.

    `type` is never rejected for being unrecognised -- it is derived into a
    label mechanically (`threat-actor` -> `ThreatActor`) unless
    `label_overrides` names something more specific, exactly as
    `catalog/labels.py` does for the five structured catalogs. Extraction from
    unstructured sources will keep introducing types this project has not seen
    yet; the API's job is to place them, not to gate them.

    It is rejected for being *unusable*, though. A label is interpolated into
    Cypher -- it cannot travel as a parameter -- so a derived name that is not a
    bare identifier is refused here, before any query is built, the same way
    `graphload/batch.py` refuses one. `to_label` only strips `-`, `_`, `.` and
    whitespace, so a `type` carrying a backtick or a parenthesis reaches this
    point intact.

    `ensured_labels` is the set of labels already known to have a uniqueness
    constraint; any label outside it gets one created, and is added to the set.
    Passing the caller's own set across requests is what stops a 120-second
    `awaitIndexes` from running on every single post.
    """
    grouped: dict[str, list[dict]] = {}
    for index, record in enumerate(records):
        entity_id = record.get("id")
        type_value = record.get("type")
        if not entity_id:
            raise IngestError(f"entities[{index}]: missing 'id'")
        if not type_value:
            raise IngestError(f"entities[{index}] ({entity_id}): missing 'type'")
        if not record.get("source"):
            raise IngestError(f"entities[{index}] ({entity_id}): {_MISSING_SOURCE}")

        record = dict(record)
        record.setdefault("collected_at", _now())

        type_value = str(type_value)
        try:
            label = label_overrides.get(type_value) or to_label(type_value)
            assert_identifier(label, "node label")
        except ValueError as exc:
            raise IngestError(f"entities[{index}] ({entity_id}): {exc}") from exc

        props = properties(
            record, structural=ENTITY_SHAPE.structural, what=label, record_id=str(entity_id)
        )
        grouped.setdefault(label, []).append({"id": str(entity_id), "props": props})

    written: dict[str, int] = {}
    new_labels: list[str] = []
    for label, rows in grouped.items():
        if label not in ensured_labels:
            # A brand-new label has no uniqueness constraint yet, and without one
            # two records could later fuse into a single node.
            create_constraints(handle, [label])
            await_indexes(handle, 120)
            ensured_labels.add(label)
            new_labels.append(label)
        query = node_query(label)
        for batch in chunked(rows, batch_size):
            handle.execute_write(lambda tx, b=batch, q=query: tx.run(q, rows=b).consume())
        written[label] = len(rows)
    return {
        "written": sum(written.values()),
        "by_label": written,
        "new_labels": sorted(new_labels),
    }


def write_relationships(
    handle: Session,
    rows: Sequence[Mapping[str, object]],
    *,
    rel_type_overrides: Mapping[str, str],
    candidate_labels: Sequence[str],
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
        if not row.get("source"):
            raise IngestError(f"relationships[{index}]: {_MISSING_SOURCE}")
        # Same reason as the label guard in write_entities: a relationship type
        # is interpolated, not parameterised. Checked here so the whole request
        # is refused before anything is written, rather than partway through.
        try:
            assert_identifier(
                to_rel_type(str(row["relationship_type"]), rel_type_overrides),
                "relationship type",
            )
        except ValueError as exc:
            raise IngestError(f"relationships[{index}] ({row['id']}): {exc}") from exc
        endpoint_ids.add(str(row["source_ref"]))
        endpoint_ids.add(str(row["target_ref"]))

    labels = resolve_labels(handle, endpoint_ids, candidate_labels)

    grouped: dict[tuple[str, str, str], list[dict]] = {}
    dangling: list[dict] = []
    for row in rows:
        row = dict(row)
        row.setdefault("collected_at", _now())
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
            row, structural=EDGE_SHAPE.structural, what=rel_type, record_id=str(row["id"])
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
