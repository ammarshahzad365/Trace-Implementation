"""The edge-loading machinery both edge stages share.

`edges.py` and `bridges.py` differ in exactly one thing -- which `Route` they
accept -- so everything else lives here: resolve both endpoints, name the
relationship type, build the properties, and hand the row to a grouped writer.

Rows are grouped by `(source label, relationship type, target label)`, because
that triple is what fixes the Cypher statement. Grouping also means each batch's
endpoint lookups hit exactly two indexes.

Nothing here rewrites an edge. The type is whatever `relationship_type` says,
uppercased; the endpoints are whatever `source_ref` and `target_ref` say; every
other field is a property. Two catalogs asserting the same link produce two
relationships unless `data-preprocessing/` gave them the same `id` -- and
deciding that they *are* the same link is a modelling call that belongs there,
where it can be documented, not in a loader that would make it invisibly.
"""

from __future__ import annotations

from neo4j import Session

from ..batch import GroupedWriter, edge_query
from ..context import Context
from ..naming import to_rel_type
from ..properties import properties
from ..reading import iter_records
from ..router import Route, classify


def load(ctx: Context, handle: Session | None, *, accept: Route, stage_name: str) -> dict:
    writer = GroupedWriter(
        handle,
        ctx.settings.batch_size,
        query_for=lambda key: edge_query(*key),
        dry_run=ctx.dry_run,
        name_index=1,
    )
    skipped_other_route = 0
    dangling = 0
    per_source: dict[str, int] = {}

    # A bridge can start in any source, so the bridge stage always reads every
    # source's edge files even when --only narrowed the node load.
    specs = ctx.all_specs if accept is Route.BRIDGE else ctx.selected_specs

    for spec in specs:
        source_rows = 0
        for edge_file in spec.edge_files():
            shape = edge_file.shape
            for row in iter_records(spec, edge_file, ctx.repo_root, ctx.limit):
                source_id = row.get(shape.source)
                target_id = row.get(shape.target)
                raw_type = row.get(shape.type)
                edge_id = row.get(shape.id)
                if not (source_id and target_id and raw_type and edge_id):
                    ctx.findings.missing_id.append(
                        f"{spec.key}/{edge_file.path}: incomplete edge row"
                    )
                    continue

                source_id, target_id = str(source_id), str(target_id)
                route, source_pair, target_pair = classify(
                    ctx.registry,
                    file_source=spec.key,
                    source_id=source_id,
                    target_id=target_id,
                )
                if route is Route.DANGLING:
                    # Recorded once globally, by the local stage only, so both
                    # stages seeing the same row do not double-count it.
                    if accept is Route.LOCAL:
                        ctx.findings.dangling.append(
                            (source_id, str(raw_type), target_id, f"{spec.key}/{edge_file.path}")
                        )
                    dangling += 1
                    continue
                if route is not accept:
                    skipped_other_route += 1
                    continue

                rel_type = to_rel_type(str(raw_type), ctx.rel_type_overrides)
                props = properties(
                    row,
                    structural=shape.structural,
                    what=rel_type,
                    record_id=str(edge_id),
                )
                writer.add(
                    (source_pair[0], rel_type, target_pair[0]),
                    {"id": str(edge_id), "s": source_id, "t": target_id, "props": props},
                )
                source_rows += 1

        if source_rows:
            per_source[spec.key] = source_rows
            ctx.log(f"  {spec.label:14} {source_rows:>9,} {stage_name} edge rows")

    writer.close()
    by_type = dict(sorted(writer.per_name.items(), key=lambda kv: (-kv[1], kv[0])))
    ctx.log(
        f"  {'total':14} {writer.result.rows:>9,} rows written across {len(by_type)} type(s)"
    )
    return {
        "rows": writer.result.rows,
        "by_type": by_type,
        "by_source": per_source,
        "dangling_seen": dangling,
        "skipped_other_route": skipped_other_route,
        "written": not (ctx.dry_run or handle is None),
    }
