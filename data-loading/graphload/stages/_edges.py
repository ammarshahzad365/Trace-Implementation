"""The edge-loading machinery both edge stages share.

`edges.py` and `bridges.py` differ in exactly one thing -- which `Route` they
accept -- so everything else lives here: resolve both endpoints, apply the
canonical rules, convert the type name, build the properties, and hand the row
to a grouped writer.

Order matters in two places:

- **Canonicalisation happens before the type name is converted.** The rules match
  on the source's own vocabulary (`related-to`, `child_of`), and a matched row
  takes the rule's output type (`HAS_WEAKNESS`) directly rather than a mechanical
  translation of its original name.
- **Union properties are chosen after canonicalisation**, since the rule that
  matched is what decides which properties accumulate as lists instead of being
  overwritten.

`asserted_by` is added to every row as the catalog key it came from, and is
always a union property -- so an edge two catalogs assert ends up carrying both,
and the provenance survives whichever stage or order they load in.
"""

from __future__ import annotations

from typing import Callable

from neo4j import Session

from ..batch import GroupedWriter, edge_query
from ..context import Context
from ..dedupe import split_union_values
from ..naming import to_rel_type
from ..reading import iter_records
from ..router import Route, classify
from ..transform import properties

RELATED_TO_MARKERS = {"related-to", "related_to"}


def load(
    ctx: Context,
    handle: Session | None,
    *,
    accept: Route,
    stage_name: str,
) -> dict:
    dry = ctx.dry_run or handle is None

    def query_for(key: tuple[str, str, str]) -> str:
        source_label, rel_type, target_label = key
        return edge_query(
            source_label,
            rel_type,
            target_label,
            ctx.canonicalizer.union_properties_for(rel_type, source_label, target_label),
        )

    writer = GroupedWriter(handle, ctx.settings.batch_size, query_for, dry_run=dry)
    skipped_other_route = 0
    dangling = 0
    canonicalized = 0
    per_source: dict[str, int] = {}

    specs = ctx.all_specs if accept is Route.BRIDGE else ctx.selected_specs
    for spec in specs:
        source_rows = 0
        for edge_file in spec.edge_files():
            shape = edge_file.shape
            drop = tuple(ctx.policy.drop_from_edges) + (shape.id, shape.type, shape.source, shape.target)
            for row in iter_records(spec, edge_file, ctx.repo_root, ctx.limit):
                source_id = row.get(shape.source)
                target_id = row.get(shape.target)
                raw_type = row.get(shape.type)
                edge_id = row.get(shape.id)
                if not (source_id and target_id and raw_type and edge_id):
                    ctx.findings.missing_id.append(f"{spec.key}/{edge_file.path}: incomplete edge row")
                    continue

                source_id, target_id = str(source_id), str(target_id)
                route, source_pair, target_pair = classify(
                    ctx.registry, file_source=spec.key, source_id=source_id, target_id=target_id
                )
                if route is Route.DANGLING:
                    # Reported once globally, not per stage, so both stages seeing
                    # the same row don't double-count it.
                    if accept is Route.LOCAL:
                        ctx.findings.dangling.append(
                            (source_id, str(raw_type), target_id, f"{spec.key}/{edge_file.path}")
                        )
                    dangling += 1
                    continue
                if route is not accept:
                    skipped_other_route += 1
                    continue

                source_label, target_label = source_pair[0], target_pair[0]
                (
                    rel_type,
                    source_id,
                    target_id,
                    source_label,
                    target_label,
                    edge_id,
                    was_canonicalized,
                ) = ctx.canonicalizer.apply(
                    rel_type=str(raw_type),
                    source_id=source_id,
                    target_id=target_id,
                    source_label=source_label,
                    target_label=target_label,
                    edge_id=str(edge_id),
                )
                if was_canonicalized:
                    canonicalized += 1
                else:
                    rel_type = to_rel_type(str(raw_type), ctx.rel_type_overrides)
                    if str(raw_type) in RELATED_TO_MARKERS:
                        key = f"{source_label} -> {target_label}"
                        ctx.findings.leftover_related_to[key] = (
                            ctx.findings.leftover_related_to.get(key, 0) + 1
                        )

                props = properties(
                    row,
                    label=rel_type,
                    drop=drop,
                    policy=ctx.policy,
                    collisions=None,
                    record_id=str(edge_id),
                )
                props["asserted_by"] = [spec.key]
                union_names = ctx.canonicalizer.union_properties_for(rel_type, source_label, target_label)
                plain, unions = split_union_values(props, union_names)

                writer.add(
                    (source_label, rel_type, target_label),
                    {"id": edge_id, "s": source_id, "t": target_id, "props": plain, "u": unions},
                )
                source_rows += 1

        if source_rows:
            per_source[spec.key] = source_rows
            ctx.log(f"  {spec.label:14} {source_rows:>9,} {stage_name} edge rows")

    writer.close()
    by_type = dict(sorted(writer.per_type.items(), key=lambda kv: (-kv[1], kv[0])))
    ctx.log(
        f"  {'total':14} {writer.result.rows:>9,} rows written across {len(by_type)} type(s)"
        + (f"; {canonicalized:,} collapsed onto canonical edges" if canonicalized else "")
    )
    return {
        "rows": writer.result.rows,
        "by_type": by_type,
        "by_source": per_source,
        "canonicalized": canonicalized,
        "dangling_seen": dangling,
        "skipped_other_route": skipped_other_route,
        "written": not dry,
    }
