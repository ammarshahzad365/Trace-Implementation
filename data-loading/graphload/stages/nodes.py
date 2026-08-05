"""Stage 2 -- entity records become nodes.

One pass per source that does three things at once, because streaming a
gigabyte of JSON twice would be the slowest part of the whole load:

1. writes the nodes,
2. collects `(id, label)` for the registry the edge stages need, and
3. saves that to the per-source cache, so a later `--stage bridges` run resolves
   endpoints from a pickle instead of re-reading the files.

Every node gets a `source` property naming the catalog it came from. Mostly
that's implied by the label, but not always -- `Consequence` holds records from
both CWE and CAPEC -- and having it uniformly makes provenance answerable
without knowing which labels happen to be shared.
"""

from __future__ import annotations

from neo4j import Session

from ..batch import GroupedWriter, node_query
from ..context import Context
from ..reading import iter_records, label_for
from ..registry import save_cached
from ..transform import properties


def run(ctx: Context, handle: Session | None) -> dict:
    per_source: dict[str, dict] = {}

    for spec in ctx.selected_specs:
        entries: list[tuple[str, str]] = []
        writer = GroupedWriter(
            handle,
            ctx.settings.batch_size,
            query_for=lambda key: node_query(key[0]),
            dry_run=ctx.dry_run or handle is None,
            type_index=0,
        )

        for entity_file in spec.entity_files():
            shape = entity_file.shape
            drop = tuple(ctx.policy.drop_from_nodes) + (shape.id, shape.type)
            for record in iter_records(spec, entity_file, ctx.repo_root, ctx.limit):
                entity_id = record.get(shape.id)
                type_value = record.get(shape.type)
                if not entity_id:
                    ctx.findings.missing_id.append(f"{spec.key}/{entity_file.path}")
                    continue
                if not type_value:
                    ctx.findings.missing_type.append(f"{spec.key}/{entity_file.path}: {entity_id}")
                    continue
                label = label_for(str(type_value), ctx.label_overrides, ctx.findings)
                if label is None:
                    continue
                entity_id = str(entity_id)
                props = properties(
                    record,
                    label=label,
                    drop=drop,
                    policy=ctx.policy,
                    collisions=ctx.collisions,
                    record_id=entity_id,
                )
                if ctx.policy.source_property in props:
                    raise SystemExit(
                        f"{spec.key}/{entity_file.path}: record {entity_id} already has a "
                        f"{ctx.policy.source_property!r} field, so stamping catalog provenance "
                        "onto it would overwrite real data. Rename "
                        "PropertyPolicy.source_property in catalog/properties.py."
                    )
                props[ctx.policy.source_property] = spec.key
                entries.append((entity_id, label))
                writer.add((label, "", ""), {"id": entity_id, "props": props})

        writer.close()
        ctx.registry.extend(entries, spec.key)
        ctx.covered_sources.add(spec.key)
        if not ctx.dry_run and ctx.limit is None and ctx.use_cache:
            save_cached(ctx.settings.cache_dir, spec, ctx.repo_root, entries)

        by_label = dict(sorted(writer.per_type.items(), key=lambda kv: -kv[1]))
        per_source[spec.key] = {"nodes": writer.result.rows, "by_label": by_label}
        ctx.log(f"  {spec.label:14} {writer.result.rows:>9,} nodes across {len(by_label)} label(s)")

    total = sum(v["nodes"] for v in per_source.values())
    ctx.log(f"  {'total':14} {total:>9,} nodes")
    return {"total": total, "by_source": per_source, "written": not (ctx.dry_run or handle is None)}
