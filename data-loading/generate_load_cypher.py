"""Validate the preprocessed dataset and generate the Cypher that loads it into Neo4j.

Reads every file under `data-preprocessing/`, checks the invariants a graph load
depends on, and writes `load.cypher`. Nothing here talks to a database -- run the
generated file with cypher-shell or Neo4j Browser (see README.md).

The load goes through `apoc.load.json` rather than CSV on purpose: JSON already
carries types, arrays, embedded newlines, and quotes, all of which a CSV round-trip
would have to escape and then re-infer. Since the preprocessors leave nothing nested,
`SET n = value` maps a whole record to properties in one step.

Validation is a hard gate, not a warning: a dangling edge endpoint silently becomes a
phantom node under `MERGE`, and a duplicate entity id silently merges two unrelated
things, so both fail generation instead.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Sequence, Tuple

from graph_schema import (
    DROPPED_NODE_PROPERTIES,
    DROPPED_RELATIONSHIP_PROPERTIES,
    NODE_LABELS,
    SHARED_LABEL,
    relationship_type,
)

SOURCES: Tuple[str, ...] = ("CVE", "CWE", "CAPEC", "mitre-attack", "mitre-defend")

RELATIONSHIP_FILENAMES = {
    "relationships.json",
    "external_relationships.json",
    "derived_relationships.json",
    "attack_pattern_relationships.json",
}


class ValidationError(RuntimeError):
    pass


def iter_records(path: Path) -> Iterator[Dict[str, Any]]:
    """Stream one record at a time out of a `json.dump(indent=2)` array.

    Keyed on that writer's fixed two-space indentation rather than parsing the whole
    document, because CVE's files run to 237 MB and json.load would hold every record
    in memory at once.
    """
    chunk: List[str] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("  {"):
                chunk = [line]
            elif line.startswith("  }"):
                chunk.append("  }")
                yield json.loads("".join(chunk))
                chunk = []
            elif chunk:
                chunk.append(line)


def collect_files(root: Path) -> Tuple[List[Path], List[Path]]:
    entity_files, relationship_files = [], []
    for source in SOURCES:
        directory = root / source
        if not directory.is_dir():
            raise ValidationError(f"expected source directory {directory} does not exist")
        for path in sorted(directory.glob("*.json")):
            (relationship_files if path.name in RELATIONSHIP_FILENAMES else entity_files).append(path)
    return entity_files, relationship_files


def scan_entities(entity_files: Sequence[Path], root: Path) -> Tuple[Dict[str, str], Dict[Tuple[str, str], int]]:
    """Return (entity id -> owning file, (file, type) -> record count), failing on any
    duplicate id or unmapped type."""
    owner: Dict[str, str] = {}
    counts: Dict[Tuple[str, str], int] = collections.Counter()
    duplicates: List[str] = []
    unmapped: set = set()

    for path in entity_files:
        relative = path.relative_to(root).as_posix()
        for record in iter_records(path):
            entity_id = record.get("id")
            entity_type = record.get("type")
            if not entity_id:
                raise ValidationError(f"{relative}: a record has no `id`")
            if not entity_type:
                raise ValidationError(f"{relative}: record {entity_id!r} has no `type`")
            if entity_type not in NODE_LABELS:
                unmapped.add(f"{entity_type} ({relative})")
            if entity_id in owner:
                duplicates.append(f"{entity_id!r} in both {owner[entity_id]} and {relative}")
            owner[entity_id] = relative
            counts[(relative, entity_type)] += 1

    if unmapped:
        raise ValidationError(
            "these `type` values have no label in graph_schema.NODE_LABELS: " + ", ".join(sorted(unmapped))
        )
    if duplicates:
        raise ValidationError(
            f"{len(duplicates)} entity id(s) claimed more than once -- a shared "
            f":{SHARED_LABEL} lookup would merge unrelated nodes:\n  "
            + "\n  ".join(duplicates[:20])
        )
    return owner, counts


def scan_relationships(
    relationship_files: Sequence[Path], root: Path, known_ids: Dict[str, str]
) -> Tuple[Dict[Tuple[str, str], int], Dict[Tuple[str, str, str], int]]:
    """Return ((file, relationship_type) -> count, (file, type, column) -> dangling count)."""
    counts: Dict[Tuple[str, str], int] = collections.Counter()
    dangling: Dict[Tuple[str, str, str], int] = collections.Counter()

    for path in relationship_files:
        relative = path.relative_to(root).as_posix()
        for record in iter_records(path):
            rel_type = record.get("relationship_type")
            if not rel_type:
                raise ValidationError(f"{relative}: a record has no `relationship_type`")
            counts[(relative, rel_type)] += 1
            for column in ("source_ref", "target_ref"):
                if record.get(column) not in known_ids:
                    dangling[(relative, rel_type, column)] += 1
    return counts, dangling


def cypher_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def key_list(keys: Sequence[str]) -> str:
    return "[" + ", ".join(cypher_string(key) for key in keys) + "]"


def generate(
    root: Path,
    url_prefix: str,
    entity_counts: Dict[Tuple[str, str], int],
    relationship_counts: Dict[Tuple[str, str], int],
    dangling: Dict[Tuple[str, str, str], int],
    batch_size: int,
) -> str:
    labels = sorted({NODE_LABELS[t] for (_, t) in entity_counts})
    total_nodes = sum(entity_counts.values())
    total_edges = sum(relationship_counts.values())

    out: List[str] = []
    out.append("// Generated by data-loading/generate_load_cypher.py -- do not edit by hand.")
    out.append("// Assumes an EMPTY database: nodes are CREATEd, not MERGEd.")
    out.append(f"// Expected result: {total_nodes:,} nodes across {len(labels)} labels, "
               f"{total_edges:,} relationships across "
               f"{len({relationship_type(t) for (_, t) in relationship_counts})} types.")
    if dangling:
        skipped = sum(dangling.values())
        out.append(f"// NOTE: {skipped} edge endpoint(s) reference an id that no entity file defines.")
        out.append("//       The MATCH in each edge statement below simply won't match, so those rows")
        out.append("//       are skipped rather than creating phantom nodes. Detail:")
        for (relative, rel_type, column), count in sorted(dangling.items()):
            out.append(f"//         {count:>5}  {relative}  {rel_type}.{column}")
    out.append("")

    out.append("// ---------------------------------------------------------------------------")
    out.append("// 1. Constraints. These must exist BEFORE any relationship statement runs: each")
    out.append(f"//    edge resolves its endpoints by :{SHARED_LABEL}(id), and without the index")
    out.append(f"//    backing this constraint that is a full scan of all {total_nodes:,} nodes, per edge.")
    out.append("// ---------------------------------------------------------------------------")
    out.append(f"CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (n:{SHARED_LABEL}) REQUIRE n.id IS UNIQUE;")
    for label in labels:
        name = "".join("_" + c.lower() if c.isupper() else c for c in label).lstrip("_")
        out.append(f"CREATE CONSTRAINT {name}_id IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE;")
    out.append("")
    out.append("CALL db.awaitIndexes();")
    out.append("")

    out.append("// ---------------------------------------------------------------------------")
    out.append("// 2. Nodes. `type` is dropped -- it has become the label.")
    out.append("// ---------------------------------------------------------------------------")
    for (relative, entity_type), count in sorted(entity_counts.items()):
        label = NODE_LABELS[entity_type]
        out.append(f"// {relative} -- {count:,} x :{label}")
        out.append("CALL apoc.periodic.iterate(")
        out.append(f"  \"CALL apoc.load.json('{url_prefix}{relative}') YIELD value "
                   f"WITH value WHERE value.type = {cypher_string(entity_type)} RETURN value\",")
        out.append(f"  \"CREATE (n:{SHARED_LABEL}:{label}) SET n = apoc.map.removeKeys(value, "
                   f"{key_list(DROPPED_NODE_PROPERTIES)})\",")
        out.append(f"  {{batchSize: {batch_size}, parallel: false}}")
        out.append(");")
    out.append("")

    out.append("// ---------------------------------------------------------------------------")
    out.append("// 3. Relationships. One statement per (file, relationship_type) so the Neo4j")
    out.append("//    type is a literal rather than a runtime-computed string.")
    out.append("// ---------------------------------------------------------------------------")
    for (relative, rel_type), count in sorted(relationship_counts.items()):
        neo4j_type = relationship_type(rel_type)
        skipped = sum(v for (f, t, _), v in dangling.items() if f == relative and t == rel_type)
        note = f"  ({skipped} endpoint ref(s) unresolvable, skipped)" if skipped else ""
        out.append(f"// {relative} -- {count:,} x :{neo4j_type}{note}")
        out.append("CALL apoc.periodic.iterate(")
        out.append(f"  \"CALL apoc.load.json('{url_prefix}{relative}') YIELD value "
                   f"WITH value WHERE value.relationship_type = {cypher_string(rel_type)} RETURN value\",")
        out.append(f"  \"MATCH (a:{SHARED_LABEL} {{id: value.source_ref}}) "
                   f"MATCH (b:{SHARED_LABEL} {{id: value.target_ref}}) "
                   f"CREATE (a)-[r:{neo4j_type}]->(b) "
                   f"SET r = apoc.map.removeKeys(value, {key_list(DROPPED_RELATIONSHIP_PROPERTIES)})\",")
        out.append(f"  {{batchSize: {batch_size}, parallel: false}}")
        out.append(");")
    out.append("")

    out.append("// ---------------------------------------------------------------------------")
    out.append("// 4. Verify. Compare these against the expected counts in the header.")
    out.append("// ---------------------------------------------------------------------------")
    out.append("MATCH (n) RETURN labels(n) AS labels, count(*) AS nodes ORDER BY nodes DESC;")
    out.append("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS rels ORDER BY rels DESC;")
    out.append(f"MATCH (n) WHERE NOT n:{SHARED_LABEL} RETURN count(*) AS nodes_missing_shared_label;")
    out.append("MATCH (n) WHERE n.id IS NULL RETURN count(*) AS nodes_without_id;")
    out.append("MATCH (n) WHERE NOT (n)--() RETURN labels(n) AS labels, count(*) AS orphans ORDER BY orphans DESC;")
    return "\n".join(out) + "\n"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--input",
        default=str(script_dir.parent / "data-preprocessing"),
        help="Directory holding the five preprocessed source folders (default: ../data-preprocessing)",
    )
    parser.add_argument(
        "--output",
        default=str(script_dir / "load.cypher"),
        help="Cypher file to write (default: ./load.cypher)",
    )
    parser.add_argument(
        "--url-prefix",
        default="file:///",
        help="Prefixed to each relative JSON path to form the apoc.load.json URL. The default "
             "assumes the five source folders sit directly in Neo4j's import directory "
             "(default: file:///)",
    )
    parser.add_argument("--batch-size", type=int, default=10000, help="apoc.periodic.iterate batchSize (default: 10000)")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    root = Path(args.input)

    try:
        entity_files, relationship_files = collect_files(root)
        print(f"[generate-load-cypher] scanning {len(entity_files)} entity + "
              f"{len(relationship_files)} relationship files under {root}")

        known_ids, entity_counts = scan_entities(entity_files, root)
        print(f"[generate-load-cypher] {sum(entity_counts.values()):,} entities, all ids unique, "
              f"{len({NODE_LABELS[t] for (_, t) in entity_counts})} labels")

        relationship_counts, dangling = scan_relationships(relationship_files, root, known_ids)
        print(f"[generate-load-cypher] {sum(relationship_counts.values()):,} relationships, "
              f"{len({relationship_type(t) for (_, t) in relationship_counts})} types")
        if dangling:
            print(f"[generate-load-cypher] warning: {sum(dangling.values())} endpoint ref(s) resolve to "
                  f"no entity and will be skipped by the load:", file=sys.stderr)
            for (relative, rel_type, column), count in sorted(dangling.items()):
                print(f"    {count:>5}  {relative}  {rel_type}.{column}", file=sys.stderr)

        cypher = generate(root, args.url_prefix, entity_counts, relationship_counts, dangling, args.batch_size)
        Path(args.output).write_text(cypher, encoding="utf-8")
        print(f"[generate-load-cypher] wrote {args.output}")
        return 0
    except (ValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
