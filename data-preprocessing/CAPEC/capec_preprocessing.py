"""CAPEC field-projection preprocessor.

Reads the raw STIX 2.1 bundle produced by the CAPEC crawler
(`data-acquisition/CAPEC/latest.json`) and writes three trimmed JSON files,
one per kept object type, each record reduced to a fixed field whitelist.
`identity` and `marking-definition` objects are dropped entirely -- they're
pure STIX attribution/marking boilerplate, not domain content.

This is a straight field projection, not entity/relationship graph-edge
extraction -- fields like `x_capec_child_of_refs` or `external_references`
are kept whole on the attack-pattern record itself, not split out into
separate edge records.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

ATTACK_PATTERN_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "description",
    "type",
    "external_references",
    "x_capec_abstraction",
    "x_capec_status",
    "x_capec_domains",
    "x_capec_child_of_refs",
    "x_capec_prerequisites",
    "x_capec_typical_severity",
    "x_capec_consequences",
    "x_capec_likelihood_of_attack",
    "x_capec_skills_required",
    "x_capec_resources_required",
    "x_capec_example_instances",
    "x_capec_execution_flow",
    "x_capec_parent_of_refs",
    "x_capec_extended_description",
    "x_capec_can_precede_refs",
    "x_capec_can_follow_refs",
    "x_capec_alternate_terms",
    "x_capec_peer_of_refs",
)

COURSE_OF_ACTION_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "description",
    "type",
)

RELATIONSHIP_FIELDS: Tuple[str, ...] = (
    "id",
    "type",
    "relationship_type",
    "source_ref",
    "target_ref",
    "created",
)

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "attack-pattern": ATTACK_PATTERN_FIELDS,
    "course-of-action": COURSE_OF_ACTION_FIELDS,
    "relationship": RELATIONSHIP_FIELDS,
}

DROPPED_TYPES = {"identity", "marking-definition"}

OUTPUT_FILENAMES: Dict[str, str] = {
    "attack-pattern": "attack_patterns.json",
    "course-of-action": "courses_of_action.json",
    "relationship": "relationships.json",
}


class ParseError(RuntimeError):
    pass


def load_objects(input_path: Path) -> List[Dict[str, Any]]:
    with input_path.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ParseError(f"Expected a STIX bundle with an 'objects' list at {input_path}")
    return [obj for obj in objects if isinstance(obj, dict)]


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        fields = FIELDS_BY_TYPE.get(obj_type)
        if fields is not None:
            result[obj_type].append(filter_object(obj, fields))
            continue
        if obj_type not in DROPPED_TYPES:
            print(f"[capec-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
        dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[capec-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
    return result


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    counts: Dict[str, int] = {}
    for obj_type, records in result.items():
        filename = OUTPUT_FILENAMES[obj_type]
        path = output_dir / filename
        with path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
        counts[obj_type] = len(records)
    return counts


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "CAPEC" / "latest.json"
    default_output_dir = script_dir

    parser = argparse.ArgumentParser(description="Trim CAPEC's STIX bundle down to a fixed field whitelist per object type")
    parser.add_argument(
        "--input",
        default=str(default_input),
        help=f"Path to CAPEC's latest.json (default: {default_input})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir),
        help=f"Directory to write attack_patterns.json / courses_of_action.json / relationships.json (default: {default_output_dir})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    try:
        objects = load_objects(input_path)
        result = parse(objects)
        counts = write_outputs(result, output_dir)
        print(
            "[capec-parser] wrote "
            f"{counts['attack-pattern']} attack-patterns, "
            f"{counts['course-of-action']} courses-of-action, "
            f"{counts['relationship']} relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
