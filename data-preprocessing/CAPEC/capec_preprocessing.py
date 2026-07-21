"""CAPEC field-projection preprocessor.

Reads the raw STIX 2.1 bundle produced by the CAPEC crawler
(`data-acquisition/CAPEC/latest.json`) and writes four trimmed JSON files.
`identity` and `marking-definition` objects are dropped entirely -- they're
pure STIX attribution/marking boilerplate, not domain content.

`external_references` is not kept verbatim on attack-pattern records:
- its `source_name == "capec"` entry (always exactly one) becomes a plain
  `capec_id` integer attribute instead of a nested reference object.
- its `cwe` / `ATTACK` entries become STIX-shaped relationship records in a
  separate `external_relationships.json` (`CAPEC-N --related-to--> CWE-N` /
  `--related-to--> T####`), the same shape as `relationships.json`'s
  `mitigates` edges.
- its `reference_from_CAPEC` / `OWASP Attacks` / `WASC` entries (bibliographic
  citations, no local entity) are dropped entirely, not stored anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

ATTACK_PATTERN_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "description",
    "type",
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

# external_references source_name values that become external_relationships.json rows.
EXTERNAL_RELATIONSHIP_SOURCE_NAMES = {"cwe", "ATTACK"}

EXTERNAL_RELATIONSHIP_TYPE = "related-to"

EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

OUTPUT_FILENAMES: Dict[str, str] = {
    "attack-pattern": "attack_patterns.json",
    "course-of-action": "courses_of_action.json",
    "relationship": "relationships.json",
    EXTERNAL_RELATIONSHIP_KEY: "external_relationships.json",
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


def extract_capec_id(obj: Dict[str, Any]) -> int:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "capec":
            external_id = str(ref.get("external_id") or "")
            return int(external_id.split("-", 1)[1])
    raise ParseError(f"attack-pattern {obj.get('id')} has no 'capec' external_reference")


def make_external_relationship(source_ref: str, target_ref: str, source_name: str) -> Dict[str, Any]:
    seed = f"capec-preprocessing:{source_ref}|{EXTERNAL_RELATIONSHIP_TYPE}|{target_ref}"
    relationship_uuid = uuid.uuid5(uuid.NAMESPACE_URL, seed)
    return {
        "id": f"relationship--{relationship_uuid}",
        "type": "relationship",
        "relationship_type": EXTERNAL_RELATIONSHIP_TYPE,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "source_name": source_name,
    }


def build_external_relationships(obj: Dict[str, Any], capec_id: int) -> List[Dict[str, Any]]:
    source_ref = f"CAPEC-{capec_id}"
    relationships = []
    for ref in obj.get("external_references", []):
        source_name = ref.get("source_name")
        if source_name not in EXTERNAL_RELATIONSHIP_SOURCE_NAMES:
            continue
        target_ref = ref.get("external_id")
        if not target_ref:
            continue
        relationships.append(make_external_relationship(source_ref, target_ref, source_name))
    return relationships


def build_attack_pattern_record(obj: Dict[str, Any], capec_id: int) -> Dict[str, Any]:
    record: Dict[str, Any] = {}
    for field in ATTACK_PATTERN_FIELDS:
        if field in obj:
            record[field] = obj[field]
        if field == "id":
            record["capec_id"] = capec_id
    return record


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        if obj_type == "attack-pattern":
            capec_id = extract_capec_id(obj)
            result["attack-pattern"].append(build_attack_pattern_record(obj, capec_id))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_external_relationships(obj, capec_id))
            continue
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
        help=(
            "Directory to write attack_patterns.json / courses_of_action.json / "
            f"relationships.json / external_relationships.json (default: {default_output_dir})"
        ),
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
            f"{counts['relationship']} relationships, "
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
