"""CWE field-projection preprocessor.

Reads the raw JSON bundle produced by the CWE crawler
(`data-acquisition/CWE/latest.json`) and writes three trimmed JSON files, one
per object type, each record reduced to a fixed field whitelist.

This is a straight field projection, not entity/relationship graph-edge
extraction -- fields like `RelatedWeaknesses` or `Relationships` are kept
whole on the record itself, not split out into separate edge records.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

COMMON_FIELDS: Tuple[str, ...] = (
    "id",
    "cwe_id",
    "Name",
    "type",
    "Status",
    "created",
    "modified",
)

WEAKNESS_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "Abstraction",
    "Structure",
    "Description",
    "ExtendedDescription",
    "RelatedWeaknesses",
    "RelatedAttackPatterns",
    "CommonConsequences",
    "ApplicablePlatforms",
    "ModesOfIntroduction",
    "WeaknessOrdinalities",
    "LikelihoodOfExploit",
    "AlternateTerms",
    "PotentialMitigations",
    "DetectionMethods",
    "DemonstrativeExamples",
    "BackgroundDetails",
    "ObservedExamples",
    "AffectedResources",
    "FunctionalAreas",
)

CATEGORY_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "Summary",
    "Relationships",
)

VIEW_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "Objective",
    "Type",
    "Members",
    "Audience",
)

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "weakness": WEAKNESS_FIELDS,
    "category": CATEGORY_FIELDS,
    "view": VIEW_FIELDS,
}

OUTPUT_FILENAMES: Dict[str, str] = {
    "weakness": "weaknesses.json",
    "category": "categories.json",
    "view": "views.json",
}


class ParseError(RuntimeError):
    pass


def load_objects(input_path: Path) -> List[Dict[str, Any]]:
    with input_path.open("r", encoding="utf-8") as handle:
        bundle = json.load(handle)
    objects = bundle.get("objects") if isinstance(bundle, dict) else None
    if not isinstance(objects, list):
        raise ParseError(f"Expected a bundle with an 'objects' list at {input_path}")
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
        print(f"[cwe-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
        dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[cwe-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
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
    default_input = script_dir.parent.parent / "data-acquisition" / "CWE" / "latest.json"
    default_output_dir = script_dir

    parser = argparse.ArgumentParser(description="Trim CWE's JSON bundle down to a fixed field whitelist per object type")
    parser.add_argument(
        "--input",
        default=str(default_input),
        help=f"Path to CWE's latest.json (default: {default_input})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir),
        help=f"Directory to write weaknesses.json / categories.json / views.json (default: {default_output_dir})",
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
            "[cwe-parser] wrote "
            f"{counts['weakness']} weaknesses, "
            f"{counts['category']} categories, "
            f"{counts['view']} views "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
