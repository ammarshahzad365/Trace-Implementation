"""CWE field-projection preprocessor.

Reads the raw JSON bundle produced by the CWE crawler
(`data-acquisition/CWE/latest.json`) and writes five trimmed JSON files.
Unlike CAPEC's source bundle, CWE's own JSON is a generic XML-to-JSON
conversion, not native STIX -- every relationship-shaped field
(`RelatedWeaknesses`, `RelatedAttackPatterns`, `AlternateTerms`,
`ObservedExamples`, `TaxonomyMappings`, `Relationships.HasMember`,
`Members.HasMember`) lives inline on the entity record itself. This script
extracts each of those into STIX-shaped `relationship` records (`id`, `type`,
`relationship_type`, `source_ref`, `target_ref`, plus a few relationship-
specific attributes) and drops the source field from the entity record, so
entities and relationships are stored completely separately -- mirroring
`capec_preprocessing.py`'s own `relationships.json` / `external_relationships
.json` split.

`PotentialMitigations` and `DetectionMethods` are left as embedded attributes
on `weakness` records, not extracted -- most entries have no stable id in the
source (1,183/1,710 mitigations, 476/959 detection methods lack
`Mitigation_ID`/`Detection_Method_ID`), so there's no reliable key to dedupe
or link against.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
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
    "CommonConsequences",
    "ApplicablePlatforms",
    "ModesOfIntroduction",
    "WeaknessOrdinalities",
    "LikelihoodOfExploit",
    "PotentialMitigations",
    "DetectionMethods",
    "BackgroundDetails",
    "AffectedResources",
    "FunctionalAreas",
)

CATEGORY_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("Summary",)

VIEW_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "Objective",
    "Type",
    "Audience",
)

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "weakness": WEAKNESS_FIELDS,
    "category": CATEGORY_FIELDS,
    "view": VIEW_FIELDS,
}

# relationship_type used for every edge pointing outside this bundle (CAPEC,
# CVE/REF, external taxonomies) -- source_name on the record disambiguates
# which external system, same convention capec_preprocessing.py uses for its
# own external_relationships.json.
EXTERNAL_RELATIONSHIP_TYPE = "related-to"

# RelatedWeakness Nature -> relationship_type. CWE's own data only ever
# stores one direction per pair (no ParentOf/CanFollow/RequiredBy values are
# present in the source), and even PeerOf -- nominally symmetric -- is only
# reciprocal in 16 of 98 pairs, so every edge is kept exactly as given
# rather than deduped/canonicalized.
NATURE_TO_RELATIONSHIP_TYPE: Dict[str, str] = {
    "ChildOf": "child_of",
    "CanPrecede": "can_precede",
    "PeerOf": "peer_of",
    "CanAlsoBe": "can_also_be",
    "Requires": "requires",
    "StartsWith": "starts_with",
}

ALSO_KNOWN_AS_RELATIONSHIP_TYPE = "also_known_as"
HAS_MEMBER_RELATIONSHIP_TYPE = "has_member"

RELATIONSHIP_KEY = "relationship"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

OUTPUT_FILENAMES: Dict[str, str] = {
    "weakness": "weaknesses.json",
    "category": "categories.json",
    "view": "views.json",
    RELATIONSHIP_KEY: "relationships.json",
    EXTERNAL_RELATIONSHIP_KEY: "external_relationships.json",
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


def as_list(value: Any) -> List[Any]:
    """CWE's XML-derived JSON collapses a single repeated element to a bare
    dict instead of a one-item list -- normalize both shapes to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    # `extra` is folded into the seed (unlike capec_preprocessing.py's version of this
    # helper) because CWE edges can legitimately repeat with the same (source, type,
    # target) but different attributes -- e.g. the same ChildOf pair recorded under two
    # different View_IDs -- and those need distinct, still-deterministic ids.
    seed_parts = [source_ref, relationship_type, target_ref]
    seed_parts.extend(f"{key}={extra[key]}" for key in sorted(extra))
    seed = "cwe-preprocessing:" + "|".join(seed_parts)
    relationship_uuid = uuid.uuid5(uuid.NAMESPACE_URL, seed)
    record: Dict[str, Any] = {
        "id": f"relationship--{relationship_uuid}",
        "type": "relationship",
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    record.update(extra)
    return record


def build_related_weakness_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("RelatedWeaknesses", {}).get("RelatedWeakness")):
        nature = item.get("Nature")
        relationship_type = NATURE_TO_RELATIONSHIP_TYPE.get(nature)
        if relationship_type is None:
            raise ParseError(f"weakness {source_ref} has unknown RelatedWeakness Nature {nature!r}")
        target_ref = f"CWE-{item.get('CWE_ID')}"
        extra: Dict[str, Any] = {}
        if item.get("Ordinal"):
            extra["ordinal"] = item["Ordinal"]
        if item.get("View_ID"):
            extra["view_id"] = item["View_ID"]
        relationships.append(make_relationship(source_ref, target_ref, relationship_type, **extra))
    return relationships


def build_also_known_as_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("AlternateTerms", {}).get("AlternateTerm")):
        term = item.get("Term")
        if not term:
            continue
        extra: Dict[str, Any] = {}
        if item.get("Description"):
            extra["description"] = item["Description"]
        relationships.append(make_relationship(source_ref, term, ALSO_KNOWN_AS_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_has_member_relationships(obj: Dict[str, Any], members_field: str) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get(members_field, {}).get("HasMember")):
        target_ref = f"CWE-{item.get('CWE_ID')}"
        extra: Dict[str, Any] = {}
        if item.get("View_ID"):
            extra["view_id"] = item["View_ID"]
        relationships.append(make_relationship(source_ref, target_ref, HAS_MEMBER_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_related_attack_pattern_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("RelatedAttackPatterns", {}).get("RelatedAttackPattern")):
        capec_id = item.get("CAPEC_ID")
        if not capec_id:
            continue
        target_ref = f"CAPEC-{capec_id}"
        relationships.append(
            make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, source_name="capec")
        )
    return relationships


def build_observed_example_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("ObservedExamples", {}).get("ObservedExample")):
        raw_ref = (item.get("Reference") or "").strip()
        if not raw_ref:
            continue
        target_ref = raw_ref.strip("[]")
        source_name = "cve" if target_ref.startswith("CVE") else "ref"
        extra: Dict[str, Any] = {"source_name": source_name}
        if item.get("Description"):
            extra["description"] = item["Description"]
        if item.get("Link"):
            extra["link"] = item["Link"]
        relationships.append(make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_taxonomy_mapping_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("TaxonomyMappings", {}).get("TaxonomyMapping")):
        taxonomy_name = item.get("Taxonomy_Name")
        entry_id = item.get("EntryID")
        entry_name = item.get("EntryName")
        if not taxonomy_name or not (entry_id or entry_name):
            continue
        target_ref = f"{taxonomy_name}:{entry_id or entry_name}"
        extra: Dict[str, Any] = {"source_name": taxonomy_name}
        if entry_id:
            extra["entry_id"] = entry_id
        if entry_name:
            extra["entry_name"] = entry_name
        if item.get("MappingFit"):
            extra["mapping_fit"] = item["MappingFit"]
        relationships.append(make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, **extra))
    return relationships


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[RELATIONSHIP_KEY] = []
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        fields = FIELDS_BY_TYPE.get(obj_type)
        if fields is None:
            print(f"[cwe-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        result[obj_type].append(filter_object(obj, fields))

        if obj_type == "weakness":
            result[RELATIONSHIP_KEY].extend(build_related_weakness_relationships(obj))
            result[RELATIONSHIP_KEY].extend(build_also_known_as_relationships(obj))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_related_attack_pattern_relationships(obj))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_observed_example_relationships(obj))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_taxonomy_mapping_relationships(obj))
        elif obj_type == "category":
            result[RELATIONSHIP_KEY].extend(build_has_member_relationships(obj, "Relationships"))
        elif obj_type == "view":
            result[RELATIONSHIP_KEY].extend(build_has_member_relationships(obj, "Members"))

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
        help=(
            "Directory to write weaknesses.json / categories.json / views.json / "
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
            "[cwe-parser] wrote "
            f"{counts['weakness']} weaknesses, "
            f"{counts['category']} categories, "
            f"{counts['view']} views, "
            f"{counts[RELATIONSHIP_KEY]} relationships, "
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
