"""CAPEC field-projection preprocessor.

Reads the raw STIX 2.1 bundle produced by the CAPEC crawler
(`data-acquisition/CAPEC/latest.json`) and writes five trimmed JSON files.
`identity` and `marking-definition` objects are dropped entirely -- they're
pure STIX attribution/marking boilerplate, not domain content.

`external_references` is not kept verbatim on attack-pattern records:
- its `source_name == "capec"` entry (always exactly one) determines the
  record's own `id`: attack-patterns are keyed by `CAPEC-N` (e.g.
  `CAPEC-85`) everywhere in this project's output, not by their STIX id.
  The original STIX id is kept alongside as `stix_id`.
- its `cwe` / `ATTACK` entries become STIX-shaped relationship records in a
  separate `external_relationships.json` (`CAPEC-N --related-to--> CWE-N` /
  `--related-to--> T####`), the same shape as `relationships.json`'s
  `mitigates` edges.
- its `reference_from_CAPEC` / `OWASP Attacks` / `WASC` entries (bibliographic
  citations, no local entity) are dropped entirely, not stored anywhere.

`relationship` objects (`relationships.json`) keep their own native STIX
`id`, but any `source_ref`/`target_ref` that points at an attack-pattern is
rewritten from that attack-pattern's STIX id to its `CAPEC-N` id, so every
reference to a CAPEC attack-pattern anywhere in this project's output uses
the same `CAPEC-N` key.

`x_capec_status` and `x_capec_execution_flow` are dropped with no
replacement. The attack-pattern-to-attack-pattern ref fields
(`x_capec_child_of_refs`/`x_capec_parent_of_refs`,
`x_capec_can_precede_refs`/`x_capec_can_follow_refs`,
`x_capec_peer_of_refs`) and `x_capec_alternate_terms` are likewise removed
from attack_patterns.json and instead become STIX-shaped relationship
records in `attack_pattern_relationships.json`:
- `child_of`/`parent_of` and `can_precede`/`can_follow` are each perfectly
  reciprocal pairs in the source data, so only one direction is emitted
  (`child_of`, `can_precede`) to avoid storing every edge twice.
- `peer_of` is symmetric but *not* consistently reciprocal in the source
  data, so it's deduplicated to one edge per unordered pair (canonical
  direction: lower capec_id -> higher capec_id).
- `x_capec_alternate_terms` becomes `also_known_as` edges where `target_ref`
  is the alias text itself (there's no other entity for an alias to point
  at).

`x_capec_consequences` and `x_capec_skills_required` are the only two fields
in CAPEC's output that were maps rather than scalars/scalar lists -- illegal
as Neo4j properties -- so both are unpacked into their own entity files plus
edges. See `build_consequence_relationships()` and
`build_skill_relationships()`.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# x_capec_consequences / x_capec_skills_required are extracted to their own
# entities + edges rather than kept here -- both were maps. See module docstring.
ATTACK_PATTERN_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "description",
    "type",
    "x_capec_abstraction",
    "x_capec_domains",
    "x_capec_prerequisites",
    "x_capec_typical_severity",
    "x_capec_likelihood_of_attack",
    "x_capec_resources_required",
    "x_capec_example_instances",
    "x_capec_extended_description",
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

# x_capec_*_refs field -> relationship_type for the one direction of each pair that's kept
# (the other direction -- parent_of/can_follow -- is a verified-reciprocal inverse, so it's
# dropped rather than stored twice).
HIERARCHY_REF_FIELDS: Dict[str, str] = {
    "x_capec_child_of_refs": "child_of",
    "x_capec_can_precede_refs": "can_precede",
}

PEER_OF_RELATIONSHIP_TYPE = "peer_of"
ALSO_KNOWN_AS_RELATIONSHIP_TYPE = "also_known_as"
HAS_CONSEQUENCE_RELATIONSHIP_TYPE = "has_consequence"
REQUIRES_SKILL_RELATIONSHIP_TYPE = "requires_skill"

ATTACK_PATTERN_RELATIONSHIP_KEY = "attack-pattern-relationship"

# Deliberately the same `type` value (and the same {scope, impact} shape) CWE's own
# preprocessor emits: a consequence means the same thing in both catalogs, so both
# should land under one Neo4j label. The node *ids* are still per-catalog, so the 4
# (scope, impact) pairs the two vocabularies share become one node each per catalog
# rather than a single shared node -- these preprocessors run independently and
# can't coordinate a joint id space.
CONSEQUENCE_ENTITY_TYPE = "consequence"
SKILL_LEVEL_ENTITY_TYPE = "skill-level"

# CAPEC writes the Access Control scope with an underscore where CWE writes a space;
# normalized to CWE's spelling so the 9 scope values are one shared vocabulary.
CONSEQUENCE_SCOPE_ALIASES: Dict[str, str] = {"Access_Control": "Access Control"}

OUTPUT_FILENAMES: Dict[str, str] = {
    "attack-pattern": "attack_patterns.json",
    "course-of-action": "courses_of_action.json",
    CONSEQUENCE_ENTITY_TYPE: "consequences.json",
    SKILL_LEVEL_ENTITY_TYPE: "skill_levels.json",
    "relationship": "relationships.json",
    EXTERNAL_RELATIONSHIP_KEY: "external_relationships.json",
    ATTACK_PATTERN_RELATIONSHIP_KEY: "attack_pattern_relationships.json",
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


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    seed = f"capec-preprocessing:{source_ref}|{relationship_type}|{target_ref}"
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
        relationships.append(make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, source_name=source_name))
    return relationships


def resolve_capec_ref(stix_id: str, id_to_capec_id: Dict[str, int]) -> str:
    capec_id = id_to_capec_id.get(stix_id)
    if capec_id is None:
        raise ParseError(f"attack-pattern ref {stix_id!r} does not resolve to any known attack-pattern")
    return f"CAPEC-{capec_id}"


def remap_attack_pattern_ref(ref: str, id_to_capec_id: Dict[str, int]) -> str:
    """Rewrite a relationship endpoint from an attack-pattern's STIX id to its CAPEC-N id.
    Endpoints that aren't a known attack-pattern STIX id (e.g. a course-of-action) pass
    through unchanged."""
    capec_id = id_to_capec_id.get(ref)
    return f"CAPEC-{capec_id}" if capec_id is not None else ref


def build_hierarchy_relationships(obj: Dict[str, Any], capec_id: int, id_to_capec_id: Dict[str, int]) -> List[Dict[str, Any]]:
    source_ref = f"CAPEC-{capec_id}"
    relationships = []
    for ref_field, relationship_type in HIERARCHY_REF_FIELDS.items():
        for target_stix_id in obj.get(ref_field, []):
            target_ref = resolve_capec_ref(target_stix_id, id_to_capec_id)
            relationships.append(make_relationship(source_ref, target_ref, relationship_type))
    return relationships


def build_also_known_as_relationships(obj: Dict[str, Any], capec_id: int) -> List[Dict[str, Any]]:
    source_ref = f"CAPEC-{capec_id}"
    return [
        make_relationship(source_ref, alias, ALSO_KNOWN_AS_RELATIONSHIP_TYPE)
        for alias in obj.get("x_capec_alternate_terms", [])
    ]


def split_impact(value: str) -> Tuple[str, Optional[str]]:
    """Split CAPEC's impact string into its short code and its trailing note.

    CAPEC glues a per-attack-pattern explanation onto the impact code in
    parentheses -- "Execute Unauthorized Commands (The attacker may be able to
    ...)". Splitting them collapses 134 distinct strings down to the 10 real impact
    codes (4 of which CWE uses verbatim) and puts the explanation on the edge, which
    is where CWE already keeps its own consequence `note`. Verified against the full
    bundle: no impact code contains a parenthesis, and every parenthetical closes at
    the end of the string, so this split is unambiguous.
    """
    index = value.find(" (")
    if index < 0 or not value.rstrip().endswith(")"):
        return value, None
    return value[:index], value[index + 2:].rstrip()[:-1]


def build_consequence_relationships(
    obj: Dict[str, Any],
    capec_id: int,
    consequence_ids: Dict[Tuple[str, str], str],
    consequences: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Unpack `x_capec_consequences` (a scope -> impact-list map) into one edge per
    (scope, impact) pair, pointing at a `consequence` entity shared across every
    attack pattern that has the same pair."""
    source_ref = f"CAPEC-{capec_id}"
    relationships = []
    seen = set()
    for raw_scope, impacts in (obj.get("x_capec_consequences") or {}).items():
        scope = CONSEQUENCE_SCOPE_ALIASES.get(raw_scope, raw_scope)
        for raw_impact in impacts:
            impact, note = split_impact(raw_impact)
            if (scope, impact, note) in seen:
                continue  # one attack pattern lists the same pair twice upstream
            seen.add((scope, impact, note))
            key = (scope, impact)
            entity_id = consequence_ids.get(key)
            if entity_id is None:
                entity_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"capec-preprocessing:{CONSEQUENCE_ENTITY_TYPE}:scope={scope}|impact={impact}")
                entity_id = f"{CONSEQUENCE_ENTITY_TYPE}--{entity_uuid}"
                consequence_ids[key] = entity_id
                # scope/impact are lists of one to match CWE's consequence records,
                # which can carry several of each
                consequences.append({"id": entity_id, "type": CONSEQUENCE_ENTITY_TYPE, "scope": [scope], "impact": [impact]})
            extra = {"note": note} if note else {}
            relationships.append(make_relationship(source_ref, entity_id, HAS_CONSEQUENCE_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_skill_relationships(
    obj: Dict[str, Any], capec_id: int, skill_levels: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Unpack `x_capec_skills_required` (a level -> prose map) into edges pointing at
    one of three `skill-level` entities, with the prose as an edge attribute.

    Unlike ATT&CK's mutable elements -- where the map keys were a 2,892-value
    long tail not worth nodes -- the keys here are a closed 3-value enum
    (Low/Medium/High), so promoting them makes "every attack pattern needing high
    skill" a one-hop query. The prose is per-attack-pattern, so it goes on the edge.
    """
    source_ref = f"CAPEC-{capec_id}"
    relationships = []
    for level, prose in (obj.get("x_capec_skills_required") or {}).items():
        entity_id = f"{SKILL_LEVEL_ENTITY_TYPE}--{level}"
        skill_levels[level] = entity_id
        extra = {"description": prose} if str(prose or "").strip() else {}
        relationships.append(make_relationship(source_ref, entity_id, REQUIRES_SKILL_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_peer_relationships(attack_patterns: Sequence[Dict[str, Any]], id_to_capec_id: Dict[str, int]) -> List[Dict[str, Any]]:
    """peer_of is symmetric but not consistently reciprocal in the source data, so dedupe
    to one edge per unordered pair (canonical direction: lower capec_id -> higher capec_id)."""
    seen_pairs = set()
    relationships = []
    for obj in attack_patterns:
        capec_id = id_to_capec_id[obj["id"]]
        for peer_stix_id in obj.get("x_capec_peer_of_refs", []):
            peer_capec_id = id_to_capec_id.get(peer_stix_id)
            if peer_capec_id is None:
                raise ParseError(f"attack-pattern ref {peer_stix_id!r} does not resolve to any known attack-pattern")
            pair = (min(capec_id, peer_capec_id), max(capec_id, peer_capec_id))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            relationships.append(make_relationship(f"CAPEC-{pair[0]}", f"CAPEC-{pair[1]}", PEER_OF_RELATIONSHIP_TYPE))
    return relationships


def build_attack_pattern_record(obj: Dict[str, Any], capec_id: int) -> Dict[str, Any]:
    record: Dict[str, Any] = {}
    for field in ATTACK_PATTERN_FIELDS:
        if field == "id":
            record["id"] = f"CAPEC-{capec_id}"
            record["stix_id"] = obj["id"]
            continue
        if field in obj:
            record[field] = obj[field]
    return record


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    attack_patterns = [obj for obj in objects if str(obj.get("type") or "") == "attack-pattern"]
    id_to_capec_id = {obj["id"]: extract_capec_id(obj) for obj in attack_patterns}

    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    result[CONSEQUENCE_ENTITY_TYPE] = []
    result[SKILL_LEVEL_ENTITY_TYPE] = []
    result[ATTACK_PATTERN_RELATIONSHIP_KEY] = build_peer_relationships(attack_patterns, id_to_capec_id)
    dropped_counts: Dict[str, int] = {}
    consequence_ids: Dict[Tuple[str, str], str] = {}
    skill_levels: Dict[str, str] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        if obj_type == "attack-pattern":
            capec_id = id_to_capec_id[obj["id"]]
            result["attack-pattern"].append(build_attack_pattern_record(obj, capec_id))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_external_relationships(obj, capec_id))
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(build_hierarchy_relationships(obj, capec_id, id_to_capec_id))
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(build_also_known_as_relationships(obj, capec_id))
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(
                build_consequence_relationships(obj, capec_id, consequence_ids, result[CONSEQUENCE_ENTITY_TYPE])
            )
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(build_skill_relationships(obj, capec_id, skill_levels))
            continue
        if obj_type == "relationship":
            record = filter_object(obj, RELATIONSHIP_FIELDS)
            record["source_ref"] = remap_attack_pattern_ref(record["source_ref"], id_to_capec_id)
            record["target_ref"] = remap_attack_pattern_ref(record["target_ref"], id_to_capec_id)
            result["relationship"].append(record)
            continue
        fields = FIELDS_BY_TYPE.get(obj_type)
        if fields is not None:
            result[obj_type].append(filter_object(obj, fields))
            continue
        if obj_type not in DROPPED_TYPES:
            print(f"[capec-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
        dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1

    result[CONSEQUENCE_ENTITY_TYPE].sort(key=lambda record: record["id"])
    result[SKILL_LEVEL_ENTITY_TYPE] = [
        {"id": entity_id, "type": SKILL_LEVEL_ENTITY_TYPE, "name": level}
        for level, entity_id in sorted(skill_levels.items())
    ]

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
            "consequences.json / skill_levels.json / relationships.json / "
            "external_relationships.json / "
            f"attack_pattern_relationships.json (default: {default_output_dir})"
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
            f"{counts[CONSEQUENCE_ENTITY_TYPE]} consequences, "
            f"{counts[SKILL_LEVEL_ENTITY_TYPE]} skill levels, "
            f"{counts['relationship']} relationships, "
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external relationships, "
            f"{counts[ATTACK_PATTERN_RELATIONSHIP_KEY]} attack-pattern relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
