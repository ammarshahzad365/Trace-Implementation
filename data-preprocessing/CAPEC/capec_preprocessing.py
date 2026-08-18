"""CAPEC field-projection preprocessor. Full rationale in README.md.

Reads the CAPEC crawler's STIX 2.1 bundle (`data-acquisition/CAPEC/latest.json`)
and writes two files: `entities.json` (attack patterns, courses of action,
consequences) and `relationships.json` (every edge). Each record's own `type`
says which kind it is. `identity`/`marking-definition` are dropped as STIX
boilerplate.

Attack patterns are keyed `CAPEC-N` from their `capec` external_reference rather
than by STIX id (kept alongside as `stix_id`), and every relationship endpoint
naming one is rewritten to match. Their `cwe`/`ATTACK` external_references become
outward edges carrying `source_name`; the bibliographic ones are dropped.

Fields that don't survive verbatim: `x_capec_status`, `x_capec_execution_flow`
and `x_capec_skills_required` are dropped; `x_capec_alternate_terms` folds into
an `aliases` property; `x_capec_consequences` (a map, illegal as a Neo4j
property) unpacks into shared `consequence` entities plus `has_consequence`
edges; the attack-pattern ref fields become edges, keeping one direction of each
reciprocal pair (`child_of`, `can_precede`) and one edge per unordered `peer_of`
pair.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

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

COURSE_OF_ACTION_FIELDS: Tuple[str, ...] = ("id", "name", "description", "type")

RELATIONSHIP_FIELDS: Tuple[str, ...] = ("id", "type", "relationship_type", "source_ref", "target_ref", "created")

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "attack-pattern": ATTACK_PATTERN_FIELDS,
    "course-of-action": COURSE_OF_ACTION_FIELDS,
    "relationship": RELATIONSHIP_FIELDS,
}

DROPPED_TYPES = {"identity", "marking-definition"}

# external_references source_name values that become outward-pointing edges.
EXTERNAL_RELATIONSHIP_SOURCE_NAMES = {"cwe", "ATTACK"}
EXTERNAL_RELATIONSHIP_TYPE = "related-to"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

# Only one direction of each reciprocal pair is kept; parent_of/can_follow are
# verified inverses, so storing them too would store every edge twice.
HIERARCHY_REF_FIELDS: Dict[str, str] = {
    "x_capec_child_of_refs": "child_of",
    "x_capec_can_precede_refs": "can_precede",
}

PEER_OF_RELATIONSHIP_TYPE = "peer_of"
HAS_CONSEQUENCE_RELATIONSHIP_TYPE = "has_consequence"
ATTACK_PATTERN_RELATIONSHIP_KEY = "attack-pattern-relationship"

# Deliberately the same `type` (and {scope, impact} shape) CWE's preprocessor emits, so
# both catalogs' consequences land under one Neo4j label. Ids stay per-catalog: these
# preprocessors run independently and can't share an id space.
CONSEQUENCE_ENTITY_TYPE = "consequence"

# CAPEC writes this scope with an underscore where CWE writes a space.
CONSEQUENCE_SCOPE_ALIASES: Dict[str, str] = {"Access_Control": "Access Control"}

# Renamed to the name another source already uses; `x_capec_*` fields have no twin
# elsewhere, so they keep their prefix.
FIELD_NAME_OVERRIDES: Dict[str, str] = {"x_capec_extended_description": "extended_description"}

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = (
    "relationship",
    EXTERNAL_RELATIONSHIP_KEY,
    ATTACK_PATTERN_RELATIONSHIP_KEY,
)


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
    seen = set()
    for ref in obj.get("external_references", []):
        source_name = ref.get("source_name")
        target_ref = ref.get("external_id")
        if source_name not in EXTERNAL_RELATIONSHIP_SOURCE_NAMES or not target_ref:
            continue
        if (source_name, target_ref) in seen:
            continue  # 3 attack patterns list the same external reference twice upstream
        seen.add((source_name, target_ref))
        relationships.append(make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, source_name=source_name))
    return relationships


def resolve_capec_ref(stix_id: str, id_to_capec_id: Dict[str, int]) -> str:
    capec_id = id_to_capec_id.get(stix_id)
    if capec_id is None:
        raise ParseError(f"attack-pattern ref {stix_id!r} does not resolve to any known attack-pattern")
    return f"CAPEC-{capec_id}"


def remap_attack_pattern_ref(ref: str, id_to_capec_id: Dict[str, int]) -> str:
    """Rewrite a relationship endpoint from an attack-pattern's STIX id to its CAPEC-N
    id. Endpoints that aren't one (e.g. a course-of-action) pass through unchanged."""
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


def apply_alternate_terms(obj: Dict[str, Any], record: Dict[str, Any]) -> None:
    """Fold `x_capec_alternate_terms` into an `aliases` list -- the name CWE/ATT&CK/
    D3FEND records use too. As edges these pointed at the alias text itself, which is
    no entity, so loading them would have invented a phantom node per alias string."""
    aliases = [alias for alias in obj.get("x_capec_alternate_terms", []) or [] if alias]
    if aliases:
        record["aliases"] = list(dict.fromkeys(aliases))


def split_impact(value: str) -> Tuple[str, Optional[str]]:
    """Split CAPEC's impact string into its short code and its trailing parenthetical
    note -- "Execute Unauthorized Commands (The attacker may ...)". That collapses 134
    distinct strings to the 10 real impact codes (4 shared verbatim with CWE) and puts
    the explanation on the edge, where CWE already keeps its consequence `note`.
    Verified unambiguous: no impact code contains a parenthesis, and every
    parenthetical closes at end of string."""
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
    attack pattern with that pair."""
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
            entity_id = consequence_ids.get((scope, impact))
            if entity_id is None:
                entity_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"capec-preprocessing:{CONSEQUENCE_ENTITY_TYPE}:scope={scope}|impact={impact}")
                entity_id = f"{CONSEQUENCE_ENTITY_TYPE}--{entity_uuid}"
                consequence_ids[(scope, impact)] = entity_id
                # lists of one, matching CWE's consequence records, which can carry several
                consequences.append({"id": entity_id, "type": CONSEQUENCE_ENTITY_TYPE, "scope": [scope], "impact": [impact]})
            extra = {"note": note} if note else {}
            relationships.append(make_relationship(source_ref, entity_id, HAS_CONSEQUENCE_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_peer_relationships(attack_patterns: Sequence[Dict[str, Any]], id_to_capec_id: Dict[str, int]) -> List[Dict[str, Any]]:
    """peer_of is symmetric but not consistently reciprocal upstream, so dedupe to one
    edge per unordered pair (canonical direction: lower capec_id -> higher)."""
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
        elif field in obj:
            record[FIELD_NAME_OVERRIDES.get(field, field)] = obj[field]
    apply_alternate_terms(obj, record)
    return record


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    attack_patterns = [obj for obj in objects if str(obj.get("type") or "") == "attack-pattern"]
    id_to_capec_id = {obj["id"]: extract_capec_id(obj) for obj in attack_patterns}

    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    result[CONSEQUENCE_ENTITY_TYPE] = []
    result[ATTACK_PATTERN_RELATIONSHIP_KEY] = build_peer_relationships(attack_patterns, id_to_capec_id)
    dropped_counts: Dict[str, int] = {}
    consequence_ids: Dict[Tuple[str, str], str] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        if obj_type == "attack-pattern":
            capec_id = id_to_capec_id[obj["id"]]
            result["attack-pattern"].append(build_attack_pattern_record(obj, capec_id))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_external_relationships(obj, capec_id))
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(build_hierarchy_relationships(obj, capec_id, id_to_capec_id))
            result[ATTACK_PATTERN_RELATIONSHIP_KEY].extend(
                build_consequence_relationships(obj, capec_id, consequence_ids, result[CONSEQUENCE_ENTITY_TYPE])
            )
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

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[capec-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
    return result


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, List[Dict[str, Any]]] = {ENTITIES_FILENAME: [], RELATIONSHIPS_FILENAME: []}
    for key, records in result.items():
        files[RELATIONSHIPS_FILENAME if key in RELATIONSHIP_KEYS else ENTITIES_FILENAME].extend(records)
    for filename, records in files.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
    return {key: len(records) for key, records in result.items()}


def format_counts(counts: Dict[str, int], keys: Sequence[str]) -> str:
    """Total plus per-kind breakdown: `1538 (559 attack-pattern, 552 course-of-action, ...)`."""
    breakdown = ", ".join(f"{counts[key]} {key}" for key in keys if counts[key])
    return f"{sum(counts[key] for key in keys)} ({breakdown})"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "CAPEC" / "latest.json"

    parser = argparse.ArgumentParser(description="Trim CAPEC's STIX bundle down to a fixed field whitelist per object type")
    parser.add_argument("--input", default=str(default_input), help=f"Path to CAPEC's latest.json (default: {default_input})")
    parser.add_argument("--output-dir", default=str(script_dir), help=f"Directory to write entities.json / relationships.json (default: {script_dir})")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    output_dir = Path(args.output_dir)

    try:
        result = parse(load_objects(Path(args.input)))
        counts = write_outputs(result, output_dir)
        entity_keys = [key for key in counts if key not in RELATIONSHIP_KEYS]
        relationship_keys = [key for key in counts if key in RELATIONSHIP_KEYS]
        print(
            f"[capec-parser] wrote {format_counts(counts, entity_keys)} entities to {ENTITIES_FILENAME} "
            f"and {format_counts(counts, relationship_keys)} relationships to {RELATIONSHIPS_FILENAME}, in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
