"""MITRE ATT&CK field-projection preprocessor. See README.md for full rationale.

Merges the three raw STIX 2.1 bundles from the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) into
one deduplicated set of entity/relationship files, keyed by each entity's
human-readable ATT&CK code (`T1055`, `S0002`, ...) rather than its STIX id
-- see `resolve_canonical_ids()`. `stix_id` keeps the original STIX id.

STIX boilerplate types and a few bookkeeping-only fields are dropped (see
`*_FIELDS`). Embedded id-list fields with no native STIX `relationship`
object (technique<->tactic, matrix->tactic, detection-strategy->analytic,
analytic->data-component) become `derived_relationships.json` edges; native
`relationship` objects go to `relationships.json` with `source_ref`/
`target_ref` rewritten to the same id space; CAPEC cross-references go to
`external_relationships.json`.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

DOMAIN_LATEST_FILES: Tuple[str, ...] = (
    "enterprise/latest.json",
    "mobile/latest.json",
    "ics/latest.json",
)

BOILERPLATE_TYPES = {"identity", "marking-definition", "x-mitre-collection"}

# external_reference source_name values that carry an object's own ATT&CK code.
ATTACK_ID_SOURCE_NAMES = {"mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"}

KILL_CHAIN_NAME_TO_DOMAIN: Dict[str, str] = {
    "mitre-attack": "enterprise-attack",
    "mitre-mobile-attack": "mobile-attack",
    "mitre-ics-attack": "ics-attack",
}

# `id`/`stix_id` are assigned in parse(), not copied from the raw STIX object.
COMMON_FIELDS: Tuple[str, ...] = (
    "type",
    "name",
    "description",
    "x_mitre_domains",
    "revoked",
    "x_mitre_deprecated",
    "created",
    "modified",
)

TECHNIQUE_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "x_mitre_platforms",
    "x_mitre_is_subtechnique",
    "x_mitre_tactic_type",
    "x_mitre_impact_type",
    "x_mitre_remote_support",
)
MALWARE_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_aliases", "is_family")
TOOL_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_aliases")
INTRUSION_SET_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("aliases",)
CAMPAIGN_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("aliases", "first_seen", "last_seen")
COURSE_OF_ACTION_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("labels",)
MATRIX_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # tactic_refs extracted to derived_relationships.json
ANALYTIC_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_mutable_elements")
DETECTION_STRATEGY_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # x_mitre_analytic_refs extracted
DATA_COMPONENT_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_log_sources",)
DATA_SOURCE_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_collection_layers", "x_mitre_platforms")
ASSET_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_sectors")

RELATIONSHIP_PASSTHROUGH_FIELDS: Tuple[str, ...] = ("id", "type", "relationship_type", "source_ref", "target_ref", "description", "created", "modified")

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "attack-pattern": TECHNIQUE_FIELDS,
    "malware": MALWARE_FIELDS,
    "tool": TOOL_FIELDS,
    "intrusion-set": INTRUSION_SET_FIELDS,
    "campaign": CAMPAIGN_FIELDS,
    "course-of-action": COURSE_OF_ACTION_FIELDS,
    "x-mitre-tactic": COMMON_FIELDS,
    "x-mitre-matrix": MATRIX_FIELDS,
    "x-mitre-analytic": ANALYTIC_FIELDS,
    "x-mitre-detection-strategy": DETECTION_STRATEGY_FIELDS,
    "x-mitre-data-component": DATA_COMPONENT_FIELDS,
    "x-mitre-data-source": DATA_SOURCE_FIELDS,
    "x-mitre-asset": ASSET_FIELDS,
}

RELATIONSHIP_KEY = "relationship"
DERIVED_RELATIONSHIP_KEY = "derived-relationship"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

HAS_TACTIC_RELATIONSHIP_TYPE = "has_tactic"
HAS_MEMBER_RELATIONSHIP_TYPE = "has_member"
HAS_ANALYTIC_RELATIONSHIP_TYPE = "has_analytic"
USES_DATA_COMPONENT_RELATIONSHIP_TYPE = "uses_data_component"
EXTERNAL_RELATIONSHIP_TYPE = "related-to"

OUTPUT_FILENAMES: Dict[str, str] = {
    "attack-pattern": "techniques.json",
    "malware": "malware.json",
    "tool": "tools.json",
    "intrusion-set": "intrusion_sets.json",
    "campaign": "campaigns.json",
    "course-of-action": "courses_of_action.json",
    "x-mitre-tactic": "tactics.json",
    "x-mitre-matrix": "matrices.json",
    "x-mitre-analytic": "analytics.json",
    "x-mitre-detection-strategy": "detection_strategies.json",
    "x-mitre-data-component": "data_components.json",
    "x-mitre-data-source": "data_sources.json",
    "x-mitre-asset": "assets.json",
    RELATIONSHIP_KEY: "relationships.json",
    DERIVED_RELATIONSHIP_KEY: "derived_relationships.json",
    EXTERNAL_RELATIONSHIP_KEY: "external_relationships.json",
}


class ParseError(RuntimeError):
    pass


def load_objects(input_dir: Path) -> List[Dict[str, Any]]:
    """Read all three domain bundles and merge them into one deduplicated object list."""
    merged: Dict[str, Dict[str, Any]] = {}
    for relative_path in DOMAIN_LATEST_FILES:
        path = input_dir / relative_path
        with path.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        objects = bundle.get("objects") if isinstance(bundle, dict) else None
        if not isinstance(objects, list):
            raise ParseError(f"Expected a STIX bundle with an 'objects' list at {path}")
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_id = obj.get("id")
            if not obj_id:
                continue
            existing = merged.get(obj_id)
            merged[obj_id] = obj if existing is None else merge_duplicate(existing, obj)
    return list(merged.values())


def merge_duplicate(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two domain bundles' copies of the same STIX id: union x_mitre_domains,
    take every other field from whichever copy has the later 'modified' timestamp."""
    newer, older = (b, a) if str(b.get("modified") or "") >= str(a.get("modified") or "") else (a, b)
    merged = dict(newer)
    domains = list(dict.fromkeys((older.get("x_mitre_domains") or []) + (newer.get("x_mitre_domains") or [])))
    if domains:
        merged["x_mitre_domains"] = sorted(domains)
    return merged


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def extract_attack_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") in ATTACK_ID_SOURCE_NAMES:
            external_id = ref.get("external_id")
            if external_id:
                return str(external_id)
    return None


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    # extra is folded into the seed: some derived edges legitimately repeat the same
    # (source, type, target) with different attributes (e.g. two log-source channels
    # feeding the same data component).
    seed_parts = [source_ref, relationship_type, target_ref]
    seed_parts.extend(f"{key}={extra[key]}" for key in sorted(extra))
    seed = "mitre-attack-preprocessing:" + "|".join(seed_parts)
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


def build_native_relationship(obj: Dict[str, Any], id_to_final_id: Dict[str, str]) -> Optional[Dict[str, Any]]:
    record = filter_object(obj, RELATIONSHIP_PASSTHROUGH_FIELDS)
    final_source = id_to_final_id.get(record["source_ref"])
    final_target = id_to_final_id.get(record["target_ref"])
    if final_source is None or final_target is None:
        return None  # one endpoint was the losing side of an id collision -- see resolve_canonical_ids
    record["source_ref"] = final_source
    record["target_ref"] = final_target
    return record


def build_capec_relationships(obj: Dict[str, Any], entity_id: Optional[str]) -> List[Dict[str, Any]]:
    if not entity_id:
        return []
    relationships = []
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") != "capec":
            continue
        target_ref = ref.get("external_id")
        if not target_ref:
            continue
        relationships.append(make_relationship(entity_id, target_ref, EXTERNAL_RELATIONSHIP_TYPE, source_name="capec"))
    return relationships


def build_technique_tactic_relationships(
    obj: Dict[str, Any], entity_id: Optional[str], tactic_by_domain_shortname: Dict[Tuple[str, str], str]
) -> List[Dict[str, Any]]:
    if not entity_id:
        return []
    relationships = []
    for kill_chain_phase in obj.get("kill_chain_phases", []) or []:
        domain = KILL_CHAIN_NAME_TO_DOMAIN.get(kill_chain_phase.get("kill_chain_name"))
        phase_name = kill_chain_phase.get("phase_name")
        if not domain or not phase_name:
            continue
        tactic_id = tactic_by_domain_shortname.get((domain, phase_name))
        if tactic_id is None:
            raise ParseError(f"technique {entity_id} kill_chain_phase {phase_name!r} in domain {domain!r} matches no x-mitre-tactic shortname")
        relationships.append(make_relationship(entity_id, tactic_id, HAS_TACTIC_RELATIONSHIP_TYPE))
    return relationships


def resolve_entity_id(stix_id: str, id_to_final_id: Dict[str, str], context: str) -> str:
    final_id = id_to_final_id.get(stix_id)
    if final_id is None:
        raise ParseError(f"{context} ref {stix_id!r} does not resolve to any known object in this bundle")
    return final_id


def build_matrix_relationships(obj: Dict[str, Any], entity_id: Optional[str], id_to_final_id: Dict[str, str]) -> List[Dict[str, Any]]:
    if not entity_id:
        return []
    relationships = []
    for tactic_stix_id in obj.get("tactic_refs", []) or []:
        target_ref = resolve_entity_id(tactic_stix_id, id_to_final_id, f"matrix {entity_id} tactic_refs")
        relationships.append(make_relationship(entity_id, target_ref, HAS_MEMBER_RELATIONSHIP_TYPE))
    return relationships


def build_detection_strategy_relationships(obj: Dict[str, Any], entity_id: Optional[str], id_to_final_id: Dict[str, str]) -> List[Dict[str, Any]]:
    if not entity_id:
        return []
    relationships = []
    for analytic_stix_id in obj.get("x_mitre_analytic_refs", []) or []:
        target_ref = resolve_entity_id(analytic_stix_id, id_to_final_id, f"detection-strategy {entity_id} x_mitre_analytic_refs")
        relationships.append(make_relationship(entity_id, target_ref, HAS_ANALYTIC_RELATIONSHIP_TYPE))
    return relationships


def build_analytic_relationships(obj: Dict[str, Any], entity_id: Optional[str], id_to_final_id: Dict[str, str]) -> List[Dict[str, Any]]:
    if not entity_id:
        return []
    relationships = []
    for log_source in obj.get("x_mitre_log_source_references", []) or []:
        data_component_stix_id = log_source.get("x_mitre_data_component_ref")
        if not data_component_stix_id:
            continue
        target_ref = resolve_entity_id(data_component_stix_id, id_to_final_id, f"analytic {entity_id} x_mitre_log_source_references")
        extra: Dict[str, Any] = {}
        if log_source.get("name"):
            extra["log_source_name"] = log_source["name"]
        if log_source.get("channel"):
            extra["channel"] = log_source["channel"]
        relationships.append(make_relationship(entity_id, target_ref, USES_DATA_COMPONENT_RELATIONSHIP_TYPE, **extra))
    return relationships


def resolve_canonical_ids(objects: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """Map every surviving entity's STIX id to its final `id` (its ATT&CK code).

    A code is only unique within its own object type upstream: 224 pre-2019
    `course-of-action` mitigations reuse their technique's `T####`, and one
    pair each of `malware`/`x-mitre-matrix` share a code outright (see
    README). Technique/mitigation collisions keep the technique (some are
    revoked but still carry this project's only CAPEC cross-reference);
    same-type collisions keep whichever side is active
    (`x_mitre_deprecated`/`revoked` both false/absent); a collision with no
    clear winner drops every member and logs a warning.

    Entities with no ATT&CK code keep their STIX id as `id`. A dropped
    object is simply absent from the returned mapping -- `parse()`/
    `build_native_relationship()` treat a missing lookup as "drop this".
    """
    entities = [obj for obj in objects if obj.get("type") in FIELDS_BY_TYPE]
    attack_id_of = {obj["id"]: extract_attack_id(obj) for obj in entities}

    groups: Dict[str, List[Dict[str, Any]]] = {}
    for obj in entities:
        attack_id = attack_id_of[obj["id"]]
        if attack_id:
            groups.setdefault(attack_id, []).append(obj)

    id_to_final_id: Dict[str, str] = {}
    for attack_id, members in groups.items():
        if len(members) == 1:
            id_to_final_id[members[0]["id"]] = attack_id
            continue

        types = {member["type"] for member in members}
        if types == {"attack-pattern", "course-of-action"}:
            winner = next(member for member in members if member["type"] == "attack-pattern")
        else:
            active = [member for member in members if not (member.get("x_mitre_deprecated") or member.get("revoked"))]
            winner = active[0] if len(active) == 1 else None

        if winner is None:
            print(
                f"[mitre-attack-parser] warning: attack_id {attack_id!r} is claimed by "
                f"{len(members)} objects with no clear winner "
                f"({sorted(member['id'] for member in members)}) -- dropping all of them",
                file=sys.stderr,
            )
            continue
        id_to_final_id[winner["id"]] = attack_id

    for obj in entities:
        if obj["id"] not in id_to_final_id and not attack_id_of[obj["id"]]:
            id_to_final_id[obj["id"]] = obj["id"]  # no ATT&CK code at all -- keep its STIX id

    return id_to_final_id


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    id_to_final_id = resolve_canonical_ids(objects)

    tactic_by_domain_shortname: Dict[Tuple[str, str], str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        final_id = id_to_final_id.get(obj["id"])
        if not final_id:
            continue
        for domain in obj.get("x_mitre_domains", []) or []:
            tactic_by_domain_shortname[(domain, obj.get("x_mitre_shortname"))] = final_id

    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[RELATIONSHIP_KEY] = []
    result[DERIVED_RELATIONSHIP_KEY] = []
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")

        if obj_type == RELATIONSHIP_KEY:
            native = build_native_relationship(obj, id_to_final_id)
            if native is not None:
                result[RELATIONSHIP_KEY].append(native)
            continue

        if obj_type in BOILERPLATE_TYPES:
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        fields = FIELDS_BY_TYPE.get(obj_type)
        if fields is None:
            print(f"[mitre-attack-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        final_id = id_to_final_id.get(obj["id"])
        if final_id is None:
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue  # losing side of an id collision -- see resolve_canonical_ids

        record = filter_object(obj, fields)
        record = {"id": final_id, "stix_id": obj["id"], **record}
        result[obj_type].append(record)

        if obj_type == "attack-pattern":
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_capec_relationships(obj, final_id))
            result[DERIVED_RELATIONSHIP_KEY].extend(build_technique_tactic_relationships(obj, final_id, tactic_by_domain_shortname))
        elif obj_type == "x-mitre-matrix":
            result[DERIVED_RELATIONSHIP_KEY].extend(build_matrix_relationships(obj, final_id, id_to_final_id))
        elif obj_type == "x-mitre-detection-strategy":
            result[DERIVED_RELATIONSHIP_KEY].extend(build_detection_strategy_relationships(obj, final_id, id_to_final_id))
        elif obj_type == "x-mitre-analytic":
            result[DERIVED_RELATIONSHIP_KEY].extend(build_analytic_relationships(obj, final_id, id_to_final_id))

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[mitre-attack-parser] parsed {len(objects)} merged objects; dropped {dropped_summary or 'nothing'}")
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
    default_input = script_dir.parent.parent / "data-acquisition" / "mitre-attack"
    default_output_dir = script_dir

    parser = argparse.ArgumentParser(description="Merge and trim ATT&CK's three domain STIX bundles down to a fixed field whitelist")
    parser.add_argument(
        "--input",
        default=str(default_input),
        help=f"Path to the ATT&CK crawler's workspace directory, containing enterprise/mobile/ics subfolders (default: {default_input})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir),
        help=f"Directory to write the trimmed entity/relationship files to (default: {default_output_dir})",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    input_dir = Path(args.input)
    output_dir = Path(args.output_dir)

    try:
        objects = load_objects(input_dir)
        result = parse(objects)
        counts = write_outputs(result, output_dir)
        print(
            "[mitre-attack-parser] wrote "
            f"{counts['attack-pattern']} techniques, "
            f"{counts['malware']} malware, "
            f"{counts['tool']} tools, "
            f"{counts['intrusion-set']} intrusion sets, "
            f"{counts['campaign']} campaigns, "
            f"{counts['course-of-action']} courses of action, "
            f"{counts['x-mitre-tactic']} tactics, "
            f"{counts['x-mitre-matrix']} matrices, "
            f"{counts['x-mitre-analytic']} analytics, "
            f"{counts['x-mitre-detection-strategy']} detection strategies, "
            f"{counts['x-mitre-data-component']} data components, "
            f"{counts['x-mitre-data-source']} data sources, "
            f"{counts['x-mitre-asset']} assets, "
            f"{counts[RELATIONSHIP_KEY]} relationships, "
            f"{counts[DERIVED_RELATIONSHIP_KEY]} derived relationships, "
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
