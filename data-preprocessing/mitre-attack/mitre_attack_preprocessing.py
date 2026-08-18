"""MITRE ATT&CK field-projection preprocessor. Full rationale in README.md.

Merges the three raw STIX 2.1 bundles from the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) into two
deduplicated files: `entities.json` (techniques, malware, tools, groups,
campaigns, mitigations, tactics, matrices, analytics, detection strategies, data
components, data sources, assets, log sources) and `relationships.json` (every
edge). Each record's own `type` says which kind it is. Entities are keyed by
their human-readable ATT&CK code (`T1055`, `S0002`) rather than STIX id, which
moves to `stix_id` -- see `resolve_canonical_ids()`.

Three kinds of edge share `relationships.json`: native STIX `relationship`
objects with both endpoints rewritten into that id space; edges derived from
embedded id-list fields with no native relationship object (technique<->tactic,
matrix->tactic, detection-strategy->analytic, analytic->data-component,
data-component->log-source); and CAPEC cross-references carrying
`source_name: "capec"`.

Nothing nests -- Neo4j properties hold scalars or scalar arrays, never maps -- so
ATT&CK's only two list-of-map fields are unpacked: `x_mitre_log_sources` into
`log-source` entities plus `has_log_source` edges, and analytics'
`x_mitre_mutable_elements` into two flat string lists.

Output `type` renames STIX's `attack-pattern`/`course-of-action` to
`attack-technique`/`attack-mitigation`: CAPEC uses those same two STIX types for
its own, different attack patterns and mitigations, so left unrenamed they'd
collide as one Neo4j label spanning two catalogs.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

DOMAIN_LATEST_FILES: Tuple[str, ...] = ("enterprise/latest.json", "mobile/latest.json", "ics/latest.json")

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
MATRIX_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # tactic_refs extracted to derived edges
ANALYTIC_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_mutable_elements")
DETECTION_STRATEGY_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # x_mitre_analytic_refs extracted
DATA_COMPONENT_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # x_mitre_log_sources extracted
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

# Log sources have no STIX object of their own -- synthesized from the
# `x_mitre_log_sources`/`x_mitre_log_source_references` maps, so this key sits alongside
# FIELDS_BY_TYPE's real STIX types rather than inside it. The id is prefixed because 7 of
# the 351 names are bare words ("File", "Process") that D3FEND also uses as artifact ids;
# the bare name stays on the record as `name`.
LOG_SOURCE_KEY = "log-source"
LOG_SOURCE_ID_PREFIX = f"{LOG_SOURCE_KEY}--"

HAS_TACTIC_RELATIONSHIP_TYPE = "has_tactic"
HAS_MEMBER_RELATIONSHIP_TYPE = "has_member"
HAS_ANALYTIC_RELATIONSHIP_TYPE = "has_analytic"
USES_DATA_COMPONENT_RELATIONSHIP_TYPE = "uses_data_component"
HAS_LOG_SOURCE_RELATIONSHIP_TYPE = "has_log_source"
EXTERNAL_RELATIONSHIP_TYPE = "related-to"

# Upstream writes a literal "None" string (not JSON null) for 184 absent log-source
# channels -- normalized away so it can't load as a real value.
ABSENT_CHANNEL_SENTINEL = "None"

MUTABLE_ELEMENT_NOTE_SEPARATOR = " -- "  # verified absent from every field name and description

# `malware`/`tool` spell their alias list `x_mitre_aliases` where `intrusion-set`/
# `campaign` use STIX's own `aliases` -- unified on `aliases`, which is also what
# CWE/CAPEC/D3FEND records use.
FIELD_NAME_OVERRIDES: Dict[str, str] = {"x_mitre_aliases": "aliases"}

# Applied to the output `type` field only; internal dispatch still keys off the raw STIX
# type. See module docstring for why.
ENTITY_TYPE_LABEL_OVERRIDES: Dict[str, str] = {
    "attack-pattern": "attack-technique",
    "course-of-action": "attack-mitigation",
}

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = (RELATIONSHIP_KEY, DERIVED_RELATIONSHIP_KEY, EXTERNAL_RELATIONSHIP_KEY)


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
            if not isinstance(obj, dict) or not obj.get("id"):
                continue
            existing = merged.get(obj["id"])
            merged[obj["id"]] = obj if existing is None else merge_duplicate(existing, obj)
    return list(merged.values())


def merge_duplicate(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two domain bundles' copies of the same STIX id: union x_mitre_domains, take
    every other field from whichever copy has the later 'modified' timestamp."""
    newer, older = (b, a) if str(b.get("modified") or "") >= str(a.get("modified") or "") else (a, b)
    merged = dict(newer)
    domains = list(dict.fromkeys((older.get("x_mitre_domains") or []) + (newer.get("x_mitre_domains") or [])))
    if domains:
        merged["x_mitre_domains"] = sorted(domains)
    return merged


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {FIELD_NAME_OVERRIDES.get(field, field): obj[field] for field in fields if field in obj}


def extract_attack_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") in ATTACK_ID_SOURCE_NAMES and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    # extra is folded into the seed: some derived edges legitimately repeat the same
    # (source, type, target) with different attributes (e.g. two log-source channels
    # feeding the same data component).
    seed_parts = [source_ref, relationship_type, target_ref]
    seed_parts.extend(f"{key}={extra[key]}" for key in sorted(extra))
    relationship_uuid = uuid.uuid5(uuid.NAMESPACE_URL, "mitre-attack-preprocessing:" + "|".join(seed_parts))
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
    return [
        make_relationship(entity_id, ref["external_id"], EXTERNAL_RELATIONSHIP_TYPE, source_name="capec")
        for ref in obj.get("external_references", []) or []
        if ref.get("source_name") == "capec" and ref.get("external_id")
    ]


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


def build_ref_field_relationships(
    obj: Dict[str, Any], entity_id: Optional[str], id_to_final_id: Dict[str, str], ref_field: str, relationship_type: str
) -> List[Dict[str, Any]]:
    """Turn an embedded list of STIX ids (a matrix's `tactic_refs`, a detection
    strategy's `x_mitre_analytic_refs`) into edges -- neither has a native
    `relationship` object upstream."""
    if not entity_id:
        return []
    return [
        make_relationship(entity_id, resolve_entity_id(stix_id, id_to_final_id, f"{entity_id} {ref_field}"), relationship_type)
        for stix_id in obj.get(ref_field, []) or []
    ]


def clean_channel(value: Any) -> Optional[str]:
    if not value or str(value).strip() in ("", ABSENT_CHANNEL_SENTINEL):
        return None
    return str(value)


def build_analytic_relationships(
    obj: Dict[str, Any], entity_id: Optional[str], id_to_final_id: Dict[str, str], log_source_names: Dict[str, None]
) -> List[Dict[str, Any]]:
    if not entity_id:
        return []
    relationships = []
    for log_source in obj.get("x_mitre_log_source_references", []) or []:
        data_component_stix_id = log_source.get("x_mitre_data_component_ref")
        if not data_component_stix_id:
            continue
        target_ref = resolve_entity_id(data_component_stix_id, id_to_final_id, f"analytic {entity_id} x_mitre_log_source_references")
        extra: Dict[str, Any] = {}
        name = log_source.get("name")
        if name:
            # every name here is also on some data component's own x_mitre_log_sources,
            # but register it anyway so log_source_ref can never dangle
            log_source_names[name] = None
            extra["log_source_ref"] = LOG_SOURCE_ID_PREFIX + name
        channel = clean_channel(log_source.get("channel"))
        if channel:
            extra["channel"] = channel
        relationships.append(make_relationship(entity_id, target_ref, USES_DATA_COMPONENT_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_log_source_relationships(
    obj: Dict[str, Any], entity_id: Optional[str], log_source_names: Dict[str, None]
) -> List[Dict[str, Any]]:
    """Unpack a data component's `x_mitre_log_sources` list-of-{name, channel} maps.
    `name` is a shared vocabulary -- 351 colon-namespaced codes (`WinEventLog:Security`)
    reused across components -- so it becomes its own entity, which also gives the
    `log_source_ref` on `uses_data_component` edges a real node to resolve against.
    `channel` is free-text analyst prose (43% of values run past 60 characters), so it
    stays an edge attribute rather than part of the log source's identity."""
    if not entity_id:
        return []
    relationships = []
    for log_source in obj.get("x_mitre_log_sources", []) or []:
        name = log_source.get("name")
        if not name:
            continue
        log_source_names[name] = None
        channel = clean_channel(log_source.get("channel"))
        extra = {"channel": channel} if channel else {}
        relationships.append(make_relationship(entity_id, LOG_SOURCE_ID_PREFIX + name, HAS_LOG_SOURCE_RELATIONSHIP_TYPE, **extra))
    return relationships


def flatten_mutable_elements(record: Dict[str, Any]) -> None:
    """Replace an analytic's `x_mitre_mutable_elements` maps with two flat string lists.
    The `field` names are the queryable half (25 are shared by 10+ analytics) so they
    become a plain list; `description` is per-analytic tuning prose (5,145 distinct
    strings across 5,177 elements), kept as self-labelling `"field -- description"`
    strings rather than a parallel list, since Cypher can't enforce index alignment."""
    elements = record.pop("x_mitre_mutable_elements", None) or []
    fields = list(dict.fromkeys(e["field"] for e in elements if e.get("field")))
    if fields:
        record["x_mitre_mutable_element_fields"] = fields
    notes = [
        f"{e['field']}{MUTABLE_ELEMENT_NOTE_SEPARATOR}{e['description']}"
        for e in elements
        if e.get("field") and e.get("description")
    ]
    if notes:
        record["x_mitre_mutable_element_notes"] = notes


def resolve_canonical_ids(objects: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """Map every surviving entity's STIX id to its final `id` (its ATT&CK code).

    A code is only unique within its own object type upstream: 224 pre-2019
    `course-of-action` mitigations reuse their technique's `T####`, and one pair each of
    `malware`/`x-mitre-matrix` share a code outright. Technique/mitigation collisions keep
    the technique (some are revoked but carry this project's only CAPEC cross-reference);
    same-type collisions keep whichever side is active; a collision with no clear winner
    drops every member and logs a warning.

    Entities with no ATT&CK code keep their STIX id. A dropped object is simply absent
    from the mapping -- callers treat a missing lookup as "drop this"."""
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

        if {member["type"] for member in members} == {"attack-pattern", "course-of-action"}:
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


def build_derived_relationships(
    obj: Dict[str, Any],
    obj_type: str,
    final_id: str,
    id_to_final_id: Dict[str, str],
    tactic_by_domain_shortname: Dict[Tuple[str, str], str],
    log_source_names: Dict[str, None],
) -> List[Dict[str, Any]]:
    """Edges derived from embedded fields, for the five types that carry any."""
    if obj_type == "attack-pattern":
        return build_technique_tactic_relationships(obj, final_id, tactic_by_domain_shortname)
    if obj_type == "x-mitre-matrix":
        return build_ref_field_relationships(obj, final_id, id_to_final_id, "tactic_refs", HAS_MEMBER_RELATIONSHIP_TYPE)
    if obj_type == "x-mitre-detection-strategy":
        return build_ref_field_relationships(obj, final_id, id_to_final_id, "x_mitre_analytic_refs", HAS_ANALYTIC_RELATIONSHIP_TYPE)
    if obj_type == "x-mitre-analytic":
        return build_analytic_relationships(obj, final_id, id_to_final_id, log_source_names)
    if obj_type == "x-mitre-data-component":
        return build_log_source_relationships(obj, final_id, log_source_names)
    return []


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
    result[LOG_SOURCE_KEY] = []
    result[RELATIONSHIP_KEY] = []
    result[DERIVED_RELATIONSHIP_KEY] = []
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    dropped_counts: Dict[str, int] = {}
    log_source_names: Dict[str, None] = {}  # insertion-ordered set, sorted at the end

    for obj in objects:
        obj_type = str(obj.get("type") or "")

        if obj_type == RELATIONSHIP_KEY:
            native = build_native_relationship(obj, id_to_final_id)
            if native is not None:
                result[RELATIONSHIP_KEY].append(native)
            continue

        if obj_type not in FIELDS_BY_TYPE:
            if obj_type not in BOILERPLATE_TYPES:
                print(f"[mitre-attack-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        final_id = id_to_final_id.get(obj["id"])
        if final_id is None:
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue  # losing side of an id collision -- see resolve_canonical_ids

        record = {"id": final_id, "stix_id": obj["id"], **filter_object(obj, FIELDS_BY_TYPE[obj_type])}
        if obj_type in ENTITY_TYPE_LABEL_OVERRIDES:
            record["type"] = ENTITY_TYPE_LABEL_OVERRIDES[obj_type]
        if obj_type == "x-mitre-analytic":
            flatten_mutable_elements(record)
        result[obj_type].append(record)

        if obj_type == "attack-pattern":
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_capec_relationships(obj, final_id))
        result[DERIVED_RELATIONSHIP_KEY].extend(
            build_derived_relationships(obj, obj_type, final_id, id_to_final_id, tactic_by_domain_shortname, log_source_names)
        )

    result[LOG_SOURCE_KEY] = [
        {"id": LOG_SOURCE_ID_PREFIX + name, "type": LOG_SOURCE_KEY, "name": name} for name in sorted(log_source_names)
    ]

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[mitre-attack-parser] parsed {len(objects)} merged objects; dropped {dropped_summary or 'nothing'}")
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
    """Total plus per-kind breakdown: `6052 (1105 attack-pattern, 823 malware, ...)`."""
    breakdown = ", ".join(f"{counts[key]} {key}" for key in keys if counts[key])
    return f"{sum(counts[key] for key in keys)} ({breakdown})"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "mitre-attack"

    parser = argparse.ArgumentParser(description="Merge and trim ATT&CK's three domain STIX bundles down to a fixed field whitelist")
    parser.add_argument("--input", default=str(default_input), help=f"Path to the ATT&CK crawler's workspace, containing enterprise/mobile/ics subfolders (default: {default_input})")
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
            f"[mitre-attack-parser] wrote {format_counts(counts, entity_keys)} entities to {ENTITIES_FILENAME} "
            f"and {format_counts(counts, relationship_keys)} relationships to {RELATIONSHIPS_FILENAME}, in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
