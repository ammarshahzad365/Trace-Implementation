"""MITRE ATT&CK field-projection preprocessor. Full rationale in README.md.

Merges the three raw STIX 2.1 bundles from the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) into two
deduplicated files: `entities.json` (techniques, malware, tools, groups,
campaigns, mitigations, tactics, matrices, analytics, detection strategies, data
components, assets) and `relationships.json` (every edge). Each record's own `type` says which kind it is. Entities are keyed by
their human-readable ATT&CK code (`T1055`, `S0002`) rather than STIX id, which
moves to `stix_id` -- see `resolve_canonical_ids()`.

Three kinds of edge share `relationships.json`: native STIX `relationship`
objects with both endpoints rewritten into that id space; edges derived from
embedded id-list fields with no native relationship object (technique<->tactic,
matrix->tactic, detection-strategy->analytic, analytic->data-component); and
CAPEC cross-references carrying
`source_name: "capec"`.

Nothing in the output nests -- every property is a scalar or an array of scalars -- so
ATT&CK's only two list-of-map fields flatten in place, both onto the record that
owns them: `x_mitre_log_sources` into `log_sources`/`log_source_notes` on the data
component, and analytics' `x_mitre_mutable_elements` into two flat string lists.

Output `type` renames STIX's `attack-pattern`/`course-of-action` to
`attack-technique`/`attack-mitigation`: CAPEC uses those same two STIX types for
its own, different attack patterns and mitigations, so left unrenamed they'd be
the only `type` values shared by two catalogs.

Every string is normalized on the way out by `clean_record()`: CRLF to LF,
non-breaking spaces and tabs to plain spaces, horizontal whitespace runs
collapsed, lines trimmed, empty values and duplicate list entries dropped.
Blank-line paragraph breaks survive; source-document indentation does not.
Markup that is quoted content (payloads, code samples) is left verbatim.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

DOMAIN_LATEST_FILES: Tuple[str, ...] = ("enterprise/latest.json", "mobile/latest.json", "ics/latest.json")

BOILERPLATE_TYPES = {"identity", "marking-definition", "x-mitre-collection"}

# Dropped on purpose, and not boilerplate. Recent ATT&CK stopped pointing a data component
# at its data source -- `x_mitre_data_source_ref` is on 0 of the 109 raw components -- and
# replaced that model with `x_mitre_log_sources`, which this parser follows. Nothing else
# in the bundle references a data-source id either, so all 42 came out with zero
# relationships in either direction (19 of them revoked): unreachable nodes, no trace ever
# crossing them. The same call was made for CAPEC's skill levels.
DROPPED_TYPES = {"x-mitre-data-source"}

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
    "x-mitre-asset": ASSET_FIELDS,
}

RELATIONSHIP_KEY = "relationship"
DERIVED_RELATIONSHIP_KEY = "derived-relationship"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

HAS_TACTIC_RELATIONSHIP_TYPE = "has_tactic"
HAS_MEMBER_RELATIONSHIP_TYPE = "has_member"
HAS_ANALYTIC_RELATIONSHIP_TYPE = "has_analytic"
USES_DATA_COMPONENT_RELATIONSHIP_TYPE = "uses_data_component"
EXTERNAL_RELATIONSHIP_TYPE = "related_to"

# Upstream writes a literal "None" string (not JSON null) where a field doesn't apply --
# 184 log-source channels and 179 `x_mitre_platforms` entries -- normalized away so it
# can't load as a real value.
ABSENT_VALUE_SENTINELS = frozenset({"None"})

NOTE_SEPARATOR = " -- "  # verified absent from every field name, description, log source name and channel

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

# Upstream free text carries CRLF endings, non-breaking spaces, tabs and the indentation
# of the document it was serialized from. None of it is content, all of it survives
# verbatim into the output and breaks string matching, so `clean_text()` normalizes it away.
COLLAPSIBLE_SPACE_PATTERN = re.compile(r"[\u00a0\u2007\u202f\ufeff\t]")
HORIZONTAL_RUN_PATTERN = re.compile(r"[^\S\n]{2,}")
BLANK_LINE_RUN_PATTERN = re.compile(r"\n{3,}")
SOFT_WRAP_PATTERN = re.compile(r"(?<!\n)\n(?!\n)")

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = (RELATIONSHIP_KEY, DERIVED_RELATIONSHIP_KEY, EXTERNAL_RELATIONSHIP_KEY)


class ParseError(RuntimeError):
    pass


def clean_text(value: str, unwrap: bool = False) -> str:
    """Normalize one free-text string: CRLF/CR to LF, non-breaking and other exotic
    spaces plus tabs to a plain space, runs of horizontal whitespace collapsed, every
    line trimmed. Blank-line paragraph breaks are preserved; with `unwrap`, a lone
    newline is treated as source-indentation wrapping and becomes a space."""
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = COLLAPSIBLE_SPACE_PATTERN.sub(" ", text)
    text = HORIZONTAL_RUN_PATTERN.sub(" ", text)
    text = "\n".join(line.strip() for line in text.split("\n"))
    if unwrap:
        text = SOFT_WRAP_PATTERN.sub(" ", text)
    return BLANK_LINE_RUN_PATTERN.sub("\n\n", text).strip()


def clean_value(value: Any) -> Any:
    """Normalize every string in a property value, dropping the ones left empty or equal
    to a sentinel, and deduping list values."""
    if isinstance(value, str):
        text = clean_text(value)
        return None if not text or text in ABSENT_VALUE_SENTINELS else text
    if isinstance(value, list):
        kept = [item for item in map(clean_value, value) if item is not None]
        return list(dict.fromkeys(kept)) or None
    return value


def clean_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Run every property through `clean_value`, dropping those left empty. Applied once
    per record on the way out, so no builder has to remember to trim or dedupe itself."""
    cleaned: Dict[str, Any] = {}
    for key, value in record.items():
        value = clean_value(value)
        if value is not None:
            cleaned[key] = value
    return cleaned


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
    # Seeded on the triple alone: `collapse_parallel_relationships()` leaves exactly one
    # record per (source, type, target), so there is nothing left for `extra` to
    # disambiguate, and an id that ignores attributes stays put when they change.
    seed_parts = [source_ref, relationship_type, target_ref]
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


def normalize_relationship_type(relationship_type: str) -> str:
    """STIX spells its own relationship types with hyphens (`subtechnique-of`), while
    every type derived here is snake_case, so native types are rewritten to match -- these
    are all single words plus hyphens, so the rewrite can't collide with an existing
    name."""
    return relationship_type.replace("-", "_")


def build_native_relationship(obj: Dict[str, Any], id_to_final_id: Dict[str, str]) -> Optional[Dict[str, Any]]:
    record = filter_object(obj, RELATIONSHIP_PASSTHROUGH_FIELDS)
    final_source = id_to_final_id.get(record["source_ref"])
    final_target = id_to_final_id.get(record["target_ref"])
    if final_source is None or final_target is None:
        return None  # one endpoint was the losing side of an id collision -- see resolve_canonical_ids
    record["relationship_type"] = normalize_relationship_type(record["relationship_type"])
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
    return clean_value(str(value)) if value else None


def clean_log_source_name(value: Any) -> Optional[str]:
    """Log source names are deduplicated against each other, so they are trimmed here
    rather than on the way out: three of the 354 upstream names carry a trailing space
    (`"networkconfig "`) and would otherwise survive alongside their trimmed twin."""
    return clean_value(value) if isinstance(value, str) else None


def build_analytic_relationships(
    obj: Dict[str, Any], entity_id: Optional[str], id_to_final_id: Dict[str, str]
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
        name = clean_log_source_name(log_source.get("name"))
        if name:
            # the bare code, not a node reference: all 307 names used here also appear in
            # some data component's own log_sources, which is where they can be looked up
            extra["log_source"] = name
        channel = clean_channel(log_source.get("channel"))
        if channel:
            extra["channel"] = channel
        relationships.append(make_relationship(entity_id, target_ref, USES_DATA_COMPONENT_RELATIONSHIP_TYPE, **extra))
    return relationships


def apply_log_sources(obj: Dict[str, Any], record: Dict[str, Any]) -> None:
    """Fold a data component's `x_mitre_log_sources` list-of-{name, channel} maps into
    `log_sources`/`log_source_notes` properties. `name` is a shared vocabulary -- 348
    mostly colon-namespaced codes (`WinEventLog:Security`) -- but a code is a label on the
    component, not a thing it points at, and as nodes those 348 held nothing except their
    own name. `channel` is free-text analyst prose that varies per mention, so as edges one
    pair needed one edge per channel: 3,165 edges carrying only 999 real
    (component, log source) facts, with `DC0085 -> NSM:Flow` alone repeated 150 times.
    Flattened, the name is listed once and each channel rides a self-labelling
    `"name -- channel"` string."""
    sources, notes = [], []
    for log_source in obj.get("x_mitre_log_sources", []) or []:
        name = clean_log_source_name(log_source.get("name"))
        if not name:
            continue
        sources.append(name)
        channel = clean_channel(log_source.get("channel"))
        if channel:
            notes.append(f"{name}{NOTE_SEPARATOR}{channel}")
    if sources:
        record["log_sources"] = list(dict.fromkeys(sources))
    if notes:
        record["log_source_notes"] = list(dict.fromkeys(notes))


def flatten_mutable_elements(record: Dict[str, Any]) -> None:
    """Replace an analytic's `x_mitre_mutable_elements` maps with two flat string lists.
    The `field` names are the queryable half (25 are shared by 10+ analytics) so they
    become a plain list; `description` is per-analytic tuning prose (5,145 distinct
    strings across 5,177 elements), kept as self-labelling `"field -- description"`
    strings rather than a parallel list, since nothing keeps two separate lists aligned."""
    elements = record.pop("x_mitre_mutable_elements", None) or []
    fields = list(dict.fromkeys(e["field"] for e in elements if e.get("field")))
    if fields:
        record["x_mitre_mutable_element_fields"] = fields
    notes = [
        f"{e['field']}{NOTE_SEPARATOR}{e['description']}"
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
) -> List[Dict[str, Any]]:
    """Edges derived from embedded fields, for the five types that carry any."""
    if obj_type == "attack-pattern":
        return build_technique_tactic_relationships(obj, final_id, tactic_by_domain_shortname)
    if obj_type == "x-mitre-matrix":
        return build_ref_field_relationships(obj, final_id, id_to_final_id, "tactic_refs", HAS_MEMBER_RELATIONSHIP_TYPE)
    if obj_type == "x-mitre-detection-strategy":
        return build_ref_field_relationships(obj, final_id, id_to_final_id, "x_mitre_analytic_refs", HAS_ANALYTIC_RELATIONSHIP_TYPE)
    if obj_type == "x-mitre-analytic":
        return build_analytic_relationships(obj, final_id, id_to_final_id)
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

        if obj_type not in FIELDS_BY_TYPE:
            if obj_type not in BOILERPLATE_TYPES and obj_type not in DROPPED_TYPES:
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
        if obj_type == "x-mitre-data-component":
            apply_log_sources(obj, record)
        result[obj_type].append(record)

        if obj_type == "attack-pattern":
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_capec_relationships(obj, final_id))
        result[DERIVED_RELATIONSHIP_KEY].extend(
            build_derived_relationships(obj, obj_type, final_id, id_to_final_id, tactic_by_domain_shortname)
        )

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[mitre-attack-parser] parsed {len(objects)} merged objects; dropped {dropped_summary or 'nothing'}")
    return result


def collapse_parallel_relationships(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One record per (`source_ref`, `relationship_type`, `target_ref`).

    The source states some links more than once, each statement carrying different
    attributes -- one analytic naming the same data component under two different log sources. Written straight through, those became parallel
    edges between the same two nodes, so `degree()` counted a node's statements rather
    than its neighbours, and retrieval that caps expansion by degree read the graph wrong.

    Nothing is dropped. Attributes identical across the group stay scalar; attributes that
    differ become a list holding one entry per original statement, in document order, and
    a field a statement did not carry holds `null` to keep that alignment -- so entry `i`
    of each of those lists belongs to the same original statement, and the original
    statements are recoverable exactly. A merged record names those fields in
    `merged_fields`, without which they could not be told apart from a field that was
    already multi-valued on a single statement -- CWE has `has_mitigation` links whose
    native two-entry `phase` sits on a record merged from two statements, where length
    alone cannot say which list is which. This runs after `clean_record()`, whose list
    handling dedupes and drops empty values, and would otherwise break the alignment
    those lists depend on.
    """
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for record in records:
        key = (record["source_ref"], record["relationship_type"], record["target_ref"])
        grouped.setdefault(key, []).append(record)

    collapsed: List[Dict[str, Any]] = []
    for group in grouped.values():
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        merged = dict(group[0])
        merged_fields = []
        for field in dict.fromkeys(field for record in group for field in record if field != "id"):
            values = [record.get(field) for record in group]
            if all(value == values[0] for value in values):
                merged[field] = values[0]
            else:
                merged[field] = values
                merged_fields.append(field)
        merged["merged_fields"] = merged_fields
        collapsed.append(merged)
    return collapsed


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, List[Dict[str, Any]]] = {ENTITIES_FILENAME: [], RELATIONSHIPS_FILENAME: []}
    counts: Dict[str, int] = {}
    for key, records in result.items():
        target = RELATIONSHIPS_FILENAME if key in RELATIONSHIP_KEYS else ENTITIES_FILENAME
        cleaned = [clean_record(record) for record in records]
        if target == RELATIONSHIPS_FILENAME:
            cleaned = collapse_parallel_relationships(cleaned)
        files[target].extend(cleaned)
        counts[key] = len(cleaned)
    for filename, records in files.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
    return counts


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
