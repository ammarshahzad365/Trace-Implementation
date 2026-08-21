"""CWE field-projection preprocessor. Full rationale in README.md.

Reads the CWE crawler's JSON bundle (`data-acquisition/CWE/latest.json`) and
writes two files: `entities.json` (weaknesses, categories, views, and the
sub-record entities promoted out of them) and `relationships.json` (every edge).
Each record's own `type` says which kind it is.

CWE's JSON is an XML-to-JSON conversion, not STIX, so every relationship-shaped
field (`RelatedWeaknesses`, `RelatedAttackPatterns`, `AlternateTerms`,
`ObservedExamples`, `*.HasMember`) and every attribute-shaped field that nests
sub-records (`CommonConsequences`, `ApplicablePlatforms`, `ModesOfIntroduction`,
`PotentialMitigations`, `DetectionMethods`) lives inline on the entity. All of it
is extracted into STIX-shaped edge records and removed from the entity. Outward
edges are scoped to CAPEC and CVE, distinguished by carrying a `source_name`;
other taxonomies referenced by `TaxonomyMappings`/`ObservedExamples` are dropped.

Sub-records whose identity is reused across weaknesses become shared nodes:
platforms by `(category, name)`, mitigations by `Mitigation_ID`, detection
methods by `Detection_Method_ID`, consequences by `(scope, impact)`,
introductions by `Phase`. The content alongside that identity genuinely varies
per referencing weakness, so it moves onto the edge instead -- same convention
`RelatedWeaknesses` already uses for `ordinal`/`view_id`. Sub-records with no
natural key get a private per-occurrence node carrying the detail directly, so no
edge ever points at an empty node. `WeaknessOrdinalities` is the exception: it
flattens in place to a plain array, no new node type.

XHTML-shaped rich text (`ExtendedDescription`, `BackgroundDetails`, a view's
`Objective`, and the `Description`/`EffectivenessNotes` sub-fields) is formatting,
not structure, so `flatten_xhtml()` renders it to one plain-text string.
`AffectedResources`/`FunctionalAreas`/`Audience` are unwrapped from their
single-key wrapper dicts to plain arrays.

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

# `cwe_id` is deliberately absent: it is the bare number behind `id` (`5` vs `CWE-5`) on
# all 1,450 catalog records, so as a second property it only duplicates the key. The raw
# field is still read directly off `obj` to build edge endpoints.
COMMON_FIELDS: Tuple[str, ...] = ("id", "Name", "type", "Status", "created", "modified")

# Fields kept verbatim -- no nesting, no flattening needed.
WEAKNESS_SCALAR_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("Abstraction", "Structure", "Description", "LikelihoodOfExploit")
CATEGORY_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("Summary",)
VIEW_SCALAR_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("Type",)

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "weakness": WEAKNESS_SCALAR_FIELDS,
    "category": CATEGORY_FIELDS,
    "view": VIEW_SCALAR_FIELDS,
}

# Every edge pointing outside this bundle; `source_name` says which external system,
# the same convention capec_preprocessing.py uses.
EXTERNAL_RELATIONSHIP_TYPE = "related_to"

# RelatedWeakness Nature -> relationship_type. CWE stores only one direction per pair
# (no ParentOf/CanFollow/RequiredBy appear), and even PeerOf is reciprocal in just 16 of
# 98 pairs, so every edge is kept as given rather than deduped/canonicalized.
NATURE_TO_RELATIONSHIP_TYPE: Dict[str, str] = {
    "ChildOf": "child_of",
    "CanPrecede": "can_precede",
    "PeerOf": "peer_of",
    "CanAlsoBe": "can_also_be",
    "Requires": "requires",
    "StartsWith": "starts_with",
}

HAS_MEMBER_RELATIONSHIP_TYPE = "has_member"
HAS_CONSEQUENCE_RELATIONSHIP_TYPE = "has_consequence"
APPLIES_TO_PLATFORM_RELATIONSHIP_TYPE = "applies_to_platform"
INTRODUCED_IN_RELATIONSHIP_TYPE = "introduced_in"
HAS_MITIGATION_RELATIONSHIP_TYPE = "has_mitigation"
HAS_DETECTION_METHOD_RELATIONSHIP_TYPE = "has_detection_method"

ALIAS_NOTE_SEPARATOR = " -- "

# CWE's XML is PascalCase; output is snake_case like every other source here. A view's
# `Type` would collide with the `type` discriminator, so it becomes `view_type`.
FIELD_NAME_OVERRIDES: Dict[str, str] = {
    "Type": "view_type",
    "LikelihoodOfExploit": "likelihood_of_exploit",
    "ExtendedDescription": "extended_description",
    "BackgroundDetails": "background_details",
    "AffectedResources": "affected_resources",
    "FunctionalAreas": "functional_areas",
    "WeaknessOrdinalities": "weakness_ordinalities",
}

# A malformed CVE id in an ObservedExample (`CVE-2002-216`, 3-digit sequence) resolves
# to nothing, so it's dropped rather than emitted as an edge to a nonexistent node.
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

RELATIONSHIP_KEY = "relationship"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

# Sub-record entity types promoted out of weakness records, deduped by a stable identity
# where the source has one and per-occurrence otherwise (see get_or_create_entity).
CONSEQUENCE_ENTITY_TYPE = "consequence"
PLATFORM_ENTITY_TYPE = "platform"
INTRODUCTION_ENTITY_TYPE = "introduction"
MITIGATION_ENTITY_TYPE = "mitigation"
DETECTION_METHOD_ENTITY_TYPE = "detection-method"

SUB_ENTITY_TYPES: Tuple[str, ...] = (
    CONSEQUENCE_ENTITY_TYPE,
    PLATFORM_ENTITY_TYPE,
    INTRODUCTION_ENTITY_TYPE,
    MITIGATION_ENTITY_TYPE,
    DETECTION_METHOD_ENTITY_TYPE,
)

# Upstream free text carries CRLF endings, non-breaking spaces, tabs and the indentation
# of the document it was serialized from. None of it is content, all of it lands verbatim
# in a Neo4j property and breaks string matching, so `clean_text()` normalizes it away.
COLLAPSIBLE_SPACE_PATTERN = re.compile(r"[\u00a0\u2007\u202f\ufeff\t]")
HORIZONTAL_RUN_PATTERN = re.compile(r"[^\S\n]{2,}")
BLANK_LINE_RUN_PATTERN = re.compile(r"\n{3,}")
SOFT_WRAP_PATTERN = re.compile(r"(?<!\n)\n(?!\n)")

# CWE writes a literal "None"/"Unknown" where a field was considered and left unset. A
# missing field is omitted rather than written out, so these are dropped to match.
ABSENT_VALUE_SENTINELS = frozenset({"None"})
UNSET_LIKELIHOOD_SENTINEL = "Unknown"

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = (RELATIONSHIP_KEY, EXTERNAL_RELATIONSHIP_KEY)

# XHTML tag keys carrying no text content of their own.
XHTML_IGNORED_TAGS = {"style", "br"}
XHTML_LIST_ITEM_TAG = "li"


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
    """CWE's XML-derived JSON collapses a single repeated element to a bare dict instead
    of a one-item list -- normalize both shapes to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


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
    to the `"None"` sentinel, and deduping list values."""
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


def flatten_xhtml(value: Any) -> Optional[str]:
    """Flatten CWE's XHTML-shaped rich text (a dict/list keyed by tag name -- `p`, `div`,
    `ul`/`ol` wrapping `li`, `b`) to one plain-text string. Paragraphs join with a blank
    line, list items render as `"- "` lines (the ordered/unordered distinction is not
    preserved, the item order is), and `style`/`br` carry no text so they're dropped."""
    if value is None:
        return None
    if isinstance(value, str):
        # unwrapped at the leaf, before this function adds its own structural newlines --
        # doing it afterwards would merge the `"- "` list items back into one line
        return clean_text(value, unwrap=True) or None
    if isinstance(value, list):
        parts = [flatten_xhtml(item) for item in value]
        return "\n".join(part for part in parts if part) or None
    if isinstance(value, dict):
        parts = []
        for tag, tag_value in value.items():
            if tag in XHTML_IGNORED_TAGS:
                continue
            if tag == XHTML_LIST_ITEM_TAG:
                bullets = [f"- {flat}" for flat in map(flatten_xhtml, as_list(tag_value)) if flat]
                if bullets:
                    parts.append("\n".join(bullets))
                continue
            flattened = flatten_xhtml(tag_value)
            if flattened:
                parts.append(flattened)
        return "\n\n".join(parts) or None
    return str(value)


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def unwrap_scalar_text(record: Dict[str, Any], *fields: str) -> Dict[str, Any]:
    """`Description`/`Summary` are plain XML text nodes rather than XHTML, so they never
    reach flatten_xhtml -- but their line breaks are the same source-document indentation
    (`"it does
        not validate"`) and unwrap the same way."""
    for field in fields:
        if isinstance(record.get(field), str):
            record[field] = clean_text(record[field], unwrap=True)
    return record


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    # `extra` is part of the seed because CWE edges legitimately repeat the same
    # (source, type, target) with different attributes -- e.g. one ChildOf pair recorded
    # under two View_IDs -- and those need distinct, still-deterministic ids.
    seed_parts = [source_ref, relationship_type, target_ref]
    seed_parts.extend(f"{key}={extra[key]}" for key in sorted(extra))
    relationship_uuid = uuid.uuid5(uuid.NAMESPACE_URL, "cwe-preprocessing:" + "|".join(seed_parts))
    record: Dict[str, Any] = {
        "id": f"relationship--{relationship_uuid}",
        "type": "relationship",
        "relationship_type": relationship_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
    }
    record.update(extra)
    return record


def get_or_create_entity(
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
    entity_type: str,
    identity_seed: str,
    fields: Dict[str, Any],
) -> str:
    """Return the id of (entity_type, identity_seed), creating it on first use. Shared
    sub-records pass their natural key (`"Language|Java"`) so repeat references resolve
    to one node; keyless ones pass a seed folding in the owning weakness and a position
    index, unique by construction, so they always get a fresh node -- one deterministic,
    rerun-stable code path for both."""
    registry = dedup_registry.setdefault(entity_type, {})
    existing = registry.get(identity_seed)
    if existing is not None:
        return existing
    entity_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"cwe-preprocessing:{entity_type}:{identity_seed}")
    entity_id = f"{entity_type}--{entity_uuid}"
    entities_by_type[entity_type].append({"id": entity_id, "type": entity_type, **fields})
    registry[identity_seed] = entity_id
    return entity_id


def snake_case(name: str) -> str:
    """`LikelihoodOfExploit` -> `likelihood_of_exploit`, `Name` -> `name`."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def normalize_field_names(record: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite PascalCase source names to snake_case, preserving field order. Applied
    once per record after every builder has run, so builders read source names verbatim."""
    return {FIELD_NAME_OVERRIDES.get(key, snake_case(key)): value for key, value in record.items()}


def build_weakness_record(obj: Dict[str, Any]) -> Dict[str, Any]:
    record = unwrap_scalar_text(filter_object(obj, WEAKNESS_SCALAR_FIELDS), "Description")

    if "ExtendedDescription" in obj:
        flat = flatten_xhtml(obj["ExtendedDescription"])
        if flat:
            record["ExtendedDescription"] = flat

    if "BackgroundDetails" in obj:
        flat = flatten_xhtml(obj["BackgroundDetails"].get("BackgroundDetail"))
        if flat:
            record["BackgroundDetails"] = flat

    for field, inner in (("AffectedResources", "AffectedResource"), ("FunctionalAreas", "FunctionalArea")):
        if field in obj:
            values = [value for value in as_list(obj[field].get(inner)) if value]
            if values:
                record[field] = values

    if "WeaknessOrdinalities" in obj:
        ordinalities = [
            item.get("Ordinality")
            for item in as_list(obj["WeaknessOrdinalities"].get("WeaknessOrdinality"))
            if item.get("Ordinality")
        ]
        if ordinalities:
            record["WeaknessOrdinalities"] = ordinalities

    apply_alternate_terms(obj, record)
    return record


def build_view_record(obj: Dict[str, Any]) -> Dict[str, Any]:
    record = filter_object(obj, VIEW_SCALAR_FIELDS)

    if "Objective" in obj:
        flat = flatten_xhtml(obj["Objective"])
        if flat:
            record["Objective"] = flat

    if "Audience" in obj:
        # only the 10 distinct stakeholder Types are kept; the per-view Description is dropped
        types = [item.get("Type") for item in as_list(obj["Audience"].get("Stakeholder")) if item.get("Type")]
        if types:
            record["Audience"] = types

    return record


def build_related_weakness_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("RelatedWeaknesses", {}).get("RelatedWeakness")):
        nature = item.get("Nature")
        relationship_type = NATURE_TO_RELATIONSHIP_TYPE.get(nature)
        if relationship_type is None:
            raise ParseError(f"weakness {source_ref} has unknown RelatedWeakness Nature {nature!r}")
        extra: Dict[str, Any] = {}
        if item.get("Ordinal"):
            extra["ordinal"] = item["Ordinal"]
        if item.get("View_ID"):
            extra["view_id"] = item["View_ID"]
        relationships.append(make_relationship(source_ref, f"CWE-{item.get('CWE_ID')}", relationship_type, **extra))
    return relationships


def apply_alternate_terms(obj: Dict[str, Any], record: Dict[str, Any]) -> None:
    """Fold `AlternateTerms` into `aliases`/`alias_notes` properties, the same `aliases`
    ATT&CK/CAPEC/D3FEND records carry. As edges these 189 pointed at the alias text
    itself, which is no entity, so loading them invented a phantom node per string. The
    105 terms with a note keep it as a self-labelling `"term -- note"` string rather than
    a second index-aligned list."""
    terms, notes = [], []
    for item in as_list(obj.get("AlternateTerms", {}).get("AlternateTerm")):
        term = item.get("Term")
        if not term:
            continue
        terms.append(term)
        note = flatten_xhtml(item.get("Description"))
        if note:
            notes.append(f"{term}{ALIAS_NOTE_SEPARATOR}{note}")
    if terms:
        record["aliases"] = list(dict.fromkeys(terms))
    if notes:
        record["alias_notes"] = notes


def build_has_member_relationships(obj: Dict[str, Any], members_field: str) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get(members_field, {}).get("HasMember")):
        extra = {"view_id": item["View_ID"]} if item.get("View_ID") else {}
        relationships.append(make_relationship(source_ref, f"CWE-{item.get('CWE_ID')}", HAS_MEMBER_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_related_attack_pattern_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    return [
        make_relationship(source_ref, f"CAPEC-{item['CAPEC_ID']}", EXTERNAL_RELATIONSHIP_TYPE, source_name="capec")
        for item in as_list(obj.get("RelatedAttackPatterns", {}).get("RelatedAttackPattern"))
        if item.get("CAPEC_ID")
    ]


def build_observed_example_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    """CVE-only: ObservedExample references that aren't a CVE id (a plain `ref`) are
    dropped, since outward-pointing edges are scoped to CVE/CAPEC."""
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("ObservedExamples", {}).get("ObservedExample")):
        target_ref = (item.get("Reference") or "").strip().strip("[]")
        if not target_ref.startswith("CVE"):
            continue
        if not CVE_ID_PATTERN.match(target_ref):
            print(f"[cwe-parser] warning: CWE-{obj['cwe_id']} ObservedExample {target_ref!r} is not a well-formed CVE id -- dropped", file=sys.stderr)
            continue
        extra: Dict[str, Any] = {"source_name": "cve"}
        if item.get("Description"):
            extra["description"] = item["Description"]
        if item.get("Link"):
            extra["link"] = item["Link"]
        relationships.append(make_relationship(source_ref, target_ref, EXTERNAL_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_consequence_relationships(
    obj: Dict[str, Any],
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("CommonConsequences", {}).get("Consequence")):
        scope = sorted(set(as_list(item.get("Scope"))))
        impact = sorted(set(as_list(item.get("Impact"))))
        if not scope and not impact:
            continue
        entity_id = get_or_create_entity(
            dedup_registry,
            entities_by_type,
            CONSEQUENCE_ENTITY_TYPE,
            f"scope={','.join(scope)}|impact={','.join(impact)}",
            {"scope": scope, "impact": impact},
        )
        extra: Dict[str, Any] = {}
        if item.get("Likelihood") and item["Likelihood"] != UNSET_LIKELIHOOD_SENTINEL:
            extra["likelihood"] = item["Likelihood"]
        note = flatten_xhtml(item.get("Note"))
        if note:
            extra["note"] = note
        relationships.append(make_relationship(source_ref, entity_id, HAS_CONSEQUENCE_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_platform_relationships(
    obj: Dict[str, Any],
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for category, value in (obj.get("ApplicablePlatforms") or {}).items():
        for index, item in enumerate(as_list(value)):
            name = item.get("Name")
            fields: Dict[str, Any] = {"category": category}
            if name:
                # a named platform is shared by every weakness naming it; an anonymous
                # one gets a private node rather than being merged with other anonymous ones
                identity_seed = f"{category}|{name}"
                fields["name"] = name
            else:
                identity_seed = f"{category}|private|{source_ref}|{index}"
            entity_id = get_or_create_entity(dedup_registry, entities_by_type, PLATFORM_ENTITY_TYPE, identity_seed, fields)
            extra: Dict[str, Any] = {}
            if item.get("Class"):
                extra["class"] = item["Class"]
            if item.get("Prevalence"):
                extra["prevalence"] = item["Prevalence"]
            relationships.append(make_relationship(source_ref, entity_id, APPLIES_TO_PLATFORM_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_introduction_relationships(
    obj: Dict[str, Any],
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("ModesOfIntroduction", {}).get("Introduction")):
        phase = item.get("Phase")
        if not phase:
            continue
        entity_id = get_or_create_entity(dedup_registry, entities_by_type, INTRODUCTION_ENTITY_TYPE, phase, {"phase": phase})
        note = flatten_xhtml(item.get("Note"))
        extra = {"note": note} if note else {}
        relationships.append(make_relationship(source_ref, entity_id, INTRODUCED_IN_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_detail_relationships(
    obj: Dict[str, Any],
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
    container: str,
    item_key: str,
    entity_type: str,
    id_field: str,
    relationship_type: str,
    scalar_fields: Tuple[str, ...],
    list_fields: Tuple[str, ...] = (),
) -> List[Dict[str, Any]]:
    """Shared body for mitigations and detection methods -- same shape, different field
    names. Where the source gives a reusable id, the node holds only that id and the
    variable detail (phase/strategy/effectiveness/description/notes) goes on the edge,
    since it genuinely differs per usage. Where it doesn't, the detail goes on the
    private node instead, so no edge ever points at an empty node."""
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for index, item in enumerate(as_list(obj.get(container, {}).get(item_key))):
        detail: Dict[str, Any] = {}
        for field in scalar_fields:
            if item.get(field):
                detail[snake_case(field)] = as_list(item[field]) if field in list_fields else item[field]
        for field in ("Description", "EffectivenessNotes"):
            flat = flatten_xhtml(item.get(field))
            if flat:
                detail[snake_case(field)] = flat

        source_id = item.get(id_field)
        if source_id:
            identity_seed, fields, extra = source_id, {snake_case(id_field): source_id}, detail
        else:
            identity_seed, fields, extra = f"private|{source_ref}|{index}", detail, {}

        entity_id = get_or_create_entity(dedup_registry, entities_by_type, entity_type, identity_seed, fields)
        relationships.append(make_relationship(source_ref, entity_id, relationship_type, **extra))
    return relationships


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[RELATIONSHIP_KEY] = []
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    for entity_type in SUB_ENTITY_TYPES:
        result[entity_type] = []

    dedup_registry: Dict[str, Dict[str, str]] = {}
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        if obj_type not in FIELDS_BY_TYPE:
            print(f"[cwe-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        if obj_type == "weakness":
            result["weakness"].append(normalize_field_names(build_weakness_record(obj)))
            result[RELATIONSHIP_KEY].extend(build_related_weakness_relationships(obj))
            result[RELATIONSHIP_KEY].extend(build_consequence_relationships(obj, dedup_registry, result))
            result[RELATIONSHIP_KEY].extend(build_platform_relationships(obj, dedup_registry, result))
            result[RELATIONSHIP_KEY].extend(build_introduction_relationships(obj, dedup_registry, result))
            result[RELATIONSHIP_KEY].extend(
                build_detail_relationships(
                    obj, dedup_registry, result, "PotentialMitigations", "Mitigation", MITIGATION_ENTITY_TYPE,
                    "Mitigation_ID", HAS_MITIGATION_RELATIONSHIP_TYPE, ("Phase", "Strategy", "Effectiveness"), ("Phase",),
                )
            )
            result[RELATIONSHIP_KEY].extend(
                build_detail_relationships(
                    obj, dedup_registry, result, "DetectionMethods", "DetectionMethod", DETECTION_METHOD_ENTITY_TYPE,
                    "Detection_Method_ID", HAS_DETECTION_METHOD_RELATIONSHIP_TYPE, ("Method", "Effectiveness"),
                )
            )
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_related_attack_pattern_relationships(obj))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_observed_example_relationships(obj))
        elif obj_type == "category":
            result["category"].append(normalize_field_names(unwrap_scalar_text(filter_object(obj, CATEGORY_FIELDS), "Summary")))
            result[RELATIONSHIP_KEY].extend(build_has_member_relationships(obj, "Relationships"))
        elif obj_type == "view":
            result["view"].append(normalize_field_names(build_view_record(obj)))
            result[RELATIONSHIP_KEY].extend(build_has_member_relationships(obj, "Members"))

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[cwe-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
    return result


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, List[Dict[str, Any]]] = {ENTITIES_FILENAME: [], RELATIONSHIPS_FILENAME: []}
    for key, records in result.items():
        target = RELATIONSHIPS_FILENAME if key in RELATIONSHIP_KEYS else ENTITIES_FILENAME
        files[target].extend(clean_record(record) for record in records)
    for filename, records in files.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
            handle.write("\n")
    return {key: len(records) for key, records in result.items()}


def format_counts(counts: Dict[str, int], keys: Sequence[str]) -> str:
    """Total plus per-kind breakdown: `5056 (964 weakness, 374 category, ...)`."""
    breakdown = ", ".join(f"{counts[key]} {key}" for key in keys if counts[key])
    return f"{sum(counts[key] for key in keys)} ({breakdown})"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "CWE" / "latest.json"

    parser = argparse.ArgumentParser(description="Trim CWE's JSON bundle down to a fixed field whitelist per object type")
    parser.add_argument("--input", default=str(default_input), help=f"Path to CWE's latest.json (default: {default_input})")
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
            f"[cwe-parser] wrote {format_counts(counts, entity_keys)} entities to {ENTITIES_FILENAME} "
            f"and {format_counts(counts, relationship_keys)} relationships to {RELATIONSHIPS_FILENAME}, in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
