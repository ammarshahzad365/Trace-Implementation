"""CWE field-projection preprocessor.

Reads the raw JSON bundle produced by the CWE crawler
(`data-acquisition/CWE/latest.json`) and writes a fully flattened,
relationship-linked pair of JSON files: `entities.json` (weaknesses,
categories, views, and the sub-record entities promoted out of them) and
`relationships.json` (every edge). A record's own `type` field is what
distinguishes the kinds inside each file.

CWE's own JSON is a generic XML-to-JSON conversion, not native STIX --
every relationship-shaped field (`RelatedWeaknesses`,
`RelatedAttackPatterns`, `AlternateTerms`, `ObservedExamples`,
`Relationships.HasMember`, `Members.HasMember`) lives inline on the entity
record itself, and so does every *attribute*-shaped field that itself nests
sub-records (`CommonConsequences`, `ApplicablePlatforms`,
`ModesOfIntroduction`, `PotentialMitigations`, `DetectionMethods`). This
script extracts all of it into STIX-shaped `relationship` records (`id`,
`type`, `relationship_type`, `source_ref`, `target_ref`, plus
relationship-specific attributes) and drops the source field from the entity
record, so entities and relationships are stored completely separately.

Edges pointing outside this bundle are scoped to CAPEC and CVE only -- other
external taxonomies referenced by `TaxonomyMappings`/`ObservedExamples`
(7 Pernicious Kingdoms, Software Fault Patterns, OWASP Top Ten, etc.) are
not extracted. They live in the same `relationships.json` as the internal
edges, distinguished by carrying a `source_name`.

## Sub-records with a reused identity become shared nodes; the rest stay private

`ApplicablePlatforms`, `PotentialMitigations`, and `DetectionMethods` each
carry a natural identity that's reused across many different weaknesses --
platforms by `(category, name)` (e.g. every weakness applicable to `Language:
Java` shares one node), mitigations by `Mitigation_ID` (70 distinct ids span
1,710 usages), detection methods by `Detection_Method_ID` (23 distinct ids
span 959 usages). But the *content* alongside that identity -- `Prevalence`,
`Phase`, `Effectiveness`, `Description`, `EffectivenessNotes` -- genuinely
varies by which weakness is referencing it (verified: 30/70 Mitigation_IDs
and 9/23 Detection_Method_IDs have different content across their usages).
So the shared node holds only the stable identity; every variable field
moves onto the `has_mitigation`/`has_detection_method`/`applies_to_platform`
relationship as an edge attribute instead -- the same convention this
project already uses for CWE's own `RelatedWeaknesses` edges (`ordinal`/
`view_id` live on the edge, not duplicated onto the target weakness).
Platform entries with no `Name` at all (an anonymous `Technology`/etc. entry)
get their own private node rather than being incorrectly merged together.

The same identity-reuse logic extends to two more fields that weren't
originally flagged as catalogs but turned out to behave the same way once
inspected: `CommonConsequences.Consequence` (deduped by its
`(scope, impact)` pair -- 113 of 311 distinct combinations recur across more
than one weakness, covering 1,039 of 1,237 total entries) and
`ModesOfIntroduction.Introduction` (deduped by `Phase` -- only 16 distinct
phases across 1,398 entries, e.g. every weakness introduced during
`Implementation` shares one node). `Likelihood`/`Note` on consequences and
`Note` on introductions are per-weakness commentary, so they follow the
same rule and live on the edge (`has_consequence`/`introduced_in`).

`WeaknessOrdinalities` doesn't get this treatment -- its only real sub-field
is `Ordinality` (Primary/Resultant/Indirect); the rare `Description` sibling
(2% of entries) is dropped, and the field is flattened in place to a plain
`WeaknessOrdinalities: ["Primary"]` array directly on the weakness record,
no new node type.

## XHTML-shaped rich text is flattened to plain text, not extracted

`ExtendedDescription`, `BackgroundDetails`, and the `Description`/
`EffectivenessNotes` sub-fields of `PotentialMitigations`/`DetectionMethods`
aren't always a bare string -- CWE's XML source wraps embedded markup
(`<xhtml:p>`, `<xhtml:ul>`, nested `<xhtml:div>`) into a JSON shape keyed by
tag name. This is formatting, not a graph relationship, so it's flattened
to one plain-text string: paragraphs join with a blank line, list items
(`ul`/`ol`, both wrapping an `li` list) render as `"- "`-prefixed lines
(the ordered/unordered distinction isn't preserved -- a cosmetic
simplification, the underlying order of items is), and the `style`
attribute some `div` nodes carry (raw CSS, e.g. `"margin-left:1em;"`) is
dropped as pure formatting noise with no content of its own. Same
treatment for a view record's `Objective`.

`AffectedResources`/`FunctionalAreas` (each wrapping a single-key list,
`{"AffectedResource": [...]}` -- a cardinality-1-collapse artifact of CWE's
XML-to-JSON conversion, the same quirk `as_list()` already exists to
normalize) are unwrapped to a plain `AffectedResources: [...]` /
`FunctionalAreas: [...]` array. A view record's `Audience.Stakeholder` (a
list of `{Type, Description}` pairs, only 10 distinct `Type` values) is
unwrapped the same way to a plain `Audience: [...]` array of stakeholder
type names; the per-view `Description` text is dropped.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

COMMON_FIELDS: Tuple[str, ...] = (
    "id",
    "cwe_id",
    "Name",
    "type",
    "Status",
    "created",
    "modified",
)

# Fields kept verbatim on weakness records -- no nesting, no flattening needed.
WEAKNESS_SCALAR_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "Abstraction",
    "Structure",
    "Description",
    "LikelihoodOfExploit",
)

CATEGORY_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("Summary",)

VIEW_SCALAR_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("Type",)

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "weakness": WEAKNESS_SCALAR_FIELDS,
    "category": CATEGORY_FIELDS,
    "view": VIEW_SCALAR_FIELDS,
}

# relationship_type used for every edge pointing outside this bundle (CAPEC,
# CVE/REF, external taxonomies) -- source_name on the record disambiguates
# which external system, the same convention capec_preprocessing.py uses for
# its own outward-pointing edges.
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

HAS_MEMBER_RELATIONSHIP_TYPE = "has_member"
HAS_CONSEQUENCE_RELATIONSHIP_TYPE = "has_consequence"
APPLIES_TO_PLATFORM_RELATIONSHIP_TYPE = "applies_to_platform"
INTRODUCED_IN_RELATIONSHIP_TYPE = "introduced_in"
HAS_MITIGATION_RELATIONSHIP_TYPE = "has_mitigation"
HAS_DETECTION_METHOD_RELATIONSHIP_TYPE = "has_detection_method"

ALIAS_NOTE_SEPARATOR = " -- "

# CWE's source XML uses PascalCase element names; every other source in this project
# uses snake_case, so output field names are normalized to match. `Type` on a view
# would collide with the `type` field carrying the node's own label, so it becomes
# `view_type`.
FIELD_NAME_OVERRIDES: Dict[str, str] = {
    "Type": "view_type",
    "LikelihoodOfExploit": "likelihood_of_exploit",
    "ExtendedDescription": "extended_description",
    "BackgroundDetails": "background_details",
    "AffectedResources": "affected_resources",
    "FunctionalAreas": "functional_areas",
    "WeaknessOrdinalities": "weakness_ordinalities",
}

# A CVE id CWE references in an ObservedExample but that isn't shaped like a real
# one (`CVE-2002-216` has a 3-digit sequence) can't resolve to anything -- dropped
# rather than emitted as an edge to a nonexistent node.
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

RELATIONSHIP_KEY = "relationship"
EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

# Sub-record entity types promoted out of weakness records. Each is deduped
# by a stable identity (see get_or_create_entity) when one exists in the
# source data, and falls back to a private per-occurrence node otherwise.
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

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; every other key holds entities. The keys
# themselves stay per-kind so the run summary can still report a breakdown, but they
# no longer map to a file each -- output is exactly two files, and a record's own
# `type` field is what distinguishes the kinds inside them.
RELATIONSHIP_KEYS: Tuple[str, ...] = (RELATIONSHIP_KEY, EXTERNAL_RELATIONSHIP_KEY)

# XHTML tag keys that carry no text content of their own.
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
    """CWE's XML-derived JSON collapses a single repeated element to a bare
    dict instead of a one-item list -- normalize both shapes to a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def flatten_xhtml(value: Any) -> Optional[str]:
    """Flatten CWE's XHTML-shaped rich text (a dict/list keyed by tag name --
    `p`, `div`, `ul`/`ol` wrapping `li`, `b`) down to one plain-text string.
    Paragraphs join with a blank line; list items render as `"- "`-prefixed
    lines; `style` (raw CSS) and `br` carry no text and are dropped."""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    if isinstance(value, list):
        parts = [flatten_xhtml(item) for item in value]
        joined = "\n".join(part for part in parts if part)
        return joined or None
    if isinstance(value, dict):
        parts = []
        for tag, tag_value in value.items():
            if tag in XHTML_IGNORED_TAGS:
                continue
            if tag == XHTML_LIST_ITEM_TAG:
                items = as_list(tag_value)
                bullet_lines = [f"- {flatten_xhtml(item)}" for item in items if flatten_xhtml(item)]
                if bullet_lines:
                    parts.append("\n".join(bullet_lines))
                continue
            flattened = flatten_xhtml(tag_value)
            if flattened:
                parts.append(flattened)
        joined = "\n\n".join(parts)
        return joined or None
    return str(value)


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    # `extra` is folded into the seed because CWE edges can legitimately repeat with the
    # same (source, type, target) but different attributes -- e.g. the same ChildOf pair
    # recorded under two different View_IDs -- and those need distinct, still-deterministic
    # ids.
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


def get_or_create_entity(
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
    entity_type: str,
    identity_seed: str,
    fields: Dict[str, Any],
) -> str:
    """Return the id of the entity identified by (entity_type, identity_seed), creating it
    on first use. Callers give shared sub-records (platform, mitigation, ...) an
    identity_seed built from their natural key (e.g. "Language|Java") so repeat references
    resolve to the same node; callers give sub-records with no natural key an identity_seed
    that folds in the owning weakness's id and a position index, which is unique by
    construction and so always creates a fresh node -- both cases share one deterministic,
    rerun-stable code path."""
    registry = dedup_registry.setdefault(entity_type, {})
    existing = registry.get(identity_seed)
    if existing is not None:
        return existing
    entity_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"cwe-preprocessing:{entity_type}:{identity_seed}")
    entity_id = f"{entity_type}--{entity_uuid}"
    record: Dict[str, Any] = {"id": entity_id, "type": entity_type}
    record.update(fields)
    entities_by_type[entity_type].append(record)
    registry[identity_seed] = entity_id
    return entity_id


def snake_case(name: str) -> str:
    """`LikelihoodOfExploit` -> `likelihood_of_exploit`, `Name` -> `name`."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def normalize_field_names(record: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite this record's PascalCase source field names to snake_case, preserving
    field order. Applied once per entity record, after every builder has finished
    adding its own fields, so builders can keep reading source names verbatim."""
    return {FIELD_NAME_OVERRIDES.get(key, snake_case(key)): value for key, value in record.items()}


def build_weakness_record(obj: Dict[str, Any]) -> Dict[str, Any]:
    record = filter_object(obj, WEAKNESS_SCALAR_FIELDS)

    if "ExtendedDescription" in obj:
        flat = flatten_xhtml(obj["ExtendedDescription"])
        if flat:
            record["ExtendedDescription"] = flat

    if "BackgroundDetails" in obj:
        flat = flatten_xhtml(obj["BackgroundDetails"].get("BackgroundDetail"))
        if flat:
            record["BackgroundDetails"] = flat

    if "AffectedResources" in obj:
        resources = [r for r in as_list(obj["AffectedResources"].get("AffectedResource")) if r]
        if resources:
            record["AffectedResources"] = resources

    if "FunctionalAreas" in obj:
        areas = [a for a in as_list(obj["FunctionalAreas"].get("FunctionalArea")) if a]
        if areas:
            record["FunctionalAreas"] = areas

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
        stakeholder_types = [
            item.get("Type") for item in as_list(obj["Audience"].get("Stakeholder")) if item.get("Type")
        ]
        if stakeholder_types:
            record["Audience"] = stakeholder_types

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


def apply_alternate_terms(obj: Dict[str, Any], record: Dict[str, Any]) -> None:
    """Fold `AlternateTerms` into `aliases`/`alias_notes` list properties on the weakness.

    These used to be `also_known_as` edges whose `target_ref` was the alias text
    itself -- but an alias is not an entity, so those 189 edges pointed at nothing
    that exists, and loading them would have invented a phantom node per alias
    string. As plain list properties they say the same thing without the phantoms,
    and they line up with the `aliases` property ATT&CK/CAPEC/D3FEND records carry
    for the same concept. 105 of the terms have an accompanying note, kept as
    self-labelling "term -- note" strings (the same shape analytics' mutable-element
    notes use) rather than a second index-aligned list.
    """
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
    """CVE-only: ObservedExample references that aren't a CVE ID (plain `ref`)
    are dropped, since outward-pointing edges are scoped to CVE/CAPEC."""
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for item in as_list(obj.get("ObservedExamples", {}).get("ObservedExample")):
        raw_ref = (item.get("Reference") or "").strip()
        if not raw_ref:
            continue
        target_ref = raw_ref.strip("[]")
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
        scope = sorted(as_list(item.get("Scope")))
        impact = sorted(as_list(item.get("Impact")))
        if not scope and not impact:
            continue
        identity_seed = f"scope={','.join(scope)}|impact={','.join(impact)}"
        entity_id = get_or_create_entity(
            dedup_registry, entities_by_type, CONSEQUENCE_ENTITY_TYPE, identity_seed, {"scope": scope, "impact": impact}
        )
        extra: Dict[str, Any] = {}
        if item.get("Likelihood"):
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
    platforms = obj.get("ApplicablePlatforms") or {}
    for category, value in platforms.items():
        for index, item in enumerate(as_list(value)):
            name = item.get("Name")
            fields: Dict[str, Any] = {"category": category}
            if name:
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
            relationships.append(
                make_relationship(source_ref, entity_id, APPLIES_TO_PLATFORM_RELATIONSHIP_TYPE, **extra)
            )
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
        entity_id = get_or_create_entity(
            dedup_registry, entities_by_type, INTRODUCTION_ENTITY_TYPE, phase, {"phase": phase}
        )
        extra: Dict[str, Any] = {}
        note = flatten_xhtml(item.get("Note"))
        if note:
            extra["note"] = note
        relationships.append(make_relationship(source_ref, entity_id, INTRODUCED_IN_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_mitigation_relationships(
    obj: Dict[str, Any],
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Mitigations reused across weaknesses (a real Mitigation_ID) keep their variable
    detail (phase/strategy/effectiveness/description/effectiveness_notes) on the edge,
    since that content genuinely differs per usage. Mitigations with no id are never
    reused -- each gets its own private node -- so the same detail goes on the node
    instead, leaving the edge attribute-free; this guarantees no edge ever points at an
    empty node."""
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for index, item in enumerate(as_list(obj.get("PotentialMitigations", {}).get("Mitigation"))):
        mitigation_id = item.get("Mitigation_ID")
        detail: Dict[str, Any] = {}
        if item.get("Phase"):
            detail["phase"] = as_list(item["Phase"])
        if item.get("Strategy"):
            detail["strategy"] = item["Strategy"]
        if item.get("Effectiveness"):
            detail["effectiveness"] = item["Effectiveness"]
        description = flatten_xhtml(item.get("Description"))
        if description:
            detail["description"] = description
        effectiveness_notes = flatten_xhtml(item.get("EffectivenessNotes"))
        if effectiveness_notes:
            detail["effectiveness_notes"] = effectiveness_notes

        if mitigation_id:
            identity_seed = mitigation_id
            fields: Dict[str, Any] = {"mitigation_id": mitigation_id}
            extra = detail
        else:
            identity_seed = f"private|{source_ref}|{index}"
            fields = detail
            extra = {}

        entity_id = get_or_create_entity(dedup_registry, entities_by_type, MITIGATION_ENTITY_TYPE, identity_seed, fields)
        relationships.append(make_relationship(source_ref, entity_id, HAS_MITIGATION_RELATIONSHIP_TYPE, **extra))
    return relationships


def build_detection_method_relationships(
    obj: Dict[str, Any],
    dedup_registry: Dict[str, Dict[str, str]],
    entities_by_type: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Same node-vs-edge split as build_mitigation_relationships: detail lives on the
    edge only for detection methods reused across weaknesses (a real
    Detection_Method_ID); id-less ones get a private node carrying the detail directly,
    so no edge ever points at an empty node."""
    source_ref = f"CWE-{obj['cwe_id']}"
    relationships = []
    for index, item in enumerate(as_list(obj.get("DetectionMethods", {}).get("DetectionMethod"))):
        detection_method_id = item.get("Detection_Method_ID")
        detail: Dict[str, Any] = {}
        if item.get("Method"):
            detail["method"] = item["Method"]
        if item.get("Effectiveness"):
            detail["effectiveness"] = item["Effectiveness"]
        description = flatten_xhtml(item.get("Description"))
        if description:
            detail["description"] = description
        effectiveness_notes = flatten_xhtml(item.get("EffectivenessNotes"))
        if effectiveness_notes:
            detail["effectiveness_notes"] = effectiveness_notes

        if detection_method_id:
            identity_seed = detection_method_id
            fields: Dict[str, Any] = {"detection_method_id": detection_method_id}
            extra = detail
        else:
            identity_seed = f"private|{source_ref}|{index}"
            fields = detail
            extra = {}

        entity_id = get_or_create_entity(
            dedup_registry, entities_by_type, DETECTION_METHOD_ENTITY_TYPE, identity_seed, fields
        )
        relationships.append(
            make_relationship(source_ref, entity_id, HAS_DETECTION_METHOD_RELATIONSHIP_TYPE, **extra)
        )
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
            result[RELATIONSHIP_KEY].extend(build_mitigation_relationships(obj, dedup_registry, result))
            result[RELATIONSHIP_KEY].extend(build_detection_method_relationships(obj, dedup_registry, result))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_related_attack_pattern_relationships(obj))
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_observed_example_relationships(obj))
        elif obj_type == "category":
            result["category"].append(normalize_field_names(filter_object(obj, CATEGORY_FIELDS)))
            result[RELATIONSHIP_KEY].extend(build_has_member_relationships(obj, "Relationships"))
        elif obj_type == "view":
            result["view"].append(normalize_field_names(build_view_record(obj)))
            result[RELATIONSHIP_KEY].extend(build_has_member_relationships(obj, "Members"))

    dropped_summary = ", ".join(f"{count} {obj_type}" for obj_type, count in sorted(dropped_counts.items()))
    print(f"[cwe-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
    return result


def write_json(path: Path, records: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(records, handle, indent=2)
        handle.write("\n")


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    entities: List[Dict[str, Any]] = []
    relationships: List[Dict[str, Any]] = []
    for key, records in result.items():
        (relationships if key in RELATIONSHIP_KEYS else entities).extend(records)
    write_json(output_dir / ENTITIES_FILENAME, entities)
    write_json(output_dir / RELATIONSHIPS_FILENAME, relationships)
    return {key: len(records) for key, records in result.items()}


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
        help=f"Directory to write entities.json / relationships.json (default: {default_output_dir})",
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
        entity_total = sum(count for key, count in counts.items() if key not in RELATIONSHIP_KEYS)
        relationship_total = sum(count for key, count in counts.items() if key in RELATIONSHIP_KEYS)
        print(
            f"[cwe-parser] wrote {entity_total} entities to {ENTITIES_FILENAME} "
            f"({counts['weakness']} weaknesses, "
            f"{counts['category']} categories, "
            f"{counts['view']} views, "
            f"{counts[CONSEQUENCE_ENTITY_TYPE]} consequences, "
            f"{counts[PLATFORM_ENTITY_TYPE]} platforms, "
            f"{counts[INTRODUCTION_ENTITY_TYPE]} introductions, "
            f"{counts[MITIGATION_ENTITY_TYPE]} mitigations, "
            f"{counts[DETECTION_METHOD_ENTITY_TYPE]} detection methods) and "
            f"{relationship_total} relationships to {RELATIONSHIPS_FILENAME} "
            f"({counts[RELATIONSHIP_KEY]} internal, "
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external), "
            f"in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
