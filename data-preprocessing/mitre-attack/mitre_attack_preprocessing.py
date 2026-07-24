"""MITRE ATT&CK field-projection preprocessor.

Reads the three raw STIX 2.1 bundles produced by the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) and
writes one merged, trimmed set of JSON files. Unlike CWE/CAPEC/CVE, ATT&CK
ships as three separate domain bundles that legitimately share entities: a
threat group, piece of malware, campaign, or data component tracked across
multiple matrices keeps the *same* STIX id in every domain bundle it
appears in (self-described via each copy's own `x_mitre_domains` list).
Techniques, analytics, detection strategies, tools, tactics, mitigations,
and matrices, by contrast, never repeat an id across domains -- each domain
has its own distinct set. Given that, this script merges all three domains
into one deduplicated object set (keyed by STIX id) rather than writing
three parallel per-domain output folders: for ids that appear in more than
one domain bundle, the `x_mitre_domains` lists are unioned (the two copies
were found to differ *only* in that field) and the rest of the fields are
taken from whichever copy has the later `modified` timestamp.

`identity`, `marking-definition`, and `x-mitre-collection` objects are
dropped entirely -- pure STIX attribution/collection-manifest boilerplate,
the same treatment CAPEC gives `identity`/`marking-definition`.

Every remaining object type is reduced to a field whitelist (see this
module's `*_FIELDS` constants). `external_references` is never kept
verbatim:

- its `mitre-attack` entry (or, on a handful of legacy revoked/deprecated
  records, `mitre-ics-attack`/`mitre-mobile-attack`) becomes a plain
  `attack_id` string attribute (e.g. `T1055`, `S0002`, `G0016`, `M1013`,
  `C0028`, `TA0009`, `DS0026`, `DET0210`, `AN0001`, `DC0103`, `A0008`) --
  the same convention CAPEC uses for its own `capec_id`. 19 records total
  (12 `attack-pattern`, 7 `malware`, all revoked or deprecated) have no
  such entry and are simply left without an `attack_id`, rather than
  raising an error the way CAPEC's stricter `extract_capec_id` does --
  this project intentionally keeps revoked/deprecated ATT&CK objects
  (unlike CVE's dropped `Rejected` records) since ATT&CK's own
  `revoked-by` relationships point *at* them, so silently discarding a
  revoked object would leave those edges dangling.
- its `capec` entries become `T#### --related-to--> CAPEC-N` records in
  `external_relationships.json` (`source_name: "capec"`) -- the reverse
  direction of CAPEC's own `CAPEC-N --related-to--> T####` edges (from its
  own `ATTACK`-sourced `external_references`).
- every other entry is a bibliographic citation (no local entity to point
  at) and is dropped, along with the field itself, on every object type --
  same treatment CWE gives `References`/`Notes`. Two derived campaign
  fields that only made sense paired with a (now-dropped) citation --
  `x_mitre_first_seen_citation`/`x_mitre_last_seen_citation` -- are dropped
  for the same reason, even though `first_seen`/`last_seen` themselves are
  kept.

Several embedded id-list fields are removed from their entity record and
rebuilt as `derived_relationships.json` edges instead, using each
endpoint's `attack_id` (not its STIX id) as `source_ref`/`target_ref` --
again the same convention CAPEC uses for its own derived
`attack_pattern_relationships.json`, as opposed to the STIX ids kept on
CAPEC's *native* `relationships.json`:

- `attack-pattern.kill_chain_phases` -> `has_tactic` edges. ATT&CK has no
  `relationship` object for technique-to-tactic membership at all -- it's
  a string match between `kill_chain_phases[].phase_name` and
  `x-mitre-tactic.x_mitre_shortname`, scoped to the domain implied by
  `kill_chain_phases[].kill_chain_name` (`mitre-attack` ->
  `enterprise-attack`, `mitre-mobile-attack` -> `mobile-attack`,
  `mitre-ics-attack` -> `ics-attack`). Tactic shortnames were verified
  unique within every domain, so this match is unambiguous.
- `x-mitre-matrix.tactic_refs` -> `has_member` edges (matrix -> tactic),
  mirroring the `has_member` edges CWE derives from its own
  `Relationships.HasMember`/`Members.HasMember` fields.
- `x-mitre-detection-strategy.x_mitre_analytic_refs` -> `has_analytic`
  edges (detection-strategy -> analytic).
- `x-mitre-analytic.x_mitre_log_source_references[].x_mitre_data_component_ref`
  -> `uses_data_component` edges (analytic -> data-component), with the
  log source's `name`/`channel` kept as edge attributes.

`x-mitre-data-source` has no formal link to `x-mitre-data-component` left
anywhere in the source data (a from-scratch grep found zero
`data_source_ref` occurrences) -- it's effectively a legacy/orphaned type
now that analytics point straight at data-components, so it's kept as a
plain entity list with no edges.

`x-mitre-asset.x_mitre_related_assets` stays embedded as an attribute
rather than becoming a relationship: it references narrower device
sub-types by free-text name (41 of 43 references don't match any other
asset's `name` in the bundle at all), not another `x-mitre-asset` entity by
id -- there's nothing to resolve.

Native `relationship` objects (`uses`, `mitigates`, `detects`,
`subtechnique-of`, `revoked-by`, `attributed-to`, `targets`) are kept
mostly as-is in `relationships.json`, with their original STIX
`source_ref`/`target_ref` untouched (unlike the derived edges above).
`revoked`/`x_mitre_deprecated` are dropped from relationship records
specifically -- verified always `False`/absent across all 24,582
relationships in this dataset, pure boilerplate with no signal.
`external_references` (citations) are dropped for the same bibliography
reason as everywhere else; `description` is kept when present since,
unlike CWE/CAPEC relationships, ATT&CK relationship descriptions carry
real analytic content (e.g. *how* a piece of malware uses a technique).
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

# external_references source_name values that carry an object's own canonical ATT&CK id.
# mitre-ics-attack/mitre-mobile-attack are a legacy convention found only on a small
# number of revoked/deprecated objects predating the unified "mitre-attack" source_name.
ATTACK_ID_SOURCE_NAMES = {"mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"}

KILL_CHAIN_NAME_TO_DOMAIN: Dict[str, str] = {
    "mitre-attack": "enterprise-attack",
    "mitre-mobile-attack": "mobile-attack",
    "mitre-ics-attack": "ics-attack",
}

COMMON_FIELDS: Tuple[str, ...] = (
    "id",
    "type",
    "name",
    "description",
    "attack_id",
    "x_mitre_domains",
    "revoked",
    "x_mitre_deprecated",
    "x_mitre_version",
    "created",
    "modified",
)

TECHNIQUE_FIELDS: Tuple[str, ...] = COMMON_FIELDS + (
    "x_mitre_platforms",
    "x_mitre_is_subtechnique",
    "x_mitre_contributors",
    "x_mitre_tactic_type",
    "x_mitre_impact_type",
    "x_mitre_remote_support",
)
MALWARE_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_aliases", "x_mitre_contributors", "is_family")
TOOL_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_aliases", "x_mitre_contributors")
INTRUSION_SET_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("aliases", "x_mitre_contributors")
CAMPAIGN_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("aliases", "first_seen", "last_seen", "x_mitre_contributors")
COURSE_OF_ACTION_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("labels",)
TACTIC_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_shortname",)
MATRIX_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # tactic_refs extracted to derived_relationships.json
ANALYTIC_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_mutable_elements")
DETECTION_STRATEGY_FIELDS: Tuple[str, ...] = COMMON_FIELDS  # x_mitre_analytic_refs extracted
DATA_COMPONENT_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_log_sources",)
DATA_SOURCE_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_collection_layers", "x_mitre_platforms", "x_mitre_contributors")
ASSET_FIELDS: Tuple[str, ...] = COMMON_FIELDS + ("x_mitre_platforms", "x_mitre_sectors", "x_mitre_related_assets")

RELATIONSHIP_PASSTHROUGH_FIELDS: Tuple[str, ...] = ("id", "type", "relationship_type", "source_ref", "target_ref", "description", "created", "modified")

FIELDS_BY_TYPE: Dict[str, Tuple[str, ...]] = {
    "attack-pattern": TECHNIQUE_FIELDS,
    "malware": MALWARE_FIELDS,
    "tool": TOOL_FIELDS,
    "intrusion-set": INTRUSION_SET_FIELDS,
    "campaign": CAMPAIGN_FIELDS,
    "course-of-action": COURSE_OF_ACTION_FIELDS,
    "x-mitre-tactic": TACTIC_FIELDS,
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
    # extra is folded into the seed because some derived edges (analytic -> data-component)
    # can legitimately repeat with the same (source, type, target) but different attributes
    # (e.g. two distinct log-source channels feeding the same data component).
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


def build_native_relationship(obj: Dict[str, Any]) -> Dict[str, Any]:
    return filter_object(obj, RELATIONSHIP_PASSTHROUGH_FIELDS)


def build_capec_relationships(obj: Dict[str, Any], attack_id: Optional[str]) -> List[Dict[str, Any]]:
    if not attack_id:
        return []
    relationships = []
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") != "capec":
            continue
        target_ref = ref.get("external_id")
        if not target_ref:
            continue
        relationships.append(make_relationship(attack_id, target_ref, EXTERNAL_RELATIONSHIP_TYPE, source_name="capec"))
    return relationships


def build_technique_tactic_relationships(
    obj: Dict[str, Any], attack_id: Optional[str], tactic_by_domain_shortname: Dict[Tuple[str, str], str]
) -> List[Dict[str, Any]]:
    if not attack_id:
        return []
    relationships = []
    for kill_chain_phase in obj.get("kill_chain_phases", []) or []:
        domain = KILL_CHAIN_NAME_TO_DOMAIN.get(kill_chain_phase.get("kill_chain_name"))
        phase_name = kill_chain_phase.get("phase_name")
        if not domain or not phase_name:
            continue
        tactic_attack_id = tactic_by_domain_shortname.get((domain, phase_name))
        if tactic_attack_id is None:
            raise ParseError(f"technique {attack_id} kill_chain_phase {phase_name!r} in domain {domain!r} matches no x-mitre-tactic shortname")
        relationships.append(make_relationship(attack_id, tactic_attack_id, HAS_TACTIC_RELATIONSHIP_TYPE))
    return relationships


def resolve_attack_id(stix_id: str, id_to_attack_id: Dict[str, str], context: str) -> str:
    attack_id = id_to_attack_id.get(stix_id)
    if attack_id is None:
        raise ParseError(f"{context} ref {stix_id!r} does not resolve to any known object with an attack_id")
    return attack_id


def build_matrix_relationships(obj: Dict[str, Any], attack_id: Optional[str], id_to_attack_id: Dict[str, str]) -> List[Dict[str, Any]]:
    if not attack_id:
        return []
    relationships = []
    for tactic_stix_id in obj.get("tactic_refs", []) or []:
        target_ref = resolve_attack_id(tactic_stix_id, id_to_attack_id, f"matrix {attack_id} tactic_refs")
        relationships.append(make_relationship(attack_id, target_ref, HAS_MEMBER_RELATIONSHIP_TYPE))
    return relationships


def build_detection_strategy_relationships(obj: Dict[str, Any], attack_id: Optional[str], id_to_attack_id: Dict[str, str]) -> List[Dict[str, Any]]:
    if not attack_id:
        return []
    relationships = []
    for analytic_stix_id in obj.get("x_mitre_analytic_refs", []) or []:
        target_ref = resolve_attack_id(analytic_stix_id, id_to_attack_id, f"detection-strategy {attack_id} x_mitre_analytic_refs")
        relationships.append(make_relationship(attack_id, target_ref, HAS_ANALYTIC_RELATIONSHIP_TYPE))
    return relationships


def build_analytic_relationships(obj: Dict[str, Any], attack_id: Optional[str], id_to_attack_id: Dict[str, str]) -> List[Dict[str, Any]]:
    if not attack_id:
        return []
    relationships = []
    for log_source in obj.get("x_mitre_log_source_references", []) or []:
        data_component_stix_id = log_source.get("x_mitre_data_component_ref")
        if not data_component_stix_id:
            continue
        target_ref = resolve_attack_id(data_component_stix_id, id_to_attack_id, f"analytic {attack_id} x_mitre_log_source_references")
        extra: Dict[str, Any] = {}
        if log_source.get("name"):
            extra["log_source_name"] = log_source["name"]
        if log_source.get("channel"):
            extra["channel"] = log_source["channel"]
        relationships.append(make_relationship(attack_id, target_ref, USES_DATA_COMPONENT_RELATIONSHIP_TYPE, **extra))
    return relationships


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    id_to_attack_id: Dict[str, str] = {}
    for obj in objects:
        if obj.get("type") in FIELDS_BY_TYPE:
            attack_id = extract_attack_id(obj)
            if attack_id:
                id_to_attack_id[obj["id"]] = attack_id

    tactic_by_domain_shortname: Dict[Tuple[str, str], str] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        attack_id = id_to_attack_id.get(obj["id"])
        if not attack_id:
            continue
        for domain in obj.get("x_mitre_domains", []) or []:
            tactic_by_domain_shortname[(domain, obj.get("x_mitre_shortname"))] = attack_id

    result: Dict[str, List[Dict[str, Any]]] = {obj_type: [] for obj_type in FIELDS_BY_TYPE}
    result[RELATIONSHIP_KEY] = []
    result[DERIVED_RELATIONSHIP_KEY] = []
    result[EXTERNAL_RELATIONSHIP_KEY] = []
    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")

        if obj_type == RELATIONSHIP_KEY:
            result[RELATIONSHIP_KEY].append(build_native_relationship(obj))
            continue

        if obj_type in BOILERPLATE_TYPES:
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        fields = FIELDS_BY_TYPE.get(obj_type)
        if fields is None:
            print(f"[mitre-attack-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        attack_id = id_to_attack_id.get(obj["id"])
        record = filter_object(obj, fields)
        if attack_id:
            record["attack_id"] = attack_id
        result[obj_type].append(record)

        if obj_type == "attack-pattern":
            result[EXTERNAL_RELATIONSHIP_KEY].extend(build_capec_relationships(obj, attack_id))
            result[DERIVED_RELATIONSHIP_KEY].extend(build_technique_tactic_relationships(obj, attack_id, tactic_by_domain_shortname))
        elif obj_type == "x-mitre-matrix":
            result[DERIVED_RELATIONSHIP_KEY].extend(build_matrix_relationships(obj, attack_id, id_to_attack_id))
        elif obj_type == "x-mitre-detection-strategy":
            result[DERIVED_RELATIONSHIP_KEY].extend(build_detection_strategy_relationships(obj, attack_id, id_to_attack_id))
        elif obj_type == "x-mitre-analytic":
            result[DERIVED_RELATIONSHIP_KEY].extend(build_analytic_relationships(obj, attack_id, id_to_attack_id))

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
