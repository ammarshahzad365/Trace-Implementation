"""CVE field-projection preprocessor.

Reads the raw STIX 2.1 bundles produced by the CVE crawler
(`data-acquisition/CVE/records/<year>/latest.json`, one bundle per year) and
writes a fully flattened, relationship-linked set of JSON files. Unlike
CWE/CAPEC, the CVE crawler shards its output by year rather than writing one
combined `latest.json`, so this script reads every `records/<year>/latest.json`
and combines them into a single set of outputs.

Every object in these bundles is a STIX `vulnerability` record built by
`cve_to_stix()` in `data-acquisition/CVE/client.py`.

## Id: the CVE name, not the STIX id

`vulnerabilities.json` records are keyed by their CVE id (`name`, e.g.
`"CVE-1999-0001"`) -- the same convention CAPEC uses for its own `CAPEC-N`
ids -- not by the STIX `vulnerability--<uuid>` id the raw bundle assigns.
The original STIX id is kept alongside as `stix_id`; the now-redundant
`name` field itself is dropped (same call as CAPEC dropping its redundant
`capec_id` once `id` became `CAPEC-N`). No relationship in this dataset
ever referenced the STIX id in the first place -- `external_relationships.json`
already keyed off `name` -- so this is a pure rename, not a rewrite of any
edge.

## Fields dropped entirely

- `external_references`: its first entry is always a self-reference
  (`source_name: "cve"`, `external_id` equal to the record's own `name`) and
  the rest are bibliographic advisory/patch URLs whose `source_name` is the
  submitting org, not a catalog id -- none of them point at another entity
  in this or any other bundle, so the field is dropped entirely (the same
  treatment CWE gives its own `References`/`Notes` fields).
- `x_nvd_configurations` (CPE applicability data): dropped entirely. Unlike
  every other relationship-shaped field in this project, it isn't a flat
  edge list -- it's a nested AND/OR boolean tree over 3.1M `cpeMatch`
  entries across 427K distinct CPE criteria strings -- so there is no
  lossless flat (source_ref, target_ref) edge to extract, and it is out of
  scope for this pass.
- Records with `x_nvd_vuln_status == "Rejected"` are dropped outright: NVD
  leaves these as empty shells (no CVSS, no CWEs, no configurations, and a
  description of just `"Rejected reason: ..."`), so they carry no
  vulnerability data worth preprocessing.

`x_nvd_weaknesses` (the CVE's CWE classification) is extracted into
`external_relationships.json` as `CVE-N --related-to--> CWE-N` edges, the
reverse direction of CWE's own `CWE-N --related-to--> CVE-N` edges (from
`RelatedWeaknesses`/`ObservedExamples` in `cwe_preprocessing.py`). Only real
`CWE-N` ids are extracted; NVD-only fallback labels (`NVD-CWE-noinfo`,
`NVD-CWE-Other`) aren't real catalog entries and are dropped, not extracted
or kept as an attribute.

## `x_nvd_cvss` is fully unnested into its own entity files

`x_nvd_cvss` is a container keyed by up to five metric-version names
(`cvssMetricV2`, `cvssMetricV30`, `cvssMetricV31`, `cvssMetricV40`,
`ssvcV203`), each a *list* of scored assessments, each of which nests its
own `cvssData`/`ssvcData` object one level deeper. None of that survives in
`vulnerabilities.json` -- the whole field is removed from the vulnerability
record and rebuilt as flat entities plus `has_cvss_v2_score` /
`has_cvss_v3_score` / `has_cvss_v4_score` / `has_ssvc_assessment` edges in
`relationships.json`:

- `cvssMetricV2` -> `cvss_v2_scores.json`. Each entry's own fields and its
  nested `cvssData` fields are merged into one flat record -- no collision,
  since v2's `baseSeverity` is the entry's own sibling field while
  `cvssData` never repeats it. What survives the derived-field pass below:
  `source`, `assessment_type`, `version`, `vectorString`, `baseScore`, and
  the five NVD booleans that have no vector representation (`acInsufInfo`,
  `obtainAllPrivilege`, `obtainOtherPrivilege`, `obtainUserPrivilege`,
  `userInteractionRequired`). The entry's own `type`
  (`Primary`/`Secondary`) is renamed `assessment_type` to avoid colliding
  with the record's own `type: "cvss-v2-score"` discriminator.
- `cvssMetricV30` / `cvssMetricV31` -> `cvss_v3_scores.json`, combined into
  one file: the two versions have an identical shape and only ever differ in
  `version`'s own value (`"3.0"` vs `"3.1"`), which stays on the flattened
  record to disambiguate. Surviving fields: `source`, `assessment_type`,
  `version`, `vectorString`, `baseScore`.
- `cvssMetricV40` -> `cvss_v4_scores.json`. Surviving fields: `source`,
  `assessment_type`, `version`, `vectorString`, `baseScore`. The 14
  environmental-override fields (`confidentialityRequirement`/
  `integrityRequirement`/`availabilityRequirement`,
  `modifiedAttackVector`/`modifiedAttackComplexity`/
  `modifiedAttackRequirements`/`modifiedPrivilegesRequired`/
  `modifiedUserInteraction`, `modifiedVulnConfidentialityImpact`/
  `modifiedVulnIntegrityImpact`/`modifiedVulnAvailabilityImpact`,
  `modifiedSubConfidentialityImpact`/`modifiedSubIntegrityImpact`/
  `modifiedSubAvailabilityImpact`) are dropped entirely -- verified
  `NOT_DEFINED` on all 29,426 v4.0 entries in this dataset, pure boilerplate
  NVD never customizes, the same treatment this project already gives other
  always-constant fields (e.g. mitre-attack's always-false
  `revoked`/`x_mitre_deprecated` on relationship records).
- `ssvcV203` -> `ssvc_assessments.json`. `source` plus `ssvcData`'s `role`,
  `version`, `timestamp` are kept flat; `ssvcData.id` (a redundant echo of
  the CVE's own id) is dropped; `ssvcData.options` -- a list of single-key
  objects, one per decision point (`exploitation`, `automatable`,
  `technicalImpact`) -- has each key merged directly onto the flat record
  instead of kept as a nested list.

## Three reductions on the score records

Severity was two-thirds of the loaded graph -- 746,387 score/assessment nodes
against 346,947 vulnerabilities, none of which the CVE -> CWE -> CAPEC ->
ATT&CK -> D3FEND trace ever traverses. Three rules cut that down without
losing anything that can't be recomputed:

1. **Derived fields are dropped** (`CVSS_V*_DERIVED_FIELDS`). Every enum
   metric is already spelled out in `vectorString`, `baseSeverity` is a band
   table over `baseScore`, and the two subscores are the published formulas
   over the vector. Verified reconstructible with 0 mismatches across all
   583,026 score records before removal. Node count unchanged; roughly a
   third of the property store.
2. **v2 scores are dropped where a v3 score exists on the same CVE**
   (`drop_superseded_v2`). v2 has been deprecated since 2019 and the loader's
   enrichment pass already ranks it below every v3, so those records were
   never the ones anything read. v2 is kept wherever it is the only
   assessment, which is 72,414 CVEs.
3. **Secondary scores that echo a Primary are dropped**
   (`drop_echoed_secondaries`). A CNA score asserting exactly what NVD's own
   Primary asserts spends a node and an edge recording agreement. One that
   *differs* is real scoring disagreement and is kept.

Rules 2 and 3 only ever remove a record that has a surviving sibling on the
same CVE, so no CVE loses its severity data outright.

Every score/assessment record gets a deterministic id
(`<entity-type>--<uuid5>`), seeded from the owning CVE id, the raw metric
key, the entry's position, and the entry's own flattened content -- reruns
against the same input produce byte-identical output, and a CVE with
multiple assessments of the same metric version (up to 4, e.g. NVD's
Primary alongside several CNA Secondary scores) still gets one distinct
record per assessment. The position in that seed is the entry's position in
the *raw* input list, so dropping a record under rules 2 and 3 never re-ids
the ones that survive alongside it.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

VULNERABILITY_FIELDS: Tuple[str, ...] = (
    "type",
    "spec_version",
    "created",
    "modified",
    "description",
    "x_nvd_vuln_status",
    "x_nvd_source_identifier",
)

DROPPED_VULN_STATUSES = {"Rejected"}

EXTERNAL_RELATIONSHIP_TYPE = "related-to"
EXTERNAL_RELATIONSHIP_SOURCE_NAME = "cwe"
REAL_CWE_PREFIX = "CWE-"

EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

# CVSS v4.0 environmental-override fields: verified NOT_DEFINED on every v4.0 entry in this
# dataset (NVD never customizes them), so they're dropped as pure boilerplate.
CVSS_V4_ENVIRONMENTAL_FIELDS: Tuple[str, ...] = (
    "confidentialityRequirement",
    "integrityRequirement",
    "availabilityRequirement",
    "modifiedAttackVector",
    "modifiedAttackComplexity",
    "modifiedAttackRequirements",
    "modifiedPrivilegesRequired",
    "modifiedUserInteraction",
    "modifiedVulnConfidentialityImpact",
    "modifiedVulnIntegrityImpact",
    "modifiedVulnAvailabilityImpact",
    "modifiedSubConfidentialityImpact",
    "modifiedSubIntegrityImpact",
    "modifiedSubAvailabilityImpact",
)

# Fields that are a lossless restatement of something else on the same record, so
# keeping them stores the same fact twice across 583,026 score records:
#
#   - every enum metric is spelled out in `vectorString` (`AV:N/AC:L/...`);
#   - `baseSeverity` is a fixed band table over `baseScore`;
#   - `exploitabilityScore`/`impactScore` are the published CVSS formulas over the
#     vector's own metrics.
#
# Verified before removal by reconstructing all three from `vectorString`/`baseScore`
# alone and diffing against NVD's own values: 0 mismatches on all 194,545 v2, 359,055
# v3 and 29,426 v4 records. For v4 the supplemental metrics are included too -- CVSS
# v4.0 omits a supplemental metric from the vector exactly when it is `NOT_DEFINED`,
# which is what 97%+ of them are.
#
# What is NOT dropped: v2's five NVD-specific booleans (`acInsufInfo`,
# `obtainAllPrivilege`, `obtainOtherPrivilege`, `obtainUserPrivilege`,
# `userInteractionRequired`) have no vector representation and are genuinely
# independent data.
CVSS_V2_DERIVED_FIELDS: Tuple[str, ...] = (
    "baseSeverity",
    "exploitabilityScore",
    "impactScore",
    "accessVector",
    "accessComplexity",
    "authentication",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
)

CVSS_V3_DERIVED_FIELDS: Tuple[str, ...] = (
    "baseSeverity",
    "exploitabilityScore",
    "impactScore",
    "attackVector",
    "attackComplexity",
    "privilegesRequired",
    "userInteraction",
    "scope",
    "confidentialityImpact",
    "integrityImpact",
    "availabilityImpact",
)

CVSS_V4_DERIVED_FIELDS: Tuple[str, ...] = (
    "baseSeverity",
    "attackVector",
    "attackComplexity",
    "attackRequirements",
    "privilegesRequired",
    "userInteraction",
    "vulnConfidentialityImpact",
    "vulnIntegrityImpact",
    "vulnAvailabilityImpact",
    "subConfidentialityImpact",
    "subIntegrityImpact",
    "subAvailabilityImpact",
    "exploitMaturity",
    "Safety",
    "Automatable",
    "Recovery",
    "valueDensity",
    "vulnerabilityResponseEffort",
    "providerUrgency",
)

# raw x_nvd_cvss key -> (entity type, relationship_type, fields to drop after flattening)
CVSS_METRIC_CONFIG: Dict[str, Tuple[str, str, Tuple[str, ...]]] = {
    "cvssMetricV2": ("cvss-v2-score", "has_cvss_v2_score", CVSS_V2_DERIVED_FIELDS),
    "cvssMetricV30": ("cvss-v3-score", "has_cvss_v3_score", CVSS_V3_DERIVED_FIELDS),
    "cvssMetricV31": ("cvss-v3-score", "has_cvss_v3_score", CVSS_V3_DERIVED_FIELDS),
    "cvssMetricV40": (
        "cvss-v4-score",
        "has_cvss_v4_score",
        CVSS_V4_ENVIRONMENTAL_FIELDS + CVSS_V4_DERIVED_FIELDS,
    ),
}

# Two records that agree on everything except these say the same thing about the
# vulnerability; the difference is only who said it.
ASSESSOR_FIELDS: Tuple[str, ...] = ("source", "assessment_type")

PRIMARY_ASSESSMENT = "Primary"

SSVC_METRIC_KEY = "ssvcV203"
SSVC_ENTITY_TYPE = "ssvc-assessment"
SSVC_RELATIONSHIP_TYPE = "has_ssvc_assessment"

CVSS_ENTITY_TYPES: Tuple[str, ...] = ("cvss-v2-score", "cvss-v3-score", "cvss-v4-score")

# entity type -> its edge type, derived from the config above so the two can't drift
CVSS_RELATIONSHIP_TYPES: Dict[str, str] = {
    entity_type: relationship_type
    for entity_type, relationship_type, _ in CVSS_METRIC_CONFIG.values()
}

OUTPUT_FILENAMES: Dict[str, str] = {
    "vulnerability": "vulnerabilities.json",
    "cvss-v2-score": "cvss_v2_scores.json",
    "cvss-v3-score": "cvss_v3_scores.json",
    "cvss-v4-score": "cvss_v4_scores.json",
    SSVC_ENTITY_TYPE: "ssvc_assessments.json",
    "relationship": "relationships.json",
    EXTERNAL_RELATIONSHIP_KEY: "external_relationships.json",
}


class ParseError(RuntimeError):
    pass


def load_objects(input_dir: Path) -> List[Dict[str, Any]]:
    """Read every records/<year>/latest.json under input_dir and combine their objects."""
    year_files = sorted(input_dir.glob("*/latest.json"))
    if not year_files:
        raise ParseError(f"No <year>/latest.json files found under {input_dir}")

    objects: List[Dict[str, Any]] = []
    for year_file in year_files:
        with year_file.open("r", encoding="utf-8") as handle:
            bundle = json.load(handle)
        bundle_objects = bundle.get("objects") if isinstance(bundle, dict) else None
        if not isinstance(bundle_objects, list):
            raise ParseError(f"Expected a bundle with an 'objects' list at {year_file}")
        objects.extend(obj for obj in bundle_objects if isinstance(obj, dict))
    return objects


def make_relationship(source_ref: str, target_ref: str, relationship_type: str, **extra: Any) -> Dict[str, Any]:
    seed = f"cve-preprocessing:{source_ref}|{relationship_type}|{target_ref}"
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


def build_vulnerability_record(obj: Dict[str, Any], cve_id: str) -> Dict[str, Any]:
    record: Dict[str, Any] = {"id": cve_id, "stix_id": obj["id"]}
    for field in VULNERABILITY_FIELDS:
        if field in obj:
            record[field] = obj[field]
    return record


def build_weakness_relationships(obj: Dict[str, Any], cve_id: str) -> List[Dict[str, Any]]:
    relationships = []
    for weakness in obj.get("x_nvd_weaknesses", []):
        if not str(weakness).startswith(REAL_CWE_PREFIX):
            continue
        relationships.append(
            make_relationship(cve_id, weakness, EXTERNAL_RELATIONSHIP_TYPE, source_name=EXTERNAL_RELATIONSHIP_SOURCE_NAME)
        )
    return relationships


def snake_case(name: str) -> str:
    """NVD's CVSS/SSVC field names are camelCase (`baseScore`, `vectorString`) with a
    few PascalCase supplemental metrics (`Automatable`, `Safety`); every other source
    in this project emits snake_case, so these are normalized to match. Verified after
    every run that no two source names collapse onto the same snake_case name."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def normalize_keys(flat: Dict[str, Any]) -> Dict[str, Any]:
    return {snake_case(key): value for key, value in flat.items()}


def flatten_cvss_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a cvssMetricV*[] entry's own fields with its nested cvssData fields into one
    flat dict. `type` (Primary/Secondary) is renamed `assessment_type` so it doesn't collide
    with the record's own `type` entity-kind discriminator."""
    flat: Dict[str, Any] = {}
    for key, value in entry.items():
        if key == "cvssData":
            continue
        flat["assessment_type" if key == "type" else key] = value
    for key, value in (entry.get("cvssData") or {}).items():
        flat[key] = value
    return normalize_keys(flat)


def flatten_ssvc_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a ssvcV203[] entry's own fields with its nested ssvcData fields (and that
    field's own options[] list of single-key decision points) into one flat dict."""
    flat: Dict[str, Any] = {}
    for key, value in entry.items():
        if key == "ssvcData":
            continue
        flat[key] = value
    for key, value in (entry.get("ssvcData") or {}).items():
        if key == "id":
            continue
        if key == "options":
            for option in value:
                flat.update(option)
            continue
        flat[key] = value
    return normalize_keys(flat)


def make_scored_entity(entity_type: str, cve_id: str, metric_key: str, index: int, flat: Dict[str, Any]) -> Dict[str, Any]:
    seed = f"cve-preprocessing:{entity_type}:{cve_id}|{metric_key}|{index}|{json.dumps(flat, sort_keys=True)}"
    entity_id = f"{entity_type}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"
    record: Dict[str, Any] = {"id": entity_id, "type": entity_type}
    record.update(flat)
    return record


def flatten_all_cvss_entries(cvss: Dict[str, Any]) -> Dict[str, List[Tuple[str, int, Dict[str, Any]]]]:
    """Flatten every cvssMetricV*[] entry on one CVE, dropping the derived fields, and
    group them by entity type. Both reduction rules compare an entry against its
    siblings on the same CVE, so none of them can be decided one entry at a time --
    hence a pass that materializes them all before any is turned into a record.

    Each entry keeps its position in the *raw* input list, which feeds the id seed, so
    dropping one never re-ids the ones that survive alongside it."""
    flattened: Dict[str, List[Tuple[str, int, Dict[str, Any]]]] = {
        entity_type: [] for entity_type in CVSS_ENTITY_TYPES
    }
    for metric_key, (entity_type, _, drop_fields) in CVSS_METRIC_CONFIG.items():
        for index, entry in enumerate(cvss.get(metric_key, [])):
            flat = flatten_cvss_entry(entry)
            for field in drop_fields:
                flat.pop(snake_case(field), None)  # flatten_cvss_entry already normalized the keys
            flattened[entity_type].append((metric_key, index, flat))
    return flattened


def assessment_payload(flat: Dict[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    """What this record asserts about the vulnerability, with the identity of the
    assessor removed. Keys are unique within a record, so sorting never has to
    compare two values of different types."""
    return tuple(sorted((key, value) for key, value in flat.items() if key not in ASSESSOR_FIELDS))


def drop_superseded_v2(
    flattened: Dict[str, List[Tuple[str, int, Dict[str, Any]]]]
) -> int:
    """CVSS v2 has been deprecated since 2019 and the loader's enrichment pass ranks it
    below every v3, so a v2 score on a CVE that also carries a v3 one is never the score
    anything reads -- it's kept only where it is genuinely the sole/fallback assessment.
    Returns how many were dropped."""
    if not flattened["cvss-v3-score"] or not flattened["cvss-v2-score"]:
        return 0
    dropped = len(flattened["cvss-v2-score"])
    flattened["cvss-v2-score"] = []
    return dropped


def drop_echoed_secondaries(
    flattened: Dict[str, List[Tuple[str, int, Dict[str, Any]]]]
) -> int:
    """A CNA `Secondary` score that asserts exactly what NVD's `Primary` already asserts
    adds a node and an edge to record agreement. Dropped; a Secondary that *differs* is
    real disagreement and is kept. Compared within one entity type, so a v3.0 Secondary
    can never be cancelled by a v3.1 Primary -- `version` is part of the payload.
    Returns how many were dropped."""
    dropped = 0
    for entity_type, items in flattened.items():
        primary_claims = {
            assessment_payload(flat)
            for _, _, flat in items
            if flat.get("assessment_type") == PRIMARY_ASSESSMENT
        }
        if not primary_claims:
            continue
        kept = []
        for item in items:
            flat = item[2]
            if flat.get("assessment_type") != PRIMARY_ASSESSMENT and assessment_payload(flat) in primary_claims:
                dropped += 1
                continue
            kept.append(item)
        flattened[entity_type] = kept
    return dropped


def build_cvss_and_ssvc(
    obj: Dict[str, Any], cve_id: str
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]], Dict[str, int]]:
    cvss = obj.get("x_nvd_cvss") or {}
    entities: Dict[str, List[Dict[str, Any]]] = {entity_type: [] for entity_type in CVSS_ENTITY_TYPES}
    entities[SSVC_ENTITY_TYPE] = []
    relationships: List[Dict[str, Any]] = []

    flattened = flatten_all_cvss_entries(cvss)
    dropped = {
        "cvss v2 scores superseded by a v3 score": drop_superseded_v2(flattened),
        "Secondary scores echoing a Primary": drop_echoed_secondaries(flattened),
    }

    for entity_type in CVSS_ENTITY_TYPES:
        relationship_type = CVSS_RELATIONSHIP_TYPES[entity_type]
        for metric_key, index, flat in flattened[entity_type]:
            entity = make_scored_entity(entity_type, cve_id, metric_key, index, flat)
            entities[entity_type].append(entity)
            relationships.append(make_relationship(cve_id, entity["id"], relationship_type))

    for index, entry in enumerate(cvss.get(SSVC_METRIC_KEY, [])):
        flat = flatten_ssvc_entry(entry)
        entity = make_scored_entity(SSVC_ENTITY_TYPE, cve_id, SSVC_METRIC_KEY, index, flat)
        entities[SSVC_ENTITY_TYPE].append(entity)
        relationships.append(make_relationship(cve_id, entity["id"], SSVC_RELATIONSHIP_TYPE))

    return entities, relationships, dropped


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {
        "vulnerability": [],
        "relationship": [],
        EXTERNAL_RELATIONSHIP_KEY: [],
    }
    for entity_type in CVSS_ENTITY_TYPES:
        result[entity_type] = []
    result[SSVC_ENTITY_TYPE] = []

    dropped_counts: Dict[str, int] = {}

    for obj in objects:
        obj_type = str(obj.get("type") or "")
        if obj_type != "vulnerability":
            print(f"[cve-parser] warning: skipping unexpected object type '{obj_type}'", file=sys.stderr)
            dropped_counts[obj_type] = dropped_counts.get(obj_type, 0) + 1
            continue

        vuln_status = str(obj.get("x_nvd_vuln_status") or "")
        if vuln_status in DROPPED_VULN_STATUSES:
            dropped_counts[f"vuln_status={vuln_status}"] = dropped_counts.get(f"vuln_status={vuln_status}", 0) + 1
            continue

        cve_id = str(obj.get("name") or "")
        result["vulnerability"].append(build_vulnerability_record(obj, cve_id))
        result[EXTERNAL_RELATIONSHIP_KEY].extend(build_weakness_relationships(obj, cve_id))

        entities, relationships, reduced = build_cvss_and_ssvc(obj, cve_id)
        for entity_type, records in entities.items():
            result[entity_type].extend(records)
        result["relationship"].extend(relationships)
        for reason, count in reduced.items():
            if count:
                dropped_counts[reason] = dropped_counts.get(reason, 0) + count

    dropped_summary = ", ".join(f"{count} {reason}" for reason, count in sorted(dropped_counts.items()))
    print(f"[cve-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
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
    default_input = script_dir.parent.parent / "data-acquisition" / "CVE" / "records"
    default_output_dir = script_dir

    parser = argparse.ArgumentParser(description="Trim CVE's per-year STIX bundles down to a fixed field whitelist")
    parser.add_argument(
        "--input",
        default=str(default_input),
        help=f"Path to the CVE crawler's records directory (default: {default_input})",
    )
    parser.add_argument(
        "--output-dir",
        default=str(default_output_dir),
        help=(
            "Directory to write vulnerabilities.json / cvss_v2_scores.json / cvss_v3_scores.json / "
            f"cvss_v4_scores.json / ssvc_assessments.json / relationships.json / external_relationships.json "
            f"(default: {default_output_dir})"
        ),
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
            "[cve-parser] wrote "
            f"{counts['vulnerability']} vulnerabilities, "
            f"{counts['cvss-v2-score']} CVSS v2 scores, "
            f"{counts['cvss-v3-score']} CVSS v3 scores, "
            f"{counts['cvss-v4-score']} CVSS v4 scores, "
            f"{counts[SSVC_ENTITY_TYPE]} SSVC assessments, "
            f"{counts['relationship']} relationships, "
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
