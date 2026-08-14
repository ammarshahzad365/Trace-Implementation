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

## `x_nvd_cvss` is folded onto the vulnerability, not made into nodes

`x_nvd_cvss` is a container keyed by up to five metric-version names
(`cvssMetricV2`, `cvssMetricV30`, `cvssMetricV31`, `cvssMetricV40`,
`ssvcV203`), each a *list* of scored assessments, each of which nests its
own `cvssData`/`ssvcData` object one level deeper.

An earlier pass unnested all five into their own entity files plus
`has_cvss_v*_score` / `has_ssvc_assessment` edges. That cost one node and one
edge per assessment -- 593,945 of each against 346,947 vulnerabilities, so
severity was roughly two thirds of the loaded graph -- to model something the
CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND trace never traverses and that every
query only ever reads as a filter or a sort key (`WHERE v.cvss_base_score >=
9.0`). Deduplicating those nodes could not fix it: 82.7% of scored CVEs carry
exactly one assessment, so the count is driven by there being a node class at
all, not by redundancy within it.

So the whole container is now flattened onto the vulnerability record itself
as plain properties. Every field keeps a `cvss_` or `ssvc_` prefix naming the
scoring system it came from, so which properties belong to which system stays
readable on a record that also carries the CVE's own fields:

    cvss_version, cvss_base_score, cvss_vector_string, cvss_source,
    cvss_assessment_type, cvss_assessment_count
    cvss_base_score_min, cvss_base_score_max        (only when disputed)
    cvss_ac_insuf_info, cvss_obtain_all_privilege,  (only when v2 wins)
    cvss_obtain_other_privilege, cvss_obtain_user_privilege,
    cvss_user_interaction_required
    ssvc_exploitation, ssvc_automatable, ssvc_technical_impact

`cvss_*` and `ssvc_*` are both absent entirely on a CVE that was never scored
by that system, rather than present-and-null.

### Which assessment wins

A CVE can carry up to four assessments of the same metric version (NVD's own
`Primary` alongside several CNA `Secondary` scores) across up to four metric
versions. `select_cvss` ranks them by `CVSS_VERSION_PRECEDENCE` (4.0 > 3.1 >
3.0 > 2.0 -- the newer standard wins, and v2 has been deprecated since 2019),
then `Primary` over `Secondary`, then higher `base_score`, then earliest
position in the raw input. That ordering is total and reads only the record's
own fields, so reruns against the same input produce byte-identical output.

### Disagreement is summarised, not discarded

Picking one winner would otherwise silently drop the fact that NVD and a CNA
disagree, which is true of a sixth of scored CVEs. `cvss_assessment_count`
counts the *distinct* claims -- `(version, vector_string, base_score)` triples
-- made about this CVE, so a `Secondary` that merely echoes a `Primary`
counts once rather than twice, and `cvss_base_score_min`/`cvss_base_score_max`
bracket the spread whenever that count exceeds one.

Both are computed only over assessments sharing the winner's major version
(`CVSS_METRIC_CONFIG`'s family), because a v2 score and a v3 score of the same
CVE are readings on different scales -- their difference is a change of
standard, not a disagreement between assessors.

### SSVC

`ssvcV203` is CISA's Stakeholder-Specific Vulnerability Categorization, a
decision-tree triage rather than a numeric score. Only its three decision
points (`exploitation`, `automatable`, `technicalImpact`, nested one level
further inside `ssvcData.options[]` as a list of single-key objects) are
folded on; the assessment's `source`, `role`, `version` and `timestamp` are
dropped as scoring-process metadata. Where a CVE carries more than one SSVC
assessment (145 of them do), the newest by `timestamp` wins.
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
# keeping them stores the same fact twice:
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
# What is NOT dropped: v2's five NVD-specific booleans (see CVSS_V2_KEPT_FIELDS) have
# no vector representation and are genuinely independent data.
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

# raw x_nvd_cvss key -> (major-version family, fields to drop after flattening). The
# family is what disagreement is measured within: v3.0 and v3.1 are the same scale
# read slightly differently, whereas v2 and v3 are different scales entirely.
CVSS_METRIC_CONFIG: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "cvssMetricV2": ("v2", CVSS_V2_DERIVED_FIELDS),
    "cvssMetricV30": ("v3", CVSS_V3_DERIVED_FIELDS),
    "cvssMetricV31": ("v3", CVSS_V3_DERIVED_FIELDS),
    "cvssMetricV40": ("v4", CVSS_V4_ENVIRONMENTAL_FIELDS + CVSS_V4_DERIVED_FIELDS),
}

# Newer standard wins. v2 has been deprecated since 2019; v3.1 supersedes v3.0.
CVSS_VERSION_PRECEDENCE: Dict[str, int] = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}

PRIMARY_ASSESSMENT = "Primary"

# What a CVSS record asserts about the vulnerability, independent of who asserted it.
# Two assessments agreeing on all three say the same thing; the difference is only
# whose name is on it.
CVSS_CLAIM_FIELDS: Tuple[str, ...] = ("version", "vector_string", "base_score")

# Carried onto the vulnerability from the winning assessment, `cvss_`-prefixed.
CVSS_KEPT_FIELDS: Tuple[str, ...] = (
    "version",
    "base_score",
    "vector_string",
    "source",
    "assessment_type",
)

# v2-only NVD additions with no representation in the vector string, so unlike the
# enum metrics they can't be recomputed and are kept when a v2 assessment wins.
CVSS_V2_KEPT_FIELDS: Tuple[str, ...] = (
    "ac_insuf_info",
    "obtain_all_privilege",
    "obtain_other_privilege",
    "obtain_user_privilege",
    "user_interaction_required",
)

CVSS_PREFIX = "cvss_"

SSVC_METRIC_KEY = "ssvcV203"
SSVC_PREFIX = "ssvc_"

# SSVC's three decision points. Everything else on the assessment (`source`, `role`,
# `version`, `timestamp`) is scoring-process metadata, not a fact about the CVE.
SSVC_KEPT_FIELDS: Tuple[str, ...] = ("exploitation", "automatable", "technical_impact")

OUTPUT_FILENAMES: Dict[str, str] = {
    "vulnerability": "vulnerabilities.json",
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
    flat dict. `type` (Primary/Secondary) is renamed `assessment_type` so it doesn't
    collide with the vulnerability record's own `type` discriminator once folded on."""
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


def flatten_all_cvss_entries(cvss: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Flatten every cvssMetricV*[] entry on one CVE, dropping the derived fields, and
    tag each with its major-version family. Returned in `CVSS_METRIC_CONFIG` order,
    which is fixed, so the selection below breaks ties the same way on every run."""
    flattened: List[Tuple[str, Dict[str, Any]]] = []
    for metric_key, (family, drop_fields) in CVSS_METRIC_CONFIG.items():
        for entry in cvss.get(metric_key) or []:
            flat = flatten_cvss_entry(entry)
            for field in drop_fields:
                flat.pop(snake_case(field), None)  # flatten_cvss_entry already normalized the keys
            flattened.append((family, flat))
    return flattened


def cvss_rank(candidate: Tuple[str, Dict[str, Any]]) -> Tuple[int, int, float]:
    """Newer standard first, then NVD's own Primary over a CNA's Secondary, then the
    higher base score. `max()` keeps the first of equal ranks, so a full tie resolves
    to the earliest position in the raw input."""
    _, flat = candidate
    base_score = flat.get("base_score")
    return (
        CVSS_VERSION_PRECEDENCE.get(str(flat.get("version")), 0),
        1 if flat.get("assessment_type") == PRIMARY_ASSESSMENT else 0,
        float(base_score) if isinstance(base_score, (int, float)) else -1.0,
    )


def cvss_claim(flat: Dict[str, Any]) -> Tuple[Any, ...]:
    """What this assessment says about the vulnerability, with the assessor's identity
    removed -- so a Secondary echoing a Primary is one claim, not two."""
    return tuple(flat.get(field) for field in CVSS_CLAIM_FIELDS)


def fold_cvss(cvss: Dict[str, Any]) -> Dict[str, Any]:
    """Collapse every CVSS assessment on one CVE into a flat set of `cvss_`-prefixed
    properties: the winning assessment's own fields, plus a summary of how much the
    assessments of that same major version disagreed."""
    candidates = flatten_all_cvss_entries(cvss)
    if not candidates:
        return {}

    winner_family, winner = max(candidates, key=cvss_rank)
    family = [flat for family_name, flat in candidates if family_name == winner_family]
    claims = {cvss_claim(flat) for flat in family}

    folded = {
        f"{CVSS_PREFIX}{field}": winner[field] for field in CVSS_KEPT_FIELDS if field in winner
    }
    folded[f"{CVSS_PREFIX}assessment_count"] = len(claims)

    if len(claims) > 1:
        scores = [flat["base_score"] for flat in family if isinstance(flat.get("base_score"), (int, float))]
        if scores:
            folded[f"{CVSS_PREFIX}base_score_min"] = min(scores)
            folded[f"{CVSS_PREFIX}base_score_max"] = max(scores)

    if winner_family == "v2":
        folded.update(
            {f"{CVSS_PREFIX}{field}": winner[field] for field in CVSS_V2_KEPT_FIELDS if field in winner}
        )
    return folded


def fold_ssvc(cvss: Dict[str, Any]) -> Dict[str, Any]:
    """Collapse a CVE's SSVC assessments into three `ssvc_`-prefixed decision points,
    taken from the newest assessment by `timestamp`."""
    entries = cvss.get(SSVC_METRIC_KEY) or []
    if not entries:
        return {}
    newest = max(entries, key=lambda entry: str((entry.get("ssvcData") or {}).get("timestamp") or ""))
    flat = flatten_ssvc_entry(newest)
    return {f"{SSVC_PREFIX}{field}": flat[field] for field in SSVC_KEPT_FIELDS if field in flat}


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {
        "vulnerability": [],
        EXTERNAL_RELATIONSHIP_KEY: [],
    }

    dropped_counts: Dict[str, int] = {}
    folded_counts = {"with a CVSS score": 0, "with an SSVC assessment": 0, "with disputed CVSS scores": 0}

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
        record = build_vulnerability_record(obj, cve_id)

        cvss = obj.get("x_nvd_cvss") or {}
        folded_cvss = fold_cvss(cvss)
        folded_ssvc = fold_ssvc(cvss)
        record.update(folded_cvss)
        record.update(folded_ssvc)

        if folded_cvss:
            folded_counts["with a CVSS score"] += 1
            if folded_cvss[f"{CVSS_PREFIX}assessment_count"] > 1:
                folded_counts["with disputed CVSS scores"] += 1
        if folded_ssvc:
            folded_counts["with an SSVC assessment"] += 1

        result["vulnerability"].append(record)
        result[EXTERNAL_RELATIONSHIP_KEY].extend(build_weakness_relationships(obj, cve_id))

    dropped_summary = ", ".join(f"{count} {reason}" for reason, count in sorted(dropped_counts.items()))
    print(f"[cve-parser] parsed {len(objects)} objects; dropped {dropped_summary or 'nothing'}")
    print("[cve-parser] folded " + ", ".join(f"{count} {reason}" for reason, count in folded_counts.items()))
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
            "Directory to write vulnerabilities.json / external_relationships.json "
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
            f"{counts[EXTERNAL_RELATIONSHIP_KEY]} external relationships "
            f"to {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
