"""CVE field-projection preprocessor. Full rationale in README.md.

Reads the CVE crawler's per-year STIX 2.1 bundles
(`data-acquisition/CVE/records/<year>/latest.json`) and combines them into two
files: `entities.json` (the vulnerabilities) and `relationships.json` (their CWE
classifications). Every object in these bundles is a STIX `vulnerability`, so
this is the one source whose entity file holds a single kind.

Records are keyed by their CVE id (`name`, e.g. `CVE-1999-0001`), the same
convention CAPEC uses; the STIX id moves to `stix_id` and the now-redundant
`name` is dropped. No edge ever referenced the STIX id, so this is a pure rename.

Dropped entirely: `external_references` (a self-reference plus bibliographic
advisory URLs -- none point at an entity in any bundle), `x_nvd_configurations`
(CPE applicability -- a nested AND/OR tree over 3.1M `cpeMatch` entries, with no
lossless flat edge to extract), and `Rejected` records (NVD leaves them as empty
shells with no CVSS, CWEs or configurations).

`x_nvd_weaknesses` becomes `CVE-N --related-to--> CWE-N` edges, the reverse of
CWE's own edges; NVD's fallback labels (`NVD-CWE-noinfo`/`-Other`) aren't catalog
entries and are dropped.

`x_nvd_cvss` is folded onto the vulnerability as `cvss_`/`ssvc_`-prefixed
properties rather than becoming nodes: an earlier pass cost one node and one edge
per assessment (593,945 of each) to model something the CVE -> ... -> D3FEND
trace never passes through and that is only ever read as a filter or sort key.
`cvss_rank` picks a winner by version precedence (4.0 > 3.1 > 3.0 > 2.0), then
`Primary` over `Secondary`, then base score, then input position -- a total order
over the record's own fields, so reruns are byte-identical. Disagreement isn't
discarded: `cvss_assessment_count` counts distinct `(version, vector, score)`
claims within the winner's major version, and `cvss_base_score_min`/`_max` bracket
the spread when that exceeds one. SSVC contributes only its three decision points,
from the newest assessment by timestamp.

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

EXTERNAL_RELATIONSHIP_TYPE = "related_to"
EXTERNAL_RELATIONSHIP_SOURCE_NAME = "cwe"
REAL_CWE_PREFIX = "CWE-"

EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

# CVSS v4.0 environmental overrides: verified NOT_DEFINED on every v4.0 entry in this
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

# Fields that restate something else on the same record: every enum metric is spelled out
# in `vectorString`, `baseSeverity` is a band table over `baseScore`, and
# `exploitabilityScore`/`impactScore` are published formulas over the vector's metrics.
# Verified by reconstructing all three from `vectorString`/`baseScore` alone -- 0
# mismatches across 194,545 v2, 359,055 v3 and 29,426 v4 records. (v2's five NVD-specific
# booleans have no vector representation, so they are kept -- see CVSS_V2_KEPT_FIELDS.)
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
# family bounds what disagreement is measured within: v3.0 and v3.1 read the same scale
# slightly differently, whereas v2 and v3 are different scales entirely.
CVSS_METRIC_CONFIG: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    "cvssMetricV2": ("v2", CVSS_V2_DERIVED_FIELDS),
    "cvssMetricV30": ("v3", CVSS_V3_DERIVED_FIELDS),
    "cvssMetricV31": ("v3", CVSS_V3_DERIVED_FIELDS),
    "cvssMetricV40": ("v4", CVSS_V4_ENVIRONMENTAL_FIELDS + CVSS_V4_DERIVED_FIELDS),
}

# Newer standard wins. v2 has been deprecated since 2019; v3.1 supersedes v3.0.
CVSS_VERSION_PRECEDENCE: Dict[str, int] = {"4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1}

PRIMARY_ASSESSMENT = "Primary"

# What an assessment asserts, independent of who asserted it -- two agreeing on all three
# say the same thing, only the name on it differs.
CVSS_CLAIM_FIELDS: Tuple[str, ...] = ("version", "vector_string", "base_score")

# Carried onto the vulnerability from the winning assessment, `cvss_`-prefixed.
CVSS_KEPT_FIELDS: Tuple[str, ...] = ("version", "base_score", "vector_string", "source", "assessment_type")

# v2-only NVD additions absent from the vector string, so unlike the enum metrics they
# can't be recomputed and are kept when a v2 assessment wins.
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

# SSVC's three decision points. The rest of the assessment (`source`, `role`, `version`,
# `timestamp`) is scoring-process metadata, not a fact about the CVE.
SSVC_KEPT_FIELDS: Tuple[str, ...] = ("exploitation", "automatable", "technical_impact")

# Upstream free text carries CRLF endings, non-breaking spaces, tabs and the indentation
# of the document it was serialized from. None of it is content, all of it survives
# verbatim into the output and breaks string matching, so `clean_text()` normalizes it away.
COLLAPSIBLE_SPACE_PATTERN = re.compile(r"[\u00a0\u2007\u202f\ufeff\t]")
HORIZONTAL_RUN_PATTERN = re.compile(r"[^\S\n]{2,}")
BLANK_LINE_RUN_PATTERN = re.compile(r"\n{3,}")
SOFT_WRAP_PATTERN = re.compile(r"(?<!\n)\n(?!\n)")

# No value here is dropped as a sentinel: NVD's own "none" (SSVC `exploitation`, CVSS
# impact metrics) is a real enum member, not an absent-value marker.
ABSENT_VALUE_SENTINELS: frozenset = frozenset()

ENTITIES_FILENAME = "entities.json"
RELATIONSHIPS_FILENAME = "relationships.json"

# Which `parse()` result keys hold edges; the rest hold entities. Keys stay per-kind so
# the run summary can report a breakdown, but they no longer map to a file each.
RELATIONSHIP_KEYS: Tuple[str, ...] = (EXTERNAL_RELATIONSHIP_KEY,)


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


def read_collected_at(manifest_path: Path) -> str | None:
    """When the acquisition layer last fetched this source, read from its manifest.

    Deliberately the *crawl* time and not this run's wall clock. Stamping records with
    the moment preprocessing happened to run would make every rerun differ, and
    byte-identical reruns are what lets a checksum tell "the source changed" apart from
    "I ran it again". This value only moves when the crawler actually refetched."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        print(f"[cve-parser] warning: no readable manifest at {manifest_path}; records get no collected_at", file=sys.stderr)
        return None
    collected_at = manifest.get("last_successful_fetch") or manifest.get("generated_at")
    if not collected_at:
        print(f"[cve-parser] warning: {manifest_path.name} has no fetch timestamp; records get no collected_at", file=sys.stderr)
    return collected_at


# Stamped onto every record by `stamp_provenance()`. Required by TRACE §3.2.4, and
# what entity alignment keys on to tell same-named nodes from different catalogs apart.
SOURCE = "cve"


def stamp_provenance(record: Dict[str, Any], collected_at: str | None) -> Dict[str, Any]:
    """Add this catalog's name and its crawl time to a finished record. Applied last --
    after `clean_record()` and any relationship collapse -- so field order stays stable and
    the value is never mistaken for a source field that differs across merged records.

    `source` answers "which catalog asserted this record", and every record carries one.
    It is deliberately not the same thing as the `source_name` a few links carry, which
    names the *foreign* catalog a cross-catalog link points at: on a CVE link,
    `source: "cve"` says NVD asserted it and `source_name: "cwe"` says the target is a CWE.

    Today the value is derivable from the record's kind -- measured against the loaded
    graph, no node label and no relationship shape is claimed by two catalogs, because
    cross-catalog restatements are already deduplicated upstream. It is stamped anyway for
    two reasons. TRACE requires it outright (§3.2.4), and entity alignment keys on it: the
    moment nodes start arriving from unstructured text, two records of the same type and
    similar description have nothing else to tell them apart by."""
    record["source"] = SOURCE
    if collected_at:
        record["collected_at"] = collected_at
    return record


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
    record.update({field: obj[field] for field in VULNERABILITY_FIELDS if field in obj})
    return record


def build_weakness_relationships(obj: Dict[str, Any], cve_id: str) -> List[Dict[str, Any]]:
    return [
        make_relationship(cve_id, weakness, EXTERNAL_RELATIONSHIP_TYPE, source_name=EXTERNAL_RELATIONSHIP_SOURCE_NAME)
        for weakness in obj.get("x_nvd_weaknesses", [])
        if str(weakness).startswith(REAL_CWE_PREFIX)
    ]


def snake_case(name: str) -> str:
    """NVD's CVSS/SSVC names are camelCase (`baseScore`) with a few PascalCase
    supplemental metrics (`Automatable`); every other source here emits snake_case.
    Verified that no two source names collapse onto the same snake_case name."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def normalize_keys(flat: Dict[str, Any]) -> Dict[str, Any]:
    return {snake_case(key): value for key, value in flat.items()}


def flatten_cvss_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a cvssMetricV*[] entry with its nested cvssData into one flat dict. `type`
    (Primary/Secondary) becomes `assessment_type` so it can't collide with the
    vulnerability's own `type` discriminator once folded on."""
    flat: Dict[str, Any] = {}
    for key, value in entry.items():
        if key != "cvssData":
            flat["assessment_type" if key == "type" else key] = value
    flat.update(entry.get("cvssData") or {})
    return normalize_keys(flat)


def flatten_ssvc_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Merge a ssvcV203[] entry with its nested ssvcData (and that field's own options[]
    list of single-key decision points) into one flat dict."""
    flat: Dict[str, Any] = {key: value for key, value in entry.items() if key != "ssvcData"}
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
    """Flatten every cvssMetricV*[] entry on one CVE, dropping the derived fields and
    tagging each with its major-version family. Returned in `CVSS_METRIC_CONFIG` order,
    which is fixed, so ties below break the same way on every run."""
    flattened: List[Tuple[str, Dict[str, Any]]] = []
    for metric_key, (family, drop_fields) in CVSS_METRIC_CONFIG.items():
        for entry in cvss.get(metric_key) or []:
            flat = flatten_cvss_entry(entry)
            for field in drop_fields:
                flat.pop(snake_case(field), None)  # flatten_cvss_entry already normalized the keys
            flattened.append((family, flat))
    return flattened


def cvss_rank(candidate: Tuple[str, Dict[str, Any]]) -> Tuple[int, int, float]:
    """Newer standard first, then NVD's Primary over a CNA's Secondary, then the higher
    base score. `max()` keeps the first of equal ranks, so a full tie resolves to the
    earliest position in the raw input."""
    _, flat = candidate
    base_score = flat.get("base_score")
    return (
        CVSS_VERSION_PRECEDENCE.get(str(flat.get("version")), 0),
        1 if flat.get("assessment_type") == PRIMARY_ASSESSMENT else 0,
        float(base_score) if isinstance(base_score, (int, float)) else -1.0,
    )


def fold_cvss(cvss: Dict[str, Any]) -> Dict[str, Any]:
    """Collapse every CVSS assessment on one CVE into flat `cvss_`-prefixed properties:
    the winner's own fields, plus a summary of how much the assessments of that same
    major version disagreed."""
    candidates = flatten_all_cvss_entries(cvss)
    if not candidates:
        return {}

    winner_family, winner = max(candidates, key=cvss_rank)
    family = [flat for family_name, flat in candidates if family_name == winner_family]
    claims = {tuple(flat.get(field) for field in CVSS_CLAIM_FIELDS) for flat in family}

    folded = {f"{CVSS_PREFIX}{field}": winner[field] for field in CVSS_KEPT_FIELDS if field in winner}
    folded[f"{CVSS_PREFIX}assessment_count"] = len(claims)

    if len(claims) > 1:
        scores = [flat["base_score"] for flat in family if isinstance(flat.get("base_score"), (int, float))]
        if scores:
            folded[f"{CVSS_PREFIX}base_score_min"] = min(scores)
            folded[f"{CVSS_PREFIX}base_score_max"] = max(scores)

    if winner_family == "v2":
        folded.update({f"{CVSS_PREFIX}{field}": winner[field] for field in CVSS_V2_KEPT_FIELDS if field in winner})
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
    result: Dict[str, List[Dict[str, Any]]] = {"vulnerability": [], EXTERNAL_RELATIONSHIP_KEY: []}

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
            reason = f"vuln_status={vuln_status}"
            dropped_counts[reason] = dropped_counts.get(reason, 0) + 1
            continue

        cve_id = str(obj.get("name") or "")
        if not cve_id:
            # every record upstream carries one, but an id-less node would silently
            # collide with the next id-less node at load time rather than fail loudly
            dropped_counts["no CVE id"] = dropped_counts.get("no CVE id", 0) + 1
            continue

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


def write_outputs(result: Dict[str, List[Dict[str, Any]]], output_dir: Path, collected_at: str | None) -> Dict[str, int]:
    """Write every entity record to entities.json and every edge to relationships.json,
    concatenated in `result`'s own insertion order so reruns are byte-stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files: Dict[str, List[Dict[str, Any]]] = {ENTITIES_FILENAME: [], RELATIONSHIPS_FILENAME: []}
    for key, records in result.items():
        target = RELATIONSHIPS_FILENAME if key in RELATIONSHIP_KEYS else ENTITIES_FILENAME
        files[target].extend(clean_record(record) for record in records)
    for filename, records in files.items():
        with (output_dir / filename).open("w", encoding="utf-8") as handle:
            json.dump([stamp_provenance(record, collected_at) for record in records], handle, indent=2)
            handle.write("\n")
    return {key: len(records) for key, records in result.items()}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir.parent.parent / "data-acquisition" / "CVE" / "records"

    parser = argparse.ArgumentParser(description="Trim CVE's per-year STIX bundles down to a fixed field whitelist")
    parser.add_argument("--input", default=str(default_input), help=f"Path to the CVE crawler's records directory (default: {default_input})")
    parser.add_argument("--output-dir", default=str(script_dir), help=f"Directory to write entities.json / relationships.json (default: {script_dir})")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    output_dir = Path(args.output_dir)

    try:
        result = parse(load_objects(Path(args.input)))
        collected_at = read_collected_at(Path(args.input).parent / "manifest.json")
        counts = write_outputs(result, output_dir, collected_at)
        print(
            f"[cve-parser] wrote {counts['vulnerability']} vulnerabilities to {ENTITIES_FILENAME} "
            f"and {counts[EXTERNAL_RELATIONSHIP_KEY]} relationships (all external, to CWE) "
            f"to {RELATIONSHIPS_FILENAME}, in {output_dir}"
        )
        return 0
    except (ParseError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
