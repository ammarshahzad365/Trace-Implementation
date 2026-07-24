"""CVE field-projection preprocessor.

Reads the raw STIX 2.1 bundles produced by the CVE crawler
(`data-acquisition/CVE/records/<year>/latest.json`, one bundle per year) and
writes two trimmed JSON files. Unlike CWE/CAPEC, the CVE crawler shards its
output by year rather than writing one combined `latest.json`, so this script
reads every `records/<year>/latest.json` and combines them into a single
output pair.

Every object in these bundles is a STIX `vulnerability` record built by
`cve_to_stix()` in `data-acquisition/CVE/client.py`. Three source fields are
dropped rather than kept or extracted:

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

`x_nvd_cvss` stays embedded as an attribute on the vulnerability record --
like CWE's `PotentialMitigations`/`DetectionMethods`, it's inherently
per-record scoring data, not a separately reusable entity.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

VULNERABILITY_FIELDS: Tuple[str, ...] = (
    "id",
    "type",
    "spec_version",
    "created",
    "modified",
    "name",
    "description",
    "x_nvd_vuln_status",
    "x_nvd_source_identifier",
    "x_nvd_cvss",
)

DROPPED_VULN_STATUSES = {"Rejected"}

EXTERNAL_RELATIONSHIP_TYPE = "related-to"
EXTERNAL_RELATIONSHIP_SOURCE_NAME = "cwe"
REAL_CWE_PREFIX = "CWE-"

EXTERNAL_RELATIONSHIP_KEY = "external-relationship"

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


def filter_object(obj: Dict[str, Any], fields: Tuple[str, ...]) -> Dict[str, Any]:
    return {field: obj[field] for field in fields if field in obj}


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


def build_weakness_relationships(obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    source_ref = str(obj.get("name") or "")
    relationships = []
    for weakness in obj.get("x_nvd_weaknesses", []):
        if not str(weakness).startswith(REAL_CWE_PREFIX):
            continue
        relationships.append(
            make_relationship(source_ref, weakness, EXTERNAL_RELATIONSHIP_TYPE, source_name=EXTERNAL_RELATIONSHIP_SOURCE_NAME)
        )
    return relationships


def parse(objects: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    result: Dict[str, List[Dict[str, Any]]] = {"vulnerability": [], EXTERNAL_RELATIONSHIP_KEY: []}
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

        result["vulnerability"].append(filter_object(obj, VULNERABILITY_FIELDS))
        result[EXTERNAL_RELATIONSHIP_KEY].extend(build_weakness_relationships(obj))

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
        help=f"Directory to write vulnerabilities.json / external_relationships.json (default: {default_output_dir})",
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
