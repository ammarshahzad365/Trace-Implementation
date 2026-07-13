"""Incremental CWE crawler.

CWE has no date-filtered fetch endpoint -- MITRE only publishes the full current
catalog. This crawler downloads that same full catalog (same network cost as the
full crawler), but instead of overwriting the local snapshot, it merges the fetch
into the existing `latest.json` and writes only the entries added or modified
since the last successful fetch to `delta.json`. "Modified" is judged per-entry
using each CWE's own Content_History (its real last-revision date), not just
whether the corpus version changed. Requires a prior run of `full_crawler.py`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Sequence

import client


def sync(
    base_dir: Path,
    source_url: str,
    timeout: int,
    user_agent: str,
    dry_run: bool,
) -> Dict[str, Any]:
    file_paths = client.paths(base_dir)
    manifest = client.load_manifest(file_paths["manifest"])
    previous_fetch = manifest.get("last_successful_fetch")
    if not previous_fetch:
        raise client.SyncError(
            "No previous successful fetch recorded in manifest.json. "
            "Run full_crawler.py at least once before incremental_crawler.py."
        )

    existing_state = client.load_state(file_paths["latest"])

    root = client.fetch_catalog_xml(source_url, timeout=timeout, user_agent=user_agent)
    version_info = client.catalog_version(root)
    print(f"[cwe] parsing CWE catalog version {version_info['version']} ({version_info['date']})...")
    objects = client.catalog_to_records(root)
    print(f"[cwe] parsed {len(objects)} entries: {client.object_type_counts(objects)}")

    incoming_state = client.normalize_objects(objects)
    print("[cwe] merging into local snapshot...")
    merged_state = client.merge_latest(existing_state, incoming_state)
    delta_objects = client.compute_delta(existing_state, incoming_state)
    delta_ids = [str(obj.get("id")) for obj in delta_objects]
    added_ids = [obj_id for obj_id in delta_ids if obj_id not in existing_state]
    modified_ids = [obj_id for obj_id in delta_ids if obj_id in existing_state]
    latest_bundle = client.build_bundle(merged_state.values(), bundle_id=client.make_bundle_id("latest"))
    delta_bundle = client.build_bundle(delta_objects, bundle_id=client.make_bundle_id(f"delta:{client.utc_now()}"))
    latest_modified = client.latest_modified_from_state(merged_state)
    last_successful_fetch = client.utc_now()

    result: Dict[str, Any] = {
        "mode": "incremental",
        "source_url": source_url,
        "cwe_version": version_info["version"],
        "cwe_content_date": version_info["date"],
        "object_type_counts": client.object_type_counts(objects),
        "previous_fetch": previous_fetch,
        "existing_object_count": len(existing_state),
        "incoming_object_count": len(incoming_state),
        "latest_object_count": len(merged_state),
        "delta_object_count": len(delta_objects),
        "objects_added": len(added_ids),
        "objects_modified": len(modified_ids),
        "latest_modified": latest_modified,
        "last_successful_fetch": last_successful_fetch,
    }

    file_status: Dict[str, str] = {}
    if not dry_run:
        print("[cwe] writing latest.json and delta.json...")
        file_status["latest.json"] = client.write_json_file_tracked(file_paths["latest"], latest_bundle)
        file_status["delta.json"] = client.write_json_file_tracked(file_paths["delta"], delta_bundle)
        file_status["manifest.json"] = client.write_json_file_tracked(file_paths["manifest"], {
            "generated_at": last_successful_fetch,
            "source_url": source_url,
            "mode": "incremental",
            "last_successful_fetch": last_successful_fetch,
            "result": result,
            "dry_run": False,
        })

    result["files"] = file_status
    return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch CWE and merge only what changed since the last successful fetch")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that contains latest.json, delta.json, and manifest.json",
    )
    parser.add_argument(
        "--source-url",
        default=client.DEFAULT_SOURCE_URL,
        help=f"CWE XML catalog URL (default: {client.DEFAULT_SOURCE_URL})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=client.DEFAULT_TIMEOUT_SECONDS,
        help=f"HTTP timeout in seconds (default: {client.DEFAULT_TIMEOUT_SECONDS})",
    )
    parser.add_argument(
        "--user-agent",
        default=client.DEFAULT_USER_AGENT,
        help=f"HTTP user agent string (default: {client.DEFAULT_USER_AGENT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and compare without writing output files",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    base_dir = Path(args.base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    try:
        result = sync(
            base_dir=base_dir,
            source_url=args.source_url,
            timeout=args.timeout,
            user_agent=args.user_agent,
            dry_run=args.dry_run,
        )

        print(client.format_summary_line(
            mode="incremental",
            added=result["objects_added"],
            modified=result["objects_modified"],
            removed=None,
            files=result["files"],
        ))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except client.SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
