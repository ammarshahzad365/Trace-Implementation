"""Incremental CVE crawler.

Reads the last successful fetch time from manifest.json and fetches only CVEs
published or modified since then, merging them into the per-year snapshots and
writing a delta bundle for each affected year.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timezone
from pathlib import Path
from typing import Any, Dict, Sequence

import client


def sync_all(
    base_dir: Path,
    api_root: str,
    api_key: str | None,
    timeout: int,
    user_agent: str,
    results_per_page: int,
    max_pages: int | None,
    dry_run: bool,
) -> Dict[str, Any]:
    manifest = client.load_manifest(client.manifest_path(base_dir))
    last_successful_fetch = manifest.get("last_successful_fetch")
    if not last_successful_fetch:
        raise client.SyncError(
            "No previous successful fetch recorded in manifest.json. "
            "Run full_crawler.py at least once before incremental_crawler.py."
        )

    start = client.parse_stix_timestamp(str(last_successful_fetch))
    end = client.parse_stix_timestamp(client.utc_now())
    if start is None or end is None:
        raise client.SyncError("Unable to determine incremental fetch window")

    windows = client.date_windows(start, end)
    if not windows:
        print("[incremental] no time has elapsed since the last successful fetch; nothing to do")

    rate_limiter = client.make_rate_limiter(api_key)
    raw_records = []

    for window_index, (window_start, window_end) in enumerate(windows, start=1):
        print(f"[incremental] window {window_index}/{len(windows)}: {client.format_stix_timestamp(window_start)} -> {client.format_stix_timestamp(window_end)}")

        def on_page(page_index: int, page_count: int, total_results: int, _window_index: int = window_index) -> None:
            print(f"[incremental] window {_window_index} page {page_index}/{page_count} ({min(page_index * results_per_page, total_results)}/{total_results} CVEs fetched)")

        base_params = {
            "lastModStartDate": _nvd_param_timestamp(window_start),
            "lastModEndDate": _nvd_param_timestamp(window_end),
        }
        window_records = client.fetch_cves(
            api_root=api_root,
            base_params=base_params,
            api_key=api_key,
            timeout=timeout,
            user_agent=user_agent,
            results_per_page=results_per_page,
            rate_limiter=rate_limiter,
            max_pages=max_pages,
            on_page=on_page,
        )
        raw_records.extend(window_records)

    print(f"[incremental] fetched {len(raw_records)} raw CVE records, converting to STIX...")
    stix_objects = [client.cve_to_stix(record) for record in raw_records]
    incoming_state_all = client.normalize_objects(stix_objects)
    grouped = client.group_by_year(incoming_state_all.values())
    print(f"[incremental] converted {len(incoming_state_all)} CVEs across {len(grouped)} year(s)")

    last_run_timestamp = client.utc_now()
    year_results: Dict[str, Any] = {}

    for year in sorted(grouped):
        print(f"[incremental] {year}: writing...")
        paths = client.year_paths(base_dir, year)
        existing_state = client.load_state(paths["latest"])
        incoming_state = client.normalize_objects(grouped[year])
        merged_state = client.merge_latest(existing_state, incoming_state)
        delta_objects = client.compute_delta(existing_state, incoming_state)
        delta_ids = [str(obj.get("id")) for obj in delta_objects]
        added_ids = [obj_id for obj_id in delta_ids if obj_id not in existing_state]
        modified_ids = [obj_id for obj_id in delta_ids if obj_id in existing_state]
        latest_bundle = client.build_bundle(merged_state.values(), bundle_id=client.make_bundle_id(f"{year}:latest"))
        delta_bundle = client.build_bundle(delta_objects, bundle_id=client.make_bundle_id(f"{year}:delta:{last_run_timestamp}"))
        latest_modified = client.latest_modified_from_state(merged_state)

        result = {
            "year": year,
            "mode": "incremental",
            "existing_object_count": len(existing_state),
            "incoming_object_count": len(incoming_state),
            "latest_object_count": len(merged_state),
            "delta_object_count": len(delta_objects),
            "objects_added": len(added_ids),
            "objects_modified": len(modified_ids),
            "latest_modified": latest_modified,
        }

        file_status: Dict[str, str] = {}
        if not dry_run:
            file_status["latest.json"] = client.write_json_file_tracked(paths["latest"], latest_bundle)
            file_status["delta.json"] = client.write_json_file_tracked(paths["delta"], delta_bundle)
        result["files"] = file_status
        year_results[str(year)] = result

    total_added = sum(r["objects_added"] for r in year_results.values())
    total_modified = sum(r["objects_modified"] for r in year_results.values())

    new_manifest = {
        "generated_at": last_run_timestamp,
        "api_root": api_root,
        "mode": "incremental",
        "last_successful_fetch": last_run_timestamp if not dry_run else last_successful_fetch,
        "previous_fetch": last_successful_fetch,
        "results_per_page": results_per_page,
        "total_objects_added": total_added,
        "total_objects_modified": total_modified,
        "years": year_results,
        "dry_run": bool(dry_run),
    }

    if not dry_run:
        client.write_json_file_tracked(client.manifest_path(base_dir), new_manifest)

    return new_manifest


def _nvd_param_timestamp(value) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000") + "Z"


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch only CVEs added or modified since the last successful fetch")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that contains the records/ folder and manifest.json",
    )
    parser.add_argument(
        "--api-root",
        default=client.DEFAULT_API_ROOT,
        help=f"NVD CVE API root URL (default: {client.DEFAULT_API_ROOT})",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="NVD API key (defaults to NVD_API_KEY from .env or the environment)",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=client.DEFAULT_RESULTS_PER_PAGE,
        help=f"Page size for NVD requests (default: {client.DEFAULT_RESULTS_PER_PAGE})",
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
        "--max-pages",
        type=int,
        default=None,
        help="Stop after N pages per window (debug/testing knob)",
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

    client.load_dotenv(base_dir / ".env")
    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    try:
        manifest = sync_all(
            base_dir=base_dir,
            api_root=args.api_root,
            api_key=api_key,
            timeout=args.timeout,
            user_agent=args.user_agent,
            results_per_page=args.results_per_page,
            max_pages=args.max_pages,
            dry_run=args.dry_run,
        )

        for year_key, result in sorted(manifest["years"].items(), key=lambda item: int(item[0])):
            print(client.format_summary_line(
                year=int(year_key),
                mode="incremental",
                added=result["objects_added"],
                modified=result["objects_modified"],
                removed=None,
                files=result["files"],
            ))

        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    except client.SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
