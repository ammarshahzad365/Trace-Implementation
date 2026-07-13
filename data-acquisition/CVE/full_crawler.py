"""Full CVE crawler.

Fetches the complete NVD CVE dataset, converts every record to STIX 2.1, and
rewrites the per-year snapshots. Reports which years had objects added,
modified, or removed compared to what was stored locally.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
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
    rate_limiter = client.make_rate_limiter(api_key)

    def on_page(page_index: int, page_count: int, total_results: int) -> None:
        print(f"[full] page {page_index}/{page_count} ({min(page_index * results_per_page, total_results)}/{total_results} CVEs fetched)")

    print("[full] starting fetch of all CVEs from NVD...")
    raw_records = client.fetch_cves(
        api_root=api_root,
        base_params={},
        api_key=api_key,
        timeout=timeout,
        user_agent=user_agent,
        results_per_page=results_per_page,
        rate_limiter=rate_limiter,
        max_pages=max_pages,
        on_page=on_page,
    )
    print(f"[full] fetched {len(raw_records)} raw CVE records, converting to STIX...")

    stix_objects = [client.cve_to_stix(record) for record in raw_records]
    grouped = client.group_by_year(stix_objects)
    print(f"[full] converted {len(stix_objects)} CVEs across {len(grouped)} year(s)")

    last_successful_fetch = client.utc_now()
    year_results: Dict[str, Any] = {}

    for year in sorted(grouped):
        print(f"[full] {year}: writing...")
        paths = client.year_paths(base_dir, year)
        existing_state = client.load_state(paths["latest"])
        remote_state = client.normalize_objects(grouped[year])
        diff = client.diff_states(existing_state, remote_state)
        latest_bundle = client.build_bundle(remote_state.values(), bundle_id=client.make_bundle_id(f"{year}:latest"))
        latest_modified = client.latest_modified_from_state(remote_state)

        result = {
            "year": year,
            "mode": "full",
            "local_object_count": len(existing_state),
            "remote_object_count": len(remote_state),
            "objects_added": len(diff["added"]),
            "objects_modified": len(diff["modified"]),
            "objects_removed": len(diff["removed"]),
            "latest_modified": latest_modified,
        }

        file_status: Dict[str, str] = {}
        if not dry_run:
            file_status["latest.json"] = client.write_json_file_tracked(paths["latest"], latest_bundle)
            if paths["delta"].exists():
                paths["delta"].unlink()
                file_status["delta.json"] = "removed"
        result["files"] = file_status
        year_results[str(year)] = result

    total_added = sum(r["objects_added"] for r in year_results.values())
    total_modified = sum(r["objects_modified"] for r in year_results.values())
    total_removed = sum(r["objects_removed"] for r in year_results.values())

    manifest = {
        "generated_at": last_successful_fetch,
        "api_root": api_root,
        "mode": "full",
        "last_successful_fetch": last_successful_fetch,
        "results_per_page": results_per_page,
        "total_object_count": sum(r["remote_object_count"] for r in year_results.values()),
        "total_objects_added": total_added,
        "total_objects_modified": total_modified,
        "total_objects_removed": total_removed,
        "years": year_results,
        "dry_run": bool(dry_run),
    }

    if not dry_run:
        client.write_json_file_tracked(client.manifest_path(base_dir), manifest)

    return manifest


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch the complete NVD CVE dataset as STIX 2.1")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that will contain the records/ folder and manifest.json",
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
        help="Stop after N pages (debug/testing knob; omit to fetch everything)",
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
                mode="full",
                added=result["objects_added"],
                modified=result["objects_modified"],
                removed=result["objects_removed"],
                files=result["files"],
            ))

        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    except client.SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
