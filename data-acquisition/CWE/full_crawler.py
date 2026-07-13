"""Full CWE crawler.

Downloads MITRE's current CWE XML catalog, converts every Weakness, Category, and
View entry to a JSON record, compares it against the local snapshot, and rewrites
`latest.json` as the new full snapshot. Reports objects added, modified, or removed
relative to what was stored locally.
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
    existing_state = client.load_state(file_paths["latest"])

    root = client.fetch_catalog_xml(source_url, timeout=timeout, user_agent=user_agent)
    version_info = client.catalog_version(root)
    print(f"[cwe] parsing CWE catalog version {version_info['version']} ({version_info['date']})...")
    objects = client.catalog_to_records(root)
    print(f"[cwe] parsed {len(objects)} entries: {client.object_type_counts(objects)}")

    remote_state = client.normalize_objects(objects)
    print("[cwe] diffing against local snapshot...")
    diff = client.diff_states(existing_state, remote_state)
    latest_bundle = client.build_bundle(remote_state.values(), bundle_id=client.make_bundle_id("latest"))
    latest_modified = client.latest_modified_from_state(remote_state)
    last_successful_fetch = client.utc_now()

    result: Dict[str, Any] = {
        "mode": "full",
        "source_url": source_url,
        "cwe_version": version_info["version"],
        "cwe_content_date": version_info["date"],
        "object_type_counts": client.object_type_counts(objects),
        "local_object_count": len(existing_state),
        "remote_object_count": len(remote_state),
        "objects_added": len(diff["added"]),
        "objects_modified": len(diff["modified"]),
        "objects_removed": len(diff["removed"]),
        "latest_modified": latest_modified,
        "last_successful_fetch": last_successful_fetch,
    }

    file_status: Dict[str, str] = {}
    if not dry_run:
        print("[cwe] writing latest.json...")
        file_status["latest.json"] = client.write_json_file_tracked(file_paths["latest"], latest_bundle)
        if file_paths["delta"].exists():
            file_paths["delta"].unlink()
            file_status["delta.json"] = "removed"
        file_status["manifest.json"] = client.write_json_file_tracked(file_paths["manifest"], {
            "generated_at": last_successful_fetch,
            "source_url": source_url,
            "mode": "full",
            "last_successful_fetch": last_successful_fetch,
            "result": result,
            "dry_run": False,
        })

    result["files"] = file_status
    return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch the complete CWE catalog as JSON")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that will contain latest.json, delta.json, and manifest.json",
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
            mode="full",
            added=result["objects_added"],
            modified=result["objects_modified"],
            removed=result["objects_removed"],
            files=result["files"],
        ))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except client.SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
