"""Incremental ATT&CK crawler.

Fetches only objects added or modified since the previous successful fetch,
merges them into the latest snapshot, and writes a delta bundle for the run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Sequence

import client


def sync_domain(
    base_dir: Path,
    domain: str,
    collections: Sequence[Dict[str, Any]],
    timeout: int,
    user_agent: str,
    limit: int,
    dry_run: bool,
) -> Dict[str, Any]:
    paths = client.domain_paths(base_dir, domain)
    spec = client.pick_collection(domain, collections)
    existing_state = client.load_state(paths["latest"])
    previous_manifest = client.load_manifest(paths["manifest"])
    previous_domain_manifest = previous_manifest.get("collections", {}).get(domain, {}) if isinstance(previous_manifest, dict) else {}
    added_after = previous_domain_manifest.get("last_successful_fetch") if isinstance(previous_domain_manifest, dict) else None

    fetched_objects = client.fetch_collection_objects(
        api_root=client.DEFAULT_API_ROOT,
        collection_id=spec.collection_id,
        timeout=timeout,
        user_agent=user_agent,
        added_after=str(added_after) if added_after else None,
        limit=limit,
    )
    incoming_state = client.normalize_objects(obj for obj in fetched_objects if isinstance(obj, dict))
    merged_state = client.merge_latest(existing_state, incoming_state)
    delta_objects = client.compute_delta(existing_state, incoming_state)
    delta_ids = [str(obj.get("id")) for obj in delta_objects]
    added_ids = [obj_id for obj_id in delta_ids if obj_id not in existing_state]
    modified_ids = [obj_id for obj_id in delta_ids if obj_id in existing_state]
    latest_bundle = client.build_bundle(merged_state.values(), bundle_id=client.make_bundle_id(domain, "latest"))
    derived_bundle = client.build_bundle(client.filter_derived(merged_state.values(), domain), bundle_id=client.make_bundle_id(domain, "derived"))
    delta_bundle = client.build_bundle(delta_objects, bundle_id=client.make_bundle_id(domain, "delta"))
    latest_modified = client.latest_modified_from_state(merged_state)
    last_successful_fetch = client.utc_now()

    result = {
        "domain": domain,
        "mode": "incremental",
        "collection_id": spec.collection_id,
        "collection_name": spec.collection_name,
        "added_after": added_after,
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
        file_status["latest.json"] = client.write_json_file_tracked(paths["latest"], latest_bundle)
        file_status["derived.json"] = client.write_json_file_tracked(paths["derived"], derived_bundle)
        file_status["delta.json"] = client.write_json_file_tracked(paths["delta"], delta_bundle)
        file_status["manifest.json"] = client.write_json_file_tracked(paths["manifest"], {
            "generated_at": last_successful_fetch,
            "api_root": client.DEFAULT_API_ROOT,
            "mode": "incremental",
            "collections": {domain: result},
            "domains": [domain],
            "dry_run": False,
        })

    result["files"] = file_status
    return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch only added or modified MITRE ATT&CK objects")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that will contain the domain folders",
    )
    parser.add_argument(
        "--api-root",
        default=client.DEFAULT_API_ROOT,
        help=f"TAXII API root URL (default: {client.DEFAULT_API_ROOT})",
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        choices=sorted(client.DOMAIN_SPECS.keys()),
        default=sorted(client.DOMAIN_SPECS.keys()),
        help="Domains to sync",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=client.DEFAULT_LIMIT,
        help=f"Page size for TAXII object requests (default: {client.DEFAULT_LIMIT})",
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
        collections = client.fetch_collections(args.api_root, timeout=args.timeout, user_agent=args.user_agent)
        results: Dict[str, Any] = {}
        for domain in args.domains:
            results[domain] = sync_domain(
                base_dir=base_dir,
                domain=domain,
                collections=collections,
                timeout=args.timeout,
                user_agent=args.user_agent,
                limit=args.limit,
                dry_run=args.dry_run,
            )

        for domain, result in results.items():
            print(client.format_summary_line(
                domain=domain,
                mode="incremental",
                added=result["objects_added"],
                modified=result["objects_modified"],
                removed=None,
                files=result["files"],
            ))

        output = {
            "api_root": args.api_root,
            "domains": list(args.domains),
            "dry_run": bool(args.dry_run),
            "generated_at": client.utc_now(),
            "collections": results,
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except client.SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
