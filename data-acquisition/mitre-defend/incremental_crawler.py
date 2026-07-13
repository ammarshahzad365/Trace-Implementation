"""Incremental D3FEND crawler.

D3FEND has no date-filtered "fetch what changed" endpoint, so this fetches the
same full dataset as full_crawler.py for each domain, but merges into the
existing local snapshot (never dropping records that disappeared from a single
fetch) and writes only the added/changed records to delta.json, using content
hashes to decide what changed since no object carries a native timestamp.
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
    api_root: str,
    domain: str,
    timeout: int,
    user_agent: str,
    now: str,
    dry_run: bool,
) -> Dict[str, Any]:
    paths = client.domain_paths(base_dir, domain)
    existing_state = client.load_state(paths["latest"], domain)

    payload = client.fetch_domain(api_root, domain, timeout=timeout, user_agent=user_agent)
    records = client.extract_records(payload, domain)
    incoming_raw = client.normalize_records(records, domain)
    incoming_state = client.stamp_records(incoming_raw, existing_state, now)

    merged_state = client.merge_latest(existing_state, incoming_state)
    delta_records = client.compute_delta(existing_state, incoming_state)
    delta_keys = {client.record_key(obj, domain) for obj in delta_records}
    added_keys = [key for key in delta_keys if key not in existing_state]
    modified_keys = [key for key in delta_keys if key in existing_state]

    snapshot = client.build_snapshot(merged_state.values(), domain)
    delta_snapshot = client.build_snapshot(delta_records, domain)

    result = {
        "domain": domain,
        "mode": "incremental",
        "existing_record_count": len(existing_state),
        "incoming_record_count": len(incoming_state),
        "latest_record_count": len(merged_state),
        "delta_record_count": len(delta_records),
        "records_added": len(added_keys),
        "records_modified": len(modified_keys),
        "last_successful_fetch": now,
    }

    file_status: Dict[str, str] = {}
    if not dry_run:
        file_status["latest.json"] = client.write_json_file_tracked(paths["latest"], snapshot)
        file_status["delta.json"] = client.write_json_file_tracked(paths["delta"], delta_snapshot)

    result["files"] = file_status
    return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fetch and merge only changed MITRE D3FEND records")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that will contain the domain folders",
    )
    parser.add_argument(
        "--api-root",
        default=client.DEFAULT_API_ROOT,
        help=f"D3FEND API root URL (default: {client.DEFAULT_API_ROOT})",
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        choices=sorted(client.DOMAIN_SPECS.keys()),
        default=sorted(client.DOMAIN_SPECS.keys()),
        help="Domains to sync",
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
        now = client.utc_now()
        version_info = client.fetch_version(args.api_root, timeout=args.timeout, user_agent=args.user_agent)

        results: Dict[str, Any] = {}
        for domain in args.domains:
            results[domain] = sync_domain(
                base_dir=base_dir,
                api_root=args.api_root,
                domain=domain,
                timeout=args.timeout,
                user_agent=args.user_agent,
                now=now,
                dry_run=args.dry_run,
            )

        for domain, result in results.items():
            print(client.format_summary_line(
                domain=domain,
                mode="incremental",
                added=result["records_added"],
                modified=result["records_modified"],
                removed=None,
                files=result["files"],
            ))

        previous_manifest = client.load_manifest(client.manifest_path(base_dir))
        previous_domains = previous_manifest.get("domains", {}) if isinstance(previous_manifest, dict) else {}
        merged_domains = {**previous_domains, **results}

        manifest = {
            "generated_at": now,
            "api_root": args.api_root,
            "mode": "incremental",
            "ontology_version": version_info.get("ontology_version"),
            "ontology_hash_sha256": version_info.get("ontology_hash_sha256"),
            "release_date": version_info.get("release_date"),
            "domains": merged_domains,
        }
        if not args.dry_run:
            client.write_json_file_tracked(client.manifest_path(base_dir), manifest)

        output = {
            "api_root": args.api_root,
            "domains": list(args.domains),
            "dry_run": bool(args.dry_run),
            "generated_at": now,
            "ontology_version": version_info.get("ontology_version"),
            "results": results,
        }
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except client.SyncError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
