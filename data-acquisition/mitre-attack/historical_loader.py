"""Historical ATT&CK loader.

Loads every versioned ATT&CK release already present in the workspace, stores a
local archive by domain, and seeds the latest/derived/manifest files so the full
crawler and incremental crawler can run afterward.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

import client

VERSIONED_FILE_PATTERN = re.compile(r"^(?P<domain>[a-z0-9-]+)-(?P<version>\d+(?:\.\d+)*)\.json$")


def version_key(version: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def discover_release_files(source_root: Path, domain: str) -> List[Tuple[str, Path]]:
    domain_source_dir = source_root / domain
    if not domain_source_dir.exists():
        raise client.SyncError(f"Missing source directory for {domain}: {domain_source_dir}")

    releases: List[Tuple[str, Path]] = []
    for path in domain_source_dir.glob("*.json"):
        if path.name == f"{domain}.json":
            continue
        match = VERSIONED_FILE_PATTERN.match(path.name)
        if not match or match.group("domain") != domain:
            continue
        releases.append((match.group("version"), path))

    releases.sort(key=lambda item: version_key(item[0]))
    if not releases:
        raise client.SyncError(f"No versioned ATT&CK releases found for {domain} in {domain_source_dir}")
    return releases


def load_bundle(path: Path) -> Dict[str, Any]:
    payload = client.load_json_file(path, default=None)
    if not isinstance(payload, dict):
        raise client.SyncError(f"Invalid STIX bundle at {path}")
    if payload.get("type") != "bundle":
        raise client.SyncError(f"Expected STIX bundle at {path}")
    objects = payload.get("objects")
    if not isinstance(objects, list):
        raise client.SyncError(f"Bundle objects must be a list at {path}")
    return payload


def archive_domain(
    base_dir: Path,
    source_root: Path,
    domain: str,
    dry_run: bool,
) -> Dict[str, Any]:
    paths = client.domain_paths(base_dir, domain)
    releases = discover_release_files(source_root, domain)
    archive_dir = paths["history"]
    existing_latest_state = client.load_state(paths["latest"])

    release_records: List[Dict[str, Any]] = []
    file_status: Dict[str, str] = {}
    latest_release_version = releases[-1][0]
    latest_release_bundle: Dict[str, Any] | None = None

    for version, source_path in releases:
        bundle = load_bundle(source_path)
        release_state = client.bundle_to_state(bundle)
        release_record = {
            "version": version,
            "source_path": str(source_path),
            "object_count": len(release_state),
            "latest_modified": client.latest_modified_from_state(release_state),
            "archive_path": str(archive_dir / f"{version}.json"),
        }
        release_records.append(release_record)
        if version == latest_release_version:
            latest_release_bundle = bundle

        if not dry_run:
            file_status[f"history/{version}.json"] = client.write_json_file_tracked(archive_dir / f"{version}.json", bundle)

    if latest_release_bundle is None:
        raise client.SyncError(f"Unable to determine latest release for {domain}")

    latest_state = client.bundle_to_state(latest_release_bundle)
    diff = client.diff_states(existing_latest_state, latest_state)
    latest_bundle = client.build_bundle(latest_state.values(), bundle_id=client.make_bundle_id(domain, "latest"))
    derived_bundle = client.build_bundle(client.filter_derived(latest_state.values(), domain), bundle_id=client.make_bundle_id(domain, "derived"))
    latest_modified = client.latest_modified_from_state(latest_state)
    now = client.utc_now()

    manifest: Dict[str, Any] = {
        "generated_at": now,
        "api_root": None,
        "mode": "historical",
        "collections": {
            domain: {
                "domain": domain,
                "mode": "historical",
                "latest_release": latest_release_version,
                "release_count": len(release_records),
                "releases": release_records,
                "objects_added": len(diff["added"]),
                "objects_modified": len(diff["modified"]),
                "objects_removed": len(diff["removed"]),
                "latest_modified": latest_modified,
                "last_successful_fetch": now,
                "history_dir": str(archive_dir),
            }
        },
        "domains": [domain],
        "dry_run": bool(dry_run),
    }

    if not dry_run:
        file_status["latest.json"] = client.write_json_file_tracked(paths["latest"], latest_bundle)
        file_status["derived.json"] = client.write_json_file_tracked(paths["derived"], derived_bundle)
        if paths["delta"].exists():
            paths["delta"].unlink()
            file_status["delta.json"] = "removed"
        file_status["manifest.json"] = client.write_json_file_tracked(paths["manifest"], manifest)

    result = manifest["collections"][domain]
    result["files"] = file_status
    return result


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Load all historical ATT&CK releases from the workspace")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="Directory that will contain the domain folders",
    )
    parser.add_argument(
        "--source-root",
        default=str(Path(__file__).resolve().parents[2] / "structured-data" / "mitre-attack" / "attack-stix-data-master"),
        help="Root directory containing the versioned ATT&CK JSON files",
    )
    parser.add_argument(
        "--domains",
        nargs="+",
        choices=sorted(client.DOMAIN_SPECS.keys()),
        default=sorted(client.DOMAIN_SPECS.keys()),
        help="Domains to load",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and compare without writing output files",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    base_dir = Path(args.base_dir)
    source_root = Path(args.source_root)
    base_dir.mkdir(parents=True, exist_ok=True)

    try:
        results: Dict[str, Any] = {}
        for domain in args.domains:
            results[domain] = archive_domain(
                base_dir=base_dir,
                source_root=source_root,
                domain=domain,
                dry_run=args.dry_run,
            )

        for domain, result in results.items():
            print(client.format_summary_line(
                domain=domain,
                mode="historical",
                added=result["objects_added"],
                modified=result["objects_modified"],
                removed=result["objects_removed"],
                files=result["files"],
            ))

        output = {
            "source_root": str(source_root),
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
