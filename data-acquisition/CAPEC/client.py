"""Shared CAPEC/STIX helpers for the full crawler and incremental crawler.

Unlike NVD (CVE) or the ATT&CK TAXII server, CAPEC has no paginated REST API and no
date-filtered "fetch what changed" endpoint. MITRE publishes the entire CAPEC
catalog as a single STIX 2.1 bundle file in the mitre/cti GitHub repository, updated
whenever a new CAPEC version is released. Both crawlers therefore always download
the same full bundle; what differs is what they do with it locally (full overwrite
vs. merge-and-diff).

CAPEC objects are already valid STIX 2.1 (attack-pattern, course-of-action,
relationship, identity, marking-definition), so no format conversion is needed here
-- only the same generic id/created/modified based state, merge, and diff helpers
used by the other crawlers in this project.
"""

from __future__ import annotations

import copy
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

DEFAULT_SOURCE_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_USER_AGENT = "capec-crawler/0.1"


class SyncError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_stix_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise SyncError(f"Invalid STIX timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def format_stix_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------

def fetch_bundle(
    source_url: str,
    timeout: int,
    user_agent: str,
    max_retries: int = 3,
) -> Mapping[str, Any]:
    request = urllib.request.Request(source_url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    attempt = 0
    backoff = 3.0
    while True:
        try:
            print(f"[capec] downloading {source_url} ...")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                raw_bytes = response.read()
                print(f"[capec] downloaded {len(raw_bytes) / 1_000_000:.2f} MB")
                payload = json.loads(raw_bytes.decode(charset))
            if not isinstance(payload, dict) or payload.get("type") != "bundle":
                raise SyncError(f"Expected a STIX bundle from {source_url}")
            objects = payload.get("objects")
            if not isinstance(objects, list):
                raise SyncError(f"Bundle objects must be a list from {source_url}")
            return payload
        except urllib.error.HTTPError as exc:
            raise SyncError(f"HTTP {exc.code} while fetching {source_url}") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            attempt += 1
            if attempt <= max_retries:
                print(f"  ... fetch failed ({exc}), retrying (attempt {attempt}/{max_retries}) in {backoff:.0f}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            raise SyncError(f"Failed to fetch {source_url}: {exc}") from exc


def object_type_counts(objects: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for obj in objects:
        obj_type = str(obj.get("type") or "unknown")
        counts[obj_type] = counts.get(obj_type, 0) + 1
    return counts


def capec_version(objects: Iterable[Mapping[str, Any]]) -> str | None:
    for obj in objects:
        version = obj.get("x_capec_version")
        if version:
            return str(version)
    return None


# --------------------------------------------------------------------------
# JSON file / state helpers (format-agnostic, mirrors the other crawlers)
# --------------------------------------------------------------------------

def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _serialize_json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8") as handle:
        handle.write(text)
    temp_path.replace(path)


def write_json_file_tracked(path: Path, payload: Any) -> str:
    """Write JSON and report whether the file was "created", "modified", or left "unchanged"."""
    previous_text = path.read_text(encoding="utf-8") if path.exists() else None
    new_text = _serialize_json(payload)
    _atomic_write_text(path, new_text)
    if previous_text is None:
        return "created"
    return "unchanged" if previous_text == new_text else "modified"


def object_modified_key(obj: Mapping[str, Any]) -> Tuple[str, datetime]:
    modified = parse_stix_timestamp(str(obj.get("modified") or obj.get("created") or utc_now()))
    if modified is None:
        raise SyncError(f"Object missing timestamp: {obj.get('id')}")
    return str(obj.get("id")), modified


def normalize_objects(objects: Iterable[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    latest: Dict[str, Mapping[str, Any]] = {}
    for obj in objects:
        obj_id = str(obj.get("id") or "")
        if not obj_id:
            continue
        current = latest.get(obj_id)
        if current is None:
            latest[obj_id] = copy.deepcopy(dict(obj))
            continue
        _, current_modified = object_modified_key(current)
        _, incoming_modified = object_modified_key(obj)
        if incoming_modified >= current_modified:
            latest[obj_id] = copy.deepcopy(dict(obj))
    return latest


def merge_latest(existing: Mapping[str, Mapping[str, Any]], incoming: Mapping[str, Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    merged: Dict[str, Mapping[str, Any]] = {obj_id: copy.deepcopy(dict(obj)) for obj_id, obj in existing.items()}
    for obj_id, obj in incoming.items():
        current = merged.get(obj_id)
        if current is None:
            merged[obj_id] = copy.deepcopy(dict(obj))
            continue
        _, current_modified = object_modified_key(current)
        _, incoming_modified = object_modified_key(obj)
        if incoming_modified >= current_modified:
            merged[obj_id] = copy.deepcopy(dict(obj))
    return merged


def compute_delta(existing: Mapping[str, Mapping[str, Any]], incoming: Mapping[str, Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    delta: List[Mapping[str, Any]] = []
    for obj_id, obj in incoming.items():
        current = existing.get(obj_id)
        if current is None:
            delta.append(copy.deepcopy(dict(obj)))
            continue
        _, current_modified = object_modified_key(current)
        _, incoming_modified = object_modified_key(obj)
        if incoming_modified > current_modified:
            delta.append(copy.deepcopy(dict(obj)))
    return delta


def diff_states(
    existing: Mapping[str, Mapping[str, Any]],
    incoming: Mapping[str, Mapping[str, Any]],
) -> Dict[str, List[str]]:
    """Compare two full object-id -> object snapshots and classify each id as added, modified, or removed."""
    added: List[str] = []
    modified: List[str] = []
    for obj_id, obj in incoming.items():
        current = existing.get(obj_id)
        if current is None:
            added.append(obj_id)
            continue
        _, current_modified = object_modified_key(current)
        _, incoming_modified = object_modified_key(obj)
        if incoming_modified > current_modified:
            modified.append(obj_id)
    removed = [obj_id for obj_id in existing if obj_id not in incoming]
    return {
        "added": sorted(added),
        "modified": sorted(modified),
        "removed": sorted(removed),
    }


def latest_modified_from_state(state: Mapping[str, Mapping[str, Any]]) -> str | None:
    latest_modified = None
    for obj in state.values():
        _, modified = object_modified_key(obj)
        if latest_modified is None or modified > latest_modified:
            latest_modified = modified
    return format_stix_timestamp(latest_modified)


def make_bundle_id(label: str) -> str:
    bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"capec-crawler:{label}")
    return f"bundle--{bundle_uuid}"


def build_bundle(objects: Iterable[Mapping[str, Any]], bundle_id: str) -> Dict[str, Any]:
    object_list = [copy.deepcopy(dict(obj)) for obj in objects]
    object_list.sort(key=lambda item: (str(item.get("type") or ""), str(item.get("name") or ""), str(item.get("id") or "")))
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": object_list,
    }


def bundle_to_state(bundle: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    objects = bundle.get("objects", []) if isinstance(bundle, Mapping) else []
    if not isinstance(objects, list):
        raise SyncError("Bundle objects must be a list")
    return normalize_objects(obj for obj in objects if isinstance(obj, Mapping))


def load_state(path: Path) -> Dict[str, Mapping[str, Any]]:
    payload = load_json_file(path, default=None)
    if payload is None:
        return {}
    return bundle_to_state(payload)


# --------------------------------------------------------------------------
# Paths / manifest
# --------------------------------------------------------------------------

def paths(base_dir: Path) -> Dict[str, Path]:
    return {
        "latest": base_dir / "latest.json",
        "delta": base_dir / "delta.json",
        "manifest": base_dir / "manifest.json",
    }


def load_manifest(path: Path) -> Dict[str, Any]:
    manifest = load_json_file(path, default=None)
    if manifest is None:
        return {
            "generated_at": None,
            "source_url": None,
            "mode": None,
            "last_successful_fetch": None,
        }
    if not isinstance(manifest, dict):
        raise SyncError(f"Invalid manifest at {path}")
    return manifest


def format_summary_line(
    mode: str,
    added: int,
    modified: int,
    removed: int | None,
    files: Mapping[str, str],
) -> str:
    change_parts = [f"+{added} added", f"~{modified} modified"]
    if removed is not None:
        change_parts.append(f"-{removed} removed")
    changes = ", ".join(change_parts)
    if files:
        file_bits = ", ".join(f"{name}: {status}" for name, status in files.items())
    else:
        file_bits = "no files written (dry run)"
    return f"[capec] {mode}: {changes} | files: {file_bits}"
