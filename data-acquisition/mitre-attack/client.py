"""Shared ATT&CK TAXII/STIX helpers for the loader, full crawler, and incremental crawler.

This module provides the common TAXII, STIX, path, and bundle utilities used by
historical_loader.py, full_crawler.py, and incremental_crawler.py.
"""

from __future__ import annotations

import copy
import json
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

DEFAULT_API_ROOT = "https://attack-taxii.mitre.org/api/v21/"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_LIMIT = 5000
DEFAULT_USER_AGENT = "mitre-attack-crawler/0.1"

DOMAIN_SPECS = {
    "enterprise-attack": {
        "folder": "enterprise",
        "collection_names": ["Enterprise ATT&CK"],
        "derived_types": {
            "attack-pattern",
            "campaign",
            "course-of-action",
            "intrusion-set",
            "malware",
            "relationship",
            "tool",
            "x-mitre-analytic",
            "x-mitre-data-component",
            "x-mitre-data-source",
            "x-mitre-detection-strategy",
            "x-mitre-matrix",
            "x-mitre-tactic",
        },
    },
    "mobile-attack": {
        "folder": "mobile",
        "collection_names": ["Mobile ATT&CK"],
        "derived_types": {
            "attack-pattern",
            "campaign",
            "course-of-action",
            "intrusion-set",
            "malware",
            "relationship",
            "tool",
            "x-mitre-analytic",
            "x-mitre-data-component",
            "x-mitre-data-source",
            "x-mitre-detection-strategy",
            "x-mitre-matrix",
            "x-mitre-tactic",
        },
    },
    "ics-attack": {
        "folder": "ics",
        "collection_names": ["ATT&CK for ICS", "ICS ATT&CK"],
        "derived_types": {
            "attack-pattern",
            "campaign",
            "course-of-action",
            "intrusion-set",
            "malware",
            "relationship",
            "tool",
            "x-mitre-analytic",
            "x-mitre-asset",
            "x-mitre-data-component",
            "x-mitre-data-source",
            "x-mitre-detection-strategy",
            "x-mitre-matrix",
            "x-mitre-tactic",
        },
    },
}


@dataclass(frozen=True)
class CollectionSpec:
    domain: str
    collection_id: str
    collection_name: str


class SyncError(RuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_stix_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise SyncError(f"Invalid STIX timestamp: {value}") from exc


def format_stix_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def domain_folder(domain: str) -> str:
    return str(DOMAIN_SPECS[domain]["folder"])


def domain_dir(base_dir: Path, domain: str) -> Path:
    return base_dir / domain_folder(domain)


def domain_paths(base_dir: Path, domain: str) -> Dict[str, Path]:
    folder = domain_dir(base_dir, domain)
    return {
        "folder": folder,
        "history": folder / "history",
        "latest": folder / "latest.json",
        "derived": folder / "derived.json",
        "delta": folder / "delta.json",
        "manifest": folder / "manifest.json",
    }


def fetch_json(url: str, timeout: int, user_agent: str) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/taxii+json; version=2.1, application/json",
            "User-Agent": user_agent,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            payload = response.read().decode(charset)
            return json.loads(payload)
    except urllib.error.HTTPError as exc:
        raise SyncError(f"HTTP {exc.code} while fetching {url}") from exc
    except urllib.error.URLError as exc:
        raise SyncError(f"Failed to fetch {url}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise SyncError(f"Invalid JSON from {url}") from exc


def fetch_collections(api_root: str, timeout: int, user_agent: str) -> List[Mapping[str, Any]]:
    url = urllib.parse.urljoin(api_root.rstrip("/") + "/", "collections/")
    payload = fetch_json(url, timeout=timeout, user_agent=user_agent)
    collections = payload.get("collections")
    if not isinstance(collections, list):
        raise SyncError(f"Unexpected TAXII collections response from {url}")
    return collections


def pick_collection(domain: str, collections: Sequence[Mapping[str, Any]]) -> CollectionSpec:
    spec = DOMAIN_SPECS[domain]
    candidate_names = {name.lower() for name in spec["collection_names"]}
    for collection in collections:
        name = str(collection.get("title") or collection.get("name") or "")
        if name.lower() in candidate_names:
            collection_id = collection.get("id")
            if collection_id:
                return CollectionSpec(domain=domain, collection_id=str(collection_id), collection_name=name)
    for collection in collections:
        name = str(collection.get("title") or collection.get("name") or "")
        description = str(collection.get("description") or "")
        haystack = f"{name} {description}".lower()
        if domain.startswith("enterprise") and "enterprise" in haystack:
            return CollectionSpec(domain=domain, collection_id=str(collection["id"]), collection_name=name)
        if domain.startswith("mobile") and "mobile" in haystack:
            return CollectionSpec(domain=domain, collection_id=str(collection["id"]), collection_name=name)
        if domain.startswith("ics") and ("ics" in haystack or "industrial" in haystack):
            return CollectionSpec(domain=domain, collection_id=str(collection["id"]), collection_name=name)
    raise SyncError(f"Could not find TAXII collection for {domain}")


def fetch_collection_objects(
    api_root: str,
    collection_id: str,
    timeout: int,
    user_agent: str,
    added_after: str | None,
    limit: int,
) -> List[Mapping[str, Any]]:
    base_url = urllib.parse.urljoin(api_root.rstrip("/") + "/", f"collections/{collection_id}/objects/")
    objects: List[Mapping[str, Any]] = []
    next_url: str | None = None
    first_page = True

    while True:
        if next_url is not None:
            url = next_url
        else:
            params: Dict[str, str] = {"limit": str(limit)}
            if added_after and first_page:
                params["added_after"] = added_after
            url = base_url + ("?" + urllib.parse.urlencode(params) if params else "")

        payload = fetch_json(url, timeout=timeout, user_agent=user_agent)
        page_objects = payload.get("objects", [])
        if not isinstance(page_objects, list):
            raise SyncError(f"Unexpected TAXII objects response from {url}")
        objects.extend(page_objects)

        more = bool(payload.get("more"))
        next_link = payload.get("next")
        if more and next_link:
            next_link_text = str(next_link)
            parsed_next = urllib.parse.urlparse(next_link_text)
            if parsed_next.scheme or parsed_next.netloc:
                next_url = next_link_text
            else:
                next_url = base_url + "?" + urllib.parse.urlencode({"next": next_link_text})
        else:
            break
        first_page = False

    return objects


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


def write_json_file(path: Path, payload: Any) -> None:
    _atomic_write_text(path, _serialize_json(payload))


def write_json_file_tracked(path: Path, payload: Any) -> str:
    """Write JSON and report whether the file was "created", "modified", or left "unchanged"."""
    previous_text = path.read_text(encoding="utf-8") if path.exists() else None
    new_text = _serialize_json(payload)
    _atomic_write_text(path, new_text)
    if previous_text is None:
        return "created"
    return "unchanged" if previous_text == new_text else "modified"


def load_manifest(path: Path) -> Dict[str, Any]:
    manifest = load_json_file(path, default=None)
    if manifest is None:
        return {
            "generated_at": None,
            "api_root": None,
            "mode": None,
            "collections": {},
        }
    if not isinstance(manifest, dict):
        raise SyncError(f"Invalid manifest at {path}")
    manifest.setdefault("collections", {})
    return manifest


def load_state(state_path: Path) -> Dict[str, Mapping[str, Any]]:
    payload = load_json_file(state_path, default=None)
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise SyncError(f"Invalid state file at {state_path}")
    objects = payload.get("objects", [])
    if not isinstance(objects, list):
        raise SyncError(f"Invalid objects list in state file at {state_path}")
    return normalize_objects(obj for obj in objects if isinstance(obj, dict))


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


def object_modified_key(obj: Mapping[str, Any]) -> Tuple[str, datetime]:
    modified = parse_stix_timestamp(str(obj.get("modified") or obj.get("created") or utc_now()))
    if modified is None:
        raise SyncError(f"Object missing timestamp: {obj.get('id')}")
    return str(obj.get("id")), modified


def latest_modified_from_state(state: Mapping[str, Mapping[str, Any]]) -> str | None:
    latest_modified = None
    for obj in state.values():
        _, modified = object_modified_key(obj)
        if latest_modified is None or modified > latest_modified:
            latest_modified = modified
    return format_stix_timestamp(latest_modified)


def build_bundle(objects: Iterable[Mapping[str, Any]], bundle_id: str) -> Dict[str, Any]:
    object_list = [copy.deepcopy(dict(obj)) for obj in objects]
    object_list.sort(key=lambda item: (str(item.get("type") or ""), str(item.get("name") or ""), str(item.get("id") or "")))
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": object_list,
    }


def make_bundle_id(domain: str, label: str) -> str:
    bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"mitre-attack-crawler:{domain}:{label}")
    return f"bundle--{bundle_uuid}"


def filter_derived(objects: Iterable[Mapping[str, Any]], domain: str) -> List[Mapping[str, Any]]:
    allowed_types = DOMAIN_SPECS[domain]["derived_types"]
    filtered = [copy.deepcopy(dict(obj)) for obj in objects if str(obj.get("type") or "") in allowed_types]
    filtered.sort(key=lambda item: (str(item.get("type") or ""), str(item.get("name") or ""), str(item.get("id") or "")))
    return filtered


def bundle_to_state(bundle: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    objects = bundle.get("objects", []) if isinstance(bundle, Mapping) else []
    if not isinstance(objects, list):
        raise SyncError("Bundle objects must be a list")
    return normalize_objects(obj for obj in objects if isinstance(obj, Mapping))


def states_match(existing: Mapping[str, Mapping[str, Any]], incoming: Mapping[str, Mapping[str, Any]]) -> bool:
    return existing == incoming


def diff_states(
    existing: Mapping[str, Mapping[str, Any]],
    incoming: Mapping[str, Mapping[str, Any]],
) -> Dict[str, List[str]]:
    """Compare two full object-id -> object snapshots and classify each id as added, modified, or removed.

    Only meaningful when `incoming` is itself a full snapshot (e.g. a full crawl or a
    historical release), not a partial delta batch such as an incremental fetch.
    """
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


def format_summary_line(
    domain: str,
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
    return f"[{domain}] {mode}: {changes} | files: {file_bits}"
