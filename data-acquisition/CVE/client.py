"""Shared NVD/STIX helpers for the CVE full crawler and incremental crawler.

This module provides the common .env loading, NVD REST API access, rate limiting,
STIX 2.1 conversion, and state/bundle utilities used by full_crawler.py and
incremental_crawler.py.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

DEFAULT_API_ROOT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_RESULTS_PER_PAGE = 2000
DEFAULT_USER_AGENT = "cve-crawler/0.1"
MAX_LAST_MOD_RANGE_DAYS = 120
NVD_TIMESTAMP_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S")

NO_KEY_RATE_LIMIT = (5, 30.0)
WITH_KEY_RATE_LIMIT = (50, 30.0)


class SyncError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# .env loading
# --------------------------------------------------------------------------

def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE pairs from a .env file into os.environ without overwriting
    variables that are already set in the real environment."""
    import os

    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


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


def normalize_nvd_timestamp(value: str | None) -> str | None:
    """Convert an NVD timestamp (naive, implicitly UTC) into a STIX 2.1 timestamp."""
    if not value:
        return None
    text = value[:-1] if value.endswith("Z") else value
    for fmt in NVD_TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return format_stix_timestamp(parsed.replace(tzinfo=timezone.utc))
    raise SyncError(f"Invalid NVD timestamp: {value}")


def date_windows(start: datetime, end: datetime, max_days: int = MAX_LAST_MOD_RANGE_DAYS) -> List[Tuple[datetime, datetime]]:
    """Split [start, end] into consecutive windows no longer than max_days each."""
    if start >= end:
        return []
    windows: List[Tuple[datetime, datetime]] = []
    cursor = start
    step = timedelta(days=max_days)
    while cursor < end:
        window_end = min(cursor + step, end)
        windows.append((cursor, window_end))
        cursor = window_end
    return windows


# --------------------------------------------------------------------------
# Rate limiting + HTTP
# --------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window rate limiter matching NVD's rolling 30-second request quota."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()

    def acquire(self) -> None:
        now = time.monotonic()
        while self._timestamps and now - self._timestamps[0] >= self.window_seconds:
            self._timestamps.popleft()
        if len(self._timestamps) >= self.max_requests:
            wait_for = self.window_seconds - (now - self._timestamps[0])
            if wait_for > 0:
                print(f"  ... rate limit reached, waiting {wait_for:.1f}s", file=sys.stderr)
                time.sleep(wait_for)
            now = time.monotonic()
            while self._timestamps and now - self._timestamps[0] >= self.window_seconds:
                self._timestamps.popleft()
        self._timestamps.append(time.monotonic())


def make_rate_limiter(api_key: str | None) -> RateLimiter:
    max_requests, window_seconds = WITH_KEY_RATE_LIMIT if api_key else NO_KEY_RATE_LIMIT
    return RateLimiter(max_requests, window_seconds)


def fetch_json(
    url: str,
    api_key: str | None,
    timeout: int,
    user_agent: str,
    rate_limiter: RateLimiter,
    max_retries: int = 5,
) -> Mapping[str, Any]:
    headers = {
        "Accept": "application/json",
        "User-Agent": user_agent,
    }
    if api_key:
        headers["apiKey"] = api_key

    attempt = 0
    backoff = 5.0
    while True:
        rate_limiter.acquire()
        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                payload = response.read().decode(charset)
                return json.loads(payload)
        except urllib.error.HTTPError as exc:
            attempt += 1
            if exc.code in (403, 429) and attempt <= max_retries:
                print(f"  ... HTTP {exc.code} from NVD, retrying (attempt {attempt}/{max_retries}) in {backoff:.0f}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            raise SyncError(f"HTTP {exc.code} while fetching {url}") from exc
        except urllib.error.URLError as exc:
            attempt += 1
            if attempt <= max_retries:
                print(f"  ... network error ({exc.reason}), retrying (attempt {attempt}/{max_retries}) in {backoff:.0f}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            raise SyncError(f"Failed to fetch {url}: {exc.reason}") from exc
        except json.JSONDecodeError as exc:
            raise SyncError(f"Invalid JSON from {url}") from exc


def fetch_cves(
    api_root: str,
    base_params: Mapping[str, str],
    api_key: str | None,
    timeout: int,
    user_agent: str,
    results_per_page: int,
    rate_limiter: RateLimiter,
    max_pages: int | None = None,
    on_page: Callable[[int, int, int], None] | None = None,
) -> List[Mapping[str, Any]]:
    """Page through the NVD CVE API, returning every raw `cve` record found."""
    records: List[Mapping[str, Any]] = []
    start_index = 0
    total_results: int | None = None
    page_index = 0

    while True:
        params = dict(base_params)
        params["resultsPerPage"] = str(results_per_page)
        params["startIndex"] = str(start_index)
        url = api_root + "?" + urllib.parse.urlencode(params)

        payload = fetch_json(url, api_key=api_key, timeout=timeout, user_agent=user_agent, rate_limiter=rate_limiter)
        if total_results is None:
            total_results = int(payload.get("totalResults", 0))

        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise SyncError(f"Unexpected NVD response shape from {url}")
        for entry in vulnerabilities:
            cve = entry.get("cve") if isinstance(entry, Mapping) else None
            if isinstance(cve, Mapping):
                records.append(cve)

        page_index += 1
        page_count = max(1, -(-total_results // results_per_page)) if total_results else page_index
        if on_page is not None:
            on_page(page_index, page_count, total_results or 0)

        start_index += results_per_page
        if max_pages is not None and page_index >= max_pages:
            break
        if total_results is not None and start_index >= total_results:
            break

    return records


# --------------------------------------------------------------------------
# STIX conversion
# --------------------------------------------------------------------------

CVE_ID_PATTERN = re.compile(r"^CVE-(\d{4})-\d+$")
STIX_NAMESPACE = uuid.NAMESPACE_URL


def cve_year(cve_id: str) -> int:
    match = CVE_ID_PATTERN.match(cve_id)
    if not match:
        raise SyncError(f"Unrecognized CVE ID format: {cve_id}")
    return int(match.group(1))


def stix_id_for_cve(cve_id: str) -> str:
    return f"vulnerability--{uuid.uuid5(STIX_NAMESPACE, f'cve:{cve_id}')}"


def _english_description(descriptions: Iterable[Mapping[str, Any]]) -> str | None:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value")
    for description in descriptions:
        return description.get("value")
    return None


def _weakness_labels(weaknesses: Iterable[Mapping[str, Any]]) -> List[str]:
    labels: List[str] = []
    for weakness in weaknesses:
        for description in weakness.get("description", []):
            value = description.get("value")
            if value and value not in labels:
                labels.append(value)
    return labels


def cve_to_stix(cve: Mapping[str, Any]) -> Dict[str, Any]:
    cve_id = str(cve.get("id") or "")
    if not cve_id:
        raise SyncError("CVE record missing id")

    descriptions = cve.get("descriptions", []) or []
    references = cve.get("references", []) or []

    external_references: List[Dict[str, Any]] = [
        {
            "source_name": "cve",
            "external_id": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    ]
    for reference in references:
        url = reference.get("url")
        if not url:
            continue
        external_references.append({
            "source_name": str(reference.get("source") or "nvd"),
            "url": url,
        })

    return {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_id_for_cve(cve_id),
        "created": normalize_nvd_timestamp(cve.get("published")),
        "modified": normalize_nvd_timestamp(cve.get("lastModified")),
        "name": cve_id,
        "description": _english_description(descriptions),
        "external_references": external_references,
        "x_nvd_vuln_status": cve.get("vulnStatus"),
        "x_nvd_source_identifier": cve.get("sourceIdentifier"),
        "x_nvd_cvss": cve.get("metrics", {}),
        "x_nvd_weaknesses": _weakness_labels(cve.get("weaknesses", []) or []),
        "x_nvd_configurations": cve.get("configurations", []),
    }


# --------------------------------------------------------------------------
# JSON file / state helpers (format-agnostic, reused across crawlers)
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
    bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"cve-crawler:{label}")
    return f"bundle--{bundle_uuid}"


def build_bundle(objects: Iterable[Mapping[str, Any]], bundle_id: str) -> Dict[str, Any]:
    object_list = [copy.deepcopy(dict(obj)) for obj in objects]
    object_list.sort(key=lambda item: str(item.get("name") or item.get("id") or ""))
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": object_list,
    }


def load_state(path: Path) -> Dict[str, Mapping[str, Any]]:
    payload = load_json_file(path, default=None)
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise SyncError(f"Invalid STIX bundle at {path}")
    objects = payload.get("objects", [])
    if not isinstance(objects, list):
        raise SyncError(f"Invalid objects list in bundle at {path}")
    return normalize_objects(obj for obj in objects if isinstance(obj, dict))


# --------------------------------------------------------------------------
# Paths / manifest
# --------------------------------------------------------------------------

def year_dir(base_dir: Path, year: int) -> Path:
    return base_dir / "records" / str(year)


def year_paths(base_dir: Path, year: int) -> Dict[str, Path]:
    folder = year_dir(base_dir, year)
    return {
        "folder": folder,
        "latest": folder / "latest.json",
        "delta": folder / "delta.json",
    }


def manifest_path(base_dir: Path) -> Path:
    return base_dir / "manifest.json"


def load_manifest(path: Path) -> Dict[str, Any]:
    manifest = load_json_file(path, default=None)
    if manifest is None:
        return {
            "generated_at": None,
            "api_root": None,
            "mode": None,
            "last_successful_fetch": None,
            "years": {},
        }
    if not isinstance(manifest, dict):
        raise SyncError(f"Invalid manifest at {path}")
    manifest.setdefault("years", {})
    return manifest


def group_by_year(objects: Iterable[Mapping[str, Any]]) -> Dict[int, List[Mapping[str, Any]]]:
    grouped: Dict[int, List[Mapping[str, Any]]] = {}
    for obj in objects:
        cve_id = str(obj.get("name") or "")
        year = cve_year(cve_id)
        grouped.setdefault(year, []).append(obj)
    return grouped


def format_summary_line(
    year: int,
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
    return f"[{year}] {mode}: {changes} | files: {file_bits}"
