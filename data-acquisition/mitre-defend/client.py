"""Shared D3FEND helpers for the full crawler and incremental crawler.

D3FEND has no STIX/TAXII interface like ATT&CK and no single versioned bundle
like CWE/CAPEC. Instead it exposes a small "alpha" REST JSON API
(d3fend.mitre.org/api/*) with one endpoint per entity type (techniques, tactics,
digital artifacts, weaknesses, referenced ATT&CK offensive techniques) plus a
bulk inferred-relationship export. There is no date-filtered "fetch what changed"
endpoint, so -- exactly like CWE/CAPEC -- both crawlers here download the same
full data every run; what differs is what they do with it locally (full
overwrite vs. merge-and-diff).

Unlike every other source in this project, D3FEND's objects carry no
`created`/`modified` timestamp at all (confirmed against the live API: entries
only have `@id`, `@type`, `rdfs:label`, `d3f:definition`, etc.). So instead of
the id/created/modified state model used by CVE/CWE/CAPEC/ATT&CK, this module
tracks state by content hash: each record gets a `_content_hash` (sha256 of its
canonical JSON) and a `_first_seen_at` timestamp that the crawler stamps itself
on first observation. "Modified" means the hash changed since the last run, not
that the object reports a newer timestamp.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

DEFAULT_API_ROOT = "https://d3fend.mitre.org"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_USER_AGENT = "mitre-defend-crawler/0.1"

# One entry per D3FEND API endpoint this crawler tracks. `folder` is the
# on-disk directory name; `path` is joined onto --api-root; `graph` marks
# whether the payload is JSON-LD ({"@graph": [...]}, keyed by "@id") or the
# relationship-bindings shape returned by the full-mappings endpoint (no
# natural id, so records are keyed by a hash of their own content).
DOMAIN_SPECS = {
    "technique": {
        "folder": "techniques",
        "path": "/api/technique/all.json",
        "graph": True,
    },
    "tactic": {
        "folder": "tactics",
        "path": "/api/tactic/all.json",
        "graph": True,
    },
    "artifact": {
        "folder": "artifacts",
        "path": "/api/dao/artifacts.json",
        "graph": True,
    },
    "weakness": {
        "folder": "weaknesses",
        "path": "/api/weakness/all.json",
        "graph": True,
    },
    "offensive-technique": {
        "folder": "offensive-techniques",
        "path": "/api/offensive-technique/all.json",
        "graph": True,
    },
    "mapping": {
        "folder": "mappings",
        "path": "/api/ontology/inference/d3fend-full-mappings.json",
        "graph": False,
    },
}

VERSION_PATH = "/api/version.json"


class SyncError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------

def _join_url(api_root: str, path: str) -> str:
    return api_root.rstrip("/") + "/" + path.lstrip("/")


def fetch_json(
    url: str,
    timeout: int,
    user_agent: str,
    max_retries: int = 3,
) -> Any:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept": "application/json"})
    attempt = 0
    backoff = 3.0
    while True:
        try:
            print(f"[d3fend] downloading {url} ...")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                raw_bytes = response.read()
                print(f"[d3fend] downloaded {len(raw_bytes) / 1_000_000:.2f} MB from {url}")
                return json.loads(raw_bytes.decode(charset))
        except urllib.error.HTTPError as exc:
            raise SyncError(f"HTTP {exc.code} while fetching {url}") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            attempt += 1
            if attempt <= max_retries:
                print(f"  ... fetch failed ({exc}), retrying (attempt {attempt}/{max_retries}) in {backoff:.0f}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            raise SyncError(f"Failed to fetch {url}: {exc}") from exc


def fetch_version(api_root: str, timeout: int, user_agent: str) -> Dict[str, Any]:
    payload = fetch_json(_join_url(api_root, VERSION_PATH), timeout=timeout, user_agent=user_agent)
    if not isinstance(payload, dict):
        raise SyncError(f"Unexpected version payload from {VERSION_PATH}")
    return payload


def fetch_domain(api_root: str, domain: str, timeout: int, user_agent: str) -> Any:
    spec = DOMAIN_SPECS[domain]
    return fetch_json(_join_url(api_root, str(spec["path"])), timeout=timeout, user_agent=user_agent)


# --------------------------------------------------------------------------
# Record extraction
# --------------------------------------------------------------------------

def extract_records(payload: Any, domain: str) -> List[Mapping[str, Any]]:
    """Unwrap a domain's raw JSON payload into a flat list of record dicts.

    Tries, in order: JSON-LD "@graph", SPARQL-style "results.bindings", then a
    bare top-level list. Raises loudly on an unrecognized shape rather than
    silently returning an empty list, since the mapping endpoint's shape was
    inferred (not confirmed against a live fetch) and must fail visibly if wrong.
    """
    if isinstance(payload, Mapping):
        graph = payload.get("@graph")
        if isinstance(graph, list):
            return [obj for obj in graph if isinstance(obj, Mapping)]
        results = payload.get("results")
        if isinstance(results, Mapping) and isinstance(results.get("bindings"), list):
            return [obj for obj in results["bindings"] if isinstance(obj, Mapping)]
    if isinstance(payload, list):
        return [obj for obj in payload if isinstance(obj, Mapping)]
    raise SyncError(
        f"Unrecognized payload shape for domain '{domain}': "
        f"expected a top-level list, an '@graph' array, or 'results.bindings'"
    )


# --------------------------------------------------------------------------
# Content hashing / state model
# --------------------------------------------------------------------------

def _canonical_json(obj: Mapping[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, default=str)


def content_hash(obj: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(obj).encode("utf-8")).hexdigest()


def record_key(obj: Mapping[str, Any], domain: str) -> str:
    spec = DOMAIN_SPECS[domain]
    if spec["graph"]:
        record_id = obj.get("@id")
        if not record_id:
            raise SyncError(f"Record missing '@id' in domain '{domain}': {obj}")
        return str(record_id)
    # Non-graph (mapping) rows have no natural id, so key on the hash of their
    # own fields -- stripped of bookkeeping so the key is stable whether the
    # object came from a fresh fetch or was reloaded from a stamped snapshot.
    return content_hash(_stripped_bookkeeping(obj))


def normalize_records(records: Iterable[Mapping[str, Any]], domain: str) -> Dict[str, Mapping[str, Any]]:
    normalized: Dict[str, Mapping[str, Any]] = {}
    for obj in records:
        key = record_key(obj, domain)
        normalized[key] = copy.deepcopy(dict(obj))
    return normalized


def _stripped_bookkeeping(obj: Mapping[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in obj.items() if not key.startswith("_")}


def _bookkeeping_hash(obj: Mapping[str, Any]) -> str:
    stored = obj.get("_content_hash")
    if isinstance(stored, str):
        return stored
    return content_hash(_stripped_bookkeeping(obj))


def stamp_records(
    incoming: Mapping[str, Mapping[str, Any]],
    existing: Mapping[str, Mapping[str, Any]],
    now: str,
) -> Dict[str, Mapping[str, Any]]:
    """Attach `_first_seen_at`/`_content_hash` bookkeeping to a fresh fetch."""
    stamped: Dict[str, Mapping[str, Any]] = {}
    for key, obj in incoming.items():
        raw = _stripped_bookkeeping(obj)
        previous = existing.get(key)
        first_seen_at = previous.get("_first_seen_at") if isinstance(previous, Mapping) else None
        stamped_obj = dict(raw)
        stamped_obj["_first_seen_at"] = first_seen_at or now
        stamped_obj["_content_hash"] = content_hash(raw)
        stamped[key] = stamped_obj
    return stamped


def merge_latest(existing: Mapping[str, Mapping[str, Any]], incoming: Mapping[str, Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    """Union merge: incoming (a full authoritative snapshot) wins for any key
    it contains; existing keys absent from incoming are kept unchanged."""
    merged: Dict[str, Mapping[str, Any]] = {key: copy.deepcopy(dict(obj)) for key, obj in existing.items()}
    for key, obj in incoming.items():
        merged[key] = copy.deepcopy(dict(obj))
    return merged


def compute_delta(existing: Mapping[str, Mapping[str, Any]], incoming: Mapping[str, Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    delta: List[Mapping[str, Any]] = []
    for key, obj in incoming.items():
        current = existing.get(key)
        if current is None or _bookkeeping_hash(current) != _bookkeeping_hash(obj):
            delta.append(copy.deepcopy(dict(obj)))
    return delta


def diff_states(
    existing: Mapping[str, Mapping[str, Any]],
    incoming: Mapping[str, Mapping[str, Any]],
) -> Dict[str, List[str]]:
    """Classify each key in `incoming` (a full snapshot) as added or modified
    relative to `existing`, and each key only in `existing` as removed."""
    added: List[str] = []
    modified: List[str] = []
    for key, obj in incoming.items():
        current = existing.get(key)
        if current is None:
            added.append(key)
        elif _bookkeeping_hash(current) != _bookkeeping_hash(obj):
            modified.append(key)
    removed = [key for key in existing if key not in incoming]
    return {
        "added": sorted(added),
        "modified": sorted(modified),
        "removed": sorted(removed),
    }


def object_type_counts(domain: str, count: int) -> Dict[str, int]:
    return {domain: count}


# --------------------------------------------------------------------------
# JSON file / state helpers (mirrors the other crawlers in this project)
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


def build_snapshot(records: Iterable[Mapping[str, Any]], domain: str) -> Dict[str, Any]:
    record_list = [copy.deepcopy(dict(obj)) for obj in records]
    record_list.sort(key=lambda item: str(item.get("@id") or item.get("_content_hash") or ""))
    return {
        "domain": domain,
        "count": len(record_list),
        "records": record_list,
    }


def snapshot_to_state(snapshot: Mapping[str, Any], domain: str) -> Dict[str, Mapping[str, Any]]:
    records = snapshot.get("records", []) if isinstance(snapshot, Mapping) else []
    if not isinstance(records, list):
        raise SyncError("Snapshot 'records' must be a list")
    return {record_key(obj, domain): copy.deepcopy(dict(obj)) for obj in records if isinstance(obj, Mapping)}


def load_state(path: Path, domain: str) -> Dict[str, Mapping[str, Any]]:
    payload = load_json_file(path, default=None)
    if payload is None:
        return {}
    return snapshot_to_state(payload, domain)


# --------------------------------------------------------------------------
# Paths / manifest
# --------------------------------------------------------------------------

def domain_folder(domain: str) -> str:
    return str(DOMAIN_SPECS[domain]["folder"])


def domain_paths(base_dir: Path, domain: str) -> Dict[str, Path]:
    folder = base_dir / domain_folder(domain)
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
            "ontology_version": None,
            "ontology_hash_sha256": None,
            "release_date": None,
            "domains": {},
        }
    if not isinstance(manifest, dict):
        raise SyncError(f"Invalid manifest at {path}")
    manifest.setdefault("domains", {})
    return manifest


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
