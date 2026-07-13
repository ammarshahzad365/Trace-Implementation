"""Shared CWE helpers for the full crawler and incremental crawler.

CWE has no STIX representation and no REST endpoint that lists or filters the
entire catalog (the official cwe-api.mitre.org REST API only looks up specific
known IDs and their relationships -- it has no bulk "give me everything" or
"give me everything modified since X" call). MITRE's only complete, authoritative
bulk export is the versioned XML catalog
(https://cwe.mitre.org/data/xml/cwec_latest.xml.zip), which is what both crawlers
here download and convert to JSON. This mirrors the CAPEC crawler's shape: a single
versioned corpus fetched in full every run, diffed/merged against the local
snapshot rather than filtered server-side.

Each XML element is converted to a plain JSON-friendly dict (tag names have their
underscores stripped to match the naming convention MITRE itself uses in the
cwe-api.mitre.org REST responses, e.g. Common_Consequences -> CommonConsequences).
`created`/`modified` timestamps are derived from each entry's Content_History
(earliest Submission date -> created, latest Modification date -> modified) so the
same generic id/created/modified based state, merge, and diff helpers used by the
other crawlers in this project work unchanged.
"""

from __future__ import annotations

import copy
import io
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple
from xml.etree import ElementTree

DEFAULT_SOURCE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_USER_AGENT = "cwe-crawler/0.1"
CWE_XML_NAMESPACE = "http://cwe.mitre.org/cwe-7"

TOP_LEVEL_SECTIONS = {
    "Weaknesses": "weakness",
    "Categories": "category",
    "Views": "view",
}


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
        raise SyncError(f"Invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def format_stix_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _date_to_timestamp(date_str: str) -> str:
    """Convert a CWE "YYYY-MM-DD" date into a STIX-style UTC timestamp."""
    parsed = datetime.strptime(date_str.strip(), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return format_stix_timestamp(parsed)


# --------------------------------------------------------------------------
# Fetch
# --------------------------------------------------------------------------

def fetch_catalog_xml(
    source_url: str,
    timeout: int,
    user_agent: str,
    max_retries: int = 3,
) -> ElementTree.Element:
    request = urllib.request.Request(source_url, headers={"User-Agent": user_agent})
    attempt = 0
    backoff = 3.0
    while True:
        try:
            print(f"[cwe] downloading {source_url} ...")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                zip_bytes = response.read()
            print(f"[cwe] downloaded {len(zip_bytes) / 1_000_000:.2f} MB")
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
                xml_names = [name for name in archive.namelist() if name.endswith(".xml")]
                if not xml_names:
                    raise SyncError(f"No XML file found inside {source_url}")
                xml_bytes = archive.read(xml_names[0])
            print(f"[cwe] extracted {xml_names[0]} ({len(xml_bytes) / 1_000_000:.2f} MB)")
            return ElementTree.fromstring(xml_bytes)
        except urllib.error.HTTPError as exc:
            raise SyncError(f"HTTP {exc.code} while fetching {source_url}") from exc
        except (urllib.error.URLError, zipfile.BadZipFile, ElementTree.ParseError) as exc:
            attempt += 1
            if attempt <= max_retries:
                print(f"  ... fetch failed ({exc}), retrying (attempt {attempt}/{max_retries}) in {backoff:.0f}s", file=sys.stderr)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            raise SyncError(f"Failed to fetch {source_url}: {exc}") from exc


# --------------------------------------------------------------------------
# XML -> JSON conversion
# --------------------------------------------------------------------------

def _local_tag(tag: str) -> str:
    return tag.split("}")[-1].replace("_", "")


def xml_element_to_json(element: ElementTree.Element) -> Any:
    children = list(element)
    text = (element.text or "").strip()

    if not children:
        if element.attrib and text:
            result: Dict[str, Any] = dict(element.attrib)
            result["_text"] = text
            return result
        if element.attrib:
            return dict(element.attrib)
        return text or None

    result = dict(element.attrib) if element.attrib else {}
    grouped: Dict[str, List[Any]] = {}
    for child in children:
        key = _local_tag(child.tag)
        grouped.setdefault(key, []).append(xml_element_to_json(child))
    for key, values in grouped.items():
        result[key] = values if len(values) > 1 else values[0]
    return result


def _content_history_dates(content_history: ElementTree.Element | None) -> Tuple[str, str]:
    if content_history is None:
        now = utc_now()
        return now, now

    ns = f"{{{CWE_XML_NAMESPACE}}}"
    submission_dates: List[str] = []
    modification_dates: List[str] = []
    for entry in content_history:
        tag = _local_tag(entry.tag)
        if tag == "Submission":
            date = entry.findtext(f"{ns}Submission_ReleaseDate") or entry.findtext(f"{ns}Submission_Date")
            if date:
                submission_dates.append(date.strip())
        elif tag == "Modification":
            date = entry.findtext(f"{ns}Modification_ReleaseDate") or entry.findtext(f"{ns}Modification_Date")
            if date:
                modification_dates.append(date.strip())

    created_date = min(submission_dates) if submission_dates else (min(modification_dates) if modification_dates else None)
    all_dates = submission_dates + modification_dates
    modified_date = max(all_dates) if all_dates else created_date

    if created_date is None or modified_date is None:
        now = utc_now()
        return now, now
    return _date_to_timestamp(created_date), _date_to_timestamp(modified_date)


def entry_to_record(element: ElementTree.Element, entry_type: str) -> Dict[str, Any]:
    ns = f"{{{CWE_XML_NAMESPACE}}}"
    cwe_id = element.get("ID")
    record: Dict[str, Any] = {
        "type": entry_type,
        "id": f"CWE-{cwe_id}",
        "cwe_id": cwe_id,
        **element.attrib,
    }
    content_history_el = element.find(f"{ns}Content_History")
    for child in element:
        key = _local_tag(child.tag)
        if key == "ContentHistory":
            continue
        record[key] = xml_element_to_json(child)
    record["created"], record["modified"] = _content_history_dates(content_history_el)
    return record


def catalog_to_records(root: ElementTree.Element) -> List[Dict[str, Any]]:
    ns = f"{{{CWE_XML_NAMESPACE}}}"
    records: List[Dict[str, Any]] = []
    for section_tag, entry_type in TOP_LEVEL_SECTIONS.items():
        section = root.find(f"{ns}{section_tag}")
        if section is None:
            continue
        for entry in section:
            records.append(entry_to_record(entry, entry_type))
    return records


def catalog_version(root: ElementTree.Element) -> Dict[str, str | None]:
    return {
        "version": root.get("Version"),
        "date": root.get("Date"),
    }


def object_type_counts(objects: Iterable[Mapping[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for obj in objects:
        obj_type = str(obj.get("type") or "unknown")
        counts[obj_type] = counts.get(obj_type, 0) + 1
    return counts


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
    bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"cwe-crawler:{label}")
    return f"bundle--{bundle_uuid}"


def build_bundle(objects: Iterable[Mapping[str, Any]], bundle_id: str) -> Dict[str, Any]:
    object_list = [copy.deepcopy(dict(obj)) for obj in objects]
    object_list.sort(key=lambda item: (str(item.get("type") or ""), int(item.get("cwe_id") or 0)))
    return {
        "type": "bundle",
        "id": bundle_id,
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
    return f"[cwe] {mode}: {changes} | files: {file_bits}"
