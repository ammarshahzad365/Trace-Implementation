"""The id -> (label, source) map, and its on-disk cache.

An edge row says `source_ref: "CVE-2021-44228"` and nothing about what kind of
thing that is. Three separate jobs need to know:

- **`stages/edges.py`** must pick a label to `MATCH` on, because a lookup scoped
  to `:Vulnerability` uses that label's index and an unscoped one scans the whole
  store.
- **`router.py`** must decide whether an edge stays inside one source or crosses
  between two -- which is the difference between the `edges` stage and the
  `bridges` stage, and cannot be read off the filename. Only 1,310 of D3FEND's
  6,471 edges actually stay within D3FEND; 3,544 point at ATT&CK ids and 1,103
  live entirely in CWE's id space.
- **`dedupe.py`** matches its rules on endpoint labels.

Memory matters here, because this map holds every id in the graph -- 1.1M of
them -- while a 1.5 GB Neo4j heap runs on the same 4 GB machine. So labels and
sources are interned into a small table and each id maps to a single small
integer, rather than to a tuple of two strings.

## The cache

Rebuilding the map means streaming every entity file, and `CVE/` alone is ~700 MB
of that. Since the whole point of the design is that adding a sixth source
shouldn't re-read the first five, the cache is **per source**, keyed by a
fingerprint of that source's entity files (path, size, mtime). Touch one file in
one source and only that source is rescanned.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from .spec import SourceSpec

CACHE_VERSION = 2


@dataclass
class Duplicate:
    id: str
    first: tuple[str, str]
    second: tuple[str, str]


@dataclass
class Registry:
    """id -> (label, source), with duplicate ids collected rather than raised."""

    _pairs: list[tuple[str, str]] = field(default_factory=list)
    _pair_index: dict[tuple[str, str], int] = field(default_factory=dict)
    _ids: dict[str, int] = field(default_factory=dict)
    duplicates: list[Duplicate] = field(default_factory=list)

    def _intern(self, label: str, source: str) -> int:
        key = (label, source)
        index = self._pair_index.get(key)
        if index is None:
            index = len(self._pairs)
            self._pairs.append(key)
            self._pair_index[key] = index
        return index

    def add(self, entity_id: str, label: str, source: str) -> None:
        index = self._intern(label, source)
        existing = self._ids.get(entity_id)
        if existing is not None:
            # Any repeat is a problem, whether or not it's the same label: two
            # records sharing an id would silently become one node.
            self.duplicates.append(Duplicate(entity_id, self._pairs[existing], (label, source)))
            return
        self._ids[entity_id] = index

    def lookup(self, entity_id: str) -> tuple[str, str] | None:
        index = self._ids.get(entity_id)
        return None if index is None else self._pairs[index]

    def label_of(self, entity_id: str) -> str | None:
        pair = self.lookup(entity_id)
        return None if pair is None else pair[0]

    def __len__(self) -> int:
        return len(self._ids)

    def counts_by_label(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for index in self._ids.values():
            out[self._pairs[index][0]] = out.get(self._pairs[index][0], 0) + 1
        return out

    def labels(self) -> set[str]:
        return {label for label, _ in self._pairs}

    def extend(self, entries: Iterable[tuple[str, str]], source: str) -> None:
        for entity_id, label in entries:
            self.add(entity_id, label, source)


def fingerprint(spec: SourceSpec, repo_root: Path) -> list[tuple[str, int, int]]:
    out = []
    for entity_file in spec.entity_files():
        path = spec.resolve(repo_root, entity_file)
        stat = path.stat()
        out.append((entity_file.path, stat.st_size, int(stat.st_mtime)))
    return sorted(out)


def cache_path(cache_dir: Path, key: str) -> Path:
    return cache_dir / f"registry-{key}.pickle"


def load_cached(cache_dir: Path, spec: SourceSpec, repo_root: Path) -> list[tuple[str, str]] | None:
    path = cache_path(cache_dir, spec.key)
    if not path.exists():
        return None
    try:
        with open(path, "rb") as handle:
            blob = pickle.load(handle)
    except Exception:
        return None
    if blob.get("version") != CACHE_VERSION:
        return None
    if blob.get("fingerprint") != fingerprint(spec, repo_root):
        return None
    return blob["entries"]


def save_cached(cache_dir: Path, spec: SourceSpec, repo_root: Path, entries: Sequence[tuple[str, str]]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    with open(cache_path(cache_dir, spec.key), "wb") as handle:
        pickle.dump(
            {"version": CACHE_VERSION, "fingerprint": fingerprint(spec, repo_root), "entries": list(entries)},
            handle,
            protocol=pickle.HIGHEST_PROTOCOL,
        )


def build(
    specs: Sequence[SourceSpec],
    repo_root: Path,
    cache_dir: Path,
    scan: Callable[[SourceSpec], list[tuple[str, str]]],
    *,
    use_cache: bool = True,
    on_progress: Callable[[str, int, bool], None] | None = None,
) -> Registry:
    registry = Registry()
    for spec in specs:
        entries = load_cached(cache_dir, spec, repo_root) if use_cache else None
        cached = entries is not None
        if entries is None:
            entries = scan(spec)
            if use_cache:
                save_cached(cache_dir, spec, repo_root, entries)
        registry.extend(entries, spec.key)
        if on_progress:
            on_progress(spec.key, len(entries), cached)
    return registry
