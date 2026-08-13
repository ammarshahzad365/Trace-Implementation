"""Streaming reader for a top-level JSON array: `[ {...}, {...}, ... ]`.

This is the shape every `data-preprocessing/` output file has, and streaming
rather than `json.load` is not a micro-optimisation here: `CVE/relationships.json`
alone is 196 MB and `CVE/vulnerabilities.json` is 249 MB, all pretty-printed at
indent=2. Parsed whole, the CVE folder's seven files peak around 4 GB of Python
objects. Streamed one record at a time, memory stays flat regardless of file
size, which is also what lets the loader run alongside a 1.5 GB Neo4j heap on a
4 GB Docker VM.

`ijson`'s C backend (yajl2) is used when available and falls back to its pure
Python one otherwise -- same output either way, roughly 10x the speed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Mapping

import ijson


def read_json_array(path: Path) -> Iterator[Mapping[str, object]]:
    with open(path, "rb") as handle:
        for record in ijson.items(handle, "item", use_float=True):
            yield record
