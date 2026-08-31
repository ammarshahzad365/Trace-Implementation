"""Streaming reader for a top-level JSON array: `[ {...}, {...}, ... ]`.

This is the shape every `data-preprocessing/` output file has, and streaming
rather than `json.load` is not a micro-optimisation: `CVE/entities.json` alone
is 402 MB and `CVE/relationships.json` 95 MB, both pretty-printed at indent=2.
Parsed whole, the CVE folder peaks at several GB of Python objects. Streamed one
record at a time, memory stays flat regardless of file size -- which is what lets
the loader run beside a Neo4j heap on the same machine without either of them
having to be sized around the other.

`ijson`'s C backend (yajl2) is used when available and falls back to its pure
Python one otherwise -- same output either way, roughly 10x the speed.

`use_float=True` matters for CVSS: without it ijson yields `Decimal`, which the
Neo4j driver refuses to serialise, and a base score of 9.8 would fail the write
rather than round-trip as a float.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Mapping

import ijson


def read_json_array(path: Path) -> Iterator[Mapping[str, object]]:
    with open(path, "rb") as handle:
        for record in ijson.items(handle, "item", use_float=True):
            yield record
