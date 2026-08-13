"""Input formats, as plugins.

A reader is any callable `(Path) -> Iterator[dict]`. All five of this project's
sources use `json_array`; the other two exist so that new data arriving as JSONL
or CSV needs a one-word change in its `SourceSpec` rather than changes to any
stage.
"""

from __future__ import annotations

from typing import Callable, Dict, Iterator, Mapping
from pathlib import Path

from .csv_rows import read_csv
from .json_array import read_json_array
from .jsonl import read_jsonl

Reader = Callable[[Path], Iterator[Mapping[str, object]]]

REGISTRY: Dict[str, Reader] = {
    "json_array": read_json_array,
    "jsonl": read_jsonl,
    "csv": read_csv,
}


def get(name: str) -> Reader:
    try:
        return REGISTRY[name]
    except KeyError:
        raise KeyError(f"unknown reader {name!r}; known readers: {sorted(REGISTRY)}") from None
