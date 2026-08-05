"""CSV with a header row.

Every value arrives as a string -- CSV has no types. Empty cells are dropped
rather than loaded as `""`, matching how the JSON sources omit absent fields
instead of writing nulls. Anything needing real numbers or arrays should be
converted in a per-source transform, not guessed at here.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator, Mapping


def read_csv(path: Path) -> Iterator[Mapping[str, object]]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            yield {k: v for k, v in row.items() if k and v not in (None, "")}
