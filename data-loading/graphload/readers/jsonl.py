"""Reader for newline-delimited JSON: one complete record per line.

Not used by any of this project's five sources -- it exists so that a source
arriving as JSONL is a one-word change in its `SourceSpec` rather than a change
to any stage. See the README's "Adding a new data source".
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Mapping


def read_jsonl(path: Path) -> Iterator[Mapping[str, object]]:
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: not valid JSON: {exc}") from exc
