"""One JSON object per line. Blank lines are skipped."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Mapping


def read_jsonl(path: Path) -> Iterator[Mapping[str, object]]:
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
