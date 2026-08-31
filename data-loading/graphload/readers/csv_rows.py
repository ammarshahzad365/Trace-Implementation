"""Reader for a CSV with a header row.

Not used by any of this project's five sources. One thing to know before
pointing a `SourceSpec` at it: **every value arrives as a string**, because that
is all a CSV carries. The loader will not coerce `"9.8"` to a float or `"true"`
to a boolean -- guessing types from text is preprocessing, and it belongs in
`data-preprocessing/` where the guess can be documented and tested. Empty cells
become `None` and are therefore skipped, which is the one concession made here,
since an empty cell and an absent field are indistinguishable in CSV.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator, Mapping


def read_csv(path: Path) -> Iterator[Mapping[str, object]]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            yield {key: (value if value != "" else None) for key, value in row.items()}
