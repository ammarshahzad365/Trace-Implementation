"""MITRE D3FEND -- 1,193 entities, 5,056 edge rows.

Three entity types: `technique`, `tactic` and `artifact`. The first two are
relabelled `DefensiveTechnique`/`DefensiveTactic` so they cannot be confused
with ATT&CK's, which is the one place `catalog/labels.py` chooses a name the
data does not literally contain.

This source is the reason `graphload/router.py` classifies edges by their
endpoints rather than by the file they came from. Its single
`relationships.json` is mostly *not* about D3FEND: only 1,310 of its 5,056 rows
are D3FEND-to-D3FEND. Over three thousand point at ATT&CK technique ids, and
more than a thousand live entirely in CWE's id space (`CWE-1004 -> CWE-732`).
Nothing about the filename says so.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="mitre-defend",
    label="D3FEND",
    root="data-preprocessing/mitre-defend",
    files=(
        EntityFile("entities.json"),
        EdgeFile("relationships.json"),
    ),
)
