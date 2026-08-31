"""CAPEC -- 1,492 entities, 2,155 edge rows.

Two entity types, `attack-pattern` and `course-of-action`, both STIX names that
ATT&CK deliberately does *not* share: `data-preprocessing/mitre-attack` renames
its own to `attack-technique`/`attack-mitigation` precisely so these two labels
stay CAPEC's alone. See `catalog/labels.py`.

Its `related_to` rows are how CAPEC points at the CWE weaknesses a pattern
exploits, so most of this source's edges are cross-source and land in the
`bridges` stage.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="capec",
    label="CAPEC",
    root="data-preprocessing/CAPEC",
    files=(
        EntityFile("entities.json"),
        EdgeFile("relationships.json"),
    ),
)
