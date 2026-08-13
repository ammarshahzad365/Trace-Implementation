"""CWE -- 5,056 nodes, 18,339 edge rows.

Eight entity files, because `cwe_preprocessing.py` pulled several sub-record
fields out into their own catalogs: platforms deduped by `(category, name)`,
mitigations by `Mitigation_ID`, detection methods by `Detection_Method_ID`,
consequences by `(scope, impact)`, and introduction phases by `Phase`. Their
per-weakness commentary lives on the edges, not on these shared nodes.

`relationships.json` holds edges within CWE (`has_member`, `child_of`,
`applies_to_platform`, ...); `external_relationships.json` holds its references
out to CVE and CAPEC, which `catalog/bridges.py` retypes into `HAS_WEAKNESS` and
`EXPLOITS`.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="cwe",
    label="CWE",
    root="data-preprocessing/CWE",
    files=(
        EntityFile("weaknesses.json"),
        EntityFile("categories.json"),
        EntityFile("views.json"),
        EntityFile("consequences.json"),
        EntityFile("platforms.json"),
        EntityFile("introductions.json"),
        EntityFile("mitigations.json"),
        EntityFile("detection_methods.json"),
        EdgeFile("relationships.json"),
        EdgeFile("external_relationships.json"),
    ),
)
