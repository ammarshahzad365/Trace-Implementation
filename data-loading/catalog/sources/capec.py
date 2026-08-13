"""CAPEC -- 1,538 nodes, 4,930 edge rows.

Three entity files and three edge files. `attack_pattern_relationships.json` is
separate from `relationships.json` because the former was derived from fields
embedded on the attack patterns themselves (`child_of`, `can_precede`, `peer_of`,
`has_consequence`) while the latter holds CAPEC's native STIX `mitigates` edges.
Both load identically here -- the split is a fact about the preprocessing, not
about the graph.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="capec",
    label="CAPEC",
    root="data-preprocessing/CAPEC",
    files=(
        EntityFile("attack_patterns.json"),
        EntityFile("courses_of_action.json"),
        EntityFile("consequences.json"),
        EdgeFile("relationships.json"),
        EdgeFile("attack_pattern_relationships.json"),
        EdgeFile("external_relationships.json"),
    ),
)
