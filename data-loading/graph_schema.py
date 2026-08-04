"""Neo4j naming for the preprocessed dataset: `type` -> node label, `relationship_type`
-> relationship type.

The preprocessed JSON deliberately keeps each source's own vocabulary in its `type`
field (`x-mitre-analytic`, `course-of-action`, `cvss-v3-score`) so the files stay
faithful to CWE/CAPEC/CVE/ATT&CK/D3FEND and remain useful outside a graph. Neo4j
wants something different, for two reasons:

- 18 of the 32 `type` values contain a hyphen, which is not a valid bare Cypher
  identifier -- `MATCH (t:attack-technique)` is a syntax error, so every query would
  need backticks forever. Labels are PascalCase here instead.
- 4 of the 93 `relationship_type` values have the same problem (`related-to`,
  `revoked-by`, `attributed-to`, `subtechnique-of`). Relationship types are
  UPPER_SNAKE, the Neo4j convention, derived mechanically.

Two label names are deliberately *not* mechanical translations. D3FEND's bare
`technique`/`tactic` become `DefensiveTechnique`/`DefensiveTactic`: they are already
distinct from ATT&CK's `attack-technique`/`x-mitre-tactic` in the data, but `Technique`
and `Tactic` as labels would read as the generic concept and invite writing a query
against the wrong one. Every `x-mitre-` prefix is dropped -- it marks a STIX custom
extension, which is a fact about the source format, not about the entity.
"""

from __future__ import annotations

from typing import Dict

# `type` value -> Neo4j node label. Every entity file's `type` must appear here;
# generate_load_cypher.py fails loudly on anything missing rather than guessing.
NODE_LABELS: Dict[str, str] = {
    # CVE
    "vulnerability": "Vulnerability",
    "cvss-v2-score": "CvssV2Score",
    "cvss-v3-score": "CvssV3Score",
    "cvss-v4-score": "CvssV4Score",
    "ssvc-assessment": "SsvcAssessment",
    # CWE
    "weakness": "Weakness",
    "category": "Category",
    "view": "View",
    "platform": "Platform",
    "introduction": "Introduction",
    "mitigation": "Mitigation",
    "detection-method": "DetectionMethod",
    # CWE + CAPEC both emit this one -- same concept, one shared label on purpose
    "consequence": "Consequence",
    # CAPEC
    "attack-pattern": "AttackPattern",
    "course-of-action": "CourseOfAction",
    # ATT&CK
    "attack-technique": "AttackTechnique",
    "attack-mitigation": "AttackMitigation",
    "x-mitre-tactic": "AttackTactic",
    "x-mitre-matrix": "AttackMatrix",
    "x-mitre-analytic": "Analytic",
    "x-mitre-detection-strategy": "DetectionStrategy",
    "x-mitre-data-component": "DataComponent",
    "x-mitre-data-source": "DataSource",
    "x-mitre-asset": "Asset",
    "log-source": "LogSource",
    "malware": "Malware",
    "tool": "Tool",
    "intrusion-set": "IntrusionSet",
    "campaign": "Campaign",
    # D3FEND
    "technique": "DefensiveTechnique",
    "tactic": "DefensiveTactic",
    "artifact": "Artifact",
}

# Every node also gets this label. Edge rows name their endpoints by bare id
# (`source_ref: "CVE-1999-0001"`) without saying what kind of thing that is, so a
# single label spanning every entity is what makes an edge resolvable in one indexed
# lookup. It is only sound because entity ids are unique across all five sources --
# verified by the preprocessors' own checks and again by generate_load_cypher.py.
SHARED_LABEL = "Entity"

# Redundant once `type` has become the label; dropped from node properties on load.
DROPPED_NODE_PROPERTIES = ("type",)

# Encoded in the edge itself (its type and its two endpoints); `id` is kept, since
# it's a deterministic uuid5 that makes a reload idempotent if needed.
DROPPED_RELATIONSHIP_PROPERTIES = ("type", "relationship_type", "source_ref", "target_ref")


def relationship_type(value: str) -> str:
    """`related-to` -> `RELATED_TO`, `has_cvss_v3_score` -> `HAS_CVSS_V3_SCORE`."""
    return value.replace("-", "_").upper()
