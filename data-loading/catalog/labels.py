"""Which node label each source `type` value becomes.

`graphload/naming.py` can derive most of these mechanically -- `cvss-v3-score`
already PascalCases to `CvssV3Score`. They're all listed anyway, because the map
doubles as the declared label set that `stages/constraints.py` builds indexes
from before any data is read, and as the gate that makes a *new*, unlisted type
in a future crawl stop the load instead of quietly inventing a label for itself.

Three groups of entries are genuine judgement calls, not translations:

- **D3FEND's `technique`/`tactic`** become `DefensiveTechnique`/`DefensiveTactic`.
  They're already distinct from ATT&CK's types in the data, but plain `Technique`
  and `Tactic` read as the generic concept and invite querying the wrong catalog.
- **The `x-mitre-` prefix is dropped** (`x-mitre-analytic` -> `Analytic`). It marks
  a STIX custom extension, which is a fact about the file format rather than about
  the entity.
- **`consequence` is deliberately shared** by CWE and CAPEC. It means the same
  thing in both catalogs and `data-preprocessing/` emits the identical
  `{scope, impact}` shape for both, so it gets one label. Ids stay per-catalog
  (the preprocessors run independently and can't share an id space), so the 7
  `(scope, impact)` pairs both vocabularies happen to share are two nodes rather
  than one -- measured against the loaded graph; CAPEC's own preprocessing README
  says 4. See README's known-limitations section for the merge query.

`attack-technique`/`attack-mitigation` exist because `data-preprocessing/mitre-attack`
renames STIX's `attack-pattern`/`course-of-action` for exactly this reason: CAPEC
reuses those two STIX types for its own unrelated attack patterns and mitigations,
and left alone they'd be the only `type` values shared by two different entity
files -- merging two catalogs' entities under one label.
"""

from __future__ import annotations

LABELS: dict[str, str] = {
    # ---- CVE (NVD) ----
    "vulnerability": "Vulnerability",
    "cvss-v2-score": "CvssV2Score",
    "cvss-v3-score": "CvssV3Score",
    "cvss-v4-score": "CvssV4Score",
    "ssvc-assessment": "SsvcAssessment",
    # ---- CWE ----
    "weakness": "Weakness",
    "category": "Category",
    "view": "View",
    "platform": "Platform",
    "introduction": "Introduction",
    "mitigation": "Mitigation",
    "detection-method": "DetectionMethod",
    # shared by CWE and CAPEC on purpose -- same concept, same shape
    "consequence": "Consequence",
    # ---- CAPEC ----
    "attack-pattern": "AttackPattern",
    "course-of-action": "CourseOfAction",
    # ---- MITRE ATT&CK ----
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
    # ---- MITRE D3FEND ----
    "technique": "DefensiveTechnique",
    "tactic": "DefensiveTactic",
    "artifact": "Artifact",
}


def all_labels() -> list[str]:
    """The label set `constraints` indexes -- deduplicated, since some are shared."""
    return sorted(set(LABELS.values()))
