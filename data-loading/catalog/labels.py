"""Which node label each source `type` value becomes, and which relationship
type each `relationship_type` value becomes.

These maps are the loader's only vocabulary. They exist for two reasons beyond
spelling: they are the declared label set `stages/constraints.py` builds indexes
from before any data is read, and they are the gate that makes a *new, unlisted*
type in a future crawl stop the load instead of quietly inventing a label for
itself. That gate is the point -- an invented label is how half of a future
ATT&CK release ends up somewhere nobody queries.

Most entries are mechanical: `graphload/naming.py` would derive `AttackPattern`
from `attack-pattern` unaided. They are all listed anyway so that the set is
declared rather than discovered. Two groups are genuine judgement calls:

- **D3FEND's `technique`/`tactic`** become `DefensiveTechnique`/`DefensiveTactic`.
  They are already distinct from ATT&CK's types in the data, but plain
  `Technique` and `Tactic` read as the generic concept and invite querying the
  wrong catalog.
- **The `x-mitre-` prefix is dropped** (`x-mitre-analytic` -> `Analytic`). It
  marks a STIX custom extension, which is a fact about the file format rather
  than about the entity.

`attack-technique`/`attack-mitigation` are not renames made here --
`data-preprocessing/mitre-attack` already emits them that way, because CAPEC
reuses STIX's `attack-pattern`/`course-of-action` for its own unrelated patterns
and mitigations. Left alone, those would be the only `type` values shared by two
catalogs, and the two would merge under one label.

Adding a type here does not make the loader interpret it. See the README's
"Adding a new data source".
"""

from __future__ import annotations

LABELS: dict[str, str] = {
    # ---- CVE (NVD) ----
    "vulnerability": "Vulnerability",
    # ---- CWE ----
    "weakness": "Weakness",
    "category": "Category",
    "view": "View",
    "platform": "Platform",
    "mitigation": "Mitigation",
    "detection-method": "DetectionMethod",
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
    "x-mitre-asset": "Asset",
    "malware": "Malware",
    "tool": "Tool",
    "intrusion-set": "IntrusionSet",
    "campaign": "Campaign",
    # ---- MITRE D3FEND ----
    "technique": "DefensiveTechnique",
    "tactic": "DefensiveTactic",
    "artifact": "Artifact",
}

# Relationship types are derived mechanically -- `child_of` -> `CHILD_OF` --
# and every value the five sources currently emit is already clean snake_case,
# so nothing needs overriding. The map stays here as the place to put one if a
# source ever emits a name that uppercases into something misleading.
#
# Note what does NOT belong here: retyping `related_to` into something more
# specific per endpoint pair. `CVE/relationships.json` states `related_to`
# 336,339 times and it loads as `RELATED_TO`. Giving it a better name means
# knowing that a CVE-to-CWE `related_to` is NVD's weakness classification --
# domain knowledge, which makes it a `data-preprocessing/` decision, documented
# beside the raw field it came from.
REL_TYPE_OVERRIDES: dict[str, str] = {}


def all_labels() -> list[str]:
    """The label set `constraints` indexes -- deduplicated, since labels may be shared."""
    return sorted(set(LABELS.values()))
