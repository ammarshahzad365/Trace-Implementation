"""MITRE ATT&CK -- 5,659 entities, 33,105 edge rows. The densest source.

Twelve entity types across three merged domain bundles (enterprise, mobile,
ICS). Seven of them keep STIX's `x-mitre-` prefix in the data; `catalog/labels.py`
drops it in the label only, and the records' own fields keep theirs verbatim
(`x_mitre_platforms` stays `x_mitre_platforms`) because renaming a field would
be preprocessing.

Its `uses` type alone is 19,988 rows -- groups using malware, malware using
techniques, tools used in campaigns. They all load as `USES`, which is what the
data says; distinguishing them by endpoint pair would be a modelling decision
for `data-preprocessing/`.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="mitre-attack",
    label="ATT&CK",
    root="data-preprocessing/mitre-attack",
    files=(
        EntityFile("entities.json"),
        EdgeFile("relationships.json"),
    ),
)
