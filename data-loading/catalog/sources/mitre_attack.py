"""MITRE ATT&CK -- 6,052 nodes, 36,346 edge rows.

Fourteen entity files, the widest set of node types in the project: techniques,
malware, tools, threat groups, campaigns, mitigations, tactics, matrices,
analytics, detection strategies, data components, data sources, ICS assets, and
log sources.

Three edge files, distinguished by where the edge came from rather than what it
means: `relationships.json` is ATT&CK's native STIX relationships (`uses`,
`mitigates`, `detects`, `subtechnique-of`, ...), `derived_relationships.json` was
rebuilt from id-list fields embedded on the entities themselves (`has_tactic`,
`has_analytic`, `uses_data_component`, `has_log_source`), and
`external_relationships.json` is 36 references out to CAPEC.

`log_sources.json` is the one entity file with no upstream STIX object -- it was
synthesised from log-source maps embedded on data components, so its records have
no `stix_id`.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="mitre-attack",
    label="MITRE ATT&CK",
    root="data-preprocessing/mitre-attack",
    files=(
        EntityFile("techniques.json"),
        EntityFile("tactics.json"),
        EntityFile("matrices.json"),
        EntityFile("courses_of_action.json"),
        EntityFile("malware.json"),
        EntityFile("tools.json"),
        EntityFile("intrusion_sets.json"),
        EntityFile("campaigns.json"),
        EntityFile("analytics.json"),
        EntityFile("detection_strategies.json"),
        EntityFile("data_components.json"),
        EntityFile("data_sources.json"),
        EntityFile("assets.json"),
        EntityFile("log_sources.json"),
        EdgeFile("relationships.json"),
        EdgeFile("derived_relationships.json"),
        EdgeFile("external_relationships.json"),
    ),
)
