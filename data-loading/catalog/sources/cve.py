"""CVE -- 1,093,334 nodes, 1,069,414 edge rows. 96% of the graph.

Five entity files, four of which are severity assessments rather than
vulnerabilities: 346,947 CVEs carry 746,387 CVSS/SSVC score nodes between them.
Nothing in the CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND trace traverses those, but
they're loaded in full and then summarised onto each `:Vulnerability` by
`catalog/enrichments.py`, so severity is filterable without a hop.

This is also the source that makes streaming non-optional -- `vulnerabilities.json`
is 249 MB and `relationships.json` 196 MB, both pretty-printed. See
`graphload/readers/json_array.py`.

`external_relationships.json` is NVD's own CWE classification (323,027 rows,
`related-to`), retyped to `HAS_WEAKNESS` by `catalog/bridges.py`.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="cve",
    label="CVE",
    root="data-preprocessing/CVE",
    files=(
        EntityFile("vulnerabilities.json"),
        EntityFile("cvss_v2_scores.json"),
        EntityFile("cvss_v3_scores.json"),
        EntityFile("cvss_v4_scores.json"),
        EntityFile("ssvc_assessments.json"),
        EdgeFile("relationships.json"),
        EdgeFile("external_relationships.json"),
    ),
)
