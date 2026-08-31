"""CVE (NVD) -- 359,355 entities, 336,339 edge rows. Most of the graph.

One entity type, `vulnerability`. The CVSS and SSVC severity assessments that
used to be separate nodes are now properties on the vulnerability record itself
(`cvss_base_score`, `cvss_vector_string`, ...), folded in upstream by
`data-preprocessing/`. The loader carries them across as ordinary properties and
has no idea what they mean.

This is the source that makes streaming non-optional: `entities.json` is 402 MB
and `relationships.json` 95 MB, both pretty-printed. See
`graphload/readers/json_array.py`.

Every one of its 336,339 edge rows points from a CVE at a CWE, so they are all
classified as cross-source and loaded by the `bridges` stage, not `edges`.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="cve",
    label="CVE",
    root="data-preprocessing/CVE",
    files=(
        EntityFile("entities.json"),
        EdgeFile("relationships.json"),
    ),
)
