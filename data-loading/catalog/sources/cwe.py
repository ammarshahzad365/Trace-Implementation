"""CWE -- 5,040 entities, 16,767 edge rows.

Seven entity types. Five of them (`platform`, `mitigation`, `detection-method`,
`consequence`, plus `category`/`view`) exist because CWE nests those inside a
weakness in the source XML and `data-preprocessing/` splits them out into their
own records -- which is what lets them be nodes here rather than JSON blobs
stuffed into a property.

`has_observed_example` is the source of this dataset's only dangling endpoints:
CWE cites CVE ids that NVD either rejected or never published. They are reported
and skipped, never invented. See `graphload/validate.py`.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="cwe",
    label="CWE",
    root="data-preprocessing/CWE",
    files=(
        EntityFile("entities.json"),
        EdgeFile("relationships.json"),
    ),
)
