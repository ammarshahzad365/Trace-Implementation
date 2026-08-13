"""MITRE D3FEND -- 1,193 nodes, 6,471 edge rows. The smallest source, and the
one whose edges cross out of it the most.

Only **1,310** of its 6,471 rows are D3FEND-to-D3FEND. The rest reach into other
catalogs' id spaces, because D3FEND deliberately publishes no local copy of a CWE
weakness or an ATT&CK technique -- stripping its `d3f:` namespace prefix yields
exactly the ids the other sources already use, so it references them directly:

- **3,544** `counters` edges, D3FEND technique -> ATT&CK technique. The headline
  fact of the whole graph: "this defence stops that attack."
- **1,103** `child_of` edges living entirely in CWE's id space (`CWE-1004 ->
  CWE-732`) -- of which 1,079 duplicate CWE's own hierarchy. See
  `catalog/bridges.py`.
- **482** artifact edges from ATT&CK techniques, and **32** from CWE weaknesses.

This is why `graphload/router.py` classifies by endpoint rather than by filename:
one file, five different id spaces, and nothing in its name says so.
"""

from __future__ import annotations

from graphload.spec import EdgeFile, EntityFile, SourceSpec

SPEC = SourceSpec(
    key="mitre-defend",
    label="MITRE D3FEND",
    root="data-preprocessing/mitre-defend",
    files=(
        EntityFile("techniques.json"),
        EntityFile("tactics.json"),
        EntityFile("artifacts.json"),
        EdgeFile("relationships.json"),
    ),
)
