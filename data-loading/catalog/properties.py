"""What happens to a record's fields on the way to becoming properties.

## Prefixes are stripped

`x_capec_abstraction` -> `abstraction`, `x_mitre_platforms` -> `platforms`,
`x_nvd_vuln_status` -> `vuln_status`. The `x_` prefix is STIX's marker for a
custom extension field: it says something about the file the record came from,
not about the thing the record describes. Stripping it means `platforms` is
spelled the same way on an ATT&CK technique and a CWE weakness, and every query
written against this graph is shorter for the rest of the project's life.

`graphload/transform.py` treats a collision as a hard error, so if two fields on
one label ever collapsed onto the same name the load stops rather than silently
dropping one. (Verified against the current data: none do.)

The full mapping is listed in the README so the graph's property names can be
traced back to the `data-preprocessing/` field names its docs use.

## Dropped fields

- `type` leaves node records: it *became* the label, so keeping it duplicates
  information and invites the two disagreeing.
- `type`, `relationship_type`, `source_ref` and `target_ref` leave edge rows:
  all four are encoded in the relationship itself. Its own `id` stays, because
  it's a deterministic uuid5 -- which is what makes a reload update the same edge
  instead of adding a second one.
- `source_name` leaves edge rows because it only ever existed to disambiguate
  `related-to`, and `catalog/bridges.py` replaces that with three directional
  types. Once the type says `HAS_WEAKNESS`, `source_name: "cwe"` is noise; the
  `asserted_by` list carries the provenance properly.

## The provenance property is `catalog`, not `source`

Every node gets a property naming which of the five catalogs it came from. It is
deliberately **not** called `source`: CVSS score and SSVC assessment records
already carry their own `source` field, holding the identity of the assessing
organisation (`nvd@nist.gov`, or a CNA's uuid). Naming the provenance property
`source` would silently overwrite that on 593,945 nodes -- the same class of
collision the prefix-stripping guard exists to catch, arriving through a
different door. `stages/nodes.py` refuses to load if a record already has a field
by this name.

Edges use `asserted_by` instead, and it's a list, because an edge can legitimately
be claimed by two catalogs at once.
"""

from __future__ import annotations

from graphload.transform import PropertyPolicy

POLICY = PropertyPolicy(
    strip_prefixes=("x_capec_", "x_mitre_", "x_nvd_"),
    drop_from_nodes=("type",),
    drop_from_edges=("type", "relationship_type", "source_ref", "target_ref", "source_name"),
    source_property="catalog",
)
