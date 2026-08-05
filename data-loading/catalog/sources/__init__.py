"""One module per data source, each a single `SourceSpec` declaration.

Adding a sixth source means adding a module here and listing it in `SOURCES` --
no change to anything in `graphload/`. See the README's "Adding a new data
source" checklist.

Order matters only for readability of the run's output; the stages resolve
cross-source references through the registry rather than through load order.
"""

from __future__ import annotations

from graphload.spec import SourceSpec

from . import capec, cve, cwe, mitre_attack, mitre_defend

SOURCES: tuple[SourceSpec, ...] = (
    cwe.SPEC,
    capec.SPEC,
    cve.SPEC,
    mitre_attack.SPEC,
    mitre_defend.SPEC,
)

BY_KEY = {spec.key: spec for spec in SOURCES}
