"""A general-purpose property-graph loader for Neo4j.

Nothing in this package knows anything about CVE, CWE, CAPEC, ATT&CK, D3FEND,
STIX, or cybersecurity. It knows two shapes:

- **entity records** -- each has an id and a type, and becomes a node
- **edge rows** -- each has a type and two endpoint ids, and becomes a relationship

Everything domain-specific lives in `catalog/`, which imports from here. The
dependency is strictly one-way: if `graphload/` ever needs to import `catalog/`,
the abstraction has sprung a leak. `main.py --self-check` asserts that.

That separation is the point. Pointing this at a different dataset means writing
a new `catalog/`, not editing anything here.
"""

__all__ = [
    "batch",
    "config",
    "context",
    "dedupe",
    "driver",
    "naming",
    "readers",
    "reading",
    "registry",
    "report",
    "router",
    "schema",
    "spec",
    "stages",
    "transform",
    "validate",
]
