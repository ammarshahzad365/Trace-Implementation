"""Copying each CVE's headline severity onto the CVE node itself.

Half the graph is severity data: 746,387 score and assessment nodes hanging off
346,947 vulnerabilities. Nothing in the CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND
trace goes through them, but "show me the critical CVEs that have a full trace to
a defence" is exactly the kind of question this project will ask constantly, and
answering it shouldn't cost a hop and a filter on every query.

So each `:Vulnerability` gets four flat properties -- `cvss_base_score`,
`cvss_base_severity`, `cvss_vector_string`, `cvss_version` -- while the full score
nodes stay in place for anything needing the detail (competing CNA assessments,
sub-scores, v2/v4 specifics).

## Why this runs after loading rather than during it

The score files don't record which CVE they belong to; that lives in
`CVE/relationships.json`. Rebuilding that join in Python would mean holding a
746,387-entry map alongside a 583,000-entry one, in a process already streaming a
gigabyte of JSON next to a 1.5 GB Neo4j heap. After loading, it's a two-hop
traversal the constraints already indexed.

## Preference order

CVSS v3.1 first, then v3.0, then v4.0, then v2.0 -- newest widely-populated
standard first, oldest last. v4.0 sits below v3 deliberately: only 29,426 CVEs
have one, so preferring it would leave the property inconsistently sourced across
the corpus for no gain. Within each version, NVD's own `Primary` assessment wins;
a `Secondary` (CNA-supplied) score is used only when there's no Primary at all.

Each pass is guarded by `cvss_base_score IS NULL`, so an earlier pass always wins
and the eight passes compose into a single preference order. That guard also makes
the whole stage idempotent -- re-running it changes nothing, and a CVE whose score
is added by a later crawl gets picked up on the next run.

The `CALL (v, s) { ... }` variable-scope form requires **Neo4j 5.23 or newer**
(`docker-compose.yml` pins 5.26 LTS). The older `CALL { WITH v, s ... }` spelling
works on any 5.x but is deprecated, and emits a warning per pass.
"""

from __future__ import annotations

from graphload.enrichment import EnrichmentStep

_ASSIGN = """
      SET v.cvss_base_score = s.base_score,
          v.cvss_base_severity = s.base_severity,
          v.cvss_vector_string = s.vector_string,
          v.cvss_version = s.version
"""


def _pass(label: str, rel: str, assessment: str, version: str | None) -> str:
    version_clause = f"AND s.version = '{version}' " if version else ""
    return f"""
MATCH (v:Vulnerability)-[:{rel}]->(s:{label})
WHERE v.cvss_base_score IS NULL
  AND s.assessment_type = '{assessment}'
  {version_clause}AND s.base_score IS NOT NULL
CALL (v, s) {{ {_ASSIGN} }} IN TRANSACTIONS OF 10000 ROWS
"""


# Ordered: the first pass to set a CVE's score wins, because every later pass
# skips nodes that already have one.
_PREFERENCE = (
    ("cvss_v31_primary", "CvssV3Score", "HAS_CVSS_V3_SCORE", "Primary", "3.1"),
    ("cvss_v30_primary", "CvssV3Score", "HAS_CVSS_V3_SCORE", "Primary", "3.0"),
    ("cvss_v40_primary", "CvssV4Score", "HAS_CVSS_V4_SCORE", "Primary", None),
    ("cvss_v2_primary", "CvssV2Score", "HAS_CVSS_V2_SCORE", "Primary", None),
    ("cvss_v31_secondary", "CvssV3Score", "HAS_CVSS_V3_SCORE", "Secondary", "3.1"),
    ("cvss_v30_secondary", "CvssV3Score", "HAS_CVSS_V3_SCORE", "Secondary", "3.0"),
    ("cvss_v40_secondary", "CvssV4Score", "HAS_CVSS_V4_SCORE", "Secondary", None),
    ("cvss_v2_secondary", "CvssV2Score", "HAS_CVSS_V2_SCORE", "Secondary", None),
)

STEPS: tuple[EnrichmentStep, ...] = tuple(
    EnrichmentStep(
        name=name,
        description=(
            f"copy {assessment} CVSS "
            + (f"v{version} " if version else f"{label.replace('Cvss', 'v').replace('Score', '')} ")
            + "base score/severity/vector onto :Vulnerability"
        ),
        cypher=_pass(label, rel, assessment, version),
    )
    for name, label, rel, assessment, version in _PREFERENCE
)
