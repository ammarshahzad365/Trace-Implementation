"""Copying each CVE's headline severity onto the CVE node itself.

Severity is the largest thing in the graph: 593,945 score and assessment nodes
hanging off 346,947 vulnerabilities. Nothing in the CVE -> CWE -> CAPEC -> ATT&CK
-> D3FEND trace goes through them, but "show me the critical CVEs that have a full
trace to a defence" is exactly the kind of question this project will ask
constantly, and answering it shouldn't cost a hop and a filter on every query.

So each `:Vulnerability` gets four flat properties -- `cvss_base_score`,
`cvss_base_severity`, `cvss_vector_string`, `cvss_version` -- while the score nodes
stay in place for anything needing the detail (competing CNA assessments, the full
metric breakdown in `vector_string`, v2/v4 specifics).

`cvss_base_severity` is computed here rather than copied: `data-preprocessing/`
drops `baseSeverity` from the score records because it is a fixed band table over
`baseScore` and storing both was storing one fact twice. See `_BAND_CVSS3`.

## Why this runs after loading rather than during it

The score files don't record which CVE they belong to; that lives in
`CVE/relationships.json`. Rebuilding that join in Python would mean holding a
593,945-entry map alongside a 430,584-entry one, in a process already streaming a
gigabyte of JSON next to a 1.5 GB Neo4j heap. After loading, it's a two-hop
traversal the constraints already indexed.

## Preference order

CVSS v3.1 first, then v3.0, then v4.0, then v2.0 -- newest widely-populated
standard first, oldest last. v4.0 sits below v3 deliberately: only 29,426 CVEs
have one, so preferring it would leave the property inconsistently sourced across
the corpus for no gain. Within each version, NVD's own `Primary` assessment wins;
a `Secondary` (CNA-supplied) score is used only when there's no Primary at all.

The two v2 passes now only ever fire for a CVE with no v3 score at all:
`data-preprocessing/` drops a v2 score outright when the same CVE also carries a
v3 one, on the grounds that this preference order meant nothing ever read it. The
one behavioural change is a CVE holding a v2 Primary *and* a v3 Secondary -- the
v2 Primary used to win on pass 4, and now the v3 Secondary wins on pass 5. That is
the newer standard winning, which is the order's intent.

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

# The severity band is a pure function of the base score, so `data-preprocessing/`
# stops storing it on the 430,584 score records and it is recomputed here instead --
# the one place in the graph that still wants it as a plain string to filter on.
#
# v3 and v4 share the official CVSS band table; v2 predates it and uses NVD's own
# three-band bucketing, which has no NONE and no CRITICAL.
_BAND_CVSS3 = """CASE
            WHEN s.base_score = 0.0 THEN 'NONE'
            WHEN s.base_score < 4.0 THEN 'LOW'
            WHEN s.base_score < 7.0 THEN 'MEDIUM'
            WHEN s.base_score < 9.0 THEN 'HIGH'
            ELSE 'CRITICAL'
          END"""

_BAND_CVSS2 = """CASE
            WHEN s.base_score < 4.0 THEN 'LOW'
            WHEN s.base_score < 7.0 THEN 'MEDIUM'
            ELSE 'HIGH'
          END"""


def _pass(label: str, rel: str, assessment: str, version: str | None) -> str:
    version_clause = f"AND s.version = '{version}' " if version else ""
    band = _BAND_CVSS2 if label == "CvssV2Score" else _BAND_CVSS3
    return f"""
MATCH (v:Vulnerability)-[:{rel}]->(s:{label})
WHERE v.cvss_base_score IS NULL
  AND s.assessment_type = '{assessment}'
  {version_clause}AND s.base_score IS NOT NULL
CALL (v, s) {{
      SET v.cvss_base_score = s.base_score,
          v.cvss_base_severity = {band},
          v.cvss_vector_string = s.vector_string,
          v.cvss_version = s.version
}} IN TRANSACTIONS OF 10000 ROWS
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
