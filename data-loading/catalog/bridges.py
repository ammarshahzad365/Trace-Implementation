"""Cross-catalog facts: one arrow each, however many sources assert them.

Every rule here was checked against the data rather than assumed; the counts in
the comments are measured.

## The three `related-to` bridges

`data-preprocessing/` leaves all cross-source references as one vague
`related-to` type disambiguated by a `source_name` property -- 328,883 rows, 29%
of every edge in the dataset, and precisely the path this project exists to
traverse. Worse, both catalogs assert the same fact from opposite ends: NVD says
`CVE-2021-44228 related-to CWE-502` while CWE says `CWE-502 related-to
CVE-2021-44228`. Loaded literally, that's two vague arrows pointing opposite ways
for one fact.

Each becomes one directional, named relationship, with the reverse direction
folded into it and `asserted_by` recording which catalogs agreed:

| Arrow | Canonical direction | Forward rows | Reverse rows folded in |
|---|---|---|---|
| `HAS_WEAKNESS`      | Vulnerability -> Weakness        | 308,742 (NVD) | 3,125 from CWE's ObservedExamples |
| `CLASSIFIED_AS`     | Vulnerability -> Category/View   | 14,285 (NVD)  | none exist |
| `EXPLOITS`          | AttackPattern -> Weakness        | 1,212 (CAPEC) | 1,212 from CWE's RelatedAttackPatterns |
| `MAPS_TO_TECHNIQUE` | AttackPattern -> AttackTechnique | 271 (CAPEC)   | 36 from ATT&CK's own capec refs |

Those eight shapes are every `(direction, label pair)` combination `related-to`
appears in across all four files -- checked exhaustively, and they sum to exactly
the 328,883 rows. `graphload/validate.py` refuses to load if a ninth ever shows
up, rather than letting it through as an untyped `RELATED_TO`.

`MAPS_TO_TECHNIQUE` is named for what it is. MITRE publishes CAPEC's ATT&CK
references as a taxonomy *correspondence* -- "this attack pattern is the same idea
as this technique" -- not as an action one performs, so `USES` would misdescribe
it. `EXPLOITS` is the opposite case: CAPEC's relation to CWE genuinely is "this
attack pattern abuses this weakness".

`description`/`link` are union properties on `HAS_WEAKNESS` because CWE's side
carries them and NVD's doesn't; 8 CWE->CVE pairs appear twice with different
text, and unioning keeps both rather than letting one overwrite the other.

## Same-fact collapses that aren't about crossing catalogs

Three more relationships repeat their endpoint pair under different ids, which
would load as parallel arrows and double-count in any traversal:

- **`CHILD_OF` between weaknesses.** CWE and D3FEND *both* publish the CWE
  hierarchy: 1,079 of D3FEND's 1,103 `child_of` rows are exact duplicates of
  CWE's, with 24 genuinely new. Separately, CWE records the same parent/child
  fact once per view it appears in (1,318 rows over 1,160 distinct pairs), so
  `view_id` and `ordinal` become union lists. Checked: only 2 of those 1,160
  pairs have an `ordinal` that differs between views, and in both it's
  `None` in view 1000 versus `Primary` in view 1003 -- so unioning loses nothing
  that pairing them preserved.
- **`HAS_LOG_SOURCE`** repeats 351 pairs, differing only in `channel`.
- **`INTRODUCED_IN`** repeats 25 pairs, differing only in `note`.

Both of those vary in exactly *one* attribute, so a union is lossless.

## Deliberately left as parallel arrows

`counters` (293 repeated pairs) and `uses_data_component` (57) also repeat their
endpoints -- but they carry several *correlated* attributes. A `counters` edge
explains itself with `def_artifact`/`def_artifact_rel`/`off_artifact`/
`off_artifact_rel`: D3FEND's `Access Modeling` counters ATT&CK's `T1078` because
both act on a `UserAccount`, one mapping it and the other using it. Unioning each
field into its own list would destroy which value pairs with which, and a second
artifact bridge for the same pair is a genuinely second justification. So they
stay two arrows, and the multiplicity is real rather than accidental.
"""

from __future__ import annotations

from graphload.dedupe import CanonicalRule

RULES: tuple[CanonicalRule, ...] = (
    # ---- the three cross-catalog bridges, replacing `related-to` entirely ----
    CanonicalRule(
        rel_type="HAS_WEAKNESS",
        source_label="Vulnerability",
        target_label="Weakness",
        matches=(
            ("related-to", "Vulnerability", "Weakness"),   # NVD's own classification
            ("related-to", "Weakness", "Vulnerability"),   # CWE's ObservedExamples
        ),
        union_properties=("description", "link"),
    ),
    # NVD doesn't only classify CVEs against weaknesses: 14,272 of its CWE
    # references point at a CWE *category* and 13 at a *view* -- organisational
    # groupings, not weaknesses. Calling those `HAS_WEAKNESS` would assert
    # something false about 14,285 edges, and hide the distinction behind a label
    # check that most queries won't write. They get their own type, which also
    # keeps `(v)-[:HAS_WEAKNESS]->(:Weakness)` honest: a CVE classified only at
    # category level genuinely has no weakness-level classification, and can still
    # reach weaknesses in two hops via the category's own HAS_MEMBER edges.
    CanonicalRule(
        rel_type="CLASSIFIED_AS",
        source_label="Vulnerability",
        target_label="Category",
        matches=(("related-to", "Vulnerability", "Category"),),
    ),
    CanonicalRule(
        rel_type="CLASSIFIED_AS",
        source_label="Vulnerability",
        target_label="View",
        matches=(("related-to", "Vulnerability", "View"),),
    ),
    CanonicalRule(
        rel_type="EXPLOITS",
        source_label="AttackPattern",
        target_label="Weakness",
        matches=(
            ("related-to", "AttackPattern", "Weakness"),   # CAPEC -> CWE
            ("related-to", "Weakness", "AttackPattern"),   # CWE's RelatedAttackPatterns
        ),
    ),
    CanonicalRule(
        rel_type="MAPS_TO_TECHNIQUE",
        source_label="AttackPattern",
        target_label="AttackTechnique",
        matches=(
            ("related-to", "AttackPattern", "AttackTechnique"),   # CAPEC -> ATT&CK
            ("related-to", "AttackTechnique", "AttackPattern"),   # ATT&CK -> CAPEC
        ),
    ),
    # ---- one fact recorded more than once, within or across catalogs ----
    CanonicalRule(
        rel_type="CHILD_OF",
        source_label="Weakness",
        target_label="Weakness",
        matches=(("child_of", "Weakness", "Weakness"),),
        union_properties=("view_id", "ordinal"),
    ),
    CanonicalRule(
        rel_type="HAS_LOG_SOURCE",
        source_label="DataComponent",
        target_label="LogSource",
        matches=(("has_log_source", "DataComponent", "LogSource"),),
        union_properties=("channel",),
    ),
    CanonicalRule(
        rel_type="INTRODUCED_IN",
        source_label="Weakness",
        target_label="Introduction",
        matches=(("introduced_in", "Weakness", "Introduction"),),
        union_properties=("note",),
    ),
)

# `relationship_type` values needing a non-mechanical Neo4j name. None do: every
# other type in the dataset converts cleanly (`subtechnique-of` ->
# `SUBTECHNIQUE_OF`, `may_be_weakness_of` -> `MAY_BE_WEAKNESS_OF`), and all 63 of
# D3FEND's artifact verbs are kept as distinct types rather than collapsed.
REL_TYPE_OVERRIDES: dict[str, str] = {}
