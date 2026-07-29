# MITRE D3FEND Preprocessing

Trims the six raw JSON files from the D3FEND crawler
(`data-acquisition/mitre-defend/{techniques,tactics,artifacts,weaknesses,
offensive-techniques,mappings}/latest.json`) down to five entity files plus
one `relationships.json`.

## Usage

```
py mitre_defend_preprocessing.py
```

Optional flags: `--input` (path to the D3FEND crawler's workspace directory
— default: the D3FEND crawler's own output) and `--output-dir` (default:
this folder).

## Why this looks different from CWE/CAPEC/CVE/ATT&CK

D3FEND's own JSON is JSON-LD, not STIX — every record is keyed by an `@id`
like `"d3f:CWE-1004"` or `"d3f:T1055.001"`, and most fields carry an
`rdfs:`/`d3f:`/`owl:`/`skos:` namespace prefix in the key itself. Unlike
CWE/CAPEC/ATT&CK — where this project's preprocessors keep source field
names verbatim, because they're already clean identifiers — every field
here is renamed to a plain snake_case attribute (`name`, `definition`,
`synonyms`, ...): a raw key containing a literal colon (`"d3f:synonym"`)
is awkward to carry into a flattened JSON output the way `x_capec_abstraction`
or `ExtendedDescription` weren't.

JSON-LD also collapses a cardinality-1 value to a bare scalar instead of a
one-item list — the same quirk CWE's own XML-to-JSON conversion has for
its single-vs-list fields, normalized here the same way (`as_list()`).
Two entity types (`tactic`, `offensive-technique`) also carry typed-literal
values (`{"@type": "...boolean", "@value": "true"}`) for a couple of
fields, unwrapped by `literal_value()`.

`_content_hash`/`_first_seen_at` are dropped from every record — this
project's *own* crawler bookkeeping (D3FEND has no native timestamps at
all, per the crawler's own README), not domain content. `@type` is dropped
too — pure OWL/RDF class-membership boilerplate (`"owl:Class"`,
`"owl:NamedIndividual"`), not useful once a record is already sorted into
its own per-type output file.

## Ids double as this dataset's own cross-references — no `external_relationships.json`

D3FEND's `weakness` records are its own mirror of CWE entries (`@id`:
`"d3f:CWE-1004"`), and its `offensive-technique` records mirror ATT&CK
techniques (`@id`: `"d3f:T1055.001"`). Stripping the fixed `d3f:` namespace
prefix from every `@id` — the one normalization applied uniformly across
all five entity types — happens to produce exactly the id strings
(`CWE-1004`, `T1055.001`) that `data-preprocessing/CWE` and
`data-preprocessing/mitre-attack` already use for the *same* underlying
concepts. Since the id values are literally identical strings across the
two datasets, there's nothing for an `external_relationships.json` to
express beyond that identity — unlike CAPEC's `CAPEC-N`/CWE's `CWE-N`,
genuinely different id spaces for genuinely different entities referencing
each other. **To join a D3FEND weakness/offensive-technique into the
CWE/ATT&CK preprocessing output, match `id` directly** — no join file
needed.

Because D3FEND provides a distinct human-facing short code
(`d3f:d3fend-id`, e.g. `D3-AMED`) for `technique` records only — not for
`artifact`/`tactic`/`weakness`/`offensive-technique` — every relationship
in this dataset (including ones with a `technique` endpoint) uses the
stripped `@id` as `source_ref`/`target_ref`, not `d3fend-id`, so there's
one consistent join key across every type. `d3fend_id` is kept as an extra
attribute on `technique` records only.

## What becomes a relationship

- `artifact.rdfs:hasSubClass` → `has_subclass` edges (artifact → child
  artifact). Verified to resolve 100% within `artifacts.json`.
- `weakness.rdfs:subClassOf` → `child_of` edges (weakness → parent
  weakness), the same relationship_type CWE's own preprocessor uses for
  the analogous edge. 10 of 1,113 parent refs point at the abstract root
  class `d3f:Weakness` itself rather than another weakness and are
  dropped, not emitted as edges to a non-entity.
- `weakness.d3f:weakness-of` / `d3f:may-be-weakness-of` → `weakness_of` /
  `may_be_weakness_of` edges (weakness → artifact). Both verified to
  resolve 100% into `artifacts.json`.
- `tactic.rdfs:subClassOf` is **dropped entirely, with no relationship
  emitted** — every one of the 7 tactics points at the same abstract root
  class `d3f:DefensiveTactic`, not at another tactic; there is no real
  tactic-to-tactic hierarchy in this data.
- `mappings/latest.json` (14,003 flattened SPARQL-result rows, one per
  defense/offense trace) is mined for four kinds of edges, each
  deduplicated against the full row set rather than kept as 14,003 raw
  rows:
  - `technique --{relation}--> artifact` (166 unique edges; relation is
    the literal D3FEND relation name — `analyzes`, `filters`, `isolates`,
    etc.) — a fact not available anywhere else in this dataset
    (`techniques.json` alone carries no artifact relation).
  - `technique --enables--> tactic` (149 edges, one per technique —
    verified stable: every technique maps to exactly one tactic across
    every row it appears in).
  - `offensive-technique --{relation}--> artifact` (482 unique edges —
    `modifies`, `may_modify`, `creates`, etc.) — likewise D3FEND-only
    information layered onto the ATT&CK technique mirror.
  - `technique --counters--> offensive-technique` (3,544 unique edges) —
    the dataset's headline fact. Kept with `def_artifact`/
    `def_artifact_rel`/`off_artifact`/`off_artifact_rel` as edge
    attributes, since those explain *why* the technique counters that
    specific offensive technique (the same kind of artifact, acted on by
    both sides, is the bridge — e.g. D3FEND's `Access Modeling` counters
    ATT&CK's `T1078` "Valid Accounts" because both act on a `UserAccount`
    artifact, one `maps`-ing it and the other `uses`-ing it). A
    `(technique, offensive-technique)` pair can legitimately have more
    than one such edge if more than one artifact-bridge justifies the
    same pairing (3,544 edges cover 3,234 distinct pairs).
  - `mapping`'s `off_tech_parent`/`off_tactic` and their `*_rel` fields are
    **not** turned into edges: they're the ATT&CK-side sub-technique and
    tactic facts, already fully captured by `data-preprocessing/mitre-attack`'s
    own `subtechnique-of` and `has_tactic` relationships — re-deriving
    them here would just duplicate that dataset. `query_def_tech_label`/
    `top_def_tech_label` are dropped for a different reason: they carry no
    id at all (only a label), and were confirmed to be other rungs of the
    technique hierarchy that happened to anchor the SPARQL query that
    produced the row, not a fact about the mapped technique itself.
- Relationship records get a deterministic `relationship--<uuid5>` id,
  seeded from every edge attribute (not just `source_ref`/
  `relationship_type`/`target_ref`) — `counters` edges can legitimately
  repeat with the same technique/offensive-technique pair but a different
  artifact bridge. Reruns against the same input produce byte-identical
  output.

## Output

Six JSON files, each a plain array of records:

| File | Count | Contents |
|---|---|---|
| `techniques.json` | 271 | D3FEND defensive techniques — id, name, `d3fend_id` (e.g. `D3-AMED`), synonyms |
| `tactics.json` | 7 | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, Restore, Model) — id, name, definition, display order/priority |
| `artifacts.json` | 915 | Digital artifacts from the D3FEND Artifact Ontology — id, name, definitions, synonyms, alt labels |
| `weaknesses.json` | 943 | CWE weaknesses as mirrored into D3FEND — id (`CWE-N`, matching `data-preprocessing/CWE`), name, `cwe_id`, definition, synonyms, comment |
| `offensive_techniques.json` | 835 | ATT&CK techniques referenced by D3FEND — id (`T####[.###]`, matching `data-preprocessing/mitre-attack`), name, `attack_id`, definition, `deprecated` (144 records) |
| `relationships.json` | 6,471 | `counters` (3,544, technique → offensive-technique), `child_of` (1,103, weakness → weakness), `has_subclass` (995, artifact → artifact), `enables` (149, technique → tactic), 63 distinct D3FEND-relation-named edges technique/offensive-technique → artifact (648 total — `modifies` 107, `produces` 67, `may_modify` 56, `analyzes` 49, `accesses` 49, ... down to several with a single edge), `weakness_of` (26, weakness → artifact), `may_be_weakness_of` (6, weakness → artifact) |
