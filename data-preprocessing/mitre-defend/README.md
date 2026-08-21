# MITRE D3FEND Preprocessing

Trims five of the six raw JSON files from the D3FEND crawler
(`data-acquisition/mitre-defend/{techniques,tactics,artifacts,weaknesses,mappings}/latest.json`)
into two files: `entities.json` (the `technique`/`tactic`/`artifact` records,
distinguished by their own `type`) and `relationships.json`.
`offensive-techniques/latest.json` isn't read here at all, and
`weaknesses/latest.json` is read only for its embedded edges — see below.

## Usage

```
py mitre_defend_preprocessing.py
```

Optional flags: `--input` (the D3FEND crawler's workspace, default: its own
output) and `--output-dir` (default: this folder).

## Why this looks different from CWE/CAPEC/CVE/ATT&CK

D3FEND's JSON is JSON-LD, not STIX: every record is keyed by an `@id` like
`"d3f:CWE-1004"` or `"d3f:T1055.001"`, and most field names carry an
`rdfs:`/`d3f:`/`owl:`/`skos:` prefix. Unlike CWE/CAPEC/ATT&CK — where this
project keeps source field names verbatim because they're already clean
identifiers — every field here is renamed to plain snake_case: a raw key
containing a literal colon (`"d3f:synonym"`) is awkward to carry into a flattened
output the way `x_capec_abstraction` or `ExtendedDescription` weren't.

Names are also unified with the rest of the project rather than kept close to
D3FEND's vocabulary: `d3f:definition` → `description` (what the other four all
call it), and `d3f:synonym` plus `skos:altLabel` merged into one `aliases` list.
Those two were separate alternate-name fields with no value in common on the 8
artifacts carrying both, so unioning loses nothing — and `aliases` was the last
of four different spellings this project had for that concept. The 8 artifacts
with several distinct `d3f:definition` values (one per industrial protocol) get
them joined into one string, so `description` is a string everywhere rather than
a string on most records and a list on 8.

JSON-LD also collapses a cardinality-1 value to a bare scalar instead of a
one-item list — the same quirk CWE's XML-to-JSON conversion has, normalized the
same way by `as_list()`. `tactic` records carry typed-literal values
(`{"@type": "...integer", "@value": "3"}`) for two fields, unwrapped by
`literal_value()`.

Nothing nests — every property is a scalar or `list[str]`, all Neo4j can store.
Unlike `mitre-attack`, which had two `list[map]` fields to unpack, D3FEND's own
nesting is confined to the typed literals and relationship endpoints already
unwrapped above.

`_content_hash`/`_first_seen_at` are dropped from every record — this project's
*own* crawler bookkeeping (D3FEND has no native timestamps at all), not domain
content. `@type` goes too: pure OWL/RDF class-membership boilerplate
(`"owl:Class"`, `"owl:NamedIndividual"`), useless once a record carries this
project's own `type` discriminator.

## Ids double as this dataset's cross-references — no `source_name` on any edge

Stripping the fixed `d3f:` prefix from every `@id` — the one normalization
applied uniformly across every entity type and every relationship endpoint —
happens to produce exactly the id strings (`CWE-1004`, `T1055.001`) that
`data-preprocessing/CWE` and `mitre-attack` already use for the same concepts.
Since the values are literally identical strings across datasets, a dedicated
external edge would express nothing beyond that identity — unlike CAPEC's
`CAPEC-N` and CWE's `CWE-N`, genuinely different id spaces for genuinely
different entities referencing each other. So unlike the other four
preprocessors, none of D3FEND's edges carry a `source_name`: the cross-catalog
ones are indistinguishable from the local ones, and that is the point.

**Neither `weakness` nor `offensive-technique` gets local entity records** —
both are pure mirrors of another source here (CWE, ATT&CK), and a full check
found nothing in either worth keeping separately:

- All 835 `offensive-technique` ids exist in `mitre-attack/entities.json`.
  D3FEND's `definition` was consistently a truncated prefix of ATT&CK's fuller
  `description` (781 of 835) — pure data loss, not distinct content — and
  D3FEND's copy lags ATT&CK on 5 renamed and 17 revoked/deprecated techniques.
- All 943 `weakness` ids exist in `CWE/entities.json`. Closer call: 97.7% of
  `definition`s matched CWE's `Description` exactly after whitespace-normalizing,
  but the remaining 2.3% had drifted in both directions (D3FEND fuller in 17
  cases, CWE fuller in 5), plus a handful of D3FEND-only alternate names and a
  single `comment` recovering content CWE's own preprocessor discards (`Notes`).
  Dropped anyway, accepting that small residue, for the same "match id directly"
  reason.

So `counters` edges' offensive-technique endpoint and the D3FEND-relation edges
to artifacts use bare `T####[.###]` ids matched against
`mitre-attack/entities.json`, and `child_of`/`weakness_of`/`may_be_weakness_of`
edges' weakness endpoint uses bare `CWE-N` ids matched against
`CWE/entities.json`.

D3FEND provides a distinct human-facing short code (`d3f:d3fend-id`, e.g.
`D3-AMED`) for `technique` records only, so every edge uses the stripped `@id`
throughout rather than `d3fend-id` — one consistent join key across every type.
`d3fend_id` is kept as an extra attribute on `technique` records.

## What becomes a relationship

- `artifact.rdfs:hasSubClass` → `has_subclass` (artifact → child artifact).
  Verified to resolve 100% within this dataset's own artifacts.
- `weakness.rdfs:subClassOf` → `child_of` (weakness → parent weakness), the same
  `relationship_type` CWE uses for the analogous edge. 10 of 1,113 parent refs
  point at the abstract root class `d3f:Weakness` rather than another weakness
  and are dropped, not emitted as edges to a non-entity.
- `weakness.d3f:weakness-of` / `d3f:may-be-weakness-of` → `weakness_of` /
  `may_be_weakness_of` (weakness → artifact). Both resolve 100% into this
  dataset's artifacts.
- `tactic.rdfs:subClassOf` is **dropped entirely, no edge emitted** — all 7
  tactics point at the same abstract root `d3f:DefensiveTactic`, not at another
  tactic; there is no real tactic-to-tactic hierarchy in this data.
- `mappings/latest.json` (14,003 flattened SPARQL-result rows, one per
  defense/offense trace) is mined for four kinds of edge, each deduplicated
  against the full row set rather than kept as 14,003 raw rows:
  - `technique --{relation}--> artifact` (166 unique edges; relation is the
    literal D3FEND relation name — `analyzes`, `filters`, `isolates`) — a fact
    available nowhere else here, since technique records carry no artifact
    relation of their own.
  - `technique --enables--> tactic` (149, one per technique — verified stable:
    every technique maps to exactly one tactic across every row it appears in).
  - `offensive-technique --{relation}--> artifact` (482 unique — `modifies`,
    `may_modify`, `creates`) — likewise D3FEND-only information layered onto
    ATT&CK's techniques (there's no local entity for the endpoint; see above).
  - `technique --counters--> offensive-technique` (3,544 unique) — the dataset's
    headline fact, kept with `def_artifact`/`def_artifact_rel`/`off_artifact`/
    `off_artifact_rel` as edge attributes, since those explain *why* the
    technique counters that specific offensive technique: the same artifact acted
    on by both sides is the bridge (D3FEND's *Access Modeling* counters `T1078`
    "Valid Accounts" because both act on a `UserAccount` artifact, one `maps`-ing
    it and the other `uses`-ing it). One pair can legitimately carry more than one
    edge when more than one bridge justifies it — 3,544 edges over 3,234 pairs.
  - A mapping's `off_tech_parent`/`off_tactic` and their `*_rel` fields are
    **not** turned into edges: they're ATT&CK-side sub-technique and tactic facts
    already captured by `mitre-attack`'s own `subtechnique_of`/`has_tactic`, so
    re-deriving them would duplicate that dataset. `query_def_tech_label`/
    `top_def_tech_label` are dropped for a different reason — they carry no id at
    all, and name other rungs of the technique hierarchy that happened to anchor
    the SPARQL query, not a fact about the mapped technique.
- Every edge gets a deterministic `relationship--<uuid5>` id seeded from every
  attribute, not just the triple — `counters` edges legitimately repeat a pair
  with a different artifact bridge. Reruns are byte-identical.

## Every string is normalized on the way out

`clean_record()` runs over every entity and every edge in `write_outputs()`, so
no builder has to remember to tidy up after itself. Per string it: converts CRLF
and lone CR to LF; turns non-breaking spaces, tabs and other exotic space
characters into a plain space; collapses runs of horizontal whitespace; trims
every line; and collapses three or more newlines to a blank line. Blank-line
paragraph breaks survive — they carry meaning — but the indentation the source
document was pretty-printed with does not. A string left empty is dropped rather
than written as `""`, and list values are deduplicated.

Two things are deliberately *not* touched. Markup that is quoted **content**
stays verbatim — XSS payloads, SOAP envelopes, C includes and `<a>`/`<script>`
samples appear inside these descriptions as the thing being described, and
stripping them would destroy the text. And a lone newline is only collapsed into
a space where the source is known to hard-wrap its text; elsewhere it is a real
line break and is kept.

## Output

Two JSON files, each a plain array of records.

### `entities.json` — 1,193 records

| `type` | Count | Contents |
|---|---|---|
| `artifact` | 915 | Digital artifacts from the D3FEND Artifact Ontology — id, name, description, aliases |
| `technique` | 271 | D3FEND defensive techniques — id, name, `d3fend_id` (e.g. `D3-AMED`), aliases |
| `tactic` | 7 | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, Restore, Model) — id, name, description, display order/priority |

### `relationships.json` — 6,471 records

Every record is `type: "relationship"` with id, relationship_type, source_ref and
target_ref. Two endpoint kinds below — `offensive-technique` and `weakness` —
have no entity record here; they join by bare id against another source:

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `counters` | 3,544 | technique → ATT&CK technique id, joining `mitre-attack/entities.json`. Carries the four artifact-bridge attributes |
| `child_of` | 1,103 | weakness → weakness, `CWE-N` ids, joining `CWE/entities.json` |
| `has_subclass` | 995 | artifact → artifact |
| `enables` | 149 | technique → tactic |
| 63 D3FEND-relation names | 648 | technique or ATT&CK-technique → artifact — `modifies` (107), `produces` (67), `may_modify` (56), `analyzes` (49), `accesses` (49), down to several with a single edge |
| `weakness_of` | 26 | weakness → artifact |
| `may_be_weakness_of` | 6 | weakness → artifact |
