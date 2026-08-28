# MITRE D3FEND Preprocessing

Reads five of the six raw files from the D3FEND crawler
(`data-acquisition/mitre-defend/{techniques,tactics,artifacts,weaknesses,mappings}/latest.json`)
and writes two: `entities.json` (the `technique`, `tactic` and `artifact`
records, told apart by their own `type`) and `relationships.json`.

`offensive-techniques/latest.json` is not read at all, and
`weaknesses/latest.json` is read only for the links embedded in it - see below.

## Usage

```
py mitre_defend_preprocessing.py
```

Optional flags: `--input` (the D3FEND crawler's workspace, default: its own
output) and `--output-dir` (default: this folder).

## Why this looks different from the other four

D3FEND's JSON is JSON-LD, not STIX. Every record is keyed by an `@id` like
`"d3f:CWE-1004"` or `"d3f:T1055.001"`, and most field names carry an `rdfs:`,
`d3f:`, `owl:` or `skos:` prefix.

For CWE, CAPEC and ATT&CK this project keeps the source field names as they are,
because they are already clean identifiers. Here every field is renamed to plain
snake_case instead: a key with a literal colon in it (`"d3f:synonym"`) is
awkward to carry into flat output in a way that `x_capec_abstraction` or
`ExtendedDescription` were not.

Names are also unified with the rest of the project rather than kept close to
D3FEND's own vocabulary:

- `d3f:definition` -> `description`, what the other four all call it.
- `d3f:synonym` and `skos:altLabel` merged into one `aliases` list. They were two
  separate alternate-name fields with no value in common on the 8 artifacts that
  had both, so merging loses nothing - and `aliases` was the last of four
  different spellings this project had for that idea.
- The 8 artifacts with several different `d3f:definition` values (one per
  industrial protocol) get them joined into one string, so `description` is a
  string everywhere rather than a string on most records and a list on 8.

JSON-LD also collapses a one-item list into a bare value - the same quirk CWE's
XML-to-JSON conversion has, normalized the same way by `as_list()`. `tactic`
records carry typed-literal values (`{"@type": "...integer", "@value": "3"}`) on
two fields, unwrapped by `literal_value()`.

Nothing nests: every property is a single value or a list of single values.
Unlike `mitre-attack`, which had two map-list fields to unpack,
D3FEND's nesting is confined to the typed literals and link endpoints already
unwrapped above.

Dropped from every record: `_content_hash` and `_first_seen_at` - this project's
*own* crawler bookkeeping (D3FEND has no timestamps of its own), not content.
`@type` goes too: pure OWL/RDF class-membership boilerplate (`"owl:Class"`,
`"owl:NamedIndividual"`), useless once a record carries this project's own `type`
field.

## The ids double as the cross-references, so no link carries `source_name`

Stripping the fixed `d3f:` prefix off every `@id` - the one normalization applied
to every entity type and every link endpoint - happens to produce exactly the id
strings (`CWE-1004`, `T1055.001`) that `data-preprocessing/CWE` and
`mitre-attack` already use for the same things.

Because the values are literally identical strings across datasets, a separate
"external" link would say nothing beyond that identity. (Contrast CAPEC's
`CAPEC-N` and CWE's `CWE-N`: genuinely different id spaces for genuinely
different entities referring to each other.) So unlike the other four
preprocessors, **none of D3FEND's links carry a `source_name`** - the
cross-catalog ones are indistinguishable from the local ones, and that is the
point.

### Why `weakness` and `offensive-technique` get no entity records

Both are pure mirrors of another source here (CWE and ATT&CK), and a full check
found nothing in either worth keeping separately:

- All 835 `offensive-technique` ids exist in `mitre-attack/entities.json`.
  D3FEND's `definition` was consistently a truncated prefix of ATT&CK's fuller
  `description` (781 of 835) - pure data loss, not different content - and
  D3FEND's copy lags ATT&CK on 5 renamed and 17 revoked/deprecated techniques.
- All 943 `weakness` ids exist in `CWE/entities.json`. This was a closer call:
  97.7% of `definition`s matched CWE's `Description` exactly after normalizing
  whitespace, but the remaining 2.3% had drifted both ways (D3FEND fuller in 17
  cases, CWE fuller in 5), plus a handful of D3FEND-only alternate names and one
  `comment` recovering content CWE's own preprocessor discards (`Notes`).
  Dropped anyway, accepting that small residue, for the same "just match the id"
  reason.

So `counters` links use bare `T####[.###]` ids matched against
`mitre-attack/entities.json`, and `child_of` / `weakness_of` /
`may_be_weakness_of` links use bare `CWE-N` ids matched against
`CWE/entities.json`.

D3FEND does provide a separate human-facing short code (`d3f:d3fend-id`, e.g.
`D3-AMED`), but only for `technique` records. So every link uses the stripped
`@id` throughout - one consistent join key across every type - and `d3fend_id`
is kept as an extra property on `technique` records.

## What becomes a link

- `artifact.rdfs:hasSubClass` -> `has_subclass` (artifact -> child artifact).
  Verified to resolve 100% inside this dataset's own artifacts.
- `weakness.rdfs:subClassOf` -> `child_of` (weakness -> parent weakness), the
  same `relationship_type` CWE uses for the equivalent link. 10 of 1,113 parent
  references point at the abstract root class `d3f:Weakness` rather than another
  weakness, and are dropped rather than becoming links to a non-entity.
- `weakness.d3f:weakness-of` / `d3f:may-be-weakness-of` -> `weakness_of` /
  `may_be_weakness_of` (weakness -> artifact). Both resolve 100% into this
  dataset's artifacts.
- `tactic.rdfs:subClassOf` is **dropped entirely, with no link written** - all 7
  tactics point at the same abstract root `d3f:DefensiveTactic`, not at another
  tactic. There is no real tactic-to-tactic hierarchy in this data.

`mappings/latest.json` (14,003 flattened SPARQL-result rows, one per
defence/attack trace) is mined for four kinds of link, each deduplicated against
the whole row set rather than kept as 14,003 raw rows:

- `technique --{relation}--> artifact` (166 unique; the relation is the literal
  D3FEND relation name - `analyzes`, `filters`, `isolates`). Available nowhere
  else here, since technique records carry no artifact relation of their own.
- `technique --enables--> tactic` (149, one per technique - verified stable:
  every technique maps to exactly one tactic across every row it appears in).
- `offensive-technique --{relation}--> artifact` (482 unique - `modifies`,
  `may_modify`, `creates`). Likewise D3FEND-only information layered onto
  ATT&CK's techniques; there is no local entity for the endpoint, as above.
- `technique --counters--> offensive-technique` (3,544 unique) - **the dataset's
  headline fact.** It keeps `def_artifact`, `def_artifact_rel`, `off_artifact`
  and `off_artifact_rel` as link attributes, because those explain *why* the
  technique counters that specific offensive technique: the same artifact acted
  on by both sides is the bridge. (D3FEND's *Access Modeling* counters `T1078`
  "Valid Accounts" because both act on a `UserAccount` artifact - one `maps` it,
  the other `uses` it.) One pair can legitimately have more than one link when
  more than one bridge justifies it: 3,544 links over 3,234 pairs.

Two things in a mapping row are deliberately **not** turned into links:

- `off_tech_parent` / `off_tactic` and their `*_rel` fields are ATT&CK-side
  sub-technique and tactic facts that `mitre-attack`'s own `subtechnique_of` and
  `has_tactic` links already capture, so re-deriving them would duplicate that
  dataset.
- `query_def_tech_label` / `top_def_tech_label` carry no id at all, and name
  other rungs of the technique hierarchy that happened to anchor the SPARQL
  query - not a fact about the mapped technique.

Every link gets a fixed `relationship--<uuid5>` id seeded from every attribute,
not just the triple, because `counters` links legitimately repeat a pair with a
different artifact bridge. Re-runs are byte-identical.

## Text cleanup

Every string in the output goes through `clean_record()` - whitespace
normalized, empty strings dropped, lists deduplicated, quoted markup left
untouched. The rules are the same for all five sources and are written up once
in [`../README.md`](../README.md#text-cleanup-applied-to-everything).

## Output

Two JSON files, each a plain list of records.

### `entities.json` - 1,193 records

| `type` | Count | Contents |
|---|---|---|
| `artifact` | 915 | Digital artifacts from the D3FEND Artifact Ontology - id, name, description, aliases |
| `technique` | 271 | D3FEND defensive techniques - id, name, `d3fend_id` (e.g. `D3-AMED`), aliases |
| `tactic` | 7 | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, Restore, Model) - id, name, description, display order/priority |

### `relationships.json` - 6,471 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref. Two endpoint kinds below - `offensive-technique` and `weakness` -
have no entity record here; they join by bare id against another source.

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `counters` | 3,544 | technique -> ATT&CK technique id, joining `mitre-attack/entities.json`. Carries the four artifact-bridge attributes |
| `child_of` | 1,103 | weakness -> weakness, `CWE-N` ids, joining `CWE/entities.json` |
| `has_subclass` | 995 | artifact -> artifact |
| `enables` | 149 | technique -> tactic |
| 63 D3FEND relation names | 648 | technique or ATT&CK technique -> artifact - `modifies` (107), `produces` (67), `may_modify` (56), `analyzes` (49), `accesses` (49), down to several with a single link |
| `weakness_of` | 26 | weakness -> artifact |
| `may_be_weakness_of` | 6 | weakness -> artifact |
