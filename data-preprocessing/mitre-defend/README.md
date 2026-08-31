# MITRE D3FEND Preprocessing

Reads six of the seven raw files from the D3FEND crawler
(`data-acquisition/mitre-defend/{techniques,tactics,artifacts,weaknesses,mappings,ontology}/latest.json`)
and writes two: `entities.json` (the `technique`, `tactic` and `artifact`
records, told apart by their own `type`) and `relationships.json`.

`offensive-techniques/latest.json` is not read at all,
`weaknesses/latest.json` is read only for the links embedded in it, and
`ontology/latest.json` only for the prose the `/api/*` endpoints omit - see below.

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
- `d3f:kb-article` -> `kb_article`, kept as its own field rather than appended to
  `description`. It is long-form prose on 193 techniques, several times the length
  of a definition, so a retriever wants to embed and rank the two separately.

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
`mitre-attack/entities.json`, and the weakness-side `child_of` and `weakness_of`
links use bare `CWE-N` ids matched against `CWE/entities.json`.

D3FEND does provide a separate human-facing short code (`d3f:d3fend-id`, e.g.
`D3-AMED`), but only for `technique` records. So every link uses the stripped
`@id` throughout - one consistent join key across every type - and `d3fend_id`
is kept as an extra property on `technique` records.

## What becomes a link

- `artifact.rdfs:hasSubClass` -> `child_of`, **reversed** to child -> parent.
  Verified to resolve 100% inside this dataset's own artifacts. D3FEND is the
  only source here that states its taxonomy downwards; emitting it as written
  meant a reader had to know which catalog a link came from before it could tell
  parent from child, so it is flipped to match CWE and CAPEC.
- `weakness.rdfs:subClassOf` is **dropped entirely, with no link written**. It
  restates the CWE hierarchy that `CWE/relationships.json` already carries from
  CWE's own `RelatedWeaknesses`: of the 1,103 `CWE-N -> CWE-N` links it used to
  produce, 1,079 were byte-identical to CWE's own and the 24 that were not
  contradicted rather than extended them - D3FEND files CWE-1051 under CWE-665
  where CWE itself has CWE-1419, and CWE-1265 under CWE-691 where CWE has
  CWE-662, the shape of a stale copy of an older CWE tree. Keeping it stored
  every CWE parent link twice and gave the graph two disagreeing answers for 24
  of them. The artifact hierarchy below is D3FEND's own and stays.
- `weakness.d3f:weakness-of` / `d3f:may-be-weakness-of` -> both become
  `weakness_of` (weakness -> artifact), separated by `certainty`. Both resolve
  100% into this dataset's artifacts.
- `tactic.rdfs:subClassOf` is **dropped entirely, with no link written** - all 7
  tactics point at the same abstract root `d3f:DefensiveTactic`, not at another
  tactic. There is no real tactic-to-tactic hierarchy in this data.

`mappings/latest.json` (14,003 flattened SPARQL-result rows, one per
defence/attack trace) is mined for four kinds of link, each deduplicated against
the whole row set rather than kept as 14,003 raw rows:

- `technique --{bucket}--> artifact` (166 unique). Available nowhere else here,
  since technique records carry no artifact relation of their own.
- `technique --enables--> tactic` (149, one per technique - verified stable:
  every technique maps to exactly one tactic across every row it appears in).
- `offensive-technique --{bucket}--> artifact` (482 unique). Likewise D3FEND-only
  information layered onto ATT&CK's techniques; there is no local entity for the
  endpoint, as above.
- `technique --counters--> offensive-technique` (3,544 unique) - **the dataset's
  headline fact.** It keeps the artifact bridge as link attributes, because those
  explain *why* the technique counters that specific offensive technique: the same
  artifact acted on by both sides is the bridge. (D3FEND's *Access Modeling*
  counters `T1078` "Valid Accounts" because both act on a `UserAccount` artifact -
  one `maps` it, the other `uses` it.) One pair can legitimately have more than
  one link when more than one bridge justifies it: 3,544 links over 3,234 pairs.

### Why the artifact relations are bucketed rather than kept as types

D3FEND names 70 distinct artifact relations across its two sides. Emitted one
per name, this file carried **67 `relationship_type` values, 61 of which shared
just 648 links** - `unmounts`, `injects`, `queries` and a dozen others with a
single link each. That is a schema too large to put in a retrieval prompt and too
sparse to query: a relation with one link cannot support an answer or an
algorithm.

It also misread the source. In D3FEND's own ontology these are **properties**
(`d3f:analyzes`, `d3f:monitors`), not classes, and the `counters` rows already
carry them as attributes - so promoting them to types was never what the catalog
meant.

Each relation now maps to one of **eight buckets**, with the original name kept
on the link as `verb`. `relationship_type` is coarse enough to traverse and to
name in a prompt; `verb` recovers the exact original. Verified lossless: every
one of the 6,471 links from the previous output reconstructs exactly, and no link
appears that was not there before.

Buckets are **per side**, because the same verb means opposite things depending
on who performs it - an attack that `deletes` a log is destroying evidence, a
defence that `deletes` a file is evicting a threat. The side is never inferred:
defensive and offensive relations arrive in different columns of the mappings
export.

| Side | Bucket | Means |
|---|---|---|
| offensive | `accesses` | reaches or reads an artifact without changing it |
| offensive | `creates` | brings one into being, or places one |
| offensive | `modifies` | changes, damages or falsifies an existing one |
| offensive | `executes` | causes one to run |
| defensive | `observes` | looks at one to learn from it |
| defensive | `constrains` | stops or limits what can be done with it |
| defensive | `hardens` | changes it so it resists attack, deception included |
| defensive | `restores` | removes one or puts it back as it was |

D3FEND hedges a relation by prefixing `may-`. That is a confidence, not a
different relation, so it becomes `certainty: "possible"` on the link and the
verb keeps its asserted spelling - collapsing eleven further types. This also
fixes a spelling split: raw D3FEND writes the hedge with a hyphen inside the
`counters` attributes (`may-modify`) but the standalone links arrived with an
underscore (`may_modify`), so one fact was spelled two ways in one file.

An unrecognised relation raises `ParseError` rather than passing through. A
D3FEND release that adds a verb fails the run loudly here, instead of arriving
silently in the output as an unmapped 68th type.

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
| `artifact` | 915 | Digital artifacts from the D3FEND Artifact Ontology - id, name, description (867 of 915), aliases |
| `technique` | 271 | D3FEND defensive techniques - id, name, `d3fend_id` (e.g. `D3-AMED`), description, `kb_article` (191 of 271), aliases |
| `tactic` | 7 | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, Restore, Model) - id, name, description, display order/priority |

1,145 of the 1,193 carry a `description`; the 48 that do not are artifacts the
ontology never defines. Before `ontology/latest.json` was read that figure was
**15** - the `/api/*` endpoints return identity fields only, so the whole
defensive catalog reached the graph with no text to embed or search.

### `relationships.json` - 5,056 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref. Two endpoint kinds below - `offensive-technique` and `weakness` -
have no entity record here; they join by bare id against another source.

12 `relationship_type` values, down from 67. Links carrying a bucket also carry
`verb` (the original D3FEND relation name) and `certainty` (`asserted` or
`possible`).

**One edge per (source, type, target).** D3FEND states some links more than once,
each statement carrying different attributes -- one defensive technique countering the same
ATT&CK technique through four different digital-artifact pairs. Those used to be written
straight through as parallel edges between the same two nodes, which made
`degree()` count a node's statements rather than its neighbours; retrieval that
caps expansion by node degree read that as a much busier graph than it is.
`collapse_parallel_relationships()` now merges each group into one record:
attributes that are the same across the group stay scalar, attributes that differ
become index-aligned lists (entry `i` of each belongs to the same original
statement, `""` where a statement did not carry the field, since Neo4j rejects a
list property holding a null), and
`merged_fields` names those lists so they can be told from a field that was
already multi-valued on one statement. 295 of the links here are merged records;
nothing is dropped, and expanding them reproduces the pre-merge file exactly.

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `counters` | 3,234 | technique -> ATT&CK technique id, joining `mitre-attack/entities.json`. Carries the artifact-bridge attributes |
| `child_of` | 995 | artifact -> artifact, reversed from `hasSubClass`. The weakness hierarchy that used to add 1,103 more is dropped as CWE's own, see above |
| `enables` | 149 | technique -> tactic |
| `modifies` | 181 | ATT&CK technique -> artifact |
| `creates` | 153 | ATT&CK technique -> artifact |
| `accesses` | 87 | ATT&CK technique -> artifact |
| `observes` | 81 | technique -> artifact |
| `executes` | 59 | ATT&CK technique -> artifact |
| `constrains` | 41 | technique -> artifact |
| `weakness_of` | 32 | weakness -> artifact (26 `asserted`, 6 `possible`) |
| `hardens` | 28 | technique -> artifact |
| `restores` | 16 | technique -> artifact |
