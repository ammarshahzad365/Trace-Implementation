# MITRE ATT&CK Preprocessing

Merges the three raw STIX 2.1 bundles from the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) into one
deduplicated pair of trimmed files — `entities.json` and `relationships.json` —
with each record's own `type` distinguishing the fourteen entity kinds, and every
embedded id-list field split out into explicit edges.

## Usage

```
py mitre_attack_preprocessing.py
```

Optional flags: `--input` (the ATT&CK crawler's workspace, containing
`enterprise/`/`mobile/`/`ics/` — default: the crawler's own output) and
`--output-dir` (default: this folder).

## Why one merged output instead of three parallel ones

Unlike CWE/CAPEC/CVE, ATT&CK ships three domain bundles that legitimately share
entities: a group, malware, campaign or data component tracked across matrices
keeps the *same* STIX id in every bundle it appears in, each copy carrying its
own `x_mitre_domains`. Techniques, analytics, detection strategies, tools,
tactics, mitigations and matrices never repeat an id across domains. So this
script merges all three into one object set keyed by STIX id, rather than writing
three per-domain folders that would triple-store every shared group. For ids
appearing in more than one bundle (checked directly — differences were found in
`x_mitre_domains` only), the domain lists are unioned and every other field taken
from whichever copy has the later `modified` timestamp.

## Ids are the human-readable ATT&CK id, not the STIX id

Like this project's other four sources, entities are keyed by a human-readable id
(`T1055`, `T1003.008`, `S0002`, `G0016`, `M1013`, `C0028`, `TA0009`, `DS0026`,
`DET0210`, `AN0001`, `DC0103`, `A0008`, or a matrix's own domain string),
extracted from `external_references`' `mitre-attack` entry — or, on a few legacy
revoked/deprecated records, `mitre-ics-attack`/`mitre-mobile-attack`. The STIX id
is kept as `stix_id`, the same convention CAPEC/CVE use. An entity with no such
reference keeps its STIX id as `id`: a defensive fallback, not exercised by any
record in this dataset.

An ATT&CK id is only unique **within its own object type** upstream. 226 ids are
each claimed by more than one object: 224 deprecated pre-2019 `course-of-action`
records reuse the `T####` of the technique they mitigate (mitigations only got
`M####` numbering later), plus one straight duplicate each in `malware` (`S0017`:
active *BISCUIT* vs. deprecated *EKANS*) and `x-mitre-matrix` (`mobile-attack`:
active *Mobile ATT&CK* vs. its deprecated predecessor *Network-Based Effects*).
These are resolved by **deleting the losing side** rather than keeping it under a
fallback id:

- Technique/mitigation collision → the technique wins. The id originally belonged
  to it, and some of these techniques, though later revoked in favour of a
  sub-technique, are this project's *only* source of a CAPEC cross-reference (all
  36 such edges come from exactly this bucket).
- The two same-type collisions → whichever side is active
  (`x_mitre_deprecated`/`revoked` both false/absent).
- No clear winner → drop every member and log a warning. Not hit by any ATT&CK
  release so far, but a safe default.

226 objects are dropped this way (224 `course-of-action`, 1 `malware`, 1
`x-mitre-matrix`) and 0 `attack-pattern`; any edge pointing at a dropped object
goes with it. Verified after every run: every remaining id is globally unique and
every endpoint resolves.

## What it does

- Drops `identity`, `marking-definition` and `x-mitre-collection` — STIX
  attribution/collection-manifest boilerplate.
- Keeps every other type, reduced to a whitelist (`*_FIELDS` in the script).
- The output `type` renames STIX's `attack-pattern` → `attack-technique` and
  `course-of-action` → `attack-mitigation` (the STIX type is unchanged everywhere
  else it appears, e.g. `kill_chain_phases` matching, and CAPEC's own records are
  untouched). CAPEC reuses those two STIX types for its own unrelated attack
  patterns and mitigations; left as-is they'd be the only `type` values shared by
  two catalogs in the whole project, merging two catalogs' distinct entities under
  one Neo4j label.
- `external_references` is never kept verbatim beyond that id extraction: `capec`
  entries become `T#### --related-to--> CAPEC-N` edges carrying
  `source_name: "capec"` (the reverse of CAPEC's own), and every other entry is a
  bibliographic citation with no local entity, dropped with the field — the same
  treatment CWE gives `References`/`Notes`.
  `campaign.x_mitre_first_seen_citation`/`x_mitre_last_seen_citation` go for the
  same reason, though `first_seen`/`last_seen` are kept.
- `revoked`/`x_mitre_deprecated` objects are **kept** (unlike CVE's `Rejected`
  records, and unlike the 226 collision-losers, which are dropped for being a
  duplicate id, not for being revoked): both flags become attributes instead,
  since ATT&CK's own `revoked-by` edges point *at* revoked objects and dropping
  them would leave those edges dangling.
- `malware`/`tool` spell their alias list `x_mitre_aliases` where
  `intrusion-set`/`campaign` use STIX's `aliases`; output unifies both on
  `aliases`, also what CWE/CAPEC/D3FEND call it.
- Dropped as bookkeeping with no graph value: `x_mitre_contributors` (write-up
  credits), `x_mitre_version` (internal revision counter), a tactic's
  `x_mitre_shortname` (a slug of its own `name`, needed only to match
  `kill_chain_phases`, done before output), and
  `x-mitre-asset.x_mitre_related_assets` (see below).
- These embedded id-list fields are removed and rebuilt as edges, using each
  endpoint's resolved `id`:
  - `attack-pattern.kill_chain_phases` → `has_tactic`. ATT&CK has no
    `relationship` object for technique-to-tactic membership at all — it's a
    string match between `phase_name` and `x-mitre-tactic.x_mitre_shortname`,
    scoped to the domain implied by `kill_chain_name`. Tactic shortnames are
    unique within a domain, so the match is unambiguous.
  - `x-mitre-matrix.tactic_refs` → `has_member` (matrix → tactic), mirroring the
    `has_member` edges CWE derives from its own `HasMember` fields.
  - `x-mitre-detection-strategy.x_mitre_analytic_refs` → `has_analytic`.
  - `x-mitre-analytic.x_mitre_log_source_references[].x_mitre_data_component_ref`
    → `uses_data_component`, with the log source as an edge attribute
    (`log_source_ref`) alongside `channel`.
  - `x-mitre-data-component.x_mitre_log_sources[].name` → `has_log_source`, with
    `channel` as an edge attribute — see below.
- `x-mitre-data-source` is kept as a plain entity list with no edges to
  `x-mitre-data-component`: a from-scratch grep found zero `data_source_ref`
  occurrences anywhere, so the two have no formal link left in this release —
  the type looks legacy now that analytics point straight at data components.
- `x-mitre-asset.x_mitre_related_assets` stays an attribute rather than becoming
  an edge: it references narrower device sub-types by free-text name (41 of 43
  don't match any other asset's `name` at all — e.g. `Application Server` →
  `File Server`), not another asset by id, so there's nothing to resolve.
- Native `relationship` objects (`uses`, `mitigates`, `detects`,
  `subtechnique-of`, `revoked-by`, `attributed-to`, `targets`) are kept, with
  their endpoints rewritten through the same id resolution, so every edge here
  joins on one id space. `revoked`/`x_mitre_deprecated` are dropped from edges
  specifically — verified always false/absent across all 24,582.
  `external_references` go for the usual bibliography reason; `description` is
  kept, since unlike CWE/CAPEC edges ATT&CK's carry real analytic content (*how*
  a piece of malware uses a technique).
- Edges built by this script get a deterministic `relationship--<uuid5>` id
  seeded from every attribute, not just the triple: some derived edges
  (`uses_data_component`) legitimately repeat the same triple with different
  attributes (two log-source channels feeding one data component). Reruns stay
  byte-identical.

## Nothing in the output nests

Neo4j properties hold scalars or homogeneous scalar arrays, never maps. ATT&CK
had exactly two `list[map]` fields, unpacked differently because the two shapes
mean different things:

- **`x-mitre-data-component.x_mitre_log_sources`** (3,165 `{name, channel}` maps
  across 114 of 123 components) → **`log-source` entities plus `has_log_source`
  edges.** `name` is a genuine shared vocabulary — 351 colon-namespaced codes
  (`WinEventLog:Security`, `AWS:CloudTrail`, `macos:unifiedlog`) reused across
  components — so it earns its own type. That also fixes a modelling gap: the log
  source already carried on 5,042 `uses_data_component` edges was a bare string
  with no node behind it, and is now a `log_source_ref` resolving to a real entity
  (all 309 names used there are among the 351; 0 dangling). A log source's `id` is
  its name prefixed with its type (`log-source--AWS:CloudTrail`), because 7 of the
  351 are bare words (`File`, `Process`, `Network`, `Command`, `Certificate`,
  `Firmware`, `Metadata`) that D3FEND also uses as artifact ids — unprefixed
  they'd be the only ids in the project claimed by two catalogs. The bare name
  stays as `name`. `channel` stays an *edge* attribute rather than joining the
  identity: 43% of its values run past 60 characters of analyst prose (`"Unusual
  kinit or klist activity"`), so it's a note about this component's use of that
  log source, not an identifier. Deleting the field instead would have lost 212
  `(component, name, channel)` facts and 42 names appearing nowhere else.
- **`x-mitre-analytic.x_mitre_mutable_elements`** (5,177 `{field, description}`
  maps across 1,793 of 2,066 analytics) → **two flat string lists, no new
  entity.** Promoting these to nodes was rejected on the numbers: 2,892 distinct
  `field` names, **83% used by exactly one analytic**, and 5,145 distinct
  descriptions — a node per tunable parameter would be roughly one node per edge,
  with nothing to traverse. What *is* queryable is the field name alone (25 are
  shared by 10+ analytics — `TimeWindow` ×659, `UserContext` ×246), so those
  become `x_mitre_mutable_element_fields`. The tuning prose is preserved
  losslessly as `x_mitre_mutable_element_notes` — `"field -- description"`
  strings, chosen over an index-aligned parallel list because Cypher can't enforce
  alignment (the ` -- ` separator is verified absent from every field name and
  description, so notes round-trip on a split).

One upstream bug is normalized here: 184 raw `x_mitre_log_sources` entries carry
the **literal string `"None"`** as `channel` rather than JSON `null` (a
`str(None)` leak on MITRE's side). Left alone that loads as a real value and
pollutes any `channel` filter, so `clean_channel()` treats `"None"`/blank as
"attribute absent" on both edge types — 84 and 521 edges respectively now simply
have no `channel` key.

## Output

Two JSON files, each a plain array of records.

### `entities.json` — 6,052 records

| `type` | Count | Contents |
|---|---|---|
| `x-mitre-analytic` | 2,066 | Detection analytics — id, stix_id, name, description, platforms, mutable-element field names + notes |
| `attack-technique` | 1,166 | Techniques/sub-techniques (STIX `attack-pattern`) — id, stix_id, name, description, platforms, sub-technique flag, and (ICS-only) tactic type/impact type/remote support |
| `x-mitre-detection-strategy` | 920 | Detection strategies — id, stix_id, name |
| `malware` | 862 | Malware — id, stix_id, name, description, platforms, aliases, `is_family` |
| `log-source` | 351 | Log sources — id (`log-source--WinEventLog:Security`), name. Synthesized from data components' embedded maps; no STIX object of its own, hence no `stix_id` |
| `intrusion-set` | 193 | Threat groups — id, stix_id, name, description, aliases |
| `x-mitre-data-component` | 123 | Log data components — id, stix_id, name, description |
| `attack-mitigation` | 110 | Mitigations (STIX `course-of-action`) — id, stix_id, name, description, compliance-framework labels |
| `tool` | 97 | Tools — id, stix_id, name, description, platforms, aliases |
| `campaign` | 60 | Named campaigns — id, stix_id, name, description, aliases, first/last seen |
| `x-mitre-data-source` | 42 | Log data sources — id, stix_id, name, description, collection layers, platforms |
| `x-mitre-tactic` | 41 | Tactics — id, stix_id, name, description |
| `x-mitre-asset` | 18 | ICS physical/logical assets — id, stix_id, name, description, platforms, sectors |
| `x-mitre-matrix` | 3 | Matrix groupings — id, stix_id, name, description |

`attack-mitigation` and `x-mitre-matrix` are smaller than a raw object count
suggests (334→110, 4→3) because of the id-collision deletions above, not any
additional filtering.

### `relationships.json` — 36,346 records

Every record is `type: "relationship"` with id, relationship_type, source_ref and
target_ref. Three origins share the file: hyphenated `relationship_type`s are
ATT&CK's native STIX edges, underscored ones are derived from embedded id-list
fields, and `related-to` is the cross-catalog edge — the only one carrying
`source_name`:

| `relationship_type` | Count | Endpoints | Origin |
|---|---|---|---|
| `uses` | 19,988 | group/campaign/malware → technique, and more | native |
| `uses_data_component` | 5,042 | analytic → data-component | derived |
| `has_log_source` | 3,165 | data-component → log-source | derived |
| `has_analytic` | 2,066 | detection-strategy → analytic | derived |
| `mitigates` | 2,017 | mitigation → technique | native |
| `has_tactic` | 1,446 | technique → tactic | derived |
| `detects` | 918 | detection-strategy → technique | native |
| `targets` | 842 | technique → ICS asset | native |
| `subtechnique-of` | 542 | sub-technique → technique | native |
| `revoked-by` | 218 | revoked object → its replacement | native |
| `has_member` | 39 | matrix → tactic | derived |
| `related-to` | 36 | `T####` → `CAPEC-N` (`source_name: "capec"`) | external |
| `attributed-to` | 27 | campaign → group | native |

Every entity carries `id` and `stix_id` (except `log-source`, which has no
upstream STIX object to trace back to), and every edge — native, derived and
external alike — uses those same `id` values as endpoints. Verified after every
run: none of the 36,346 rows carries a raw STIX id in either column, and every
endpoint resolves to an entity that exists.
