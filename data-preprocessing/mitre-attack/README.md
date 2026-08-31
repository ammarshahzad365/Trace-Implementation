# MITRE ATT&CK Preprocessing

Merges the three raw STIX 2.1 bundles from the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) into one
deduplicated pair of files - `entities.json` and `relationships.json` - with
each record's own `type` naming which of the fourteen kinds it is, and every
embedded id-list field pulled out into explicit links.

## Usage

```
py mitre_attack_preprocessing.py
```

Optional flags: `--input` (the ATT&CK crawler's workspace, containing
`enterprise/`, `mobile/` and `ics/` - default: the crawler's own output) and
`--output-dir` (default: this folder).

## Why one merged file instead of three

Unlike CWE, CAPEC and CVE, ATT&CK ships three domain bundles that genuinely
share entities. A group, malware, campaign or data component tracked across
matrices keeps the *same* STIX id in every bundle it appears in, with each copy
carrying its own `x_mitre_domains`. (Techniques, analytics, detection
strategies, tools, tactics, mitigations and matrices never repeat an id across
domains.)

So this script merges all three into one set keyed by STIX id, instead of
writing three per-domain folders that would store every shared group three
times. Where an id appears in more than one bundle, the domain lists are
combined and every other field is taken from whichever copy has the later
`modified` timestamp. (Checked directly: `x_mitre_domains` was the only field
that ever differed.)

## Ids are the readable ATT&CK id, not the STIX id

Like the project's other four sources, entities are keyed by a readable id -
`T1055`, `T1003.008`, `S0002`, `G0016`, `M1013`, `C0028`, `TA0009`, `DET0210`,
`AN0001`, `DC0103`, `A0008`, or a matrix's own domain string. It is
taken from the `mitre-attack` entry in `external_references` (or, on a few old
revoked/deprecated records, `mitre-ics-attack` / `mitre-mobile-attack`). The
STIX id is kept as `stix_id`, the same convention CAPEC and CVE use. An entity
with no such reference keeps its STIX id as `id` - a safety net that no record
in this dataset actually needs.

### Resolving duplicate ids

Upstream, an ATT&CK id is only unique **within its own object type**. 226 ids
are claimed by more than one object:

- 224 deprecated pre-2019 `course-of-action` records reuse the `T####` of the
  technique they mitigate (mitigations only got their own `M####` numbering
  later).
- One duplicate in `malware` (`S0017`: active *BISCUIT* vs deprecated *EKANS*).
- One in `x-mitre-matrix` (`mobile-attack`: active *Mobile ATT&CK* vs its
  deprecated predecessor *Network-Based Effects*).

These are settled by **deleting the loser**, not by giving it a fallback id:

- Technique vs mitigation -> the technique wins. The id was originally the
  technique's, and some of these techniques - though later revoked in favour of
  a sub-technique - are this project's *only* source of a CAPEC cross-reference
  (all 36 such links come from exactly this group).
- Two objects of the same type -> whichever is active wins
  (`x_mitre_deprecated` and `revoked` both false or absent).
- No clear winner -> drop them all and log a warning. No ATT&CK release has hit
  this yet, but it is a safe default.

226 objects are dropped this way (224 `course-of-action`, 1 `malware`, 1
`x-mitre-matrix`) and 0 `attack-pattern`; any link pointing at a dropped object
goes with it. Checked after every run: every remaining id is globally unique and
every link endpoint resolves.

## What it does

- Drops `identity`, `marking-definition` and `x-mitre-collection` - STIX
  attribution and manifest boilerplate.
- Keeps every other type, cut down to a whitelist (the `*_FIELDS` lists in the
  script).
- Renames two output `type` values: STIX `attack-pattern` ->
  `attack-technique`, and `course-of-action` -> `attack-mitigation`. (The STIX
  type is left alone everywhere else it appears, e.g. `kill_chain_phases`
  matching, and CAPEC's own records are untouched.) CAPEC reuses those two STIX
  types for its own, unrelated attack patterns and mitigations; left as they
  were, they would be the only `type` values shared by two catalogs in the whole
  project, merging two catalogs' distinct entities under one `type`.
- `external_references` is not kept beyond the id extraction. `capec` entries
  become `T#### --related_to--> CAPEC-N` links carrying `source_name: "capec"`
  (the reverse of CAPEC's own); everything else is a citation with no matching
  entity here and is dropped with the field - the same treatment CWE gives
  `References`/`Notes`. `campaign.x_mitre_first_seen_citation` and
  `x_mitre_last_seen_citation` go for the same reason, though `first_seen` and
  `last_seen` are kept.
- `revoked` and `x_mitre_deprecated` objects are **kept**, with both flags
  becoming attributes. (This is unlike CVE's `Rejected` records, and unlike the
  226 duplicate-id losers - those are dropped for having a duplicate id, not for
  being revoked.) They stay because ATT&CK's own `revoked_by` links point *at*
  revoked objects, and dropping them would leave those links dangling.
- `malware` and `tool` spell their alias list `x_mitre_aliases`, while
  `intrusion-set` and `campaign` use STIX's `aliases`. Both come out as
  `aliases` - also what CWE, CAPEC and D3FEND call it.
- Dropped as bookkeeping with no value here: `x_mitre_contributors`
  (write-up credits), `x_mitre_version` (an internal revision counter), a
  tactic's `x_mitre_shortname` (a slug of its own `name`, needed only to match
  `kill_chain_phases`, which happens before output), and
  `x-mitre-asset.x_mitre_related_assets` (see below).
- These embedded id-list fields are removed and rebuilt as links, using each
  endpoint's resolved `id`:
  - `attack-pattern.kill_chain_phases` -> `has_tactic`. ATT&CK has **no**
    relationship object for technique-to-tactic membership at all; it is a string
    match between `phase_name` and `x-mitre-tactic.x_mitre_shortname`, scoped to
    the domain named by `kill_chain_name`. Tactic shortnames are unique within a
    domain, so the match is unambiguous.
  - `x-mitre-matrix.tactic_refs` -> `has_member` (matrix -> tactic), mirroring
    the `has_member` links CWE builds from its own `HasMember` fields.
  - `x-mitre-detection-strategy.x_mitre_analytic_refs` -> `has_analytic`.
  - `x-mitre-analytic.x_mitre_log_source_references[].x_mitre_data_component_ref`
    -> `uses_data_component`, with the log source name kept as a link attribute
    (`log_source`) alongside `channel`.
- `x-mitre-data-source` is **dropped**. A from-scratch grep found zero
  `data_source_ref` anywhere in the bundle, so nothing points at these 42 records
  and they point at nothing - after preprocessing all 42 came out with zero links
  in either direction, and 19 were already `revoked`. The model moved: analytics
  now reach detection data through `x-mitre-data-component`, which carries its
  log sources as properties. Keeping them would add 42 nodes no trace can ever cross, so
  they go, the same call made for CAPEC's skill levels and CWE's alias
  "entities". Their 42 names and descriptions are the whole cost.
- `x-mitre-asset.x_mitre_related_assets` stays an attribute rather than becoming
  links: it names narrower device sub-types as free text (41 of 43 match no
  other asset's `name` at all - e.g. `Application Server` -> `File Server`), not
  another asset by id, so there is nothing to resolve.
- Native `relationship` objects (`uses`, `mitigates`, `detects`,
  `subtechnique_of`, `revoked_by`, `attributed_to`, `targets`) are kept, with
  their endpoints rewritten through the same id resolution, so every link joins
  on one id space. STIX spells three of those with a hyphen
  (`subtechnique-of`, `revoked-by`, `attributed-to`); they are rewritten to
  snake_case, so that every relationship type in the output is spelled one way. `revoked`/`x_mitre_deprecated` are dropped from links specifically -
  verified always false or absent across all 24,582. `external_references` go
  for the usual citation reason, but `description` is kept: unlike CWE's and
  CAPEC's, ATT&CK's links carry real content (*how* a piece of malware uses a
  technique).
- Links built by this script get a fixed `relationship--<uuid5>` id seeded from
  every attribute, not just the triple - some derived links
  (`uses_data_component`) legitimately repeat a triple with different attributes
  - 57 of its 4,966 analytic/component pairs appear more than once, naming a
  different log source or channel each time. Re-runs stay byte-identical.

## Nothing in the output nests

Every value in the output is a single value or a list of single values, never a
map. ATT&CK had exactly two map-list fields, unpacked differently because the two
shapes mean different things.

**`x-mitre-data-component.x_mitre_log_sources`** (3,165 `{name, channel}` maps
across 114 of 123 components) **flattens onto the data component** as a
`log_sources` list plus a `log_source_notes` list.

`name` is a real shared vocabulary - 348 mostly colon-namespaced codes
(`WinEventLog:Security`, `AWS:CloudTrail`, `macos:unifiedlog`) reused across
components - and it did become its own entity type at first. That was the wrong
shape. A code is a label on the component, not a thing the component points at,
and those 348 nodes held nothing but their own name: `{id, type, name}`, with the
`id` just the `name` with a prefix glued on.

The `channel` field is what made it worse. It is free-text analyst prose (43% of
values run past 60 characters, `"Unusual kinit or klist activity"`) that varies
per mention, and as a link attribute it forced one link per channel rather than
one per fact. The result was **3,165 links carrying only 999 real
(component, log source) pairs** - `DC0085 -> NSM:Flow` alone repeated **150
times**, once for each channel string. Flattened, the name is listed once in
`log_sources` and every channel rides a self-labelling
`"NSM:Flow -- mqtt.log, xmpp.log, amqp.log"` string in `log_source_notes`, the
shape `alias_notes` and `mutable_element_notes` already use. Nothing is lost: all
999 pairs and all 3,081 channel facts survive. Details:

- Names are still trimmed before they are deduplicated: three upstream names
  carry a trailing space (`"networkconfig "`) and would otherwise survive
  alongside their trimmed twin.
- The prefixed id (`log-source--AWS:CloudTrail`) existed because 7 of the 348 are
  bare words (`File`, `Process`, `Network`, `Command`, `Certificate`, `Firmware`,
  `Metadata`) that D3FEND also uses as artifact ids - unprefixed they would have
  been the only ids in the project claimed by two catalogs. With no node, there is
  no id to collide, and the problem goes away rather than being worked around.
- The 5,042 `uses_data_component` links keep their log source as a plain
  `log_source` name instead of a `log_source_ref` id. All 307 names used there
  also appear in some component's `log_sources`, which is where they resolve.

**`x-mitre-analytic.x_mitre_mutable_elements`** (5,177 `{field, description}`
maps across 1,793 of 2,066 analytics) becomes **two flat string lists, no new
entity.** Turning these into nodes was rejected on the numbers: 2,892 distinct
`field` names, **83% used by exactly one analytic**, and 5,145 distinct
descriptions - roughly one node per link, with nothing to traverse. What *is*
queryable is the field name alone (25 are shared by 10+ analytics -
`TimeWindow` x659, `UserContext` x246), so those become
`x_mitre_mutable_element_fields`. The tuning prose is kept losslessly as
`x_mitre_mutable_element_notes` - `"field -- description"` strings, chosen over
two lists lined up by position because nothing keeps two separate lists aligned.
The ` -- ` separator is verified absent from every field name, description, log
source name and channel, so the notes split back apart cleanly. (51 channels do
contain `--`, always as a command-line flag like `log stream --predicate`, never
with a space on both sides.)

One upstream bug is fixed here: 184 raw `x_mitre_log_sources` entries carry the
**literal string `"None"`** as `channel` instead of JSON `null` (a `str(None)`
leak on MITRE's side). Left alone it loads as a real value and pollutes any
`channel` filter, so `clean_channel()` treats `"None"` and blank as "field
absent" wherever it appears - 521 `uses_data_component` links and the
component-side entries now simply have no `channel`.

## Text cleanup

Every string in the output goes through `clean_record()` - whitespace
normalized, empty strings dropped, lists deduplicated, quoted markup left
untouched. The rules are the same for all five sources and are written up once
in [`../README.md`](../README.md#text-cleanup-applied-to-everything).

Two ATT&CK-specific details on top of that:

- ATT&CK writes a literal `"None"` string (not JSON null) where a field does not
  apply - 184 log-source `channel` values and 179 `x_mitre_platforms` entries.
  Those are dropped, leaving the property absent.
- Descriptions keep their native markdown and the inline `<code>` tags ATT&CK
  writes them with. Unlike CAPEC's XHTML wrapper, that markup marks *which part
  of the prose is a literal* (a path, a command), so flattening it would lose
  information rather than remove noise.

## Output

Two JSON files, each a plain list of records.

### `entities.json` - 5,659 records

| `type` | Count | Contents |
|---|---|---|
| `x-mitre-analytic` | 2,066 | Detection analytics - id, stix_id, name, description, platforms, mutable-element field names + notes |
| `attack-technique` | 1,166 | Techniques and sub-techniques (STIX `attack-pattern`) - id, stix_id, name, description, platforms, sub-technique flag, and (ICS only) tactic type, impact type, remote support |
| `x-mitre-detection-strategy` | 920 | Detection strategies - id, stix_id, name |
| `malware` | 862 | Malware - id, stix_id, name, description, platforms, aliases, `is_family` |
| `intrusion-set` | 193 | Threat groups - id, stix_id, name, description, aliases |
| `x-mitre-data-component` | 123 | Log data components - id, stix_id, name, description |
| `attack-mitigation` | 110 | Mitigations (STIX `course-of-action`) - id, stix_id, name, description, compliance-framework labels |
| `tool` | 97 | Tools - id, stix_id, name, description, platforms, aliases |
| `campaign` | 60 | Named campaigns - id, stix_id, name, description, aliases, first/last seen |
| `x-mitre-tactic` | 41 | Tactics - id, stix_id, name, description |
| `x-mitre-asset` | 18 | ICS physical and logical assets - id, stix_id, name, description, platforms, sectors |
| `x-mitre-matrix` | 3 | Matrix groupings - id, stix_id, name, description |

`attack-mitigation` and `x-mitre-matrix` are smaller than the raw object counts
suggest (334 -> 110, 4 -> 3) because of the duplicate-id deletions above, not
any extra filtering.

### `relationships.json` - 33,105 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref. Three origins share the file - ATT&CK's own STIX links, links
derived from embedded id-list fields, and `related_to`, the cross-catalog link
and the only one carrying `source_name`. The name alone no longer tells you
which is which (every type is snake_case now), so the Origin column says it.

**One edge per (source, type, target).** ATT&CK states some links more than once,
each statement carrying different attributes -- one analytic naming the same data
component under two different `log_source`/`channel` pairs. Those used to be written
straight through as parallel edges between the same two nodes, which made
`degree()` count a node's statements rather than its neighbours; retrieval that
caps expansion by node degree read that as a much busier graph than it is.
`collapse_parallel_relationships()` now merges each group into one record:
attributes that are the same across the group stay scalar, attributes that differ
become index-aligned lists (entry `i` of each belongs to the same original
statement, `null` where a statement did not carry the field), and
`merged_fields` names those lists so they can be told from a field that was
already multi-valued on one statement. 57 of the links here are merged records;
nothing is dropped, and expanding them reproduces the pre-merge file exactly.

| `relationship_type` | Count | Endpoints | Origin |
|---|---|---|---|
| `uses` | 19,988 | group/campaign/malware -> technique, and more | native |
| `uses_data_component` | 4,966 | analytic -> data-component, carrying `log_source` and `channel` | derived |
| `has_analytic` | 2,066 | detection-strategy -> analytic | derived |
| `mitigates` | 2,017 | mitigation -> technique | native |
| `has_tactic` | 1,446 | technique -> tactic | derived |
| `detects` | 918 | detection-strategy -> technique | native |
| `targets` | 842 | technique -> ICS asset | native |
| `subtechnique_of` | 542 | sub-technique -> technique | native |
| `revoked_by` | 218 | revoked object -> its replacement | native |
| `has_member` | 39 | matrix -> tactic | derived |
| `related_to` | 36 | `T####` -> `CAPEC-N` (`source_name: "capec"`) | external |
| `attributed_to` | 27 | campaign -> group | native |

Every entity carries `id` and `stix_id`, and every link - native, derived and
external alike - uses those `id` values as endpoints. Checked after every run:
none of the 33,105 rows carries a raw STIX id in either column, and every
endpoint resolves to an entity that exists.
