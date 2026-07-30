# MITRE ATT&CK Preprocessing

Merges the three raw STIX 2.1 bundles from the ATT&CK crawler
(`data-acquisition/mitre-attack/{enterprise,mobile,ics}/latest.json`) into
one deduplicated set of trimmed entity/relationship files, splitting every
embedded id-list field out into explicit relationship records.

## Usage

```
py mitre_attack_preprocessing.py
```

Optional flags: `--input` (path to the ATT&CK crawler's workspace directory,
containing `enterprise/`/`mobile/`/`ics/` subfolders — default: the ATT&CK
crawler's own output) and `--output-dir` (default: this folder).

## Why one merged output instead of three parallel ones

Unlike CWE/CAPEC/CVE, ATT&CK ships as three domain bundles that legitimately
share entities: a threat group, piece of malware, campaign, or data
component tracked across multiple matrices keeps the *same* STIX id in
every domain bundle it appears in (each copy carries its own
`x_mitre_domains` list, e.g. `["enterprise-attack", "ics-attack"]`).
Techniques, analytics, detection strategies, tools, tactics, mitigations,
and matrices never repeat an id across domains — each domain has its own
distinct set. Given that split, this script merges all three domains into
one deduplicated object set keyed by STIX id, rather than writing three
parallel per-domain folders that would triple-store every shared threat
group. For ids that appear in more than one domain bundle (checked
directly — differences were found in `x_mitre_domains` only), the
`x_mitre_domains` lists are unioned and every other field is taken from
whichever copy has the later `modified` timestamp.

## Ids: every entity's own `id` is its human-readable ATT&CK id, not its STIX id

Unlike this project's other four sources — whose preprocessors all key
entities by a human-readable id (`CAPEC-N`, `CVE-N`, `CWE-N`) — this script
used to leave `id` as the raw STIX `<type>--<uuid>` and carry the
human-readable code in a separate `attack_id` attribute instead. That's now
fixed: `id` is the ATT&CK id (`T1055`, `T1003.008` for a sub-technique,
`S0002`, `G0016`, `M1013`, `C0028`, `TA0009`, `DS0026`, `DET0210`, `AN0001`,
`DC0103`, `A0008`, or a matrix's own domain string,
`enterprise-attack`/`mobile-attack`/`ics-attack`) wherever one exists,
extracted from `external_references`' `mitre-attack` entry (or, on a
handful of legacy revoked/deprecated records, `mitre-ics-attack`/
`mitre-mobile-attack`). The original STIX id is kept alongside as `stix_id`
on every record — the same convention CAPEC/CVE use for their own `stix_id`.

An entity with no `external_references` entry to extract an id from at all
simply keeps its STIX id as `id` instead — a defensive fallback, not
currently exercised by any record in this dataset (verified: every
`attack-pattern`/`malware` object in the current bundles has one).

An ATT&CK id is only unique **within its own object type** upstream, not
globally — 226 ids are each claimed by more than one object in the merged
set: 224 deprecated pre-2019 `course-of-action` records reuse the `T####`
id of the technique they mitigate (mitigations only got their own `M####`
numbering later), plus one straight duplicate each in `malware` (`S0017`:
active `BISCUIT` vs. deprecated `EKANS`) and `x-mitre-matrix`
(`mobile-attack`: active "Mobile ATT&CK" vs. its deprecated predecessor
"Network-Based Effects"). These are resolved by **deleting the losing
side** rather than keeping it under a fallback id:

- For a technique/mitigation collision, the technique always wins and the
  mitigation is dropped — the id originally belonged to the technique, and
  some of these techniques, though later revoked in favor of a
  subtechnique, are the *only* source of a CAPEC cross-reference this
  project has for them (all 36 rows of `external_relationships.json` come
  from exactly this bucket) — keeping a revoked technique beats deleting
  the one link to CAPEC it carries.
- For the two same-type collisions (`malware`, `x-mitre-matrix`), whichever
  side is active (`x_mitre_deprecated`/`revoked` both false/absent) wins.
- A collision matching neither rule (no clear winner) drops every member
  and logs a warning — not currently hit by any ATT&CK release, but a safe
  default if a future one produces one.

226 objects are dropped this way (224 `course-of-action`, 1 `malware`, 1
`x-mitre-matrix`) — 0 `attack-pattern` records. Any relationship in
`relationships.json` that pointed at a dropped object is dropped along with
it. Verified after every run: every remaining entity id is globally unique,
and every relationship endpoint (native, derived, and external) resolves.

## What it does

- Drops `identity`, `marking-definition`, and `x-mitre-collection` objects
  entirely — pure STIX attribution/collection-manifest boilerplate, the
  same treatment CAPEC gives `identity`/`marking-definition`.
- Keeps every other object type, each reduced to a whitelist of fields (see
  `mitre_attack_preprocessing.py`'s `*_FIELDS` constants for the exact
  list per type).
- `external_references` is never kept verbatim, beyond the id extraction
  described above, on any type:
  - its `capec` entries become `T#### --related-to--> CAPEC-N` records in
    `external_relationships.json` (`source_name: "capec"`) — the reverse
    direction of CAPEC's own `CAPEC-N --related-to--> T####` edges.
  - every other entry is a bibliographic citation with no local entity to
    point at, and is dropped along with the field itself — same treatment
    CWE gives `References`/`Notes`. `campaign.x_mitre_first_seen_citation`/
    `x_mitre_last_seen_citation` are dropped for the same reason (they only
    made sense paired with a citation), even though `first_seen`/
    `last_seen` themselves are kept.
- Objects are kept even when `revoked`/`x_mitre_deprecated` is `true`
  (unlike CVE's dropped `Rejected` records, and unlike the 226
  collision-losing objects above, which are dropped specifically because
  they're a duplicate id, not because they're revoked) — both flags are
  kept as attributes instead, since ATT&CK's own `revoked-by` relationships
  point *at* revoked objects, and dropping them would leave those edges
  dangling.
- `x_mitre_contributors` (write-up credit lists), `x_mitre_version`
  (ATT&CK's internal revision counter), a tactic's `x_mitre_shortname`
  (a slug of its own `name`, only ever needed internally to match
  `kill_chain_phases`, which is now done before this id-based output is
  written), and `x-mitre-asset.x_mitre_related_assets` (free-text
  device-type references — see below) are dropped entirely as bookkeeping
  with no graph value.
- The following embedded id-list fields are removed from their entity
  record and rebuilt as relationships instead, using each endpoint's own
  (resolved) `id` as `source_ref`/`target_ref` — the same convention CAPEC
  uses for its own derived `attack_pattern_relationships.json`:
  - `attack-pattern.kill_chain_phases` → `derived_relationships.json`,
    `has_tactic` edges. ATT&CK has no `relationship` object for
    technique-to-tactic membership at all — it's a string match between
    `kill_chain_phases[].phase_name` and `x-mitre-tactic.x_mitre_shortname`,
    scoped to the domain implied by `kill_chain_phases[].kill_chain_name`
    (`mitre-attack` → `enterprise-attack`, `mitre-mobile-attack` →
    `mobile-attack`, `mitre-ics-attack` → `ics-attack`). Tactic shortnames
    are unique within every domain, so this match is unambiguous.
  - `x-mitre-matrix.tactic_refs` → `derived_relationships.json`,
    `has_member` edges (matrix → tactic) — mirrors the `has_member` edges
    CWE derives from its own `Relationships.HasMember`/`Members.HasMember`.
  - `x-mitre-detection-strategy.x_mitre_analytic_refs` →
    `derived_relationships.json`, `has_analytic` edges (detection-strategy
    → analytic).
  - `x-mitre-analytic.x_mitre_log_source_references[].x_mitre_data_component_ref`
    → `derived_relationships.json`, `uses_data_component` edges (analytic
    → data-component), with the log source's `name`/`channel` kept as edge
    attributes (`log_source_name`/`channel`).
- `x-mitre-data-source` is kept as a plain entity list with no edges to
  `x-mitre-data-component` — a from-scratch grep of the source data found
  zero `data_source_ref` occurrences anywhere, so the two types have no
  formal link left in this ATT&CK release; `x-mitre-data-source` looks
  like a legacy/orphaned type now that analytics point straight at
  data-components.
- `x-mitre-asset.x_mitre_related_assets` stays embedded as an attribute
  rather than becoming a relationship: it references narrower device
  sub-types by free-text name (41 of 43 references don't match any other
  asset's `name` in the bundle at all — e.g. `Application Server` →
  `File Server`), not another `x-mitre-asset` entity by id, so there's
  nothing to resolve.
- Native `relationship` objects (`uses`, `mitigates`, `detects`,
  `subtechnique-of`, `revoked-by`, `attributed-to`, `targets`) are kept in
  `relationships.json`, but — unlike before — their `source_ref`/
  `target_ref` are no longer their endpoints' raw STIX ids: they're
  rewritten through the same id resolution described above, so every
  relationship file in this project's output (native, derived, and
  external alike) now joins on the same human-readable id space.
  `revoked`/`x_mitre_deprecated` are dropped from relationship records
  specifically — verified always `false`/absent across all 24,582
  relationships in this dataset, pure boilerplate with no signal.
  `external_references` (citations) are dropped for the same bibliography
  reason as everywhere else; `description` is kept when present, since —
  unlike CWE/CAPEC relationships — ATT&CK relationship descriptions carry
  real analytic content (e.g. *how* a piece of malware uses a technique).
- Relationship records built by this script get a deterministic
  `relationship--<uuid5>` id, seeded from every edge attribute (not just
  `source_ref`/`relationship_type`/`target_ref`) — some derived edges
  (`uses_data_component`) can legitimately repeat with the same triple but
  different attributes (e.g. two distinct log-source channels feeding the
  same data component). Reruns against the same input produce
  byte-identical output.

## Output

Sixteen JSON files, each a plain array of records:

| File | Count | Contents |
|---|---|---|
| `techniques.json` | 1,166 | ATT&CK techniques/sub-techniques (`attack-pattern`) — id, stix_id, name, description, platforms, sub-technique flag, and (ICS-only) tactic type/impact type/remote support |
| `malware.json` | 862 | `malware` — id, stix_id, name, description, platforms, aliases, `is_family` |
| `tools.json` | 97 | `tool` — id, stix_id, name, description, platforms, aliases |
| `intrusion_sets.json` | 193 | Threat groups (`intrusion-set`) — id, stix_id, name, description, aliases |
| `campaigns.json` | 60 | Named campaigns (`campaign`) — id, stix_id, name, description, aliases, first/last seen dates |
| `courses_of_action.json` | 110 | Mitigations (`course-of-action`) — id, stix_id, name, description, compliance-framework labels |
| `tactics.json` | 41 | ATT&CK tactics (`x-mitre-tactic`) — id, stix_id, name, description |
| `matrices.json` | 3 | Matrix groupings (`x-mitre-matrix`) — id, stix_id, name, description |
| `analytics.json` | 2,066 | Detection analytics (`x-mitre-analytic`) — id, stix_id, name, description, platforms, mutable elements |
| `detection_strategies.json` | 920 | Detection strategies (`x-mitre-detection-strategy`) — id, stix_id, name |
| `data_components.json` | 123 | Log data components (`x-mitre-data-component`) — id, stix_id, name, description, log sources |
| `data_sources.json` | 42 | Log data sources (`x-mitre-data-source`) — id, stix_id, name, description, collection layers, platforms |
| `assets.json` | 18 | ICS physical/logical assets (`x-mitre-asset`) — id, stix_id, name, description, platforms, sectors |
| `relationships.json` | 24,552 | Native STIX edges — `uses` (19,988), `mitigates` (2,017), `detects` (918), `targets` (842, technique → ICS asset), `subtechnique-of` (542), `revoked-by` (218), `attributed-to` (27) |
| `derived_relationships.json` | 8,593 | Edges rebuilt from embedded id-list fields — `uses_data_component` (5,042, analytic → data-component), `has_analytic` (2,066, detection-strategy → analytic), `has_tactic` (1,446, technique → tactic), `has_member` (39, matrix → tactic) |
| `external_relationships.json` | 36 | `T#### --related-to--> CAPEC-N` edges, `source_name: "capec"` |

`courses_of_action.json` and `matrices.json` are smaller than a raw object
count would suggest (334→110, 4→3) because of the id-collision deletions
above, not because of any additional filtering.

Every entity record carries `id` (its ATT&CK id, or a STIX id fallback —
see above) and `stix_id` (always the original STIX id, for traceability).
Every relationship file — native, derived, and external alike —
consistently uses these same `id` values as `source_ref`/`target_ref`;
verified after every run that none of the 24,552 + 8,593 + 36 rows carries
a raw STIX id (`<type>--<uuid>`) in either column.
