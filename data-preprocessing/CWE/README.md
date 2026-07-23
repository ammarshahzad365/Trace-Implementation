# CWE Preprocessing

Trims the raw CWE bundle (`data-acquisition/CWE/latest.json`) down to a
fixed field whitelist per object type, and splits every relationship-shaped
field out into separate STIX-style relationship records. Unlike CAPEC's
source bundle, CWE's own JSON is a generic XML-to-JSON conversion, not
native STIX — every relation (`RelatedWeaknesses`, `RelatedAttackPatterns`,
`AlternateTerms`, `ObservedExamples`, `TaxonomyMappings`,
`Relationships.HasMember`, `Members.HasMember`) starts out embedded inline
on the entity record itself. This script pulls each of those out into its
own `relationship` object (`id`, `type`, `relationship_type`, `source_ref`,
`target_ref`, plus a few relationship-specific attributes) and removes the
source field from the entity record, so entities and relationships are
stored completely separately — the same split `capec_preprocessing.py` uses
for its own `relationships.json` / `external_relationships.json`.

## Usage

```
py cwe_preprocessing.py
```

Optional flags: `--input` (path to `latest.json`, default: the CWE
crawler's own output) and `--output-dir` (default: this folder).

## What it does

- Keeps `weakness`, `category`, and `view` objects, each reduced to a
  whitelist of fields (see `cwe_preprocessing.py`'s `*_FIELDS` constants for
  the exact list). A field missing on a given record (most non-common
  fields are optional) is simply omitted, not written as `null`.
- Drops the redundant raw `ID` field (duplicate of `cwe_id`) and
  `MappingNotes` from every record. Also drops `References`, `Notes`,
  `Diagram`, and `DemonstrativeExamples` from `weakness`; `References`/
  `Notes` from `category`; `References`/`Notes`/`Filter` from `view` —
  bibliographic citations, free-text notes, an image path, and semi-HTML
  example markup, none of which have an extractable entity or edge in this
  bundle (CWE's own bibliography content isn't part of this crawl).
- `PotentialMitigations` and `DetectionMethods` stay embedded as attributes
  on `weakness` records rather than being extracted. Both fields do contain
  a reused catalog under the hood (23 distinct `Detection_Method_ID`s span
  959 usages, 70 distinct `Mitigation_ID`s span 1,710 usages) — but most
  individual entries have no id at all (1,183/1,710 mitigations,
  476/959 detection methods), so there's no reliable key to dedupe or link
  the rest against, and splitting only the id-bearing minority would leave
  the data half-normalized.
- The following fields are removed from their entity record and rebuilt as
  relationship records instead:
  - `weakness.RelatedWeaknesses` → `relationships.json`, one edge per
    `RelatedWeakness` entry. `relationship_type` is the `Nature` value
    lower-snake-cased (`child_of`, `can_precede`, `peer_of`, `can_also_be`,
    `requires`, `starts_with`); `ordinal`/`view_id` are kept as edge
    attributes when present. Every edge is stored exactly as it appears in
    the source, with no deduping or canonicalizing: CWE's data already
    stores only one direction for every `Nature` except `PeerOf`, and even
    `PeerOf` is reciprocal in just 16 of its 98 pairs, so collapsing would
    silently drop real one-directional edges rather than remove redundancy.
  - `weakness.AlternateTerms` → `relationships.json`, `also_known_as` edges
    where `target_ref` is the alias text itself (there's no other entity
    for an alias to point at — same convention CAPEC uses for its own
    `x_capec_alternate_terms`).
  - `category.Relationships.HasMember` / `view.Members.HasMember` →
    `relationships.json`, `has_member` edges from the category/view to each
    member weakness, with `view_id` kept as an edge attribute.
  - `weakness.RelatedAttackPatterns` → `external_relationships.json`,
    `CWE-N --related-to--> CAPEC-N` edges (`source_name: "capec"`) — the
    reverse direction of CAPEC's own `CAPEC-N --related-to--> CWE-N` edges.
  - `weakness.ObservedExamples` → `external_relationships.json`,
    `CWE-N --related-to--> CVE-N` edges (`source_name: "cve"`), with
    `description`/`link` as edge attributes. The 8 examples whose
    `Reference` is a bare bibliography id instead of a CVE (e.g.
    `[REF-1374]`) become `source_name: "ref"` edges instead, target_ref
    stripped of its brackets.
  - `weakness.TaxonomyMappings` → `external_relationships.json`,
    `CWE-N --related-to--> "{Taxonomy_Name}:{EntryID or EntryName}"` edges
    (`source_name` is the taxonomy name). 154 of the 421 distinct
    `(Taxonomy_Name, EntryID)` pairs are reused by more than one CWE, so
    this is real cross-taxonomy classification, not a one-off citation —
    unlike `References`, which points to CWE's own bibliography with no
    content available in this bundle.
  - Relationship records get a deterministic `relationship--<uuid5>` id.
    Unlike CAPEC's version of this helper, the seed also folds in every
    extra edge attribute (not just `source_ref`/`relationship_type`/
    `target_ref`), because CWE edges can legitimately repeat with the same
    source/type/target but different attributes — e.g. the same `ChildOf`
    pair recorded once per `View_ID`. Reruns against the same input still
    produce byte-identical output.

## Output

Five JSON files, each a plain array of records:

| File | Count | Contents |
|---|---|---|
| `weaknesses.json` | 969 | CWE weaknesses — id, name, description, abstraction/structure/status, common consequences, applicable platforms, modes of introduction, ordinalities, likelihood of exploit, potential mitigations, detection methods, background details, affected resources, functional areas |
| `categories.json` | 422 | Organizational groupings — id, name, summary |
| `views.json` | 59 | Organizational groupings for browsing/filtering — id, name, objective, type, intended audience |
| `relationships.json` | 6,815 | Edges between entities defined in this bundle — `has_member` (5,024: category/view → weakness), `child_of` (1,318), `also_known_as` (189), `can_precede` (143), `peer_of` (98), `can_also_be` (27), `requires` (13), `starts_with` (3) |
| `external_relationships.json` | 5,983 | Edges to identifiers outside this bundle, `relationship_type: "related-to"` throughout, disambiguated by `source_name` — `cve` (3,126, from `ObservedExamples`), `capec` (1,212, from `RelatedAttackPatterns`), 17 external taxonomies (1,637 total, from `TaxonomyMappings` — `Software Fault Patterns`, `PLOVER`, `CERT C Secure Coding`, etc.), `ref` (8, bibliography ids instead of CVEs in `ObservedExamples`) |
