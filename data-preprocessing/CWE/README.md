# CWE Preprocessing

Trims the raw CWE bundle (`data-acquisition/CWE/latest.json`) down to a
fully flattened, relationship-linked set of JSON files. CWE's own JSON is a
generic XML-to-JSON conversion, not native STIX — every relation
(`RelatedWeaknesses`, `RelatedAttackPatterns`,
`ObservedExamples`, `Relationships.HasMember`,
`Members.HasMember`) starts out embedded inline on the entity record
itself, and so do several *attribute*-shaped fields that themselves nest
sub-records (`CommonConsequences`, `ApplicablePlatforms`,
`ModesOfIntroduction`, `PotentialMitigations`, `DetectionMethods`). This
script pulls every one of those out into its own `relationship` object
(`id`, `type`, `relationship_type`, `source_ref`, `target_ref`, plus a few
relationship-specific attributes) and removes the source field from the
entity record, so entities and relationships are stored completely
separately — the same split `capec_preprocessing.py` uses for its own
`relationships.json` / `external_relationships.json`.

## Usage

```
py cwe_preprocessing.py
```

Optional flags: `--input` (path to `latest.json`, default: the CWE
crawler's own output) and `--output-dir` (default: this folder).

## Field names are snake_cased; `AlternateTerms` becomes a property

CWE's source XML uses PascalCase element names (`Name`, `LikelihoodOfExploit`,
`ExtendedDescription`). Every other source in this project emits snake_case,
so output field names are normalized to match — `name`,
`likelihood_of_exploit`, `extended_description`. One rename isn't mechanical:
a view's `Type` would collide with the `type` field carrying the record's own
entity kind, so it becomes `view_type`.

`AlternateTerms` used to become `also_known_as` edges whose `target_ref` was
the alias *text* — but an alias isn't an entity, so all 189 of those edges
pointed at nothing that exists anywhere in this project, and loading them into
a graph would have invented a phantom node per alias string. They're now an
`aliases` list property on the weakness instead, which is also the name
CAPEC/ATT&CK/D3FEND records use for the same concept (this project previously
had four different spellings for it). 105 of the terms carry an explanatory
note, kept as self-labelling `"term -- note"` strings in a parallel
`alias_notes` property rather than an index-aligned second list, since Cypher
can't enforce alignment.

One `ObservedExample` reference (`CVE-2002-216`, on CWE-837) isn't shaped like
a real CVE id and is dropped with a warning rather than emitted as an edge to
something that cannot exist. Four *well-formed* CVE references remain
unresolvable — CWE cites CVEs that the CVE side of this project doesn't
contain, one because NVD marks it `Rejected` (and `cve_preprocessing.py` drops
all 17,655 rejected records) and the rest because they aren't in the NVD
snapshot at all. Those are left in place: they're correct citations, and
`data-loading/` reports and skips them rather than inventing the nodes.

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
  - `category.Relationships.HasMember` / `view.Members.HasMember` →
    `relationships.json`, `has_member` edges from the category/view to each
    member weakness, with `view_id` kept as an edge attribute.
  - `weakness.RelatedAttackPatterns` → `external_relationships.json`,
    `CWE-N --related-to--> CAPEC-N` edges (`source_name: "capec"`) — the
    reverse direction of CAPEC's own `CAPEC-N --related-to--> CWE-N` edges.
  - `weakness.ObservedExamples` → `external_relationships.json`,
    `CWE-N --related-to--> CVE-N` edges (`source_name: "cve"`), with
    `description`/`link` as edge attributes. Examples whose `Reference` is a
    bare bibliography id instead of a CVE (e.g. `[REF-1374]`) are dropped,
    not extracted, since `external_relationships.json` is scoped to
    CVE/CAPEC only.
  - Relationship records get a deterministic `relationship--<uuid5>` id.
    Unlike CAPEC's version of this helper, the seed also folds in every
    extra edge attribute (not just `source_ref`/`relationship_type`/
    `target_ref`), because CWE edges can legitimately repeat with the same
    source/type/target but different attributes — e.g. the same `ChildOf`
    pair recorded once per `View_ID`. Reruns against the same input still
    produce byte-identical output.

## Sub-records with a reused identity become shared nodes; the rest stay private

`ApplicablePlatforms`, `PotentialMitigations`, and `DetectionMethods` each
carry a natural identity that's reused across many different weaknesses —
platforms by `(category, name)` (e.g. every weakness applicable to
`Language: Java` shares one node), mitigations by `Mitigation_ID` (70
distinct ids span 1,710 usages), detection methods by `Detection_Method_ID`
(23 distinct ids span 959 usages). But the *content* alongside that
identity — `Prevalence`, `Phase`, `Effectiveness`, `Description`,
`EffectivenessNotes` — genuinely varies by which weakness references it
(verified: 30/70 `Mitigation_ID`s and 9/23 `Detection_Method_ID`s have
different content across their usages). So the shared node holds only the
stable identity, and every variable field moves onto the
`has_mitigation`/`has_detection_method`/`applies_to_platform` relationship
as an edge attribute instead — the same convention this project already
uses for CWE's own `RelatedWeaknesses` edges (`ordinal`/`view_id` live on
the edge, not duplicated onto the target weakness).

Mitigations/detection methods with no id at all (the majority — 1,183/1,710
and 476/959) are never reused, so putting their detail on the edge would
leave the node itself completely empty (just `{id, type}`, an edge pointing
at nothing). Since a private node is referenced by exactly one edge, there's
no cross-usage conflict to guard against for it, so these instead get their
detail (`phase`/`strategy`/`effectiveness`/`description`/
`effectiveness_notes` for mitigations, `method`/`effectiveness`/
`description`/`effectiveness_notes` for detection methods) put directly on
the node, with no attributes on the edge at all — no edge in this dataset
ever points at a content-free node. Platform entries with no `Name` at all
(an anonymous `Technology`/etc. entry) get their own private node the same
way, keeping only `category`; they don't have the empty-node problem since
`category` is always present.

The same identity-reuse logic extends to two more fields that weren't
originally expected to behave like a catalog but turned out to, once
inspected: `CommonConsequences.Consequence` (deduped by its
`(scope, impact)` pair — 113 of 311 distinct combinations recur across more
than one weakness, covering 1,039 of 1,237 total entries) and
`ModesOfIntroduction.Introduction` (deduped by `Phase` — only 16 distinct
phases across 1,398 entries, e.g. every weakness introduced during
`Implementation` shares one node). `Likelihood`/`Note` on consequences and
`Note` on introductions are per-weakness commentary, so they follow the
same rule and live on the edge (`has_consequence`/`introduced_in`).

`WeaknessOrdinalities` doesn't get this treatment — its only real sub-field
is `Ordinality` (Primary/Resultant/Indirect); the rare `Description`
sibling (2% of entries) is dropped, and the field is flattened in place to
a plain `WeaknessOrdinalities: ["Primary"]` array directly on the weakness
record, no new node type.

Every sub-entity record gets a deterministic `<entity-type>--<uuid5>` id —
seeded from its natural identity when one exists (so repeat references
resolve to the same node), or from the owning weakness's id plus a
position index when it doesn't (so it's still rerun-stable, just never
reused). Reruns against the same input produce byte-identical output.

## XHTML-shaped rich text is flattened to plain text, not extracted

`weakness.ExtendedDescription`, `weakness.BackgroundDetails`, the
`Description`/`EffectivenessNotes` sub-fields of `PotentialMitigations`/
`DetectionMethods`, `AlternateTerms`' own `Description` (now an
`alias_notes` entry rather than an edge attribute), and `view.Objective` aren't always a bare string — CWE's XML source wraps
embedded markup (`<xhtml:p>`, `<xhtml:ul>`, nested `<xhtml:div>`) into a
JSON shape keyed by tag name. This is formatting, not a graph relationship,
so it's flattened to one plain-text string: paragraphs join with a blank
line, list items (`ul`/`ol`, both wrapping an `li` list) render as
`"- "`-prefixed lines (the ordered/unordered distinction isn't preserved —
a cosmetic simplification; the underlying item order is), and the `style`
attribute some `div` nodes carry (raw CSS, e.g. `"margin-left:1em;"`) is
dropped as pure formatting noise with no content of its own. One caveat:
the source JSON groups content by tag (all `p` paragraphs together, then
all `ul` lists together) rather than preserving true document order across
tag types, so a bullet list that originally appeared mid-paragraph in the
CWE HTML source may render after all paragraphs instead — a pre-existing
limitation of CWE's own XML-to-JSON conversion, not something introduced
by this flattening pass.

`weakness.AffectedResources`/`weakness.FunctionalAreas` (each wrapping a
single-key list, `{"AffectedResource": [...]}` — a cardinality-1-collapse
artifact of CWE's XML-to-JSON conversion, the same quirk `as_list()`
already exists to normalize) are unwrapped to a plain
`AffectedResources: [...]` / `FunctionalAreas: [...]` array.
`view.Audience.Stakeholder` (a list of `{Type, Description}` pairs, only 10
distinct `Type` values) is unwrapped the same way to a plain
`Audience: [...]` array of stakeholder type names; the per-view
`Description` text is dropped.

## Output

Ten JSON files, each a plain array of records:

| File | Count | Contents |
|---|---|---|
| `weaknesses.json` | 969 | CWE weaknesses — id, name, description, extended description, abstraction/structure/status, ordinalities (flat array), likelihood of exploit, background details, affected resources, functional areas, aliases + alias notes |
| `categories.json` | 422 | Organizational groupings — id, name, summary |
| `views.json` | 59 | Organizational groupings for browsing/filtering — id, name, objective, `view_type` (renamed from the source's `Type` to avoid colliding with the entity-kind `type`), audience (flat array of stakeholder types) |
| `consequences.json` | 311 | Deduped `(scope, impact)` pairs — id, type, scope (array), impact (array) |
| `platforms.json` | 1,527 | Deduped `(category, name)` platforms (plus private nodes for unnamed entries) — id, type, category, name |
| `introductions.json` | 16 | Deduped introduction phases — id, type, phase |
| `mitigations.json` | 1,253 | Deduped-by-`Mitigation_ID` mitigations (70) plus private per-weakness nodes for the rest (1,183) — id, type, mitigation_id |
| `detection_methods.json` | 499 | Deduped-by-`Detection_Method_ID` detection methods (23) plus private per-weakness nodes for the rest (476) — id, type, detection_method_id |
| `relationships.json` | 14,002 | Edges between entities defined in this bundle — `has_member` (5,024: category/view → weakness), `applies_to_platform` (2,072), `has_mitigation` (1,710), `introduced_in` (1,398), `child_of` (1,318), `has_consequence` (1,237), `has_detection_method` (959), `can_precede` (143), `peer_of` (98), `can_also_be` (27), `requires` (13), `starts_with` (3) |
| `external_relationships.json` | 4,337 | Edges to identifiers outside this bundle, `relationship_type: "related-to"` throughout, disambiguated by `source_name` — `cve` (3,125, from `ObservedExamples`), `capec` (1,212, from `RelatedAttackPatterns`) |
