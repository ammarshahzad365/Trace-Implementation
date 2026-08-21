# CWE Preprocessing

Trims the raw CWE bundle (`data-acquisition/CWE/latest.json`) into a fully
flattened, relationship-linked pair of files — `entities.json` and
`relationships.json` — with each record's own `type` distinguishing the kinds
inside.

CWE's JSON is a generic XML-to-JSON conversion, not native STIX, so every
relation (`RelatedWeaknesses`, `RelatedAttackPatterns`, `ObservedExamples`,
`Relationships.HasMember`, `Members.HasMember`) starts out embedded on the
entity, and so do several *attribute*-shaped fields that nest sub-records
(`CommonConsequences`, `ApplicablePlatforms`, `ModesOfIntroduction`,
`PotentialMitigations`, `DetectionMethods`). This script pulls all of it into
`relationship` records and removes the source field, so entities and edges are
stored separately — the same split `capec_preprocessing.py` uses.

## Usage

```
py cwe_preprocessing.py
```

Optional flags: `--input` (path to `latest.json`, default: the CWE crawler's own
output) and `--output-dir` (default: this folder).

## Field names are snake_cased; `AlternateTerms` becomes a property

CWE's XML uses PascalCase (`Name`, `LikelihoodOfExploit`); every other source
here emits snake_case, so output names are normalized to match. One rename isn't
mechanical: a view's `Type` would collide with the `type` carrying the record's
own kind, so it becomes `view_type`.

`AlternateTerms` used to become `also_known_as` edges whose `target_ref` was the
alias *text* — but an alias isn't an entity, so all 189 pointed at nothing that
exists and would have invented a phantom node per string. They're now an
`aliases` list property, also the name CAPEC/ATT&CK/D3FEND use for the concept
(the project previously had four spellings for it). 105 terms carry a note, kept
as self-labelling `"term -- note"` strings in `alias_notes` rather than an
index-aligned second list, since Cypher can't enforce alignment.

## What it does

- Keeps `weakness`, `category` and `view`, each reduced to a whitelist
  (`*_FIELDS` in the script). A missing field is omitted, not written as `null`.
- Drops the redundant `ID` and `cwe_id` (both spell the record's own `id`:
  `CWE-5` carries `ID: "CWE-5"` and `cwe_id: "5"`, so as properties they only
  duplicate the key — the raw `cwe_id` is still read to build edge endpoints) and
  `MappingNotes` from every record; `References`, `Notes`, `Diagram` and `DemonstrativeExamples` from
  `weakness`; `References`/`Notes` from `category`; `References`/`Notes`/`Filter`
  from `view` — bibliographic citations, free-text notes, an image path, and
  semi-HTML example markup, none with an extractable entity or edge here (CWE's
  own bibliography isn't part of this crawl).
- These fields are removed from the entity and rebuilt as edges:
  - `weakness.RelatedWeaknesses` → one edge per entry, `relationship_type` being
    the `Nature` lower-snake-cased (`child_of`, `can_precede`, `peer_of`,
    `can_also_be`, `requires`, `starts_with`), with `ordinal`/`view_id` as edge
    attributes. Stored exactly as given, with no deduping or canonicalizing:
    CWE already stores one direction for every Nature except `PeerOf`, and even
    `PeerOf` is reciprocal in just 16 of 98 pairs, so collapsing would drop real
    one-directional edges rather than remove redundancy.
  - `category.Relationships.HasMember` / `view.Members.HasMember` → `has_member`
    edges to each member weakness, with `view_id` as an edge attribute.
  - `weakness.RelatedAttackPatterns` → `CWE-N --related_to--> CAPEC-N`
    (`source_name: "capec"`), the reverse of CAPEC's own edges.
  - `weakness.ObservedExamples` → `CWE-N --related_to--> CVE-N`
    (`source_name: "cve"`), with `description`/`link` as edge attributes.
    References that are a bare bibliography id (`[REF-1374]`) are dropped, since
    outward edges are scoped to CVE/CAPEC only.
  - Those last two are the only edges carrying `source_name`, which is what marks
    an edge as pointing outside this bundle; they share `relationships.json` with
    the internal edges rather than sitting in a file of their own.
- Every edge gets a deterministic `relationship--<uuid5>` id. Unlike CAPEC's
  helper, the seed folds in every extra attribute, because CWE edges legitimately
  repeat with the same source/type/target but different attributes — e.g. one
  `ChildOf` pair recorded once per `View_ID`. Reruns stay byte-identical.

One `ObservedExample` reference (`CVE-2002-216`, on CWE-837) isn't shaped like a
real CVE id and is dropped with a warning rather than emitted as an edge to
something that cannot exist. Four *well-formed* references remain unresolvable —
CWE cites CVEs the CVE side of this project doesn't contain, one because NVD
marks it `Rejected` (and `cve_preprocessing.py` drops all 17,958 rejected
records) and the rest because they aren't in the NVD snapshot. Those are left in
place: they're correct citations, and `data-loading/` reports and skips them
rather than inventing the nodes.

## Sub-records with a reused identity become shared nodes; the rest stay private

`ApplicablePlatforms`, `PotentialMitigations` and `DetectionMethods` each carry a
natural identity reused across many weaknesses — platforms by `(category, name)`
(every weakness applicable to `Language: Java` shares one node), mitigations by
`Mitigation_ID` (70 ids span 1,710 usages), detection methods by
`Detection_Method_ID` (23 span 959). But the *content* alongside that identity —
`Prevalence`, `Phase`, `Effectiveness`, `Description`, `EffectivenessNotes` —
genuinely varies per referencing weakness (verified: 30/70 `Mitigation_ID`s and
9/23 `Detection_Method_ID`s differ across usages). So the shared node holds only
the stable identity and every variable field moves onto the
`has_mitigation`/`has_detection_method`/`applies_to_platform` edge — the same
convention `RelatedWeaknesses` already uses for `ordinal`/`view_id`.

Mitigations and detection methods with no id (the majority — 1,183/1,710 and
476/959) are never reused, so edge-side detail would leave the node empty (just
`{id, type}`). A private node is referenced by exactly one edge, so there's no
cross-usage conflict to guard against; these get their detail on the node
instead, with no edge attributes at all. No edge in this dataset ever points at
a content-free node. Unnamed platform entries get a private node the same way,
keeping only `category`, which is always present.

The same logic extends to two fields that weren't expected to behave like a
catalog but do: `CommonConsequences.Consequence` (deduped by `(scope, impact)` —
113 of 311 distinct combinations recur across more than one weakness, covering
1,039 of 1,237 entries) and `ModesOfIntroduction.Introduction` (deduped by
`Phase` — only 16 distinct phases across 1,398 entries). `Likelihood`/`Note` on
consequences and `Note` on introductions are per-weakness commentary, so they
live on the edge.

`WeaknessOrdinalities` doesn't get this treatment — its only real sub-field is
`Ordinality` (Primary/Resultant/Indirect), the rare `Description` sibling (2% of
entries) is dropped, and it flattens in place to a plain array on the weakness.

Every sub-entity gets a deterministic `<entity-type>--<uuid5>` id, seeded from
its natural identity where one exists (so repeat references resolve to the same
node) or from the owning weakness plus a position index where it doesn't (still
rerun-stable, just never reused).

## XHTML-shaped rich text is flattened to plain text, not extracted

`ExtendedDescription`, `BackgroundDetails`, `view.Objective`, the
`Description`/`EffectivenessNotes` sub-fields of
`PotentialMitigations`/`DetectionMethods`, and `AlternateTerms`' own
`Description` aren't always a bare string — CWE's XML wraps embedded markup
(`<xhtml:p>`, `<xhtml:ul>`, nested `<xhtml:div>`) into a JSON shape keyed by tag
name. That's formatting, not a relationship, so it flattens to one plain-text
string: paragraphs join with a blank line, list items (`ul`/`ol`, both wrapping
an `li` list) render as `"- "` lines (the ordered/unordered distinction isn't
preserved — cosmetic; the item order is), and the raw-CSS `style` attribute some
`div` nodes carry is dropped as formatting noise. One caveat: the source JSON
groups content by tag (all `p`, then all `ul`) rather than preserving document
order across tag types, so a list that appeared mid-paragraph in CWE's HTML may
render after all paragraphs — a pre-existing limitation of CWE's own XML-to-JSON
conversion, not of this pass.

`AffectedResources`/`FunctionalAreas` each wrap a single-key list
(`{"AffectedResource": [...]}` — a cardinality-1-collapse artifact of that same
conversion, the quirk `as_list()` exists to normalize) and are unwrapped to plain
arrays. `view.Audience.Stakeholder` (a list of `{Type, Description}` pairs, only
10 distinct `Type`s) is unwrapped the same way to an array of stakeholder types;
the per-view `Description` is dropped.

## Every string is normalized on the way out

`clean_record()` runs over every entity and every edge in `write_outputs()`, so
no builder has to remember to tidy up after itself. Per string it: converts CRLF
and lone CR to LF; turns non-breaking spaces, tabs and other exotic space
characters into a plain space; collapses runs of horizontal whitespace; trims
every line; and collapses three or more newlines to a blank line. Blank-line
paragraph breaks survive — they carry meaning — but the indentation the source
document was pretty-printed with does not. A string left empty is dropped rather
than written as `""`, and list values are deduplicated.

CWE's `Description`/`Summary` are plain XML text nodes rather than XHTML, so they
never reach `flatten_xhtml()` — but their line breaks are the same source
indentation (`"it does\n        not validate"`), so they are unwrapped the same
way. Inside `flatten_xhtml()` the unwrapping happens at the leaf string, before
the structural newlines are added, so `"- "` list items don't get merged back
into one line. A `Likelihood` of `Unknown` and an `Effectiveness` of `None` are
dropped rather than stored: a missing field already means "not assessed" here.

Two things are deliberately *not* touched. Markup that is quoted **content**
stays verbatim — XSS payloads, SOAP envelopes, C includes and `<a>`/`<script>`
samples appear inside these descriptions as the thing being described, and
stripping them would destroy the text. And a lone newline is only collapsed into
a space where the source is known to hard-wrap its text; elsewhere it is a real
line break and is kept.

## Output

Two JSON files, each a plain array of records.

### `entities.json` — 5,056 records

The first three are CWE's own object kinds; the rest are sub-records promoted
out of `weakness`:

| `type` | Count | Contents |
|---|---|---|
| `platform` | 1,527 | Deduped `(category, name)` platforms plus private nodes for unnamed entries — id, category, name |
| `mitigation` | 1,253 | 70 deduped by `Mitigation_ID` plus 1,183 private per-weakness nodes — id, mitigation_id (or the detail itself, when private) |
| `weakness` | 969 | CWE weaknesses — id, name, description, extended description, abstraction/structure/status, ordinalities, likelihood of exploit, background details, affected resources, functional areas, aliases + alias notes |
| `detection-method` | 499 | 23 deduped by `Detection_Method_ID` plus 476 private nodes — id, detection_method_id (or the detail, when private) |
| `category` | 422 | Organizational groupings — id, name, summary |
| `consequence` | 311 | Deduped `(scope, impact)` pairs — id, scope, impact |
| `view` | 59 | Groupings for browsing/filtering — id, name, objective, `view_type`, audience |
| `introduction` | 16 | Deduped introduction phases — id, phase |

### `relationships.json` — 18,339 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref. The 4,337 `related_to` edges point *outside* this bundle and are
the only ones carrying `source_name`:

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `has_member` | 5,024 | category/view → weakness |
| `related_to` | 4,337 | weakness → CVE (3,125, from `ObservedExamples`) or → CAPEC (1,212, from `RelatedAttackPatterns`) |
| `applies_to_platform` | 2,072 | weakness → platform |
| `has_mitigation` | 1,710 | weakness → mitigation |
| `introduced_in` | 1,398 | weakness → introduction |
| `child_of` | 1,318 | weakness → weakness |
| `has_consequence` | 1,237 | weakness → consequence |
| `has_detection_method` | 959 | weakness → detection-method |
| `can_precede` | 143 | weakness → weakness |
| `peer_of` | 98 | weakness → weakness |
| `can_also_be` | 27 | weakness → weakness |
| `requires` | 13 | weakness → weakness |
| `starts_with` | 3 | weakness → weakness |
