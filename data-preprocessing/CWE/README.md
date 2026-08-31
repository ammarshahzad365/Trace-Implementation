# CWE Preprocessing

Turns the raw CWE bundle (`data-acquisition/CWE/latest.json`) into two flat
files - `entities.json` and `relationships.json` - with each record's own `type`
saying what kind it is.

CWE's JSON is a generic XML-to-JSON conversion, not STIX, so everything starts
out **embedded inside the entity**: the real relations (`RelatedWeaknesses`,
`RelatedAttackPatterns`, `ObservedExamples`, `Relationships.HasMember`,
`Members.HasMember`) and also several attribute-looking fields that hide
sub-records (`CommonConsequences`, `ApplicablePlatforms`, `ModesOfIntroduction`,
`PotentialMitigations`, `DetectionMethods`). This script pulls all of it out into
link records and removes the original field, so entities and links end up stored
separately - the same split `capec_preprocessing.py` uses.

## Usage

```
py cwe_preprocessing.py
```

Optional flags: `--input` (path to `latest.json`, default: the CWE crawler's own
output) and `--output-dir` (default: this folder).

## Naming

CWE's XML uses PascalCase (`Name`, `LikelihoodOfExploit`); every other source
here uses snake_case, so field names are converted to match. One rename is not
mechanical: a view's `Type` would clash with the `type` field that carries the
record's own kind, so it becomes `view_type`.

`AlternateTerms` used to become `also_known_as` links whose target was the alias
*text*. But an alias is not a thing, so all 189 pointed at nothing that exists
and would have invented a phantom node per string. They are now an `aliases`
list property - also the name CAPEC, ATT&CK and D3FEND use for the same idea
(the project previously had four different spellings for it). 105 terms come
with a note, kept as self-labelling `"term -- note"` strings in `alias_notes`
rather than a second list lined up by position, since nothing keeps two separate
lists aligned.

## What it does

- Keeps `weakness`, `category` and `view`, each cut down to a whitelist (the
  `*_FIELDS` lists in the script). A missing field is left out, not written as
  `null`.
- Drops `ID` and `cwe_id` from every record - both just repeat the record's own
  `id` (`CWE-5` carries `ID: "CWE-5"` and `cwe_id: "5"`), so as properties they
  only duplicate the key. The raw `cwe_id` is still read while building link
  endpoints.
- Also drops: `MappingNotes` everywhere; `References`, `Notes`, `Diagram` and
  `DemonstrativeExamples` from `weakness`; `References` and `Notes` from
  `category`; `References`, `Notes` and `Filter` from `view`. These are
  citations, free-text notes, an image path and semi-HTML example markup - none
  of them produce an entity or a link here, and CWE's own bibliography is not
  part of this crawl.
- These fields are removed from the entity and rebuilt as links:
  - `weakness.RelatedWeaknesses` -> one link per entry. The
    `relationship_type` is the `Nature`, lower-snake-cased (`child_of`,
    `can_precede`, `peer_of`, `can_also_be`, `requires`, `starts_with`), with
    `ordinal` and `view_id` as link attributes. Stored exactly as given, with no
    deduplicating or flipping: CWE already stores only one direction for every
    Nature except `PeerOf`, and even `PeerOf` is reciprocal in just 16 of 98
    pairs - so collapsing would delete real one-way links rather than remove
    duplicates.
  - `category.Relationships.HasMember` / `view.Members.HasMember` ->
    `has_member` links to each member weakness, with `view_id` as an attribute.
  - `weakness.RelatedAttackPatterns` -> `CWE-N --related_to--> CAPEC-N`
    (`source_name: "capec"`), the reverse of CAPEC's own links.
  - `weakness.ObservedExamples` -> `CWE-N --has_observed_example--> CVE-N`
    (`source_name: "cve"`), with `description` and `link` as attributes. Its own
    `relationship_type`, not the `related_to` the CAPEC links use: NVD's
    `CVE-N -> CWE-N` classification in `CVE/relationships.json` is a different
    claim - *this vulnerability is an instance of this weakness* - from CWE
    citing a CVE to illustrate itself. Sharing one name put 932 of these on the
    same endpoint pair and type as an NVD link running the other way, so a load
    that merges on (source, type, target) would have folded them together and
    dropped the `description`/`link` text that only this side carries.
    References that are just a bibliography id (`[REF-1374]`) are dropped, since
    outward links only go to CVE and CAPEC.
  - Those last two are the only links carrying `source_name`, which is what
    marks a link as pointing outside this bundle. They share
    `relationships.json` with the internal links rather than getting a file of
    their own.
- Every link gets a fixed `relationship--<uuid5>` id. Unlike CAPEC's version,
  the seed includes every extra attribute, because CWE links legitimately repeat
  with the same source, type and target but different attributes - e.g. one
  `ChildOf` pair recorded once per `View_ID`. Re-runs stay byte-identical.

**Two known reference problems.** One `ObservedExample` (`CVE-2002-216`, on
CWE-837) is not shaped like a real CVE id, so it is dropped with a warning
rather than turned into a link to something that cannot exist. Four *well-formed*
references still cannot be resolved: CWE cites CVEs this project does not hold -
one because NVD marks it `Rejected` (and `cve_preprocessing.py` drops all 17,958
rejected records), the rest because they are not in the NVD snapshot. Those links
are kept as-is, because they are correct citations - they simply have no matching
record on the CVE side, rather than being invented to fill the gap.

## Shared sub-records become shared nodes; the rest stay private

`ApplicablePlatforms`, `PotentialMitigations` and `DetectionMethods` each have a
natural identity that many weaknesses reuse - platforms by `(category, name)`
(every weakness that applies to `Language: Java` shares one node), mitigations by
`Mitigation_ID` (70 ids covering 527 of the 1,710 uses), detection methods by
`Detection_Method_ID` (23 ids covering 483 of the 959).

The *content* next to that identity - `Prevalence`, `Phase`, `Effectiveness`,
`Description`, `EffectivenessNotes` - can vary per weakness (checked: 30 of 70
`Mitigation_ID`s and 9 of 23 `Detection_Method_ID`s differ somewhere between
uses). So every field is copied onto the `has_mitigation` /
`has_detection_method` / `applies_to_platform` link, which is where a consumer
reads the value that applies to *this* weakness - the same convention
`RelatedWeaknesses` already uses for `ordinal` and `view_id`.

The shared node keeps its own copy as well, taken from its first use in document
order. Moving the text off the node entirely would leave 70 mitigations and 23
detection methods holding nothing but `{id, type, mitigation_id}` - unreadable
on their own, and useless as embedding or search targets, which matters because
these are exactly the reusable, most-referenced entries (`MIT-20` alone is cited
by 72 weaknesses). Variation is also the exception rather than the rule: for the
40 mitigation ids and 14 detection-method ids that never differ, the link
attribute and the node field are simply the same string. Nothing is dropped
either way - the link remains the authoritative per-weakness value.

Mitigations and detection methods with **no id** (the majority - 1,183 of 1,710
and 476 of 959) are never reused, so putting their detail on the link would
leave the node empty (just `{id, type}`). A private node is pointed at by exactly
one link, so there is no cross-use conflict to worry about; these keep their
detail on the node and carry no link attributes at all. Between the two rules,
**no link in this dataset ever points at a node with no content of its own** -
the one exception is a single `CWE-597` mitigation whose source `Description` is
an empty `<br/><br/>` element with no words in it. Unnamed platform entries get a private
node the same way, keeping only `category`, which is always present.

The same logic turned out to fit one field that was not expected to behave like
a catalog: `CommonConsequences.Consequence`, deduplicated by `(scope, impact)` -
113 of 311 distinct combinations appear on more than one weakness, covering
1,039 of 1,237 entries. `Likelihood` and `Note` are per-weakness commentary, so
they live on the link.

Two fields do **not** get this treatment, because what looks like their identity
is a vocabulary term rather than a thing - the same objection that retired
`also_known_as` above. `WeaknessOrdinalities` has one real sub-field,
`Ordinality` (Primary/Resultant/Indirect); the rare `Description` sibling (2% of
entries) is dropped and it flattens to a plain list on the weakness.
`ModesOfIntroduction.Introduction` did become nodes at first, and it was a
mistake: 16 phases, each holding nothing but its own name, between them absorbing
1,398 links from 944 weaknesses. "Implementation" is a label on a weakness, not
an entity it relates to, and as a node it was a hub that every traversal then had
to route around - `Implementation` alone would pull in several hundred unrelated
weaknesses in one hop. It now flattens to `modes_of_introduction` on the
weakness, with the 433 `Note` entries kept as self-labelling `"phase -- note"`
strings in `introduction_notes`, the same shape `alias_notes` uses. That form
also survives a weakness listing one phase twice with two different notes, which
`CWE-15` does.

Every sub-entity gets a fixed `<entity-type>--<uuid5>` id, built from its natural
identity where it has one (so repeat references land on the same node) or from
the owning weakness plus a position number where it does not (still stable
across re-runs, just never reused).

## Rich text is flattened to plain text, not turned into structure

`ExtendedDescription`, `BackgroundDetails`, `view.Objective`, the `Description`
and `EffectivenessNotes` sub-fields of `PotentialMitigations` and
`DetectionMethods`, and `AlternateTerms`' own `Description` are not always plain
strings - CWE's XML wraps embedded markup (`<xhtml:p>`, `<xhtml:ul>`, nested
`<xhtml:div>`) into JSON keyed by tag name. That is formatting, not a
relationship, so it flattens into one plain-text string: paragraphs joined by a
blank line, list items (`ul`/`ol`, both wrapping an `li` list) rendered as `"- "`
lines, and the raw-CSS `style` attribute some `div` nodes carry dropped as
noise. The ordered/unordered distinction is not preserved - it is cosmetic - but
item order is.

One caveat: the source JSON groups content by tag (all the `p`s, then all the
`ul`s) instead of keeping document order, so a list that sat mid-paragraph in
CWE's HTML may end up after all the paragraphs. That is a limitation of CWE's own
XML-to-JSON conversion, not of this script.

`AffectedResources` and `FunctionalAreas` each wrap a single-key list
(`{"AffectedResource": [...]}`) - an artifact of that same conversion collapsing
one-item collections, which is what `as_list()` exists to normalize - and are
unwrapped to plain lists. `view.Audience.Stakeholder` (a list of
`{Type, Description}` pairs, only 10 distinct `Type`s) is unwrapped the same way
into a list of stakeholder types; the per-view `Description` is dropped.

## Text cleanup

Every string in the output goes through `clean_record()` - whitespace
normalized, empty strings dropped, lists deduplicated, quoted markup left
untouched. The rules are the same for all five sources and are written up once
in [`../README.md`](../README.md#text-cleanup-applied-to-everything).

Two CWE-specific details on top of that:

- `Description` and `Summary` are plain XML text, not XHTML, so they never reach
  `flatten_xhtml()`. But their line breaks are the same source indentation
  (`"it does
        not validate"`), so they get unwrapped the same way.
  Inside `flatten_xhtml()` this unwrapping happens at the leaf string, before
  the structural newlines are added, so `"- "` list items do not get merged back
  into one line.
- A `Likelihood` of `Unknown` and an `Effectiveness` of `None` are dropped
  rather than stored - a missing field already means "not assessed" here.

## Output

Two JSON files, each a plain list of records.

### `entities.json` - 5,040 records

The first three are CWE's own kinds; the rest are sub-records lifted out of
`weakness`.

| `type` | Count | Contents |
|---|---|---|
| `platform` | 1,527 | Deduplicated `(category, name)` platforms, plus private nodes for unnamed entries - id, category, name |
| `mitigation` | 1,253 | 70 deduplicated by `Mitigation_ID`, plus 1,183 private per-weakness nodes - phase, strategy, effectiveness, description, effectiveness_notes; the shared ones also carry mitigation_id |
| `weakness` | 969 | CWE weaknesses - id, name, description, extended description, abstraction/structure/status, ordinalities, likelihood of exploit, background details, affected resources, functional areas, modes of introduction + introduction notes, aliases + alias notes |
| `detection-method` | 499 | 23 deduplicated by `Detection_Method_ID`, plus 476 private nodes - method, effectiveness, description, effectiveness_notes; the shared ones also carry detection_method_id |
| `category` | 422 | Groupings - id, name, summary |
| `consequence` | 311 | Deduplicated `(scope, impact)` pairs - id, scope, impact |
| `view` | 59 | Groupings for browsing and filtering - id, name, objective, `view_type`, audience |

### `relationships.json` - 16,767 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref. The 1,212 `related_to` and 3,117 `has_observed_example` links
point *outside* this bundle and are the only ones carrying `source_name`.

**One edge per (source, type, target).** CWE states some links more than once,
each statement carrying different attributes -- the same `ChildOf` parent recorded under four
different `view_id`s, once per view that asserts it. Those used to be written
straight through as parallel edges between the same two nodes, which made
`degree()` count a node's statements rather than its neighbours; retrieval that
caps expansion by node degree read that as a much busier graph than it is.
`collapse_parallel_relationships()` now merges each group into one record:
attributes that are the same across the group stay scalar, attributes that differ
become index-aligned lists (entry `i` of each belongs to the same original
statement, `""` where a statement did not carry the field, since Neo4j rejects a
list property holding a null), and
`merged_fields` names those lists so they can be told from a field that was
already multi-valued on one statement. 134 of the links here are merged records;
nothing is dropped, and expanding them reproduces the pre-merge file exactly.

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `has_member` | 5,024 | category/view -> weakness |
| `has_observed_example` | 3,117 | weakness -> CVE, from `ObservedExamples`. Carries `description` and `link` |
| `related_to` | 1,212 | weakness -> CAPEC, from `RelatedAttackPatterns` |
| `applies_to_platform` | 2,072 | weakness -> platform |
| `has_mitigation` | 1,704 | weakness -> mitigation |
| `child_of` | 1,160 | weakness -> weakness. `view_id` is a list where the same parent is asserted in several views |
| `has_consequence` | 1,235 | weakness -> consequence |
| `has_detection_method` | 959 | weakness -> detection-method |
| `can_precede` | 143 | weakness -> weakness |
| `peer_of` | 98 | weakness -> weakness |
| `can_also_be` | 27 | weakness -> weakness |
| `requires` | 13 | weakness -> weakness |
| `starts_with` | 3 | weakness -> weakness |
