# CAPEC Preprocessing

Trims the raw CAPEC STIX bundle (`data-acquisition/CAPEC/latest.json`) to a
fixed field whitelist per object type and splits its reference fields out into
edges. Output is two files — `entities.json` and `relationships.json` — with
each record's own `type` distinguishing the kinds inside. A field-projection
pass; `data-preprocessing/CAPEC_STRUCTURE.md` is the full field reference this
whitelist was chosen from.

## Usage

```
py capec_preprocessing.py
```

Optional flags: `--input` (path to `latest.json`, default: the CAPEC crawler's
own output) and `--output-dir` (default: this folder).

## What it does

- Drops `identity`/`marking-definition` (STIX boilerplate, no domain content).
- Keeps `attack-pattern`, `course-of-action` and `relationship`, each reduced to
  a whitelist (`*_FIELDS` in the script). A missing field is omitted, not
  written as `null`.
- `external_references` is never kept verbatim on an attack pattern:
  - the `source_name == "capec"` entry (always exactly one) gives the record its
    `id`: attack patterns are keyed `CAPEC-N` everywhere in this project's
    output, with the STIX id kept alongside as `stix_id` and used as a join key
    for nothing.
  - `cwe`/`ATTACK` entries become edges carrying `source_name`, which is what
    marks them as pointing outside this catalog. Three attack patterns list the
    same reference twice upstream; the exact duplicate is dropped, so 1,483
    edges come from 1,486 entries.
  - `reference_from_CAPEC`/`OWASP Attacks`/`WASC` entries are bibliographic
    citations with no local entity, and are dropped entirely.
- Native `relationship` records (`mitigates`) keep their STIX `id`, but any
  endpoint pointing at an attack pattern is rewritten to its `CAPEC-N` id.
  `course-of-action` endpoints stay STIX ids — CAPEC numbers attack patterns,
  not mitigations.
- `x_capec_status` and `x_capec_execution_flow` are dropped with no replacement.
- `x_capec_alternate_terms` becomes an `aliases` list property. As
  `also_known_as` edges its `target_ref` was the alias *text*, so all 27 pointed
  at nothing that exists and would have invented a phantom node per string.
  `aliases` is also what CWE/ATT&CK/D3FEND call this concept.
- `x_capec_extended_description` is renamed `extended_description` and
  `x_capec_abstraction` is renamed `abstraction`, both to match CWE, which spells
  its own catalog-level fields that way (CAPEC's values are Meta/Standard/
  Detailed where CWE's are Pillar/Class/Base/Variant/Compound, but the field
  plays the same role in both hierarchies). The remaining `x_capec_*` fields keep
  their prefix — no other source spells them.
- `created`/`modified` are kept on attack patterns, courses of action and native
  edges alike, matching CWE/CVE/ATT&CK, so every node in the graph that has
  upstream provenance timestamps carries them under the same two names.
- The attack-pattern ref fields become edges too:
  - `child_of`/`parent_of` and `can_precede`/`can_follow` are perfectly
    reciprocal upstream, so only one direction is emitted rather than storing
    every edge twice.
  - `peer_of` is symmetric but *not* consistently reciprocal, so it's deduped to
    one edge per unordered pair (canonical direction: lower → higher `capec_id`).
- Every edge this script generates (i.e. all but the native `mitigates` ones)
  gets a deterministic `relationship--<uuid5>` id seeded from
  `(source_ref, relationship_type, target_ref)`, so reruns are byte-identical.

## Nothing in the output nests

Neo4j properties hold scalars or scalar arrays, never maps, so a map-valued
field can't be loaded at all. `x_capec_consequences` and
`x_capec_skills_required` were the only two here; everything else is already a
scalar or `list[str]`.

**`x_capec_consequences`** (a scope → impact-list map on 369 attack patterns)
becomes **46 `consequence` entities** plus 1,563 `has_consequence` edges, reusing
CWE's existing model rather than a new one:

- CWE's preprocessor already emits `consequence` records with exactly the
  `{id, type, scope, impact}` shape and its own `has_consequence` edges. A
  consequence means the same thing in both catalogs, so both belong under one
  Neo4j label — the opposite of the `attack-pattern` case, where CAPEC and ATT&CK
  use one STIX type for two genuinely different things and are deliberately split
  apart. Ids stay per-catalog (these preprocessors run independently and can't
  coordinate an id space), so the 4 `(scope, impact)` pairs both vocabularies
  share are one node each per catalog.
- CAPEC glues a per-attack-pattern explanation onto the impact code in
  parentheses — `"Execute Unauthorized Commands (The attacker may be able to
  ...)"`. Splitting it collapses 134 distinct impact strings to the 10 real
  codes and moves the explanation to the edge's `note` (394 of the 1,563 edges
  carry one), where CWE already keeps the equivalent text. Verified unambiguous:
  no impact code contains a parenthesis, and every parenthetical closes at
  end-of-string.

CAPEC writes `Access_Control` where CWE writes `Access Control`; normalized to
CWE's spelling, which makes CAPEC's 9 scope values an exact subset of CWE's.
`CAPEC-132` lists the same `(Integrity, Modify Data)` consequence twice
upstream, hence 1,563 edges from 1,564 pairs.

**`x_capec_skills_required`** (a skill-level → prose map on 296 attack patterns)
is **dropped**, not extracted. It previously became 3 `skill-level` records plus
364 `requires_skill` edges carrying the prose. A skill level is a coarse
three-value judgement, not a thing this graph says anything about: the nodes
existed only as those edges' targets, nothing else pointed at them, and no
traversal crossed them — so removing the edges removed their only reason to
exist, the same call made for CWE's alias "entities" and D3FEND's mirrored
weaknesses. The 364 prose strings go with them; if wanted back, the shape is a
self-labelling `list[str]` on the attack pattern (`"High -- <prose>"`, as
CWE's `alias_notes` does), not a re-promotion to nodes.

## Every string is normalized on the way out

`clean_record()` runs over every entity and every edge in `write_outputs()`, so
no builder has to remember to tidy up after itself. Per string it: converts CRLF
and lone CR to LF; turns non-breaking spaces, tabs and other exotic space
characters into a plain space; collapses runs of horizontal whitespace; trims
every line; and collapses three or more newlines to a blank line. Blank-line
paragraph breaks survive — they carry meaning — but the indentation the source
document was pretty-printed with does not. A string left empty is dropped rather
than written as `""`, and list values are deduplicated.

CAPEC additionally arrives with its rich text still wrapped in XHTML markup —
`description`, `x_capec_extended_description`, `x_capec_example_instances` and
`x_capec_resources_required` carry literal `<xhtml:p>`/`<xhtml:li>` tags on 365
values between them. `flatten_xhtml()` renders those to the same plain text CWE's
own flattener produces: paragraphs separated by a blank line, list items as `"- "`
lines. Only the `xhtml:` namespace is treated as markup — every other tag in
those fields is quoted content and is left alone. Whitespace hugging a *block*
tag is source indentation and goes; whitespace around an inline `<xhtml:b>` is
spacing between words and stays.

Two things are deliberately *not* touched. Markup that is quoted **content**
stays verbatim — XSS payloads, SOAP envelopes, C includes and `<a>`/`<script>`
samples appear inside these descriptions as the thing being described, and
stripping them would destroy the text. And a lone newline is only collapsed into
a space where the source is known to hard-wrap its text; elsewhere it is a real
line break and is kept.

## Output

Two JSON files, each a plain array of records.

### `entities.json` — 1,538 records

| `type` | Count | Contents |
|---|---|---|
| `course-of-action` | 877 | Mitigations — id (a STIX id; CAPEC has no numbering for these), name, description, created, modified (CAPEC's `name` here is a generic placeholder, not a real title) |
| `attack-pattern` | 615 | Attack patterns — id (`CAPEC-N`), stix_id, name, description, created, modified, `abstraction`, `extended_description`, `aliases`, and the remaining `x_capec_*` analytic fields (domains, prerequisites, typical severity, likelihood of attack, resources required, example instances) |
| `consequence` | 46 | Distinct `(scope, impact)` pairs, same shape and `type` as CWE's — id (`consequence--<uuid5>`), scope, impact |

### `relationships.json` — 4,930 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref:

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `has_consequence` | 1,563 | attack-pattern → consequence, with the split-out `note` on 394 |
| `related_to` | 1,483 | `CAPEC-N` → `CWE-N`/`T####`, from each attack pattern's `cwe`/`ATTACK` external_references — the only edges carrying `source_name` |
| `mitigates` | 1,172 | course-of-action → attack-pattern (STIX id → `CAPEC-N`). The only edges keeping their upstream STIX id, and the only ones carrying `created`/`modified` |
| `child_of` | 533 | attack-pattern → attack-pattern (one direction; `parent_of` is its exact inverse) |
| `can_precede` | 162 | attack-pattern → attack-pattern (one direction; `can_follow` is its exact inverse) |
| `peer_of` | 17 | attack-pattern → attack-pattern, deduped per unordered pair |
