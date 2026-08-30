# CAPEC Preprocessing

Takes the raw CAPEC STIX bundle (`data-acquisition/CAPEC/latest.json`), keeps a
fixed list of fields per object type, and splits every reference field out into
its own link record. Output is `entities.json` and `relationships.json`, with
each record's own `type` saying what kind it is.

## Usage

```
py capec_preprocessing.py
```

Optional flags: `--input` (path to `latest.json`, default: the CAPEC crawler's
own output) and `--output-dir` (default: this folder).

## What it does

- Drops `identity` and `marking-definition` - STIX boilerplate with no real
  content.
- Keeps `attack-pattern`, `course-of-action` and `relationship`, each cut down
  to a whitelist (the `*_FIELDS` lists in the script). A missing field is left
  out, not written as `null`.
- **`external_references` is never kept as-is on an attack pattern.** It is
  split three ways:
  - the `source_name == "capec"` entry (always exactly one) gives the record its
    `id`. Attack patterns are keyed `CAPEC-N` everywhere in this project; the
    STIX id is kept alongside as `stix_id` and used as a join key for nothing.
  - `cwe` and `ATTACK` entries become links carrying `source_name`, which is
    what marks a link as pointing outside this catalog. Three attack patterns
    list the same reference twice upstream, so 1,486 entries produce 1,483
    links.
  - `reference_from_CAPEC`, `OWASP Attacks` and `WASC` entries are just
    citations with no matching entity here, and are dropped.
- Native `relationship` records (`mitigates`) keep their STIX `id`, but any
  endpoint pointing at an attack pattern is rewritten to its `CAPEC-N` id.
  `course-of-action` endpoints stay as STIX ids, because CAPEC numbers attack
  patterns but not mitigations.
- `x_capec_status` and `x_capec_execution_flow` are dropped with no replacement.
- `x_capec_alternate_terms` becomes an `aliases` list. As `also_known_as` links
  its target was the alias *text*, so all 27 pointed at nothing real and would
  have invented a phantom node per string. `aliases` is also what CWE, ATT&CK
  and D3FEND call this.
- Two renames to match CWE, which uses the same names for the same ideas:
  `x_capec_extended_description` -> `extended_description` and
  `x_capec_abstraction` -> `abstraction`. (The values differ - CAPEC uses
  Meta/Standard/Detailed, CWE uses Pillar/Class/Base/Variant/Compound - but the
  field plays the same role in both hierarchies.) The other `x_capec_*` fields
  keep their prefix, since no other source has them.
- `created`/`modified` are kept on attack patterns, mitigations and native links
  alike, matching CWE/CVE/ATT&CK, so everything with upstream timestamps carries
  them under the same two names.
- Attack-pattern reference fields become links too:
  - `child_of`/`parent_of` and `can_precede`/`can_follow` are exact mirrors of
    each other upstream, so only one direction is written instead of storing
    every link twice.
  - `peer_of` is symmetric but not reliably mirrored, so it is deduplicated to
    one link per pair (direction: lower `capec_id` -> higher).
- Every link this script creates (all but the native `mitigates` ones) gets a
  fixed `relationship--<uuid5>` id built from
  `(source_ref, relationship_type, target_ref)`, so re-runs are byte-identical.

## Nothing in the output nests

Every value in the output is a single value or a list of single values, never a
map. CAPEC had two map-valued fields.

**`x_capec_consequences`** - a scope-to-impacts map on 369 attack patterns -
**flattens onto the attack pattern** as a `consequences` list, with a matching
`consequence_notes` list where CAPEC supplies an explanation:

- It used to become 46 shared `(scope, impact)` nodes plus 1,563
  `has_consequence` links, mirroring CWE's model. That was the wrong shape here.
  A scope/impact pair is a label on an attack pattern, not a thing the pattern
  points at, and those 46 nodes held nothing but the pair itself while absorbing
  1,563 links from 368 patterns - `Confidentiality: Read Data` alone would pull
  in over a hundred unrelated patterns in a single hop. The same objection
  retired CAPEC's alias "entities" and CWE's introduction phases.
- Each entry reads `"Confidentiality: Read Data"` - scope, then impact.
- CAPEC glues an explanation onto the impact code in brackets:
  `"Execute Unauthorized Commands (The attacker may be able to ...)"`. Splitting
  that collapses 134 distinct impact strings down to the 10 real codes, and the
  explanation is kept as a self-labelling
  `"Availability: Unreliable Execution -- The attacker may be able to ..."`
  string in `consequence_notes` (394 of the 1,563), the same shape CWE's
  `alias_notes` uses. Nothing has to stay lined up by position, and it survives
  one pattern giving the same pair two different notes. Verified safe: no impact
  code contains a bracket, and every bracket closes at the end of the string.
- CAPEC writes `Access_Control` where CWE writes `Access Control`; normalized to
  CWE's spelling, which makes CAPEC's 9 scope values an exact subset of CWE's.
  `CAPEC-132` lists the same `(Integrity, Modify Data)` twice, hence 1,563
  entries from 1,564 pairs.
- CWE's own `consequence` nodes stay as they are. There the pair carries
  per-weakness `Likelihood` and `Note` on the link and is deduplicated across
  1,237 uses, so it still behaves like a shared record; CAPEC's never did.

**`x_capec_skills_required`** - a skill-level-to-prose map on 296 attack
patterns - is **dropped**, not converted. It used to become 3 `skill-level`
records plus 364 `requires_skill` links carrying the prose. But a skill level is
a coarse three-value judgement, not something this dataset says anything about:
those nodes existed only as the links' targets, nothing else pointed at them,
and no trace ever crossed them. The same call was made for CWE's alias
"entities" and D3FEND's mirrored weaknesses. The 364 prose strings go too; if
they are ever wanted back, the right shape is a self-labelling list on the
attack pattern (`"High -- <prose>"`, the way CWE's `alias_notes` works), not
nodes.

## Text cleanup

Every string in the output goes through `clean_record()` - whitespace
normalized, empty strings dropped, lists deduplicated, quoted markup left
untouched. The rules are the same for all five sources and are written up once
in [`../README.md`](../README.md#text-cleanup-applied-to-everything).

CAPEC needs one extra pass: its rich text arrives still wrapped in XHTML markup.
`description`, `x_capec_extended_description`, `x_capec_example_instances` and
`x_capec_resources_required` carry literal `<xhtml:p>`/`<xhtml:li>` tags on 365
values between them. `flatten_xhtml()` renders those to the same plain text
CWE's flattener produces - paragraphs separated by a blank line, list items as
`"- "` lines. Only the `xhtml:` namespace counts as markup; every other tag in
those fields is quoted content and is left alone. Whitespace hugging a *block*
tag is source indentation and goes; whitespace around an inline `<xhtml:b>` is
spacing between words and stays.

## Output

Two JSON files, each a plain list of records.

### `entities.json` - 1,492 records

| `type` | Count | Contents |
|---|---|---|
| `course-of-action` | 877 | Mitigations - id (a STIX id; CAPEC does not number these), name, description, created, modified. CAPEC's `name` here is a generic placeholder, not a real title |
| `attack-pattern` | 615 | Attack patterns - id (`CAPEC-N`), stix_id, name, description, created, modified, `abstraction`, `extended_description`, `aliases`, and the remaining `x_capec_*` fields (domains, prerequisites, typical severity, likelihood of attack, resources required, example instances), plus `consequences` and `consequence_notes` |

### `relationships.json` - 3,367 records

Every record is `type: "relationship"` with id, relationship_type, source_ref
and target_ref.

| `relationship_type` | Count | Endpoints |
|---|---|---|
| `related_to` | 1,483 | `CAPEC-N` -> `CWE-N` or `T####`, from each attack pattern's `cwe`/`ATTACK` references. The only links carrying `source_name` |
| `mitigates` | 1,172 | course-of-action -> attack-pattern (STIX id -> `CAPEC-N`). The only links that keep their upstream STIX id, and the only ones carrying `created`/`modified` |
| `child_of` | 533 | attack-pattern -> attack-pattern (one direction; `parent_of` is its exact mirror) |
| `can_precede` | 162 | attack-pattern -> attack-pattern (one direction; `can_follow` is its exact mirror) |
| `peer_of` | 17 | attack-pattern -> attack-pattern, one per pair |
