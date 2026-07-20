# CAPEC Parser

Trims the raw CAPEC STIX bundle (`data-acquisition/CAPEC/latest.json`) down
to a fixed field whitelist per object type. A field-projection pass, not
entity/relationship graph-edge extraction — see
`data-preprocessing/CAPEC_STRUCTURE.md` for the full field reference this
whitelist was chosen from.

## Usage

```
py capec_parser.py
```

Optional flags: `--input` (path to `latest.json`, default: the CAPEC
crawler's own output) and `--output-dir` (default: this folder).

## What it does

- Drops `identity` and `marking-definition` objects entirely (STIX
  attribution/marking boilerplate, no domain content).
- Keeps `attack-pattern`, `course-of-action`, and `relationship` objects,
  each reduced to a whitelist of fields (see `capec_parser.py`'s
  `*_FIELDS` constants for the exact list). A field missing on a given
  record (most `x_capec_*` fields are optional) is simply omitted, not
  written as `null`.

## Output

Three JSON files, each a plain array of trimmed records:

| File | Count | Contents |
|---|---|---|
| `attack_patterns.json` | 615 | CAPEC attack patterns — id, name, description, external_references, and all `x_capec_*` analytic fields (abstraction, status, domains, severity, likelihood, prerequisites, consequences, skills/resources required, examples, execution flow, related-pattern refs, alternate terms) |
| `courses_of_action.json` | 877 | Mitigations — id, name, description only (CAPEC's own `name` for these is a generic placeholder, not a real title) |
| `relationships.json` | 1,172 | `course-of-action --mitigates--> attack-pattern` edges — id, relationship_type, source_ref, target_ref, created |
