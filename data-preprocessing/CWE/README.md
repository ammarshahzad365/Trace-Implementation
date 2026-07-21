# CWE Preprocessing

Trims the raw CWE bundle (`data-acquisition/CWE/latest.json`) down to a
fixed field whitelist per object type. A field-projection pass, not
entity/relationship graph-edge extraction — fields like `RelatedWeaknesses`
or `Relationships` are kept whole on the record itself, not split into
separate edge records.

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
  `MappingNotes` from every record.
- Drops `TaxonomyMappings`, `References`, `Notes`, `Diagram`, and
  `DemonstrativeExamples` from `weakness`; `References`/`Notes`/
  `TaxonomyMappings` from `category`; `References`/`Filter` from `view`.

## Output

Three JSON files, each a plain array of trimmed records:

| File | Count | Contents |
|---|---|---|
| `weaknesses.json` | 969 | CWE weaknesses — id, name, description, abstraction/structure/status, related-weakness and related-attack-pattern refs, common consequences, applicable platforms, modes of introduction, ordinalities, likelihood of exploit, alternate terms, potential mitigations, detection methods, background details, observed (CVE) examples, affected resources, functional areas |
| `categories.json` | 422 | Organizational groupings — id, name, summary, member weaknesses (`Relationships.HasMember`) |
| `views.json` | 59 | Organizational groupings for browsing/filtering — id, name, objective, type, member weaknesses (`Members.HasMember`), intended audience |
