# CWE Crawlers

This folder contains the CWE (Common Weakness Enumeration) data acquisition tools.

## Why this folder looks like CAPEC, not CVE

CWE has no STIX representation and, unlike NVD, the official
[CWE REST API](https://cwe-api.mitre.org/api/v1/) has no bulk "list everything" or
"list everything modified since X" call — it only looks up specific known IDs and
their relationships. The only complete, authoritative export MITRE publishes is the
versioned XML catalog
(`https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`), covering every Weakness,
Category, and View. Both crawlers download that same full XML catalog every run and
convert it to JSON; what differs is what they do with it locally:

- **Full crawler**: overwrites the local snapshot with exactly what was fetched
  (a true resync — locally-stored entries no longer in the catalog are dropped
  from `latest.json`).
- **Incremental crawler**: merges the fetch into the existing local snapshot
  (never drops anything not present in the new fetch) and writes only the
  entries added/modified since the last successful run to `delta.json`.

"Modified" is judged per-entry, not just by corpus version: each CWE entry carries
its own `Content_History` (submission + every later revision), so `created` is the
entry's earliest submission date and `modified` is its latest revision date —
independent of whether other, unrelated entries changed in the same MITRE release.

## Quick Start

1. Open PowerShell in this folder.
2. Run `.\run.ps1` and choose `1` (full crawler, first run) or `2` (incremental
   crawler).

Both scripts print live progress (download/extract size, parsed entry counts by
type, diff/merge/write steps) while they run, then a one-line summary and a JSON
report.

Run `full_crawler.py` at least once before `incremental_crawler.py` — the
incremental crawler needs a `last_successful_fetch` timestamp in `manifest.json`.

## Layout

```
data-acquisition/CWE/
├── client.py              # shared: XML download/unzip/parse, XML->JSON conversion, state/merge/diff helpers
├── full_crawler.py         # full re-sync: download, diff vs local, overwrite latest.json
├── incremental_crawler.py  # download, merge into latest.json, write delta.json
├── run.ps1
├── latest.json             # full JSON snapshot of every Weakness/Category/View entry stored locally
├── delta.json              # written only by incremental_crawler: this run's added/modified entries
└── manifest.json           # last_successful_fetch, mode, and counts from the last run
```

No API key or rate limiting is needed — `cwe.mitre.org` is a public download, no
authentication required.

## What the data looks like

`latest.json`/`delta.json` are one JSON object each:
`{"id": "bundle--...", "type": "bundle", "objects": [ ...records... ]}`, mixing
all three entry types in one flat array. Each XML entry (`Weakness`,
`Category`, or `View`) becomes one JSON object:

- `type`: `"weakness"`, `"category"`, or `"view"`
- `id`: `"CWE-<ID>"` (globally unique across all three types)
- `cwe_id`: the bare numeric ID as a string
- `created` / `modified`: derived from the entry's `Content_History` (earliest
  submission date / latest revision date), formatted as UTC timestamps
- every other XML field, converted generically (child elements become nested
  JSON objects/arrays; tag names have underscores stripped to match MITRE's own
  `cwe-api.mitre.org` JSON naming, e.g. `Common_Consequences` -> `CommonConsequences`)

A `weakness` record is the deepest of the three (trimmed — a real one has many
more optional nested sections such as `DetectionMethods`, `ObservedExamples`,
`TaxonomyMappings`):

```json
{
  "type": "weakness", "id": "CWE-89", "cwe_id": "89",
  "Name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "Abstraction": "Base", "Structure": "Simple", "Status": "Stable",
  "RelatedWeaknesses": {"RelatedWeakness": [{"Nature": "ChildOf", "CWE_ID": "943", "View_ID": "1000"}]},
  "CommonConsequences": {"Consequence": [{"Scope": ["Confidentiality","Integrity","Availability"], "Impact": "Execute Unauthorized Code or Commands"}]},
  "RelatedAttackPatterns": {"RelatedAttackPattern": [{"CAPEC_ID": "108"}, {"CAPEC_ID": "66"}]},
  "created": "2006-07-19T00:00:00.000Z",
  "modified": "2025-12-11T00:00:00.000Z"
}
```

`RelatedAttackPatterns` is the direct CWE → CAPEC cross-reference (bare
numeric CAPEC ids). `category` and `view` records are much flatter — their
only meaningful nested field is membership (`Relationships`/`Members` →
`HasMember`, a list of `{CWE_ID, View_ID}` pairs):

```json
{"type": "category", "id": "CWE-19", "cwe_id": "19", "Name": "Data Processing Errors", "Status": "Draft",
 "Relationships": {"HasMember": [{"CWE_ID": "130", "View_ID": "699"}, {"CWE_ID": "166", "View_ID": "699"}]}}
```

## Useful flags

- `--dry-run` - fetch and diff without writing any files.
- `--source-url` - override the CWE catalog URL (e.g. to pin a specific version
  like `cwec_v4.20.xml.zip`).
- `--timeout`, `--user-agent`, `--base-dir` - see `--help` on either script.
