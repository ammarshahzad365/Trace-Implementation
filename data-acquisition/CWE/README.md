# CWE Crawlers

Fetches MITRE's CWE catalog (Weakness/Category/View entries) and stores it
locally as JSON.

## How it works

MITRE's CWE REST API has no bulk "list everything" endpoint, so both
crawlers download the same full XML catalog (`cwec_latest.xml.zip`) every
run and convert it to JSON. What differs is what happens locally:

- `full_crawler.py` — overwrites `latest.json` with exactly what was
  fetched (true resync; entries no longer in the catalog are dropped).
- `incremental_crawler.py` — merges into `latest.json` (never drops
  anything) and writes only this run's added/modified entries to
  `delta.json`.

"Modified" is judged per-entry from each entry's own `Content_History`, not
the corpus version as a whole.

## Running

1. PowerShell in this folder: `.\run.ps1`, choose `1` (full — run this
   first) or `2` (incremental). Or run the scripts directly: `py
   full_crawler.py` / `py incremental_crawler.py`.
2. Run `full_crawler.py` at least once before `incremental_crawler.py` —
   incremental needs a `last_successful_fetch` timestamp in
   `manifest.json`.
3. Flags (either script): `--dry-run` (fetch + diff, no writes),
   `--source-url` (pin a specific version, e.g. `cwec_v4.20.xml.zip`),
   `--timeout`, `--user-agent`, `--base-dir`. See `--help` for the full list.

No API key or rate limiting needed — `cwe.mitre.org` is a public download.

## Files

```
client.py               shared: XML fetch/parse, XML->JSON conversion, state/merge/diff helpers
full_crawler.py          full re-sync -> overwrites latest.json
incremental_crawler.py   merge -> latest.json, writes delta.json
run.ps1
latest.json              full snapshot (current: 1,450 objects, corpus v4.20)
delta.json               incremental-only: this run's added/modified entries
manifest.json            last_successful_fetch, mode, counts
```

## What the data looks like

`latest.json`/`delta.json`: `{"id": "bundle--...", "type": "bundle",
"objects": [...]}` — one flat array mixing 3 entry types: `weakness` (969),
`category` (422), `view` (59).

Every entry carries `type`, `id` (`"CWE-<ID>"`), `cwe_id` (bare numeric id),
`Name`, `Status`, `MappingNotes`, and `created`/`modified` (derived from the
entry's own `Content_History`). Every other XML field converts generically:
nested elements become nested JSON, tag underscores are stripped
(`Common_Consequences` -> `CommonConsequences`).

**`weakness`** — the deepest type. Always has `Abstraction`, `Structure`,
`Description`. Commonly has `CommonConsequences`, `RelatedWeaknesses`
(935/969 — CWE's own `ChildOf`/`ParentOf`/etc. hierarchy, scoped per
`View_ID`), `PotentialMitigations`, `TaxonomyMappings`, `ObservedExamples`,
`DetectionMethods`. Less commonly has `RelatedAttackPatterns` (336/969 —
direct CWE -> CAPEC link, bare CAPEC ids), `AlternateTerms`,
`LikelihoodOfExploit`.

```json
{
  "type": "weakness", "id": "CWE-89", "cwe_id": "89",
  "Name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "Abstraction": "Base", "Structure": "Simple", "Status": "Stable",
  "RelatedWeaknesses": {"RelatedWeakness": [{"Nature": "ChildOf", "CWE_ID": "943", "View_ID": "1000"}]},
  "RelatedAttackPatterns": {"RelatedAttackPattern": [{"CAPEC_ID": "108"}, {"CAPEC_ID": "66"}]},
  "created": "2006-07-19T00:00:00.000Z", "modified": "2025-12-11T00:00:00.000Z"
}
```

**`category`**/**`view`** — much flatter, organizational groupings, not
weaknesses themselves. Membership is the one meaningful nested field:
`category` via `Relationships.HasMember` (368/422), `view` via
`Members.HasMember` (40/59) — both a list of `{CWE_ID, View_ID}` pairs.

```json
{"type": "category", "id": "CWE-19", "cwe_id": "19", "Name": "Data Processing Errors",
 "Relationships": {"HasMember": [{"CWE_ID": "130", "View_ID": "699"}]}}
```
