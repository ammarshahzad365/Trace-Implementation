# CWE Crawlers

Downloads MITRE's CWE catalog (weaknesses, categories and views) and stores it
locally as JSON.

## How it works

MITRE's CWE API has no "list everything" endpoint, so both crawlers download the
same full XML catalog (`cwec_latest.xml.zip`) every run and convert it to JSON.
The difference is what they do with it afterwards:

- `full_crawler.py` - overwrites `latest.json` with exactly what was downloaded.
  A true resync: entries that are no longer in the catalog disappear.
- `incremental_crawler.py` - merges into `latest.json` and never drops anything,
  and writes only this run's new/changed entries to `delta.json`.

"Changed" is decided per entry, from that entry's own `Content_History` - not
from the catalog version as a whole.

## Running

1. Open PowerShell here and run `.\run.ps1`. Choose `1` (full - run this first)
   or `2` (incremental). You can also run `py full_crawler.py` /
   `py incremental_crawler.py` directly.
2. The incremental crawler needs a `last_successful_fetch` in `manifest.json`,
   so run the full crawler at least once first.
3. Flags for either script: `--dry-run` (fetch and compare, write nothing),
   `--source-url` (pin a version, e.g. `cwec_v4.20.xml.zip`), `--timeout`,
   `--user-agent`, `--base-dir`. See `--help` for the full list.

No API key or rate limiting needed - `cwe.mitre.org` is a public download.

## Files

```
client.py                shared: XML fetch/parse, XML->JSON, save/merge/compare helpers
full_crawler.py          full resync -> overwrites latest.json
incremental_crawler.py   merge -> latest.json, plus delta.json
run.ps1
latest.json              full snapshot (currently 1,450 objects, catalog v4.20)
delta.json               incremental runs only: this run's new/changed entries
manifest.json            last_successful_fetch, mode, counts
```

## What the data looks like

`latest.json` and `delta.json` are
`{"id": "bundle--...", "type": "bundle", "objects": [...]}` - one flat list
mixing three kinds: `weakness` (969), `category` (422) and `view` (59).

Every entry has `type`, `id` (`"CWE-<ID>"`), `cwe_id` (just the number), `Name`,
`Status`, `MappingNotes`, and `created`/`modified` taken from its own
`Content_History`. Every other XML field is converted generically: nested
elements become nested JSON, and underscores in tag names are removed
(`Common_Consequences` -> `CommonConsequences`).

**`weakness`** is the richest kind. It always has `Abstraction`, `Structure` and
`Description`. It usually has `CommonConsequences`, `RelatedWeaknesses`
(935 of 969 - CWE's own ChildOf/ParentOf hierarchy, scoped per `View_ID`),
`PotentialMitigations`, `TaxonomyMappings`, `ObservedExamples` and
`DetectionMethods`. Less often it has `RelatedAttackPatterns` (336 of 969 - the
direct CWE -> CAPEC link, holding bare CAPEC numbers), `AlternateTerms` and
`LikelihoodOfExploit`.

```json
{
  "type": "weakness", "id": "CWE-89", "cwe_id": "89",
  "Name": "Improper Neutralization of Special Elements used in an SQL Command",
  "Abstraction": "Base", "Structure": "Simple", "Status": "Stable",
  "RelatedWeaknesses": {"RelatedWeakness": [{"Nature": "ChildOf", "CWE_ID": "943", "View_ID": "1000"}]},
  "RelatedAttackPatterns": {"RelatedAttackPattern": [{"CAPEC_ID": "108"}, {"CAPEC_ID": "66"}]},
  "created": "2006-07-19T00:00:00.000Z", "modified": "2025-12-11T00:00:00.000Z"
}
```

**`category`** and **`view`** are much flatter. They are groupings, not
weaknesses themselves, and their one meaningful nested field is membership:
`category` uses `Relationships.HasMember` (368 of 422), `view` uses
`Members.HasMember` (40 of 59). Both are lists of `{CWE_ID, View_ID}` pairs.

```json
{"type": "category", "id": "CWE-19", "cwe_id": "19", "Name": "Data Processing Errors",
 "Relationships": {"HasMember": [{"CWE_ID": "130", "View_ID": "699"}]}}
```
