# CAPEC Crawlers

This folder contains the CAPEC data acquisition tools. CAPEC (Common Attack Pattern
Enumeration and Classification) is fetched from MITRE's
[cti GitHub repository](https://github.com/mitre/cti), which publishes the entire
catalog as a single STIX 2.1 bundle
(`capec/2.1/stix-capec.json`) — `attack-pattern`, `course-of-action`,
`relationship`, `identity`, and `marking-definition` objects. The objects are
already valid STIX 2.1, so no format conversion is needed (unlike the CVE crawler,
which converts NVD's JSON into STIX).

## Important difference from the CVE/ATT&CK crawlers

CAPEC has no paginated API and no "fetch what changed since X" filter — MITRE only
ever publishes the current full bundle. So both crawlers here download the exact
same ~4-5 MB file every run; what differs is what they do with it locally:

- **Full crawler**: overwrites the local snapshot with exactly what was fetched
  (a true resync — locally-stored objects that no longer appear upstream are
  dropped from `latest.json`).
- **Incremental crawler**: merges the fetch into the existing local snapshot
  (never drops anything not present in the new fetch) and writes only the
  added/modified objects since the last successful run to `delta.json`.

"Incremental" here means less *local* work and a smaller *delta* to look at — not a
smaller network request, since there's nothing to filter server-side.

## Quick Start

1. Open PowerShell in this folder.
2. Run `.\run.ps1` and choose `1` (full crawler, first run) or `2` (incremental
   crawler).

Both scripts print live progress (download size, parsed object counts by type,
diff/write steps) while they run, then a one-line summary and a JSON report.

Run `full_crawler.py` at least once before `incremental_crawler.py` — the
incremental crawler needs a `last_successful_fetch` timestamp in `manifest.json`.

## Layout

```
data-acquisition/CAPEC/
├── client.py              # shared: bundle fetch + state/merge/diff helpers
├── full_crawler.py         # full re-sync: download, diff vs local, overwrite latest.json
├── incremental_crawler.py  # download, merge into latest.json, write delta.json
├── run.ps1
├── latest.json             # full STIX 2.1 bundle of the CAPEC catalog stored locally
├── delta.json              # written only by incremental_crawler: this run's added/modified objects
└── manifest.json           # last_successful_fetch, mode, and counts from the last run
```

No API key or rate limiting is needed — `raw.githubusercontent.com` is a public CDN.

## What the data looks like

`latest.json` *is* the STIX bundle itself:
`{"type": "bundle", "id": "...", "objects": [ ...2666 objects... ]}`, mixing
five STIX types: `attack-pattern` (615), `course-of-action` (877),
`relationship` (1,172), plus one `identity` and one `marking-definition`
shared by every object. An `attack-pattern` (trimmed):

```json
{
  "id": "attack-pattern--94208f8a-f779-4be5-a97b-d9ab781a3f5e",
  "name": "AJAX Footprinting",
  "external_references": [
    {"external_id": "CAPEC-85", "source_name": "capec", "url": "https://capec.mitre.org/data/definitions/85.html"},
    {"external_id": "CWE-79", "source_name": "cwe", "url": "http://cwe.mitre.org/data/definitions/79.html"}
  ],
  "x_capec_abstraction": "Detailed", "x_capec_likelihood_of_attack": "High", "x_capec_typical_severity": "Low",
  "x_capec_child_of_refs": ["attack-pattern--22a65c6a-9498-4e7f-a03a-030ab1c907dc"],
  "x_capec_version": "3.9"
}
```

`external_references` with `source_name: "cwe"` is the direct CAPEC → CWE
cross-reference. Attack-pattern-to-attack-pattern relatedness (parent/child,
peer, can-precede/can-follow) lives in the custom `x_capec_*_refs` array
fields shown above — **not** in STIX `relationship` objects. Every one of the
1,172 `relationship` objects in this bundle is the single triple
`(course-of-action, "mitigates", attack-pattern)`:

```json
{
  "id": "relationship--000e54be-d542-4ff3-9e55-2b5ce4b1023d",
  "relationship_type": "mitigates",
  "source_ref": "course-of-action--1f048925-3094-483c-abf2-c5efe689193a",
  "target_ref": "attack-pattern--d859e461-7ca6-46a6-842e-3f1750bc8415"
}
```

`course-of-action` objects are sparse — `name` is a generic `coa-<N>-<M>` id;
the actual mitigation text lives entirely in `description`.

## Useful flags

- `--dry-run` - fetch and diff without writing any files.
- `--source-url` - override the CAPEC bundle URL (e.g. to pin a specific STIX 2.0
  copy or a fork).
- `--timeout`, `--user-agent`, `--base-dir` - see `--help` on either script.
