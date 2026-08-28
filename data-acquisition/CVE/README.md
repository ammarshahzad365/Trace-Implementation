# CVE Crawlers

Downloads CVE records from the
[NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) and saves
each one as a STIX 2.1 `vulnerability` object.

## Quick start

1. Put your NVD API key in the `.env` at the **repository root** (not here):
   `NVD_API_KEY=your-key-here`.
2. Open PowerShell here and run `.\run.ps1`. Choose `1` (full crawler - use this
   for the first run) or `2` (incremental).

Both print live progress - pages fetched, rate-limit waits, writes per year -
then a summary and a JSON report.

## The files here

- `client.py` - shared helpers: loading `.env` from the repo root, calling NVD
  with rate limiting and retries, converting NVD records to STIX 2.1, and the
  save/merge/compare utilities.
- `full_crawler.py` - fetches every CVE in NVD, compares it to the local copy,
  rewrites the whole per-year snapshot, and reports what was added, changed or
  removed per year.
- `incremental_crawler.py` - reads `last_successful_fetch` from `manifest.json`
  and fetches only CVEs published or changed since then. NVD's changed-since
  filter allows windows of at most 120 days, so it splits the range into chunks.
  Results are merged into the per-year snapshot, and each year it touched also
  gets a delta file.
- `run.ps1` - simple menu.

Run the full crawler at least once first - the incremental one needs a
`last_successful_fetch` timestamp to know where to start.

## Layout

```
data-acquisition/CVE/
├── client.py
├── full_crawler.py
├── incremental_crawler.py
├── run.ps1
├── manifest.json         # last_successful_fetch + per-year counts from the last run
└── records/
    └── <year>/           # year comes from the CVE id: CVE-2023-xxxxx -> records/2023/
        ├── latest.json    # every CVE stored locally for that year
        └── delta.json     # incremental runs only: this run's new/changed objects
```

`manifest.json` is global, not per-year, because NVD isn't fetched year by year:
one paginated sweep covers the whole dataset (or the whole changed-since
window). Only the storage is split by year, not the fetching.

## What the data looks like

Each file is one JSON object:
`{"id": "bundle--<uuid5>", "objects": [ ...vulnerability objects... ]}`. Each
object is a STIX 2.1 `vulnerability` built from one NVD record:

```json
{
  "id": "vulnerability--bc9f5fb3-...",   // uuid5 hash of the CVE id
  "name": "CVE-1999-0001",               // the CVE id
  "type": "vulnerability", "spec_version": "2.1",
  "created": "1999-12-30T05:00:00.000Z", // NVD "published"
  "modified": "2026-06-16T21:47:13.977Z",// NVD "lastModified"
  "description": "ip_input.c in BSD-derived TCP/IP implementations allows ...",
  "external_references": [               // one "cve" entry + one per NVD reference URL
    {"source_name": "cve", "external_id": "CVE-1999-0001", "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0001"}
  ],
  "x_nvd_cvss": { "cvssMetricV2": [ ... ] },   // raw NVD scores: CVSS v2/v3.0/v3.1/v4.0
  "x_nvd_weaknesses": ["CWE-20"],              // the direct CVE -> CWE link
  "x_nvd_configurations": [ ... ],             // raw "which products are affected" data
  "x_nvd_vuln_status": "Modified",             // NVD bookkeeping
  "x_nvd_source_identifier": "cve@mitre.org"
}
```

`x_nvd_weaknesses` holds a real CWE id, or an NVD placeholder like
`"NVD-CWE-noinfo"` when NVD hasn't picked one.

Objects are pretty-printed with sorted keys, so fields appear alphabetically
rather than in the order the code builds them. Nothing is random - the STIX `id`
is a hash of the CVE id - so re-fetching unchanged data gives a byte-identical
file.

## API key and rate limits

Without a key NVD allows 5 requests per rolling 30 seconds; with one, 50 - about
10x faster for a full crawl. Put `NVD_API_KEY=...` in the `.env` at the
**repository root**: one credentials file for the whole project, already covered
by the root `.gitignore`. It is loaded automatically (then a real environment
variable, then `--api-key`).

The key is looked up relative to `client.py`'s own location, deliberately **not**
relative to `--base-dir`. `--base-dir` says where output goes and can point
anywhere, so using it would tie your credentials to wherever you happen to write
files. Both crawlers back off and retry on NVD's temporary HTTP 403 and 429
responses.

## Useful flags

- `--dry-run` - fetch and compare, write nothing.
- `--max-pages N` - stop after N pages (per window, for the incremental
  crawler). Good for a quick test against the live API.
- `--api-key`, `--api-root`, `--results-per-page`, `--timeout`, `--user-agent`,
  `--base-dir` - run `--help` on either script for the rest.
