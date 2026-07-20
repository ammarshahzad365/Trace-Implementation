# CVE Crawlers

This folder contains the CVE data acquisition tools. CVE records are fetched from the
[NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) and converted to
STIX 2.1 `vulnerability` objects.

## Quick Start

1. Put your NVD API key in `.env` in this folder: `NVD_API_KEY=your-key-here`.
2. Open PowerShell in this folder.
3. Run `.\run.ps1` and choose `1` (full crawler, first run) or `2` (incremental crawler).

That is the easiest way to use this folder. Both scripts print live progress
(page-by-page fetch counts, rate-limit waits, per-year writes) while they run, and a
one-line summary per year plus a JSON report when they finish.

## What this folder does

- `client.py` - shared helpers: `.env` loading, NVD API access with rate limiting and
  retry, conversion of NVD CVE records to STIX 2.1, and the state/bundle utilities
  used by both crawlers.
- `full_crawler.py` - fetches every CVE currently in NVD, compares it against what is
  stored locally, and rewrites the full per-year snapshot. Reports objects added,
  modified, or removed per year.
- `incremental_crawler.py` - reads `last_successful_fetch` from `manifest.json`,
  fetches only CVEs published or modified since then (via NVD's
  `lastModStartDate`/`lastModEndDate` filters, chunked into ≤120-day windows as NVD
  requires), merges them into the per-year snapshot, and writes a delta file per
  affected year.
- `run.ps1` - simple interactive launcher.

Run `full_crawler.py` at least once before `incremental_crawler.py` — the incremental
crawler needs a `last_successful_fetch` timestamp to know where to start from.

## Layout

```
data-acquisition/CVE/
├── client.py
├── full_crawler.py
├── incremental_crawler.py
├── run.ps1
├── .env                  # NVD_API_KEY=... (not committed; loaded automatically)
├── manifest.json         # last_successful_fetch + per-year counts from the last run
└── records/
    └── <year>/           # year taken from the CVE ID, e.g. CVE-2023-xxxxx -> records/2023/
        ├── latest.json    # full STIX 2.1 bundle of every CVE for that year stored locally
        └── delta.json     # written only by incremental_crawler: this run's added/modified objects
```

`manifest.json` is global rather than per-year: NVD fetches are not partitioned by
year (one paginated call sweeps the whole dataset, or the whole modified-since
window), so the fetch bookkeeping is global and only the storage is sharded by year.

## What the data looks like

Every `records/<year>/latest.json` (and `delta.json`) is one JSON object:
`{"id": "bundle--<uuid5>", "objects": [ ...vulnerability objects... ]}`. Each
entry in `objects` is a STIX 2.1 `vulnerability` object, e.g. (trimmed):

```json
{
  "created": "1999-12-30T05:00:00.000Z",
  "description": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.",
  "external_references": [
    {"external_id": "CVE-1999-0001", "source_name": "cve", "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0001"},
    {"source_name": "cve@mitre.org", "url": "http://www.openbsd.org/errata23.html#tcpfix"}
  ],
  "id": "vulnerability--bc9f5fb3-6f23-5604-ab10-c90e78c60857",
  "modified": "2026-06-16T21:47:13.977Z",
  "name": "CVE-1999-0001",
  "spec_version": "2.1",
  "type": "vulnerability",
  "x_nvd_configurations": [ /* raw NVD CPE-applicability nodes, unchanged */ ],
  "x_nvd_cvss": { "cvssMetricV2": [ /* raw NVD metrics, all versions/sources verbatim */ ] },
  "x_nvd_source_identifier": "cve@mitre.org",
  "x_nvd_vuln_status": "Modified",
  "x_nvd_weaknesses": ["CWE-20"]
}
```

Objects are pretty-printed with sorted keys, so fields appear alphabetically,
not in the order `cve_to_stix()` builds them. `x_nvd_weaknesses` is the direct
CVE → CWE cross-reference (a CWE id, or an NVD fallback label like
`"NVD-CWE-noinfo"` when NVD hasn't assigned a specific CWE). Every field is
deterministic across runs (the `id` is a `uuid5` hash of the CVE ID, not
random), so re-fetching unchanged data produces byte-identical output.

## STIX mapping

Each NVD CVE record becomes one STIX 2.1 `vulnerability` object:

- `id`: deterministic `vulnerability--<uuid5>` derived from the CVE ID
- `name`: the CVE ID (e.g. `CVE-2024-12345`)
- `created` / `modified`: NVD's `published` / `lastModified` timestamps
- `description`: the English-language NVD description
- `external_references`: a `{"source_name": "cve", "external_id": "<CVE-ID>", ...}`
  entry (the standard STIX 2.1 way of referencing a CVE) plus one entry per NVD
  reference URL
- `x_nvd_cvss`: the raw NVD `metrics` block (CVSS v2/v3.0/v3.1/v4.0 scores)
- `x_nvd_weaknesses`: CWE labels
- `x_nvd_configurations`: raw CPE applicability configuration
- `x_nvd_vuln_status`, `x_nvd_source_identifier`: NVD bookkeeping fields

## NVD API key & rate limits

Without a key, NVD allows 5 requests per rolling 30 seconds. With a key, that rises to
50 requests per rolling 30 seconds — roughly 10x faster for a full crawl. Put your key
in `.env` as `NVD_API_KEY=...`; it's loaded automatically (falls back to a real
`NVD_API_KEY` environment variable, then `--api-key`). Both crawlers back off and
retry automatically on NVD's transient HTTP 403/429 responses.

## Useful flags

- `--dry-run` - fetch and diff without writing any files.
- `--max-pages N` - stop after N pages (per window, for the incremental crawler).
  Useful for a quick smoke test against the live API without waiting for a full sweep.
- `--api-key`, `--api-root`, `--results-per-page`, `--timeout`, `--user-agent`,
  `--base-dir` - see `--help` on either script for the full list.
