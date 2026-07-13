# MITRE D3FEND Crawlers

This folder contains the D3FEND data acquisition tools. D3FEND (Detection,
Denial, and Disruption Framework Empowering Network Defense) is fetched from
MITRE's own "alpha" REST JSON API at
[d3fend.mitre.org](https://d3fend.mitre.org/api-docs/) — one endpoint per
entity type, plus a bulk inferred-relationship export:

| domain                | endpoint                                                | contents |
|------------------------|----------------------------------------------------------|----------|
| `technique`            | `/api/technique/all.json`                                | D3FEND defensive techniques |
| `tactic`               | `/api/tactic/all.json`                                    | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, ...) |
| `artifact`             | `/api/dao/artifacts.json`                                 | Digital artifacts from the D3FEND Artifact Ontology |
| `weakness`             | `/api/weakness/all.json`                                  | CWE weaknesses as mapped into D3FEND |
| `offensive-technique`  | `/api/offensive-technique/all.json`                       | ATT&CK techniques referenced by D3FEND |
| `mapping`              | `/api/ontology/inference/d3fend-full-mappings.json`       | The full inferred technique↔artifact↔ATT&CK relationship export |

## Important differences from the other crawlers in this project

**No date-filtered endpoint.** Like CWE/CAPEC, D3FEND has no "fetch what
changed since X" API — both crawlers here download the same full data for
every domain on every run. What differs is what they do with it locally: the
full crawler overwrites each domain's `latest.json` (a true resync — anything
that disappeared upstream is dropped); the incremental crawler merges into the
existing snapshot (never drops anything) and writes only added/changed records
to `delta.json`.

**No native timestamps, so change detection is content-hash based.** Unlike
CVE/CWE/CAPEC/ATT&CK, D3FEND's objects carry no `created`/`modified` field at
all — just an `@id`, labels, definitions, and relationships. So instead of
comparing timestamps, this crawler stamps two bookkeeping fields onto every
record itself: `_first_seen_at` (when this crawler first observed the record,
carried forward across runs) and `_content_hash` (a sha256 of the record's own
fields). A record counts as "modified" when its `_content_hash` changes between
runs, not because D3FEND reports a newer timestamp.

**`mapping` is the odd domain out.** The five entity endpoints are JSON-LD
(`{"@graph": [...]}`, each entry keyed by `@id`); `mapping`
(`d3fend-full-mappings.json`) is documented as returning "OntologyBindings" and
is large enough that it wasn't possible to preview its exact shape while
building this crawler. `client.py`'s `extract_records()` tries `@graph`, then
a SPARQL-style `results.bindings` array, then a bare top-level list, and rows
with no natural `@id` are keyed by a hash of their own content instead. Run
`full_crawler.py --dry-run --domains mapping` first and sanity-check the
reported record count if you're touching this domain.

The corpus-level version (`ontology_version`, `ontology_hash_sha256`,
`release_date`) comes from `/api/version.json` and is stored in the top-level
`manifest.json`, playing the same role as CWE's `catalog_version()` / CAPEC's
`capec_version()`.

## Quick Start

1. Open PowerShell in this folder.
2. Run `.\run.ps1` and choose `1` (full crawler, first run) or `2` (incremental
   crawler), then pick domain(s).

Both scripts print live progress (download size per domain, diff/write steps)
while they run, then a one-line summary per domain and a JSON report.

## Layout

```
data-acquisition/mitre-defend/
├── client.py                 # shared: fetch + content-hash state/merge/diff helpers
├── full_crawler.py            # full re-sync per domain: download, diff vs local, overwrite latest.json
├── incremental_crawler.py     # download, merge into latest.json, write delta.json per domain
├── run.ps1
├── techniques/{latest.json, delta.json}
├── tactics/{latest.json, delta.json}
├── artifacts/{latest.json, delta.json}
├── weaknesses/{latest.json, delta.json}
├── offensive-techniques/{latest.json, delta.json}
├── mappings/{latest.json, delta.json}
└── manifest.json              # ontology_version/hash/release_date + per-domain last_successful_fetch and counts
```

No API key or rate limiting is needed — the D3FEND API has no stated auth or
quota, though it is documented as "alpha".

## Useful flags

- `--dry-run` - fetch and diff without writing any files.
- `--domains` - one or more of `technique tactic artifact weakness
  offensive-technique mapping` (default: all).
- `--api-root` - override the D3FEND API root (default:
  `https://d3fend.mitre.org`).
- `--timeout`, `--user-agent`, `--base-dir` - see `--help` on either script.
