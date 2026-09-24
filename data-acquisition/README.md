# Data Acquisition (stage 1)

Downloads the five raw catalogs and keeps a local copy that can be re-checked
and diffed. Standard library only; no install needed.

## Run it

```bash
py -m full_crawler                      # every source, from scratch (a few hours, mostly CVE)
py -m incremental_crawler               # later runs: only what changed
py -m full_crawler --sources cve cwe    # just some sources
py -m full_crawler --dry-run            # fetch and compare, write nothing
```

Or run `.\run.ps1` in PowerShell for a menu. Each source folder also has its own
`full_crawler.py`, `incremental_crawler.py` and `run.ps1` to run it alone.

- Run the **full** crawler once before the **incremental** one: incremental
  needs the `last_successful_fetch` in `manifest.json` from a previous run.
- For CVE, put `NVD_API_KEY` in the repo-root `.env`. Without it NVD allows
  5 requests per 30 s instead of 50, about 10x slower.
- `--stop-on-error` stops at the first failing source; by default it carries on
  and lists failures in the final JSON summary.

## The five sources

| Folder | Comes from | Stored as | How "incremental" works |
|---|---|---|---|
| `CVE/` | NVD REST API 2.0 | STIX 2.1 `vulnerability` objects, one file per year | Asks NVD for records changed since the last run (in 120-day windows) |
| `CWE/` | MITRE's XML catalog (`cwec_latest.xml.zip`) | XML converted to JSON: weaknesses, categories, views | Downloads everything, merges only entries whose own history changed |
| `CAPEC/` | MITRE's STIX bundle on GitHub | The STIX bundle as-is | Downloads everything, merges only new or changed objects |
| `mitre-attack/` | ATT&CK TAXII 2.1 server | STIX 2.1, per domain (enterprise, mobile, ics), with version history | Asks TAXII for objects added since the last run |
| `mitre-defend/` | D3FEND REST API + its OWL ontology | JSON-LD records, per domain | Downloads everything, compares by content hash |

Every source writes `latest.json` (the full current snapshot), `delta.json`
(what the last incremental run changed) and `manifest.json` (when it last
fetched, and counts).

## Key decisions

- **Re-fetching unchanged data gives byte-identical files.** Ids are hashes of
  the record's own content, never random, so a diff shows only real changes.
- **Full means resync, incremental means merge.** A full run drops records that
  are gone upstream; an incremental run never drops anything.
- **D3FEND has no timestamps,** so the crawler adds `_content_hash` and
  `_first_seen_at` to each record and detects changes by hash.
- **D3FEND's ontology is fetched too.** Its API returns names only (15 of 1,193
  records have a definition); the ontology has definitions for 271/271
  techniques and 867/915 artifacts, which extraction needs for matching.
- **ATT&CK has a historical loader** (`mitre-attack/historical_loader.py`) that
  archives every past release under `<domain>/history/`. Run it before the first
  ATT&CK crawl.

## How the five sources link to each other

These are the joins stage 2 turns into graph edges:

| From | To | Where the link is |
|---|---|---|
| CVE | CWE | `x_nvd_weaknesses` on each CVE |
| CWE | CVE | `ObservedExamples` (real CVEs that show the weakness) |
| CWE ↔ CAPEC | | `RelatedAttackPatterns` in CWE; `external_references` in CAPEC |
| CAPEC ↔ ATT&CK | | `external_references` on both (CAPEC's side is fuller: 272 vs 36) |
| D3FEND | CWE | `d3f:cwe-id` (943 of 943 resolve) |
| D3FEND | ATT&CK | `d3f:attack-id` and the `mappings` export (835 of 835 resolve) |

There is **no direct ATT&CK → CWE or D3FEND → CAPEC link**; those are only
reachable through another source. ATT&CK and CAPEC mention some CVEs in free
text only (175 and 59 distinct ids), which is the kind of thing stage 4 reads.

## Good to know

- NVD's rejected CVEs are kept here as empty shells; stage 2 drops them.
- CWE and CAPEC store some ids bare (`"79"`, `"85"`) and some prefixed
  (`"CWE-79"`); stage 2 normalises them. ATT&CK ids are consistent everywhere.
- The whole raw download is about 2.3 GB, of which CVE is 2.2 GB.
