# Data Acquisition (stage 1)

This folder downloads the raw data. There is one crawler per source, and they
all have the same shape:

- `client.py` - shared fetching and bookkeeping helpers
- `full_crawler.py` - download everything again from scratch
- `incremental_crawler.py` - download and merge only what changed
- `run.ps1` - a menu that runs the above
- `README.md` - what makes that source special

| Folder | Source | What it fetches |
|---|---|---|
| [`CVE/`](CVE/README.md) | NVD CVE REST API 2.0 | Every published CVE, converted to STIX 2.1, split into one file per year |
| [`CWE/`](CWE/README.md) | MITRE's CWE XML catalog | Every weakness, category and view |
| [`CAPEC/`](CAPEC/README.md) | MITRE's CAPEC STIX bundle | Every attack pattern and mitigation |
| [`mitre-attack/`](mitre-attack/README.md) | MITRE ATT&CK TAXII 2.1 server | Enterprise, Mobile and ICS ATT&CK, each with its version history |
| [`mitre-defend/`](mitre-defend/README.md) | MITRE D3FEND REST API | Techniques, tactics, artifacts, weaknesses, referenced ATT&CK techniques, and the full defence-to-attack mapping |

[`DATA_STORAGE_REPORT.md`](DATA_STORAGE_REPORT.md) is the deep reference: exact
file layouts, schemas, sample records and counts for each source - plus **every
link that exists between the five datasets**. It says which fields join CVE to
CWE, CWE to CAPEC, D3FEND to ATT&CK and so on, and which links are only hidden
in free text or missing entirely.

## Running every source at once

This folder has its own `full_crawler.py`, `incremental_crawler.py` and
`run.ps1`. They don't download anything themselves - they just run each source's
own crawler in turn, from that source's own folder.

**Easiest way**: open PowerShell here, run `.\run.ps1`, pick full (1) or
incremental (2), then pick the source(s).

**Directly**:

```
py -m full_crawler
py -m incremental_crawler
```

Run the full crawler at least once per source before the incremental one. Every
incremental crawler needs a `manifest.json` from a previous successful run (for
ATT&CK, a per-domain `last_successful_fetch`). CVE also wants an `NVD_API_KEY`
in the `.env` at the repo root for a decent rate limit - it works without one,
just much slower.

### Flags

- `--sources` - any of `cve cwe capec mitre-attack mitre-defend` (default: all
  five). Lets you re-run one source without changing folder.
- `--dry-run` - passed straight to every crawler: fetch and compare, write
  nothing.
- `--stop-on-error` - stop at the first source that fails. By default it keeps
  going and reports the failures at the end.
- `--base-dir` - use a different folder as the parent of the five source
  folders.

Each crawler prints its own progress and JSON report as it runs; nothing is
hidden or reformatted. The top-level script adds one line per source (`ok` or
`FAILED (exit <code>)`) and a final JSON summary. So a non-zero exit code always
means "look at `failed` in the JSON output".

## Layout

```
data-acquisition/
├── client.py                # runs a source's crawler as a subprocess
├── full_crawler.py          # runs every source's full crawler
├── incremental_crawler.py   # runs every source's incremental crawler
├── run.ps1
├── DATA_STORAGE_REPORT.md   # what's stored where + every link between the 5 sources
├── CVE/
├── CWE/
├── CAPEC/
├── mitre-attack/
└── mitre-defend/
```
