# Data Acquisition

This folder holds one crawler per threat-intelligence source, all following
the same shape: a `client.py` (shared fetch/state helpers), a
`full_crawler.py` (re-sync everything), an `incremental_crawler.py` (fetch/
merge only what changed), a `run.ps1` menu, and a `README.md` explaining that
source's specific design.

| Folder | Source | What it fetches |
|---|---|---|
| [`CVE/`](CVE/README.md) | NVD CVE REST API 2.0 | Every published CVE, converted to STIX 2.1 `vulnerability` objects, sharded by year |
| [`CWE/`](CWE/README.md) | MITRE's versioned CWE XML catalog | Every weakness/category/view in the CWE corpus |
| [`CAPEC/`](CAPEC/README.md) | MITRE's CAPEC STIX 2.1 bundle | Every attack pattern and mitigation in the CAPEC catalog |
| [`mitre-attack/`](mitre-attack/README.md) | MITRE ATT&CK TAXII 2.1 server | Enterprise/Mobile/ICS ATT&CK, each with a full version history |
| [`mitre-defend/`](mitre-defend/README.md) | MITRE D3FEND REST API | Techniques, tactics, artifacts, weaknesses, ATT&CK-referenced offensive techniques, and the full inferred defense↔offense mapping export |

See [`DATA_STORAGE_REPORT.md`](DATA_STORAGE_REPORT.md) for a deep, verified
breakdown of exactly what's stored on disk for each source (file layouts,
schemas, sample records, record counts) and, critically, **every relationship
that exists between the five datasets** — which fields join CVE to CWE, CWE
to CAPEC, D3FEND to ATT&CK, and so on, including which links are structured,
which are only recoverable from free text, and which don't exist at all.

## Running every source at once

This folder itself also has a `full_crawler.py` / `incremental_crawler.py` /
`run.ps1` — these don't fetch anything themselves, they just run each
source's own full/incremental crawler in turn, from the same entry points
each source's own README documents (`py -m full_crawler`, `py -m
incremental_crawler`, invoked in that source's own folder as the working
directory).

**Quick start**: open PowerShell in this folder and run `.\run.ps1`, choose
full (1) or incremental (2), then choose which source(s) to run.

**Directly**:
```
py -m full_crawler
py -m incremental_crawler
```

Run the full crawler at least once (per source) before the incremental one —
every source's incremental crawler needs a `manifest.json` (or, for MITRE
ATT&CK, a per-domain `last_successful_fetch`) from a prior successful run.
CVE also needs a `.env` with `NVD_API_KEY` in `CVE/` for a reasonable rate
limit (it still works without one, just slower).

### Useful flags

- `--sources` — one or more of `cve cwe capec mitre-attack mitre-defend`
  (default: all five). Use this to re-run just one source without `cd`-ing
  into its folder.
- `--dry-run` — passed straight through to every source's crawler (fetch and
  diff without writing any files).
- `--stop-on-error` — stop at the first source that fails instead of
  continuing through the rest (default: continue through all selected
  sources and report which ones failed at the end).
- `--base-dir` — override the directory containing the five source folders
  (default: this folder).

Each source's own crawler prints its own progress/summary/JSON report as it
runs (nothing here is swallowed or reformatted); the top-level scripts add
one line per source (`ok` / `FAILED (exit <code>)`) and a final JSON summary
listing which sources failed, so a non-zero exit code from the top-level
script always means "check the JSON output for `failed`."

## Layout

```
data-acquisition/
├── client.py               # shared: run a source's full/incremental_crawler.py as a subprocess
├── full_crawler.py          # runs every source's own full_crawler.py in turn
├── incremental_crawler.py   # runs every source's own incremental_crawler.py in turn
├── run.ps1
├── DATA_STORAGE_REPORT.md   # what's stored where, and every relationship between the 5 sources
├── CVE/
├── CWE/
├── CAPEC/
├── mitre-attack/
└── mitre-defend/
```
