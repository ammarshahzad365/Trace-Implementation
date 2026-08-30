# Trace-Implementation

This project pulls five public cyber-security catalogs from the internet, cleans
them up, and turns them into one connected set of entity and relationship files -
a knowledge graph in JSON form.

## The two stages

| Stage | Folder | What it does |
|---|---|---|
| **1. Get the data** | [`data-acquisition/`](data-acquisition/) | Downloads CVE, CWE, CAPEC, ATT&CK and D3FEND and saves a local copy you can re-check and diff |
| **2. Clean the data** | [`data-preprocessing/`](data-preprocessing/) | Turns each source into flat JSON: one entity file and one relationship file per source |

Each stage only reads the stage before it, so you can re-run any one of them on
its own.

## Running it

You need Python 3.12 or newer.

### 1. Credentials

Make a `.env` file in this folder. It is gitignored, so nothing in it reaches
git:

```ini
# Only needed for stage 1. Free key: https://nvd.nist.gov/developers/request-an-api-key
# Without a key NVD allows 5 requests per 30s instead of 50 - about 10x slower.
NVD_API_KEY=<your key>
```

### 2. Download the raw data

```bash
cd data-acquisition
py -m full_crawler              # everything, from scratch (takes a few hours)
py -m incremental_crawler       # later runs: only fetch what changed
py -m full_crawler --dry-run    # check what would change, write nothing
```

Add `--sources cve` to run just one source. Details are in
[`data-acquisition/README.md`](data-acquisition/README.md) and in each source's
own README.

### 3. Clean it into flat JSON

```bash
cd data-preprocessing
py main.py                      # all five sources
py main.py --only cwe capec     # or just some of them
```

This writes exactly 10 files: an `entities.json` and a `relationships.json` in
each of the five source folders. Nothing is nested, ids are readable, entities
and links are kept apart, and re-runs are byte-identical.
[`data-preprocessing/README.md`](data-preprocessing/README.md) explains those
rules and the shared text cleanup; each source folder has its own README saying
why each field was kept, renamed or dropped.

### Keeping it up to date

```bash
cd data-acquisition      && py -m incremental_crawler   # fetch what changed
cd ../data-preprocessing && py main.py                  # clean it again
```

## The five sources

| Source | What it adds | Entities | Links | Comes from |
|---|---|---|---|---|
| **CVE** (NVD) | Real, specific vulnerabilities, plus their severity scores | 359,355 | 336,339 | NVD REST API 2.0 |
| **MITRE ATT&CK** | What attackers do: techniques, malware, groups, detections | 6,049 | 36,346 | TAXII 2.1 |
| **CWE** | Kinds of software weakness, and how to fix them | 5,040 | 16,941 | Versioned XML catalog |
| **CAPEC** | Attack patterns: how a weakness gets abused | 1,492 | 3,367 | Pre-built STIX bundle |
| **MITRE D3FEND** | Defences, and what each one counters | 1,193 | 6,471 | D3FEND REST API |



## Folder map

```
.env                     credentials, gitignored
README.md                you are here

data-acquisition/        stage 1 - five crawlers plus one runner for all of them
  DATA_STORAGE_REPORT.md what the raw data looks like, per source
  <SOURCE>/              client.py, full_crawler.py, incremental_crawler.py, README.md

data-preprocessing/      stage 2 - five cleaners plus one runner
  README.md              output rules shared by all five, and the text cleanup
  main.py                runs all five
  <SOURCE>/              <source>_preprocessing.py, entities.json,
                         relationships.json, README.md
```

Everything the code generates is gitignored (`*.json`). Those files are derived
from the sources, so they are meant to be regenerated, not committed.

## Where to read what

Docs sit next to the code they describe, and explain **why** a decision was made
rather than repeating what the code does.

| Question | Read |
|---|---|
| How do I run everything? | this file |
| What do the cleaned output files look like? | [`data-preprocessing/README.md`](data-preprocessing/README.md) |
| What does the raw downloaded data look like? | [`data-acquisition/DATA_STORAGE_REPORT.md`](data-acquisition/DATA_STORAGE_REPORT.md) |
| How does one crawler work? | that source's `data-acquisition/<SOURCE>/README.md` |
| Why was this field dropped, renamed or split out? | that source's `data-preprocessing/<SOURCE>/README.md` |
