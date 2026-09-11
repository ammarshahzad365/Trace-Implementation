# Trace-Implementation

This project pulls five public cyber-security catalogs from the internet, cleans
them up, turns them into one connected set of entity and relationship files,
loads that into Neo4j as a single queryable knowledge graph — and then grows the
graph from prose, using a local LLM to read APT reports, advisories and papers
the way the TRACE paper describes.

## The four stages

| Stage | Folder | What it does |
|---|---|---|
| **1. Get the data** | [`data-acquisition/`](data-acquisition/) | Downloads CVE, CWE, CAPEC, ATT&CK and D3FEND and saves a local copy you can re-check and diff |
| **2. Clean the data** | [`data-preprocessing/`](data-preprocessing/) | Turns each source into flat JSON: one entity file and one relationship file per source |
| **3. Load the graph** | [`data-loading/`](data-loading/) | Streams those ten files into Neo4j — 372,739 nodes and 393,418 relationships — and serves an HTTP API for records that arrive later |
| **4. Read the prose** | [`data-extraction/`](data-extraction/) | Posts an unstructured document to a local LLM, extracts entities and relations, aligns them with what the graph already knows, and writes through stage 3's API |

Each stage only reads the stage before it, so you can re-run any one of them on
its own. Stages talk through files and HTTP, never imports.

## Running it

You need Python 3.12 or newer. Stage 3 also needs a Neo4j 5.x server; see
[`data-loading/README.md`](data-loading/README.md#starting-a-database).

### 1. Credentials

Make a `.env` file in this folder. It is gitignored, so nothing in it reaches
git — [`.env.example`](.env.example) lists every key with its default:

```ini
# Only needed for stage 1. Free key: https://nvd.nist.gov/developers/request-an-api-key
# Without a key NVD allows 5 requests per 30s instead of 50 - about 10x slower.
NVD_API_KEY=<your key>

# Needed for stage 3.
NEO4J_PASSWORD=<your password>
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

### 4. Load it into Neo4j

```bash
cd data-loading
py -m pip install -r requirements.txt
py main.py --dry-run            # validate the files; needs no database
py main.py --check              # confirm Python can reach the database
py main.py                      # load, about two minutes
```

You run this once — Neo4j keeps the graph on disk, so it survives restarts.
[`data-loading/README.md`](data-loading/README.md) covers starting a database,
connecting through an SSH tunnel, and [`queries.cypher`](data-loading/queries.cypher)
has a starter set including the CVE → CWE → CAPEC → ATT&CK → D3FEND traversal
this project exists for.

### 5. Extract from unstructured text

```bash
cd data-extraction
py -m pip install -r requirements.txt
py -m extract.embed_corpus          # once: index existing nodes for alignment
py -m extract.serve                 # http://127.0.0.1:8100/docs
```

Needs Ollama running locally with the extractor and embedder pulled. POST a
report, poll the job, review what it proposes, commit. Every merge decision and
every edge's justifying sentence is shown before anything is written.
[`data-extraction/README.md`](data-extraction/README.md) has the walkthrough and
the measurements behind the model and threshold choices.

### Keeping it up to date

```bash
cd data-acquisition      && py -m incremental_crawler   # fetch what changed
cd ../data-preprocessing && py main.py                  # clean it again
cd ../data-loading       && py main.py                  # load it again
```

## The five sources

| Source | What it adds | Entities | Links | Comes from |
|---|---|---|---|---|
| **CVE** (NVD) | Real, specific vulnerabilities, plus their severity scores | 359,355 | 336,339 | NVD REST API 2.0 |
| **MITRE ATT&CK** | What attackers do: techniques, malware, groups, detections | 5,659 | 33,105 | TAXII 2.1 |
| **CWE** | Kinds of software weakness, and how to fix them | 5,040 | 16,767 | Versioned XML catalog |
| **CAPEC** | Attack patterns: how a weakness gets abused | 1,492 | 2,155 | Pre-built STIX bundle |
| **MITRE D3FEND** | Defences, and what each one counters | 1,193 | 5,056 | D3FEND REST API |

Counted from the `relationships.json` each source produces. The graph holds
fewer relationships than the column totals (393,418 against 393,422): a handful
of edges name an endpoint no catalog publishes — CWE citing CVEs NVD rejected —
and those are reported and skipped rather than invented.



## Folder map

```
.env                     credentials, gitignored
.env.example             every key it can hold, with defaults
README.md                you are here

data-acquisition/        stage 1 - five crawlers plus one runner for all of them
  DATA_STORAGE_REPORT.md what the raw data looks like, per source
  <SOURCE>/              client.py, full_crawler.py, incremental_crawler.py, README.md

data-preprocessing/      stage 2 - five cleaners plus one runner
  README.md              output rules shared by all five, and the text cleanup
  main.py                runs all five
  <SOURCE>/              <source>_preprocessing.py, entities.json,
                         relationships.json, README.md

data-loading/            stage 3 - the ten files become one Neo4j graph
  README.md              running it, connecting to the graph, adding a source
  main.py                the batch loader, five stages
  graphload/             the engine: reads records, names them, writes them
  catalog/               this dataset as declarations - five specs, two name maps
  ingest/                HTTP API for records that arrive after the load
  queries.cypher         starter queries, including the full CVE-to-D3FEND path

data-extraction/         stage 4 - prose becomes records, through a local LLM
  README.md              running it, reviewing a proposal, what was measured
  extract/               the pipeline: ontology, prompts, alignment, jobs, API
  extract/eval/          the threshold calibration and its gold set
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
| How do I start Neo4j, connect to it, or query the graph? | [`data-loading/README.md`](data-loading/README.md) |
| How do I add records after the load? | [`data-loading/ingest/README.md`](data-loading/ingest/README.md) |
| How do I extract records from a report or paper? | [`data-extraction/README.md`](data-extraction/README.md) |
| Which entity and relation types can the LLM produce, and why those? | [`data-extraction/extract/ontology.py`](data-extraction/extract/ontology.py) |
