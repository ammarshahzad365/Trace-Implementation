# Trace-Implementation

A four-stage pipeline that turns five public MITRE/NIST cyber-threat-intelligence
catalogs into a single queryable Neo4j knowledge graph — the "Trace" graph, which
connects a **real vulnerability** to the **defence that stops it**:

```
CVE  ──▶  CWE  ──▶  CAPEC  ──▶  ATT&CK  ◀──  D3FEND
 a real      the kind      how attackers   the technique   the countermeasure
 bug         of mistake    abuse it        adversaries use  that defeats it
 it is
```

That chain is the whole point. In a table-shaped database it's five joins and a
lot of pain; in the graph it's one query that runs in milliseconds:

```cypher
MATCH path = (v:Vulnerability {id: "CVE-2021-44228"})
             -[:HAS_WEAKNESS]->(:Weakness)
             <-[:EXPLOITS]-(:AttackPattern)
             -[:MAPS_TO_TECHNIQUE]->(:AttackTechnique)
             <-[:COUNTERS]-(:DefensiveTechnique)
RETURN path
```

**Current state: all four stages are built and the graph is loaded** —
1,107,173 nodes and 1,129,919 relationships, with 81,625 CVEs reaching 124
defensive techniques through the complete five-catalog trace.

---

## The pipeline

| Stage | Folder | What it does | Run it with |
|---|---|---|---|
| **1. Acquire** | [`data-acquisition/`](data-acquisition/) | Crawls CVE, CWE, CAPEC, ATT&CK and D3FEND from upstream into a consistent, diffable local snapshot | `py -m full_crawler` |
| **2. Preprocess** | [`data-preprocessing/`](data-preprocessing/) | Flattens each source to graph-ready JSON: one entity file + one relationship file per source, nothing nested, human-readable ids | `py main.py` |
| **3. Load** | [`data-loading/`](data-loading/) | Loads it all into Neo4j — labels, typed relationships, cross-catalog dedupe, validation | `py main.py` |
| **4. Query** | [`data-loading/queries.cypher`](data-loading/queries.cypher) | ~20 starter queries, headed by the trace above | Neo4j Browser |

Each stage reads only the previous stage's output, so you can re-run any one of
them alone.

---

## Running the whole thing from scratch

Assumes Python 3.12+ and Docker. Total time: a few hours for stage 1 (it's
rate-limited by NVD), then about 8 minutes for stages 2 and 3 together.

### 0. Credentials

Create `.env` in the repo root (it's gitignored — nothing here reaches git):

```ini
# Stage 1 only. Free from https://nvd.nist.gov/developers/request-an-api-key
# Without it NVD allows 5 requests/30s instead of 50 — roughly 10x slower.
NVD_API_KEY=<your key>

# Stage 3. The password is yours to choose; it's applied on first container start.
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<choose one>
NEO4J_DATABASE=neo4j
```

### 1. Acquire the raw data

```bash
cd data-acquisition
py -m full_crawler              # everything, from scratch
py -m incremental_crawler       # afterwards: fetch only what changed
py -m full_crawler --dry-run    # check sync status without writing
```

`--sources cve` restricts it to one source. See
[`data-acquisition/README.md`](data-acquisition/README.md), and each source's own
README for its upstream quirks.

### 2. Preprocess into graph-ready JSON

```bash
cd data-preprocessing
py main.py                      # all five sources
py main.py --only cwe capec     # or a subset
```

Produces exactly 10 JSON files: an `entities.json` and a `relationships.json`
in each of the five source folders. Every record is flat (no nested maps — Neo4j
can't store them), every id is human-readable (`CVE-2021-44228`, `CWE-79`,
`T1055`), and relationships live in their own file rather than embedded on
entities. Within a file, each record's own `type` field says what kind it is
(`weakness`, `attack-technique`, `vulnerability`, …), so no further files are
needed to tell the kinds apart. Each source folder has a README explaining every
field decision.

### 3. Load into Neo4j

```bash
cd data-loading
py -m pip install -r requirements.txt

docker compose --env-file ../.env up -d    # start the database
py main.py --check                         # confirm Python can reach it
py main.py --dry-run                       # validate everything, write nothing
py main.py                                 # load (~7 minutes)
```

Six stages run in order; any can be run alone with `--stage`. Re-running is safe
— everything is matched on id, so a second run updates rather than duplicates.
Full details in [`data-loading/README.md`](data-loading/README.md), module map in
[`data-loading/ARCHITECTURE.md`](data-loading/ARCHITECTURE.md).

### 4. Look at the graph

Open **<http://localhost:7474>**, log in as `neo4j` with your password, and paste:

```cypher
CALL db.schema.visualization()
```

That draws every label and how they connect — the fastest way to get oriented.
Then work through [`data-loading/queries.cypher`](data-loading/queries.cypher).

> **Don't run a bare `MATCH (n) RETURN n`.** With 1.1M nodes the browser will try
> to draw all of them and lock up. Always `LIMIT`, or start from a specific
> `{id: ...}`.

### Keeping it current

```bash
cd data-acquisition  && py -m incremental_crawler   # fetch what changed
cd ../data-preprocessing && py main.py              # re-flatten
cd ../data-loading  && py main.py                   # update the graph in place
```

---

## The five sources

| Source | What it contributes | Nodes | Upstream |
|---|---|---|---|
| **CVE** (NVD) | Specific real-world vulnerabilities, plus CVSS/SSVC severity | 940,892 | NVD REST API 2.0 |
| **MITRE ATT&CK** | Adversary techniques, malware, threat groups, detections | 6,049 | TAXII 2.1 |
| **CWE** | Classes of software weakness, and their mitigations | 5,056 | Versioned XML catalog |
| **CAPEC** | Attack patterns — how weaknesses get abused | 1,538 | Pre-built STIX bundle |
| **MITRE D3FEND** | Defensive countermeasures, and what they counter | 1,193 | D3FEND REST API |

CVE is 96% of the graph by volume, and severity scores alone are half of it. The
genuinely interesting part — the trace path — is about 20,000 nodes: a small dense
core inside a large CVE shell.

---

## Repository map

```
.env                     credentials for all stages (gitignored)
PROJECT_CONTEXT.md       full project history and current state — read this to
                         pick the work up cold
README.md                you are here

data-acquisition/        stage 1 — five crawlers + a top-level orchestrator
  DATA_STORAGE_REPORT.md what the raw data looks like, per source
  <SOURCE>/              client.py, full_crawler.py, incremental_crawler.py, README.md

data-preprocessing/      stage 2 — five preprocessors + orchestrator
  main.py                runs all five
  <SOURCE>/              <source>_preprocessing.py, entities.json,
                         relationships.json, README.md

data-loading/            stage 3 — the Neo4j loader
  main.py                orchestrator: --stage, --only, --dry-run, --check
  graphload/             reusable engine (knows nothing about CTI)
  catalog/               this dataset, declared (labels, sources, bridge rules)
  docker-compose.yml     the Neo4j container
  queries.cypher         stage 4 — starter queries
  README.md              modelling decisions, verified results, how to extend
  ARCHITECTURE.md        file-by-file map

Prompts/                 LLM templates for a possible later text-extraction pass
structured-data/         vendored MITRE ATT&CK STIX archive (seeds ATT&CK history)
```

Everything a stage generates is gitignored (`*.json`, `data-loading/.cache/`) —
these are derived artefacts, meant to be regenerated rather than committed.

---

## Where the documentation lives

Documentation sits next to the code it describes, and explains **why** a decision
was made rather than restating what the code does:

| Question | Read |
|---|---|
| What's the state of this project? What's left? | [`PROJECT_CONTEXT.md`](PROJECT_CONTEXT.md) |
| How do I run everything? | this file |
| How does the graph model work? Why these labels/relationships? | [`data-loading/README.md`](data-loading/README.md) |
| Which file does what in the loader? | [`data-loading/ARCHITECTURE.md`](data-loading/ARCHITECTURE.md) |
| How do I add a sixth data source? | [`data-loading/README.md`](data-loading/README.md) → "Adding a new data source" |
| What does the raw data look like? | [`data-acquisition/DATA_STORAGE_REPORT.md`](data-acquisition/DATA_STORAGE_REPORT.md) |
| Why was this field dropped/renamed/unpacked? | that source's `data-preprocessing/<SOURCE>/README.md` |
| What can I ask the graph? | [`data-loading/queries.cypher`](data-loading/queries.cypher) |
