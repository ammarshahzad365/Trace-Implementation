# Trace-Implementation

A reproduction of the TRACE paper. It downloads five public cyber-security
catalogs, cleans them, loads them into one Neo4j knowledge graph, and then grows
that graph from plain-text reports using a local LLM.

## The four stages

| Stage | Folder | What it does |
|---|---|---|
| 1. Get the data | [`data-acquisition/`](data-acquisition/README.md) | Downloads CVE, CWE, CAPEC, ATT&CK and D3FEND |
| 2. Clean the data | [`data-preprocessing/`](data-preprocessing/README.md) | Turns each source into two flat JSON files (10 in total) |
| 3. Load the graph | [`data-loading/`](data-loading/README.md) | Loads the 10 files into Neo4j and serves an API for adding records later |
| 4. Read reports | [`data-extraction/`](data-extraction/README.md) | Extracts entities and relationships from prose with a local LLM and adds them to the graph |

Each stage reads only the output of the stage before it, through files or HTTP,
never through imports. Any stage can be re-run on its own.

## How to run everything

The live copy runs on the university server **dinf-anhinga (10.44.83.124)**,
in `~/trace/`, and the graph there is already loaded. If you only want to use
it, skip to [step 4](#4-start-the-services-on-the-server).

### 1. What you need

- Python 3.12 or newer
- Neo4j 5.x (stages 3 and 4) — see [data-loading](data-loading/README.md#starting-a-database)
- Ollama and a GPU with ~40 GB (stage 4 only)

Install each stage's dependencies once:

```bash
py -m pip install -r data-loading/requirements.txt
py -m pip install -r data-extraction/requirements.txt
```

Stages 1 and 2 use only the standard library. On the Linux server use
`../.venv/bin/python` (or `python3`) wherever this page says `py`.

### 2. Credentials

Copy [`.env.example`](.env.example) to `.env` in the repo root and fill it in.
`.env` is gitignored.

```ini
NVD_API_KEY=<your key>       # stage 1; free at nvd.nist.gov, ~10x faster with it
NEO4J_PASSWORD=<password>    # stages 3 and 4
ALIGN_THRESHOLD=0.55         # stage 4; the calibrated value (see data-extraction)
```

### 3. Build the graph (stages 1–3)

Only needed once, or when you want fresh data. Neo4j keeps the graph on disk,
so it survives restarts.

```bash
cd data-acquisition
py -m full_crawler              # first time: everything (a few hours)
py -m incremental_crawler       # later: only what changed

cd ../data-preprocessing
py main.py                      # writes the 10 JSON files

cd ../data-loading
py main.py --dry-run            # check the files; needs no database
py main.py --check              # check the database connection
py main.py                      # load (about 2 minutes)
```

A good load reports **372,739 nodes and 393,418 relationships**.

### 4. Start the services on the server

Nothing restarts by itself after a reboot. Start these four **in order**, each
in its own SSH command. The `< /dev/null ... &` part matters: without it the SSH
session hangs.

```bash
# 1. Neo4j — the graph (ports 7474, 7687)
ulimit -n 40000; ~/opt/neo4j/bin/neo4j start

# 2. Ingest API — writes new records (port 8000)
cd ~/trace/data-loading && setsid nohup ../.venv/bin/python -m ingest.serve > ~/ingest.log 2>&1 < /dev/null &

# 3. Ollama — the LLM and the embedder (port 11434)
setsid nohup ~/ollama/start.sh > ~/ollama/serve.log 2>&1 < /dev/null &

# 4. Extraction API — the review page (port 8100)
setsid nohup ~/extract-serve.sh > ~/extract.log 2>&1 < /dev/null &
```

To stop: `~/opt/neo4j/bin/neo4j stop`, `pkill -f '[i]ngest.serve'`,
`pkill -f '[e]xtract.serve'`. Keep the square brackets, or `pkill` matches its
own command line and kills your shell.

### 5. Connect from your laptop

Everything binds to `127.0.0.1` on the server, so reach it through an SSH
tunnel. Leave this terminal open; the tunnel is the connection.

```bash
ssh -L 7474:localhost:7474 -L 7687:localhost:7687 -L 8000:localhost:8000 -L 8100:localhost:8100 <user>@10.44.83.124
```

| Page | Address |
|---|---|
| Neo4j Browser (view the graph) | http://localhost:7474 |
| Ingest API docs | http://localhost:8000/docs |
| Extraction review page | http://localhost:8100/ui |

### 6. View the knowledge graph

Open http://localhost:7474 and log in with connect URL `bolt://localhost:7687`,
user `neo4j` and the password from `.env`. Type a query in the top bar and press
**Ctrl+Enter**.

```cypher
// The shape of the whole graph: every label and how they connect
CALL db.schema.visualization();

// One full attack chain: a CVE through to the defences against it
MATCH path = (v:Vulnerability {id: 'CVE-2021-44228'})-[:RELATED_TO]->(:Weakness)
      -[:RELATED_TO]->(:AttackPattern)-[:RELATED_TO]->(:AttackTechnique)
      <-[:COUNTERS]-(:DefensiveTechnique)
RETURN path LIMIT 25;

// Everything one report added (use the report's source id)
MATCH path = ()-[r]->() WHERE r.source = 'report.txt' RETURN path LIMIT 50;
```

- Click a node to see its properties; double-click to expand its neighbours.
- A query that returns nodes or paths draws a graph; one that returns counts or
  text gives a table.
- Always use `LIMIT`. `MATCH (n) RETURN n` over 372,739 nodes draws nothing useful.
- More queries: [`data-loading/queries.cypher`](data-loading/queries.cypher).

### 7. Extract from a report

First time only (already done on the server):

```bash
ollama pull qwen3:32b           # the extractor, ~20 GB
ollama pull bge-m3              # the embedder, ~1.2 GB
cd data-extraction
py -m extract.embed_corpus --all-except Vulnerability   # vectors for alignment
```

Then, every time:

1. Open http://localhost:8100/ui.
2. Upload a `.txt` or `.md` file (convert PDFs first) and choose its genre:
   APT report, repair notice or paper.
3. Wait a few minutes while it runs.
4. Check what it found, remove anything wrong, approve.
5. Check the matches to existing nodes, then commit. Only now is anything written.

Or in one call: `curl -s localhost:8100/extract/file -F "file=@report.txt" -F "genre=apt-report"`.

### 8. Keep it up to date

```bash
cd data-acquisition   && py -m incremental_crawler
cd ../data-preprocessing && py main.py
cd ../data-loading    && py main.py
```

Re-loading is safe: records are merged on their ids, never duplicated.

### 9. Check it works

| Service | Check (on the server) |
|---|---|
| Neo4j | `~/opt/neo4j/bin/neo4j status` |
| Ingest API | `curl localhost:8000/health` |
| Ollama | `curl localhost:11434/api/tags` |
| Extraction API | `curl localhost:8100/docs` |

| Problem | Fix |
|---|---|
| Nothing responds | The server rebooted. Redo step 4. |
| Tunnel will not bind 7474/7687 | A local Neo4j or old tunnel holds the ports. Stop it. |
| `NEO4J_PASSWORD is not set` | Create or fill in `.env`. |
| Neo4j dies on start with `Invalid memory configuration` | Heap + page cache exceed RAM; lower them in `conf/neo4j.conf`. |
| An extraction job shows `interrupted` | The API restarted mid-run. Submit it again. |
| Commit fails with "not declared in catalog/labels.py" | The server's `data-loading/` is out of date. Copy it over and restart the ingest API. |

## The five sources

| Source | What it adds | Entities | Links |
|---|---|---|---|
| CVE (NVD) | Specific vulnerabilities and their severity scores | 359,355 | 336,339 |
| MITRE ATT&CK | What attackers do: techniques, malware, groups, detections | 5,659 | 33,105 |
| CWE | Kinds of software weakness, and their fixes | 5,040 | 16,767 |
| CAPEC | Attack patterns: how a weakness gets abused | 1,492 | 2,155 |
| MITRE D3FEND | Defences, and what each one counters | 1,193 | 5,056 |

The links add up to 393,422; the graph holds 393,418 because 4 CWE links cite
CVEs that NVD never published, and those are skipped rather than invented.
Only 23.8% of CVEs reach a D3FEND defence through the full chain; the gaps are
in the source data (56,702 CVEs have no CWE at all).

## Folder map

```
.env.example            every setting, with defaults (copy to .env)
data-acquisition/       stage 1: one crawler folder per source
data-preprocessing/     stage 2: one cleaner per source, plus main.py
data-loading/           stage 3: main.py (batch loader), ingest/ (API), queries.cypher
data-extraction/        stage 4: extract/ (pipeline, API, review page, calibration)
```

Everything generated (`*.json`, `.cache/`) is gitignored and can be rebuilt.
Each folder has one README; module docstrings explain the reasoning in detail.
