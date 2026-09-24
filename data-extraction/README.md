# Data Extraction (stage 4)

Reads plain-text security documents (APT reports, repair notices, papers) with
a local LLM, extracts entities and relationships, matches them to what the graph
already holds, and writes them through stage 3's `/ingest` API. It implements
sections 3.2.2–3.2.4 of the TRACE paper. Nothing here writes to Neo4j directly.

## Run it

Needs, on the server (all on `127.0.0.1`, reached through the SSH tunnel):

| Service | Address | Check |
|---|---|---|
| Neo4j | `bolt://localhost:7687` | `curl localhost:7474` |
| Ingest API (stage 3) | `http://127.0.0.1:8000` | `curl localhost:8000/health` |
| Ollama | `http://127.0.0.1:11434` | `curl localhost:11434/api/tags` |

Once:

```bash
ollama pull qwen3:32b          # the extractor and judge, ~20 GB, fits one A100-40GB
ollama pull bge-m3             # the embedder, ~1.2 GB
../.venv/bin/python -m pip install -r requirements.txt
../.venv/bin/python -m extract.embed_corpus --all-except Vulnerability
```

`embed_corpus` gives every existing node an embedding so alignment has something
to compare against (about 10,000 nodes). Re-run it only if the embedder changes.
CVEs are skipped: they always match by id.

Start the API (port 8100):

```bash
setsid nohup ../.venv/bin/python -m extract.serve > ~/extract.log 2>&1 < /dev/null &
```

Then use it:

- **Review page:** http://localhost:8100/ui. Upload a file, watch it run, check
  what was found, approve, check the merges, commit.
- **One call:** `curl -s localhost:8100/extract/file -F "file=@report.txt" -F "genre=apt-report"`
  runs everything and returns the result. Only `.txt`/`.md`; convert PDFs first.
- **Step by step:**

| Call | Does |
|---|---|
| `POST /extract` | Start a job with `text`, `source` (the document id) and `genre` (`apt-report`, `repair-notice`, `paper`). Add `"review": true` to stop before alignment. |
| `GET /extract/{id}` | Progress: `queued` → `running` → `done` (or `awaiting_review`, `skipped`) |
| `POST /extract/{id}/align` | Continue after review, with `drop_entities` / `drop_relations` |
| `POST /extract/{id}/commit` | Write to the graph, with `drop_ids` for anything rejected |

Interactive docs are at `/docs`. Finished jobs are saved in `.cache/jobs/`, so
results survive a restart; a job that was running during a restart shows
`interrupted` and must be resubmitted.

## What happens inside

1. **Clean and screen.** Fix PDF leftovers so equal names are equal strings.
   Reject texts under 400 characters or 80 words.
2. **Relevance** (papers only). One yes/no model call on the title and opening.
3. **Chunk.** About 4,000 characters, on paragraph or sentence ends, 200
   characters of overlap.
4. **Entities (step one).** A regex finds standard ids (`CVE-…`, `CWE-…`,
   `T1190`, `G1028`) and looks them up. Then the model lists each entity with a
   name, type and one-line description.
5. **Relations (step two).** The model proposes the links the text states. Each
   one then goes back to the model, ten at a time: *does the text say this?* The
   quoted sentence is stored as the edge's `evidence`, and the code checks that
   it names both ends.
6. **Filter.** Drop an entity only if it has no links *and* is named only by a
   serial number.
7. **Standardise.** Ids are `<type>--<uuid5>` from type and name, so re-runs
   give the same ids. `source` and `collected_at` go on every record.
8. **Align.** Match to existing nodes: by id, by exact name within the type, by
   a name containing a known one (`Cobalt Strike beacon` → S0154), or by
   embedding: the 20 nearest of the same type at or above θ, then the model
   picks one or declines. A match redirects the edges to the existing node.

## Key decisions

**Open vocabulary.** The model may use any of these names, and invents a new one
only when none fits ("a wrong type is worse than a new one"):

| | Offered | New names |
|---|---|---|
| Entity types | 53: the graph's 25 labels + STIX 2.1 objects + report observables (hash, IP, domain, URL, email, registry key, mutex …) | kebab-case; the loader derives a label |
| Relation types | 60: the graph's 34 + STIX 2.1 relationships | snake_case; the loader uppercases it |

- The list lives in `extract/ontology.py`. Synonyms are folded (`APT group` →
  `intrusion-set`, `backdoor` → `malware`), so a synonym never becomes a new type.
- Hidden from the model: `related_to` (it became the answer to everything) and
  `revoked_by` (ATT&CK bookkeeping).
- Removed on 2026-09-23: the paper's `discovers`, `causes`, `mitigated_by` and
  `used_by`, each a duplicate of a STIX name. `uses` and `targets` stay: they are
  ATT&CK's own and carry 20,187 edges.
- The paper's 7 types survive as `PAPER_TYPES`, so per-type scores stay
  comparable with its Table 4.
- Names are free strings, not an enum: with an enum plus `other`, the model never
  once chose `other` and forced a wrong name instead.
- The code, not the model, owns direction: a backwards link is turned round; a
  group that "uses" a victim, place or vulnerability `targets` it; an actor that
  "exploits" a vulnerability `targets` it (STIX keeps `exploits` for malware and
  tools).

**θ = 0.55, not the paper's 0.9.** The paper tuned 0.9 for an embedder it never
names, and cosine scales differ between models. On the paper's own example,
*Hafnium* vs ATT&CK's `HAFNIUM` scores 0.630 with `bge-m3` (embedding name +
description; description alone ranks it 4th). Calibrated with
`py -m extract.eval.calibrate` on 30 hand-labelled entities (23 with a true
match, 7 new), on 2026-09-10:

| θ | Embedding only (F1) | With the LLM judge (F1) |
|---|---|---|
| 0.50 | 0.72 | 0.98 |
| 0.55 | 0.73 | 0.98 |
| 0.60 | 0.71 | 0.93 |
| 0.90 (paper) | 0.00 | 0.00 |

Embedding alone cannot separate true matches from look-alikes (`LockBit` vs
`StealBit` scores 0.72); the judge refuses those. So θ is a coarse filter and the
judge makes the decision. The gold set is small and labelled by one person.

**An aligned entity is never written as a node, only its edges.** Writing it
would replace a real node's properties (a CVE's CVSS scores) with the model's few
fields. The mention is recorded on the edge's `source`.

**Two human review points.** Optionally before alignment (reject entities or
links by reading the text), and always before commit (check the merges, near
misses and new names). The first gate sits before alignment because a wrong merge
silently attaches a document's edges to the wrong node.

**Models are chosen by measurement, not reputation.** `qwen3:32b` fits one GPU,
is Apache-2.0 and handles constrained output well; `bge-m3` has the context
length needed. Both are settings. Thinking mode is off: it took 2.5× longer for
the same answer. Output can still differ across Ollama versions, quantisations
and GPUs, so record the model tag you ran with any number you report.

## What a result contains

| Field | Holds |
|---|---|
| `entities` | New nodes, in the shape `/ingest` takes |
| `relationships` | Edges, each with its evidence sentence |
| `aligned` | Merges into existing nodes, with cosine and the judge's reason. Read these first. |
| `near_misses` | New entities with the closest node they did *not* match |
| `dropped` | What was removed, and why |
| `new_types` / `new_relations` | Names the model coined |
| `stats` | Counts per type and relation |

## Differences from the paper

- Local open models, not o1 / DeepSeek-R1 / Claude 3.7: the likeliest reason
  for a lower F1.
- Neo4j, not MongoDB; a named embedder, since the paper names only the library.
- Open vocabularies instead of the paper's fixed 7 types and 6 relations.
- D3FEND ids here are names (`AccessMediation`), not `D3-PLA`-style codes, so
  defensive techniques align by embedding only.
- One document at a time, by hand: the paper's automatic re-crawl loop is not
  built.

**Watch:** 53 types is the regime where the paper saw type confusion, and output
varies slightly run to run. A per-type scored gold set is the next measurement.

## Settings

Read from the repo-root `.env` (a real environment variable wins).

| Key | Default | What |
|---|---|---|
| `OLLAMA_URL` | `http://127.0.0.1:11434` | |
| `EXTRACT_MODEL` | `qwen3:32b` | Extractor and judge |
| `EMBED_MODEL` | `bge-m3` | Embedder; changing it means re-running `embed_corpus` |
| `EMBED_DIMENSIONS` | `1024` | Must match the embedder |
| `ALIGN_THRESHOLD` | `0.9` | Set to **0.55** (the server does); see above |
| `EXTRACT_THINK` | `false` | qwen3 reasoning on/off |
| `EXTRACT_WORKERS` | `1` | Concurrent jobs; one GPU, one job |
| `OLLAMA_TIMEOUT` | `600` | Seconds per model call |
| `INGEST_URL` | `http://127.0.0.1:8000` | Where commits go |
| `INGEST_API_KEY` / `EXTRACT_API_KEY` | unset | Bearer tokens, if set |
| `NEO4J_*` | as stage 3 | Read-only, for alignment |
