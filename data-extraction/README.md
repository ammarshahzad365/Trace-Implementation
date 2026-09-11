# Extracting knowledge from unstructured text

This is the fourth stage. The first three turn structured catalogs into a graph;
this one reads prose -- APT reports, vendor repair notices, academic papers --
and produces the same entity and relationship records, using a local LLM. It
implements section 3.2.2 through 3.2.4 of the TRACE paper: two-step extraction,
filtering, standardisation, and entity alignment against what the graph already
holds.

Nothing here writes to Neo4j directly. Finished records go through
`POST /ingest` on the loading stage, so a record extracted from a report is
validated, labelled and merged by exactly the code that handles a batch load.

## What you need running

Three processes on the server, all loopback-only, all reached through the usual
SSH tunnel:

| What | Where | How to check |
|---|---|---|
| Neo4j | `bolt://localhost:7687` | `curl localhost:7474` |
| The ingest API (stage 3) | `http://127.0.0.1:8000` | `curl localhost:8000/health` |
| Ollama with the models | `http://127.0.0.1:11434` | `curl localhost:11434/api/tags` |

Ollama is installed in `~/ollama` as a tarball (no root on this host) and
started with `~/ollama/start.sh`. The models it needs:

```bash
ollama pull qwen3:32b     # the extractor, ~20 GB, fits one A100-40GB
ollama pull bge-m3        # the embedder, ~1.2 GB
```

Then, once:

```bash
cd data-extraction
../.venv/bin/python -m pip install -r requirements.txt
../.venv/bin/python -m extract.embed_corpus --all-except Vulnerability
```

The last line gives every existing node an `embedding` so alignment has
something to compare against. It takes a while (about ten thousand nodes) and
only needs re-running when the embedding model changes. `Vulnerability` is
skipped on purpose: 359,355 CVEs that align by identifier anyway.

Start the API:

```bash
setsid nohup ../.venv/bin/python -m extract.serve > ~/extract.log 2>&1 < /dev/null &
```

Port 8100. Interactive docs at `/docs`, like the ingest API.

## Using it

**The short way: upload a file, get the answer back.**

```bash
curl -s localhost:8100/extract/file -F "file=@report.txt" -F "genre=apt-report"
```

That runs the whole pipeline and returns the extracted entities and
relationships in the same response (plus what was aligned, what nearly matched,
and a `job_id` you can commit with). `source` defaults to the file name. A long
document can take minutes; if it passes `timeout` (default 1800 s) the response
says so and the job id fetches the result later. Only `.txt`/`.md` are accepted
-- convert PDFs first.

**The long way, step by step:**

**1. Post a document.** Plain text; convert PDFs first.

```bash
curl -s localhost:8100/extract -H 'Content-Type: application/json' -d '{
  "text": "...the report...",
  "source": "apt-report-2026-114",
  "genre": "apt-report"
}'
# {"job_id":"3f2a9c1d8e7b","status_url":"/extract/3f2a9c1d8e7b","status":"queued"}
```

`genre` is one of `apt-report`, `repair-notice`, `paper`. It decides which
entity types the model is offered (section 3.1.1 tailors the ontology per genre)
and whether the relevance check runs (papers only, section 3.2.2). `source` is
the document id; it lands on every record produced, as section 3.2.4 requires.

**2. Poll.** Extraction takes minutes, so it runs as a job.

```bash
curl -s localhost:8100/extract/3f2a9c1d8e7b
```

`status` moves `queued` → `running` → `done`. While running, `progress` says
where it is ("extracting, chunk 4 of 11"). A paper the classifier judged
irrelevant ends as `skipped`, which is an outcome, not an error.

**3. Review the proposal.** When done, the response carries it:

```json
{
  "entities":      [ ...new nodes, in the shape /ingest takes... ],
  "relationships": [ ...edges, each with the sentence that justified it... ],
  "aligned":       [ {"name": "Hafnium", "type": "group",
                      "matched_id": "G0125", "matched_name": "HAFNIUM",
                      "cosine": 0.63, "method": "embedding",
                      "reason": "same group, same targeting"} ],
  "near_misses":   [ {"name": "ToddyCat", "type": "group",
                      "closest_name": "Threat Group-3390", "cosine": 0.41,
                      "why_new": "nothing of this type reached theta=0.55; closest was ..."} ],
  "dropped":       [ {"name": "SN-4471", "why": "isolated, and named only by a serial number"} ],
  "other":         [ {"name": "OrpaCrab", "other_type": "backdoor", "description": "..."} ],
  "stats":         { ... }
}
```

Read `aligned` first. Each entry is a merge decision the model made -- this
extracted thing *is* that existing node -- with the similarity and the reason.
A wrong one here points every edge at the wrong entity, which is the failure
worth ten seconds of your attention. Then `near_misses`: every new entity with
the closest existing node it did *not* match and the score. If the right answer
keeps appearing there just under θ, θ is wrong for this embedder.

**4. Commit.** Writes through the ingest API. `drop_ids` removes anything you
rejected; dropping an entity also drops the edges that touched it.

```bash
curl -s localhost:8100/extract/3f2a9c1d8e7b/commit \
  -H 'Content-Type: application/json' -d '{"drop_ids": []}'
```

The response is the ingest API's own, so `skipped_dangling` and friends mean
what `data-loading/ingest/README.md` says they mean.

## What happens inside

Each stage names the section of the paper it comes from.

1. **Cleanse and screen** (§3.2.2, §3.2.3). Normalise the PDF debris that makes
   equal-looking names unequal strings; refuse documents with no prose in them.
2. **Relevance** (§3.2.2, papers only). One yes/no model call on title and
   opening text.
3. **Chunk.** ~4,000 characters, on paragraph boundaries, with overlap.
4. **Step one -- nodes** (§3.2.2). Per chunk: regex for standard identifiers
   (`CVE-…`, `T1190`, `G1028`, …), resolved against the graph; then the model,
   offered only the genre's types, with worked examples and the identifier hits
   as "what this graph already calls things". Output is schema-constrained, so
   a type outside the ontology cannot be produced.
5. **Step two -- relations** (§3.2.2). Form every pair the fixed triple patterns
   allow, among entities that co-occurred in a chunk, and ask the model per
   batch: *does the text state this?* Each entity is shown with its own
   extracted description, and the quoted sentence becomes the edge's
   `evidence` property. Two mechanical checks then apply: the sentence must
   name each concrete entity (tool, group, CVE, asset), and must lexically
   overlap the description of each paraphrased one (a technique). Measured on
   one Volt Typhoon report: 54 of 90 pairs were confirmed before these checks
   -- nearly every technique paired with every tool in the document -- and 14
   after, all of them defensible.
6. **Filter** (§3.2.3). Drop nodes that are isolated *and* named only by a
   serial number. Both conditions.
7. **Standardise** (§3.2.4). Ids minted as `<type>--<uuid5>` from type and
   name, so a re-run lands on the same id. `source` and `collected_at` on
   everything.
8. **Align** (§3.2.4, §5.2.2). Identifiers match directly; so does an exact
   name within the same type (`Mimikatz` is S0002, no model needed). Otherwise embed the
   description, fetch the 20 nearest of the same type, keep those at or above
   θ, and let the model choose among them or decline. Matches redirect edges to
   the existing node.

The vocabulary -- entity types per genre, triple patterns, how the paper's names
map onto this graph's labels -- lives in one file, `extract/ontology.py`, and
its docstring explains why the list is closed.

## Three things worth knowing before trusting a number

**An aligned entity is never written as a node.** `ingest/writer.py` MERGEs
with `SET n = props`, which replaces every property. Writing an aligned entity
would overwrite a real CVE's CVSS scores with the four fields a model produced.
So only its edges are written, and they carry `source: <document id>`, which is
where "this report mentioned that CVE" lives. This is also what §5.2.2
describes: the matched node's properties replace the extracted one's. The
consequence is that an existing node's own `source` field does not gain the new
document -- provenance for a mention is on the edge.

**θ = 0.9 is not this project's number.** The paper set it "after fine-tuning"
for its own sentence-transformer, which it never names. Cosine values are not
comparable across embedding models -- the same pair scores differently under
different encoders -- so importing 0.9 onto `bge-m3` is reading a constant off
the wrong scale.

Measured on this server, 2026-09-10, on the paper's own case study: the
extracted entity *Hafnium* against every `IntrusionSet` in the graph, using
`bge-m3`.

| Embedded text | ATT&CK `HAFNIUM` ranked | cosine |
|---|---|---|
| description only (as §5.2.2 says) | 4th, behind APT17 and UNC2452 | 0.537 |
| name only | 1st | 0.468 |
| name + description | 1st, next-best 0.552 | **0.630** |

So at θ = 0.9 the correct match is unreachable, and group alignment would never
fire -- silently. Two consequences. `align.embedding_text` embeds name and
description together, on both sides (the extracted description is a one-line
paraphrase that fits a dozen APTs; the name is where the identity lives). And
`ALIGN_THRESHOLD` must be calibrated for the embedder and reported alongside
the paper's 0.9, not imported.

`py -m extract.eval.calibrate` does that calibration on
`extract/eval/gold/alignment.jsonl` -- 30 entities, 23 with a true match in
the graph and 7 genuinely new, descriptions written as the extractor
paraphrases them rather than copied from ATT&CK. Measured 2026-09-10 with
`bge-m3` and `qwen3:32b`:

| θ | embedding only, top-1 | with the LLM judge |
|---|---|---|
| 0.50 | F1 0.72 | **F1 0.98** (P 0.96, R 1.00) |
| 0.55 | F1 0.73 | **F1 0.98** |
| 0.60 | F1 0.71 | F1 0.93 |
| 0.70 | F1 0.47 | -- |
| 0.90 (paper) | **F1 0.00** | **F1 0.00** |

Two things the table shows. The embedder alone tops out at 0.73 because the
cosine ranges overlap: true matches score 0.59-0.82, but the genuinely new
entities *also* score 0.55-0.72 against their nearest neighbour (`LockBit` vs
`StealBit` 0.72, `Procdump` vs `gsecdump` 0.67). No threshold separates them.
The judge lifts F1 to 0.98 by refusing exactly those -- which is the paper's
two-stage design doing what it is for. A lower θ is therefore not a loosening:
θ is the coarse filter, the judge is the decision, and the judge is what makes a
permissive θ safe. The server runs with `ALIGN_THRESHOLD=0.55`.

The gold set is small and one person labelled it; say so next to the number.
Adding to it is one line per entity.

Separately, Neo4j returns `(1+cos)/2` rather than raw cosine, and
`graph.similar` converts back -- see its docstring for why getting this wrong
would look fine and be wrong.

**The model choices are defended by measurement, not by name.** `qwen3:32b`
fits one A100, is Apache-2.0, and does constrained decoding well; it has no
cybersecurity-specific claim. `bge-m3` has the context length and dimensions
this needs; it is not "the best embedder". Both are config (`EXTRACT_MODEL`,
`EMBED_MODEL`), so the honest answer is a comparison on the same gold set --
which is also closer to the paper, whose Figures 2 and 4 are exactly such a
comparison across three LLMs. `EXTRACT_THINK=true` turns qwen3's reasoning
back on; measured here it cost 2.5× the time for an identical answer on easy
text, and has not yet been measured on hard text.

## Deviations from the paper, and why

- **Neo4j, not MongoDB.** Project-wide choice; see `data-loading/README.md`.
- **A named local embedder, not "sentence-transformers".** The paper names the
  library, not the model, so there is nothing to reproduce -- only to choose and
  justify.
- **Local open-weight models, not o1 / DeepSeek-R1 / Claude 3.7.** The likeliest
  source of a lower F1 than the paper's.
- **`reflects` and `solves` are absent.** §3.1.2 names them in prose; nothing
  in the paper gives them a triple pattern or evaluates them. Figure 2's seven
  patterns are what is implemented.
- **D3FEND ids are names, not `D3-PLA`.** In this graph a defensive technique's
  id is `AccessMediation`, not the short code Figure 3 shows, so no regex can
  find one in prose. Defensive techniques reach their node by embedding
  alignment or not at all.
- **One document at a time, by hand.** Algorithm 1's outer loop -- re-run every
  δ, pull new documents -- and the crawlers that feed it are not here.

## Settings

All read from the repo-root `.env` or the environment, environment winning.

| Key | Default | What |
|---|---|---|
| `OLLAMA_URL` | `http://127.0.0.1:11434` | |
| `EXTRACT_MODEL` | `qwen3:32b` | the extractor and judge |
| `EMBED_MODEL` | `bge-m3` | the embedder; changing it means re-running `embed_corpus` |
| `EMBED_DIMENSIONS` | `1024` | must match the embedder; the index is built at this width |
| `ALIGN_THRESHOLD` | `0.9` | raw cosine; see above |
| `EXTRACT_THINK` | `false` | reasoning on/off for `qwen3` |
| `EXTRACT_WORKERS` | `1` | concurrent jobs; one GPU, one job |
| `OLLAMA_TIMEOUT` | `600` | seconds per model call |
| `INGEST_URL` | `http://127.0.0.1:8000` | where commits go |
| `INGEST_API_KEY` | unset | sent as a bearer token on commit if set |
| `EXTRACT_API_KEY` | unset | required on `POST` endpoints if set |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` / `NEO4J_DATABASE` | as stage 3 | read-only, for alignment |

Finished jobs are kept as JSON under `data-extraction/.cache/jobs/`, so a result
survives an API restart. A job that was mid-run during a restart is reported as
`interrupted`; submit the document again.
