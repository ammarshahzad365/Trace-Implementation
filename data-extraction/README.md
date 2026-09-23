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

The ingest API must be the committed version (any entity `type` accepted, label
derived on the fly). The copy on the server was from 1 September until
2026-09-17 and refused `identity` with a 422; redeploy `data-loading/` if a
commit ever says "not declared in catalog/labels.py".

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

**The easy way: the review page.** `http://<host>:8100/ui` walks the whole
thing -- drop a document in, watch it run, look at what the text says, approve
it, look at what alignment decided to merge, commit. It is one static file
served by this API (`extract/ui/index.html`), so it is same-origin with the
endpoints, needs no build step and adds no dependency. Everything below is what
that page calls.

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

`genre` is one of `apt-report`, `repair-notice`, `paper`. It names the document
to the model ("an APT report" primes differently from "a document") and decides
whether the relevance check runs (papers only, §3.2.2). It no longer narrows the
types offered -- §3.1.1's per-genre lists went with the open vocabulary.
`source` is the document id; it lands on every record produced, as §3.2.4
requires.

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
  "aligned":       [ {"name": "Hafnium", "type": "intrusion-set",
                      "matched_id": "G0125", "matched_name": "HAFNIUM",
                      "cosine": 0.63, "method": "embedding",
                      "reason": "same group, same targeting"} ],
  "near_misses":   [ {"name": "ToddyCat", "type": "intrusion-set",
                      "closest_name": "Threat Group-3390", "cosine": 0.41,
                      "why_new": "nothing of this type reached theta=0.55; closest was ..."} ],
  "dropped":       [ {"name": "SN-4471", "why": "isolated, and named only by a serial number"} ],
  "new_types":     [ {"type": "cryptocurrency-wallet", "count": 1, "examples": ["44AfFq...9zG"]} ],
  "new_relations": [ {"relation": "shares_code_with", "count": 1,
                      "example": "ShadowPad ... shares a large part of its code base with PlugX"} ],
  "stats":         { ..., "relation_types": {"uses": 12, "targets": 2} }
}
```

Read `aligned` first. Each entry is a merge decision the model made -- this
extracted thing *is* that existing node -- with the similarity and the reason.
A wrong one here points every edge at the wrong entity, which is the failure
worth ten seconds of your attention. Then `near_misses`: every new entity with
the closest existing node it did *not* match and the score. If the right answer
keeps appearing there just under θ, θ is wrong for this embedder. Then
`new_types` and `new_relations`: entity and relation types the vocabulary does
not hold yet, which the model coined because none of the existing ones fit.
They *are* written on commit -- the loader derives a label from a new type and
creates its constraint -- and these lists are where you see them first.

**4. Commit.** Writes through the ingest API. `drop_ids` removes anything you
rejected; dropping an entity also drops the edges that touched it.

```bash
curl -s localhost:8100/extract/3f2a9c1d8e7b/commit \
  -H 'Content-Type: application/json' -d '{"drop_ids": []}'
```

The response is the ingest API's own, so `skipped_dangling` and friends mean
what `data-loading/ingest/README.md` says they mean.

### Reviewing *before* alignment

Add `"review": true` to step 1 and the job stops one stage earlier, at
`awaiting_review`, holding a **draft** instead of a proposal: the entities the
document names and the relations it states, each with the sentence that
justified it, and nothing yet decided about what the graph already holds.

```bash
curl -s localhost:8100/extract -H 'Content-Type: application/json' \
  -d '{"text":"...","source":"apt-report-2026-114","review":true}'
# ... poll until status is awaiting_review, then:
curl -s localhost:8100/extract/3f2a9c1d8e7b/align \
  -H 'Content-Type: application/json' \
  -d '{"drop_entities":["malware:china chopper"],"drop_relations":[]}'
```

`drop_entities` takes the draft's entity keys (`type:lowercased name`) and
`drop_relations` its relation ids (`source_key|relation|target_key`). Rejecting
an entity also rejects every relation touching it, and both are recorded in the
proposal's `dropped` list as `rejected during review`, so the record still
accounts for everything the extractor found. Alignment then runs on what
survived and the job settles at `done` with an ordinary proposal, which
`/commit` writes as usual.

**Why the gate goes here.** Alignment is the decision that is expensive to
undo: a wrong merge attaches this document's edges to the wrong existing node
and nothing downstream complains. Everything before it can be checked against
the text by reading, without knowing anything about the graph. So the cheap
check comes first. Keeping the second gate as well is deliberate -- the merges
themselves, with their cosines and the judge's reasons, are the other thing
worth a human glance.

A parked job survives an API restart; it is written to disk like any other
settled state, and only `queued`, `running` and `aligning` are reported as
`interrupted`. Left at the default `review: false`, both stages run back to
back exactly as before, and `POST /extract/file` is unchanged.

## What happens inside

Each stage names the section of the paper it comes from.

1. **Cleanse and screen** (§3.2.2, §3.2.3). Normalise the PDF debris that makes
   equal-looking names unequal strings; refuse documents with no prose in them.
2. **Relevance** (§3.2.2, papers only). One yes/no model call on title and
   opening text.
3. **Chunk.** ~4,000 characters, on paragraph boundaries, with overlap.
4. **Step one -- nodes** (§3.2.2). Per chunk: regex for standard identifiers
   (`CVE-…`, `CWE-…`, `T1190`, `G1028`, …), resolved against the graph; then
   the model, shown the whole type vocabulary (below) with worked examples and
   the identifier hits as "what this graph already calls things". It copies a
   type name, or writes a new one when none fits; `ontology.normalise_type`
   folds spelling and an alias table ("APT group" → `intrusion-set`, "C2
   server" → `infrastructure`) so a synonym never becomes a duplicate type.
5. **Step two -- relations** (§3.2.2), in two halves. First, per chunk, the
   model is shown the entities found there and the relation vocabulary (below)
   and asked which relationships the text states between them, copying an
   existing relation name where one fits and writing a new snake_case name
   where none does. Second, every proposed relation goes back to the model in
   batches of ten: *does the text state this?* Each entity is shown with its
   own extracted description, and the quoted sentence becomes the edge's
   `evidence` property. Mechanical checks then apply: the sentence must name
   each concrete entity (tool, group, CVE, asset) -- or, for the one group in
   a chunk, refer to it as "the actor", "the group" or "it" -- and must
   lexically overlap the description of each paraphrased one (a technique).
   The code also owns direction: a relation stated backwards is turned round
   against the known patterns, and a `uses` whose object is an asset,
   identity, location or vulnerability becomes `targets`.
6. **Filter** (§3.2.3). Drop nodes that are isolated *and* named only by a
   serial number. Both conditions.
7. **Standardise** (§3.2.4). Ids minted as `<type>--<uuid5>` from type and
   name, so a re-run lands on the same id. `source` and `collected_at` on
   everything.
8. **Align** (§3.2.4, §5.2.2). Identifiers match directly; so does an exact
   name within the same type (`Mimikatz` is S0002, no model needed), and so
   does a proper-noun name that contains an existing one (`Cobalt Strike
   beacon` is S0154). Otherwise embed the description, fetch the 20 nearest of
   the same type, keep those at or above θ, and let the model choose among
   them or decline. Matches redirect edges to the existing node.

The vocabulary -- entity types per genre, relation types, how the paper's names
map onto this graph's labels -- lives in one file, `extract/ontology.py`, and
its docstring explains what is closed and what is not.

## The vocabulary

Both lists are open, decided 2026-09-17 at the user's direction. What the
model is offered, and what it may add:

| | Offered | May add a new one? |
|---|---|---|
| Entity types | the graph's 25 labels + every STIX 2.1 domain object + STIX's report-relevant observables (hash, IP, domain, URL, email, registry key, certificate, mutex …) = **53** | yes -- a new kebab-case name; written, label derived by the loader |
| Relation types | the graph's 34 + STIX 2.1's relationships = **60** | yes -- a new snake_case name; written, uppercased by the loader |

The table lives in `extract/ontology.py` (`ENTITY_GROUPS`, `RELATION_GROUPS`),
each entry with a one-line definition and, for entities, the `type` value the
loader expects and the labels alignment searches (`tool` searches `Tool` and
`Malware`; `threat-actor` searches `ThreatActor` and `IntrusionSet`, because
ATT&CK files most actors as intrusion sets). Two names are known but never
offered: `related_to` (NVD's cross-reference; offered, it became the fallback
for everything) and `revoked_by` (ATT&CK bookkeeping).

Four names the paper used are **gone** (2026-09-23): `discovers`, `causes`,
`mitigated_by` and `used_by`. Each was the paper's alone, each named a fact
STIX already names -- a group that exploits a CVE `targets` it, a mitigation
`mitigates` -- and none had a single edge in this graph except five written by
our own ProxyLogon test, since deleted. The paper's other two, `uses` and
`targets`, are ATT&CK's own vocabulary carrying 20,187 edges, and stay in the
list as ATT&CK's rather than as the paper's.

The paper's seven types are the subset `PAPER_TYPES`, under their new names
(`vuln` → `vulnerability`, `group` → `intrusion-set`, `technique` →
`attack-technique`, `defend_technique` → `defensive-technique`), and per-type
F1 against Table 4 is reported over that subset. The old names remain as
aliases so the gold set still resolves.

**How the model chooses a name.** It must copy an offered name exactly when
its definition genuinely describes the thing, and write a new one only when
none does -- "do not stretch an existing type; a wrong type is worse than a
new one". The code then canonicalises: `Threat Actor` → `threat-actor`,
`backdoor` → `malware`, `Exfiltrates To` → `exfiltrates_to`; whatever is not
a known name after that is new. Direction is owned by the schema, not the
model (a relation stated backwards is turned round against the known
patterns), and a few definitions are enforced in code because the model did
not always follow them: `uses` of an asset, identity, location or
vulnerability is `targets`; an actor or campaign that `exploits` a
vulnerability `targets` it, since STIX reserves `exploits` for malware and
tools; an actor that "drops" or "delivers" something `uses` it.

**Why free strings, not enums.** Both names were JSON-schema enums with an
`other` escape at first. Under constrained decoding the model never once
chose `other`: for two malware families that share code it tried `uses`,
`subtechnique_of` and `targets` in turn. An enum makes the escape value
unreachable in practice, so the schema now constrains only what the code can
check afterwards (a relation's endpoints are enums of the entities actually
found) and the naming moved into code.

**What was measured on the way here**, on the same test documents:

| Design | What happened |
|---|---|
| Seven paper patterns, code forms the pairs (before 2026-09-11) | `group uses tool` -- the commonest statement in an APT report, 1,159 edges in the graph -- was unrepresentable |
| Graph's 37 relations offered, `related_to` included | "shares code with" and "bundled with" both became `related_to`; and `has_analytic` was used for tool → tool because no analytic could then be extracted |
| Relation as an enum plus `other` | `other` never chosen |
| Free string, 11 relations between the then-extractable types | `shares_code_with`, `successor_of`, `bundled_with` coined where needed; nothing new where not |
| Open entity and relation vocabulary (2026-09-17) | On an IoC-rich report: 21 new nodes across 12 STIX types (campaign, identity, location, email, domain, IPv4, file, certificate, registry key, mutex …), `beacons_to` / `resolves_to` / `attributed_to` / `indicates` from STIX, `signed_with` and `stores_configuration_in` coined. On the earlier four documents the same relations as before plus `targets` on identities and `impersonates`, `exfiltrates_to`, `compromises`. |

The verification half of step two is what keeps the open vocabulary honest:
opening what a thing may be *called* did not loosen what counts as evidence
for it. Three rules there were added under measurement: "the actor", "the
group", "it" resolve to the most recently named actor before the evidence
sentence, "the campaign" to the most recently named campaign, and word
overlap between a paraphrased name and its evidence compares six-letter
stems, so `Exfiltration` matches "exfiltrated".

**What to watch.** A fifty-type list is the regime the paper's own error
analysis warns about (tool/technique confusion with five types), so
`stats.new_types`, `stats.new_relation_types` and the per-type counts are in
every proposal; run-to-run variation on the same text is visible (the model
is at temperature 0 but Ollama's batching is not bit-reproducible), and a
gold set scored per type is the next measurement, not an optional one.

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
- **Open vocabularies, and none of the paper's own relation names.**
  Everything the graph and STIX 2.1 know is offered, and a new name is
  allowed as a last resort; see "The vocabulary" above for why and for what
  was measured. Four of the paper's six relation names were dropped on
  2026-09-23 as duplicates of STIX's; the two that remain are ATT&CK's.
  `reflects` and `solves`, which §3.1.2 names in prose but never patterns or
  evaluates, were never implemented -- a model may propose either as a new
  name if a text states it. The paper's seven entity types survive only as
  `PAPER_TYPES`, a subset kept so per-type results stay comparable with
  Table 4.
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
| `EXTRACT_API_KEY` | unset | required on every endpoint but `/ui` if set |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` / `NEO4J_DATABASE` | as stage 3 | read-only, for alignment |

Finished jobs are kept as JSON under `data-extraction/.cache/jobs/`, so a result
survives an API restart. A job that was mid-run during a restart is reported as
`interrupted`; submit the document again.
