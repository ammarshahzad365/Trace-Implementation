# Project Context: Trace Implementation

Paste this whole file as context before your own instructions in a new
session (with Claude Code or otherwise) to pick this project up with no
other background needed. It describes what exists, why it's built the way it
is, what's verified, and what's next.

## 1. What this project is

This repo ("Trace-Implementation", part of a "Literature Review / Trace
Paper" research project) builds a data-acquisition pipeline that pulls raw
cyber-threat-intelligence data from five public MITRE/NIST sources — CVE,
CWE, CAPEC, MITRE ATT&CK, and MITRE D3FEND — lands it locally in a
consistent, diffable format, and is heading toward extracting entities and
relationships from that data to build a knowledge graph (a "Trace" graph
connecting vulnerabilities → weaknesses → attack patterns → techniques →
defensive countermeasures). There's also a `Prompts/` folder
(`ie.txt`/`et.txt`/`link.txt`/`input_source_url.txt`) with LLM prompt
templates for a later information-extraction stage — likely for pulling
entities/relationships out of free text (CVE/ATT&CK/CAPEC descriptions),
complementary to the structured-field extraction the data itself supports.

## 2. What exists: five crawlers, one per source, all in `data-acquisition/`

Every source folder follows the same shape: `client.py` (fetch, retry/
backoff, and state-diff helpers), `full_crawler.py` (re-sync everything,
overwrite the local snapshot), `incremental_crawler.py` (fetch/merge only
what changed, write a delta file), `run.ps1` (interactive menu), and a
`README.md` (that source's specific design, plus a "what the data looks
like" section with real sample records).

| Source | Folder | Upstream | Local format | Notable design point |
|---|---|---|---|---|
| CVE | `data-acquisition/CVE/` | NVD REST API 2.0 | STIX 2.1 `vulnerability` objects, sharded by year (1999–2026) | Converts raw NVD JSON to STIX; sliding-window rate limiter matching NVD's quota (5/30s, 50/30s with an API key in `.env`); 120-day incremental fetch windowing (NVD's own limit) |
| CWE | `data-acquisition/CWE/` | MITRE's versioned XML catalog (no bulk REST API exists) | Generic XML→JSON (`weakness`/`category`/`view` records, flat array) | No native timestamp field — `created`/`modified` synthesized per entry from its own embedded `Content_History` |
| CAPEC | `data-acquisition/CAPEC/` | MITRE's pre-built STIX 2.1 bundle (mitre/cti GitHub repo) | STIX 2.1, used as-is | No conversion needed; corpus version read from `x_capec_version` (no separate version endpoint) |
| MITRE ATT&CK | `data-acquisition/mitre-attack/` | MITRE's TAXII 2.1 server | STIX 2.1, per domain (enterprise/mobile/ics), each with a full version-history archive (`history/<version>.json`, seeded once via `historical_loader.py` from a vendored `mitre/attack-stix-data` clone) | The only source with a genuine date-filtered upstream API (`added_after` TAXII cursor) — incremental runs actually fetch less, not just diff less |
| MITRE D3FEND | `data-acquisition/mitre-defend/` | D3FEND's own "alpha" REST JSON API, 6 endpoints | JSON-LD entities (5 domains: technique/tactic/artifact/weakness/offensive-technique) + a SPARQL-bindings-shaped relationship export (`mappings`, ~14k rows, ~45MB) | **Built this project** (not pre-existing). No native timestamps at all — change detection is content-hash based (`_content_hash`/`_first_seen_at` stamped by the crawler itself), unlike the timestamp-ordering model the other four use. A real bug was found+fixed here during verification (unstable content-hash keys for the `mappings` domain across save/reload). |

**Top-level orchestrator**: `data-acquisition/full_crawler.py` /
`incremental_crawler.py` / `run.ps1` / `client.py` (also built this project)
run every source's own crawler in turn (or a `--sources` subset), streaming
each one's own progress through and finishing with a per-source ok/failed
line plus an aggregate JSON summary. This is what you should generally run
rather than `cd`-ing into each folder individually:
```
py -m full_crawler            # from data-acquisition/
py -m incremental_crawler
```
`--dry-run` fetches and diffs without writing anything — useful for checking
sync status against live upstream without touching local state.

`data-acquisition/README.md` is the top-level index; each source's own
`README.md` has the full detail for that source specifically.

## 3. Current verification status (as of last check)

Internal consistency (does what's on disk match what the manifests claim):
**all 5 sources check out exactly** — no gaps, no silent truncation, manifest
counts match actual file counts everywhere, D3FEND's `mappings` join-keys
resolve with 0 orphans against the other 5 D3FEND domains.

Live upstream comparison (is local data actually everything currently
published):
- CWE, CAPEC, MITRE ATT&CK (all 3 domains), MITRE D3FEND (all 6 domains):
  **fully in sync**, 0 drift, verified via live `--dry-run` crawls.
- **CVE is stale**: local has 364,602 records; NVD's live total was
  367,778 at last check (~3,176 behind). Last successful CVE sync was
  `2026-07-10`, a week behind the other sources (`2026-07-17`). This is just
  staleness, not a bug — **run `py -m incremental_crawler --sources cve`
  from `data-acquisition/` to catch it up** if that hasn't been done yet.


## 4. The knowledge-graph parser architecture already scoped out (not yet built)

Analysis concluded **one parser is not enough** — the sources split into 4
structurally different formats, plus a separate text-extraction concern:

1. **STIX-bundle parser** (shared base, reusable across CVE/CAPEC/ATT&CK) —
   walks `objects`, emits generic entities from non-relationship SDOs and
   generic edges from STIX `relationship` objects (`source_ref`/
   `relationship_type`/`target_ref`). Needs a **thin per-source extension**
   layered on top for each source's own custom relation fields, because
   these differ even though the base format is shared: CVE's
   `x_nvd_weaknesses` list; CAPEC's `x_capec_*_refs` embedded arrays; ATT&CK's
   `kill_chain_phases`↔`x_mitre_shortname` string-match, `tactic_refs`,
   `x_mitre_analytic_refs`, `log_source_references`.
2. **CWE parser** (standalone) — generic XML-derived JSON, entities and
   relations both live on the same record (`RelatedWeaknesses`,
   `RelatedAttackPatterns`, `ObservedExamples`, `HasMember` are all fields on
   the entity object itself, not separate objects) — one pass, two output
   streams.
3. **D3FEND JSON-LD entity parser** (standalone, shared across the 5 D3FEND
   entity domains) — same "one pass, two streams" pattern (`@id`/`@type`/
   `label` → entity; `subClassOf`/`hasSubClass`/`weakness-of`/`cwe-id`/
   `attack-id` → relations).
4. **D3FEND mappings-row parser** (standalone, `mappings` domain only) — this
   file is almost pure relationship data (SPARQL-bindings shape, no `@id`);
   should probably not emit new entities at all, just edges referencing
   entities the JSON-LD parser already defined.
5. **Text-IE pass** (not a JSON parser) — for the ~175 CVE mentions found in
   ATT&CK free text and ~59 in CAPEC free text; likely reuses `Prompts/`'s
   existing templates. Tag these as a separate, lower-confidence edge type
   (e.g. `MENTIONS`), never silently merged with the structured edges.

Recommended output contract for every parser above: two JSONL streams,
`entities.jsonl` (`{id, label, source, name, properties}`) and
`relationships.jsonl` (`{subject_id, predicate, object_id, source,
properties}`), followed by **one shared id-normalization/entity-resolution
pass** across all parsers' outputs before assembling triples (see
`DATA_STORAGE_REPORT.md` §7.8 / §11.4 — the same CWE/CAPEC id shows up
prefixed in some sources and bare in others; ATT&CK technique ids are the one
id that's already consistent everywhere).

## 6. Immediate next steps

1. Catch up the stale CVE data (§3).
2. Implement the parsers described in §5 — this is the next concrete
   engineering task, not yet started.
3. Run the parsers, do the id-normalization pass, assemble the first
   end-to-end knowledge graph.
4. Validate the assembled graph against the verified 5-source traversal
   example in `DATA_STORAGE_REPORT.md` §8 as a sanity check.
