# MITRE D3FEND Crawlers

This folder contains the D3FEND data acquisition tools. D3FEND (Detection,
Denial, and Disruption Framework Empowering Network Defense) is fetched from
MITRE's own "alpha" REST JSON API at
[d3fend.mitre.org](https://d3fend.mitre.org/api-docs/) — one endpoint per
entity type, plus a bulk inferred-relationship export:

| domain                | endpoint                                                | contents |
|------------------------|----------------------------------------------------------|----------|
| `technique`            | `/api/technique/all.json`                                | D3FEND defensive techniques |
| `tactic`               | `/api/tactic/all.json`                                    | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, ...) |
| `artifact`             | `/api/dao/artifacts.json`                                 | Digital artifacts from the D3FEND Artifact Ontology |
| `weakness`             | `/api/weakness/all.json`                                  | CWE weaknesses as mapped into D3FEND |
| `offensive-technique`  | `/api/offensive-technique/all.json`                       | ATT&CK techniques referenced by D3FEND |
| `mapping`              | `/api/ontology/inference/d3fend-full-mappings.json`       | The full inferred technique↔artifact↔ATT&CK relationship export |

## Important differences from the other crawlers in this project

**No date-filtered endpoint.** Like CWE/CAPEC, D3FEND has no "fetch what
changed since X" API — both crawlers here download the same full data for
every domain on every run. What differs is what they do with it locally: the
full crawler overwrites each domain's `latest.json` (a true resync — anything
that disappeared upstream is dropped); the incremental crawler merges into the
existing snapshot (never drops anything) and writes only added/changed records
to `delta.json`.

**No native timestamps, so change detection is content-hash based.** Unlike
CVE/CWE/CAPEC/ATT&CK, D3FEND's objects carry no `created`/`modified` field at
all — just an `@id`, labels, definitions, and relationships. So instead of
comparing timestamps, this crawler stamps two bookkeeping fields onto every
record itself: `_first_seen_at` (when this crawler first observed the record,
carried forward across runs) and `_content_hash` (a sha256 of the record's own
fields). A record counts as "modified" when its `_content_hash` changes between
runs, not because D3FEND reports a newer timestamp.

**`mapping` is the odd domain out.** The five entity endpoints are JSON-LD
(`{"@graph": [...]}`, each entry keyed by `@id`); `mapping`
(`d3fend-full-mappings.json`) is documented as returning "OntologyBindings" and
is large enough that it wasn't possible to preview its exact shape while
building this crawler. `client.py`'s `extract_records()` tries `@graph`, then
a SPARQL-style `results.bindings` array, then a bare top-level list, and rows
with no natural `@id` are keyed by a hash of their own content instead. Run
`full_crawler.py --dry-run --domains mapping` first and sanity-check the
reported record count if you're touching this domain.

The corpus-level version (`ontology_version`, `ontology_hash_sha256`,
`release_date`) comes from `/api/version.json` and is stored in the top-level
`manifest.json`, playing the same role as CWE's `catalog_version()` / CAPEC's
`capec_version()`.

## Quick Start

1. Open PowerShell in this folder.
2. Run `.\run.ps1` and choose `1` (full crawler, first run) or `2` (incremental
   crawler), then pick domain(s).

Both scripts print live progress (download size per domain, diff/write steps)
while they run, then a one-line summary per domain and a JSON report.

## Layout

```
data-acquisition/mitre-defend/
├── client.py                 # shared: fetch + content-hash state/merge/diff helpers
├── full_crawler.py            # full re-sync per domain: download, diff vs local, overwrite latest.json
├── incremental_crawler.py     # download, merge into latest.json, write delta.json per domain
├── run.ps1
├── techniques/{latest.json, delta.json}
├── tactics/{latest.json, delta.json}
├── artifacts/{latest.json, delta.json}
├── weaknesses/{latest.json, delta.json}
├── offensive-techniques/{latest.json, delta.json}
├── mappings/{latest.json, delta.json}
└── manifest.json              # ontology_version/hash/release_date + per-domain last_successful_fetch and counts
```

No API key or rate limiting is needed — the D3FEND API has no stated auth or
quota, though it is documented as "alpha".

## What the data looks like

Every `<domain>/latest.json`/`delta.json` is
`{"domain": "...", "count": N, "records": [...]}`. For the five JSON-LD
domains (`technique`/`tactic`/`artifact`/`weakness`/`offensive-technique`),
each record is keyed by `@id` and stamped with the two bookkeeping fields this
crawler adds itself (`_first_seen_at`, `_content_hash` — see above):

```json
{"@id": "d3f:AccessMediation", "d3f:d3fend-id": "D3-AMED", "rdfs:label": "Access Mediation", "d3f:synonym": "Access Control"}
{"@id": "d3f:CWE-119", "d3f:cwe-id": ["CWE-119"], "rdfs:label": ["Improper Restriction of Operations within the Bounds of a Memory Buffer"], "d3f:weakness-of": [{"@id": "d3f:RawMemoryAccessFunction"}]}
{"@id": "d3f:T1001", "d3f:attack-id": "T1001", "rdfs:label": "Data Obfuscation"}
```

`weakness.d3f:cwe-id` is the direct D3FEND → CWE link; `offensive-technique.
d3f:attack-id` is the direct D3FEND → ATT&CK link (an exact `T####[.###]`
match against ATT&CK's own `external_id`). `rdfs:subClassOf`/`hasSubClass` and
`d3f:weakness-of` express hierarchy/relatedness *within* D3FEND's own
ontology. Note that these five domains carry **no** relation to each other's
techniques/tactics/artifacts beyond that — technique↔tactic↔artifact
relationships live only in `mapping`.

`mapping` rows look nothing like the other five — no `@id`, every field
wrapped SPARQL-binding-style as `{"type": "uri"|"literal", "value": ...}` —
because each row is a full defense↔offense trace, not an entity:

```json
{
  "def_tech_label": {"value": "File Analysis"},
  "def_artifact_label": {"value": "File"}, "def_artifact_rel_label": {"value": "analyzes"},
  "def_tactic_label": {"value": "Detect"},
  "off_tech_id": {"value": "T1055.001"}, "off_tech_label": {"value": "Dynamic-link Library Injection"},
  "off_tech_parent_label": {"value": "Process Injection"},
  "off_artifact_label": {"value": "Shared Library File"}, "off_artifact_rel_label": {"value": "adds"},
  "off_tactic_label": {"value": "Defense Evasion"}
}
```

Read as: *D3FEND's "File Analysis" technique (analyzes File artifacts, under
Detect) counters ATT&CK's T1055.001 "Dynamic-link Library Injection" (a
sub-technique of Process Injection, under Defense Evasion, which adds a
Shared Library File artifact)*. Every `def_tech`/`def_artifact`/`off_tech_id`
value is a foreign key back into the other five domains' `@id`/`d3f:attack-id`
fields.

## Useful flags

- `--dry-run` - fetch and diff without writing any files.
- `--domains` - one or more of `technique tactic artifact weakness
  offensive-technique mapping` (default: all).
- `--api-root` - override the D3FEND API root (default:
  `https://d3fend.mitre.org`).
- `--timeout`, `--user-agent`, `--base-dir` - see `--help` on either script.
