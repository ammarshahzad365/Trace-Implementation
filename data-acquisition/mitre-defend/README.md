# MITRE D3FEND Crawlers

Downloads D3FEND (Detection, Denial, and Disruption Framework Empowering Network
Defense) from MITRE's own "alpha" REST JSON API at
[d3fend.mitre.org](https://d3fend.mitre.org/api-docs/). There is one endpoint
per entity type, plus one bulk mapping export:

| Domain | Endpoint | Contents |
|---|---|---|
| `technique` | `/api/technique/all.json` | D3FEND defensive techniques |
| `tactic` | `/api/tactic/all.json` | D3FEND tactics (Harden, Detect, Isolate, Deceive, Evict, ...) |
| `artifact` | `/api/dao/artifacts.json` | Digital artifacts from the D3FEND Artifact Ontology |
| `weakness` | `/api/weakness/all.json` | CWE weaknesses as D3FEND maps them |
| `offensive-technique` | `/api/offensive-technique/all.json` | ATT&CK techniques that D3FEND refers to |
| `mapping` | `/api/ontology/inference/d3fend-full-mappings.json` | The full worked-out defence <-> artifact <-> ATT&CK mapping |

## Three things that make this crawler different

**No "changed since" endpoint.** Like CWE and CAPEC, D3FEND can only give you
everything, so both crawlers download the full data for every domain every run.
The full crawler overwrites each domain's `latest.json` (a true resync -
anything gone upstream is dropped); the incremental crawler merges into the
existing snapshot, never drops anything, and writes only the new/changed records
to `delta.json`.

**No timestamps, so changes are detected by hashing.** Unlike the other four
sources, D3FEND records carry no `created` or `modified` field at all - just an
`@id`, labels, definitions and relationships. So this crawler stamps two of its
own fields onto every record: `_first_seen_at` (when it first saw the record,
carried forward between runs) and `_content_hash` (a SHA-256 of the record's own
fields). A record counts as "changed" when its `_content_hash` changes, not
because D3FEND said so.

**`mapping` is the odd one out.** The five entity endpoints return JSON-LD
(`{"@graph": [...]}`, each entry keyed by `@id`). `mapping` is documented as
returning "OntologyBindings" and was too large to preview while this crawler was
being written, so `client.py`'s `extract_records()` tries three shapes in order:
`@graph`, then a SPARQL-style `results.bindings` list, then a plain top-level
list. Rows with no natural `@id` get keyed by a hash of their own content. If
you touch this domain, run `full_crawler.py --dry-run --domains mapping` first
and sanity-check the record count it reports.

The catalog-level version (`ontology_version`, `ontology_hash_sha256`,
`release_date`) comes from `/api/version.json` and is stored in the top-level
`manifest.json`.

## Quick start

Open PowerShell here and run `.\run.ps1`. Choose `1` (full crawler, for the
first run) or `2` (incremental), then pick the domain(s). Both print live
progress per domain, then a summary and a JSON report.

## Layout

```
data-acquisition/mitre-defend/
├── client.py                # shared: fetch + content-hash save/merge/compare helpers
├── full_crawler.py          # per domain: download, compare, overwrite latest.json
├── incremental_crawler.py   # per domain: download, merge, write delta.json
├── run.ps1
├── techniques/{latest.json, delta.json}
├── tactics/{latest.json, delta.json}
├── artifacts/{latest.json, delta.json}
├── weaknesses/{latest.json, delta.json}
├── offensive-techniques/{latest.json, delta.json}
├── mappings/{latest.json, delta.json}
└── manifest.json            # ontology version/hash/date + per-domain fetch time and counts
```

No API key or rate limiting needed - the D3FEND API states no auth or quota,
though it is labelled "alpha".

## What the data looks like

Every `<domain>/latest.json` and `delta.json` is
`{"domain": "...", "count": N, "records": [...]}`.

For the five entity domains, each record is keyed by `@id` and carries the two
bookkeeping fields described above:

```json
{"@id": "d3f:AccessMediation", "d3f:d3fend-id": "D3-AMED", "rdfs:label": "Access Mediation", "d3f:synonym": "Access Control"}
{"@id": "d3f:CWE-119", "d3f:cwe-id": ["CWE-119"], "rdfs:label": ["Improper Restriction of Operations within the Bounds of a Memory Buffer"], "d3f:weakness-of": [{"@id": "d3f:RawMemoryAccessFunction"}]}
{"@id": "d3f:T1001", "d3f:attack-id": "T1001", "rdfs:label": "Data Obfuscation"}
```

The cross-source links live here:

- `weakness.d3f:cwe-id` is the direct D3FEND -> CWE link.
- `offensive-technique.d3f:attack-id` is the direct D3FEND -> ATT&CK link (an
  exact match on ATT&CK's own `T####[.###]` ids).
- `rdfs:subClassOf` / `hasSubClass` and `d3f:weakness-of` describe hierarchy
  *inside* D3FEND.

Beyond that, **these five domains say nothing about each other**. The links
between techniques, tactics and artifacts exist only in `mapping`.

`mapping` rows look nothing like the rest: no `@id`, and every field wrapped
SPARQL-style as `{"type": "uri"|"literal", "value": ...}`, because a row is a
full defence-to-attack trace rather than an entity:

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

Read that as: *D3FEND's "File Analysis" technique (which analyzes File
artifacts, under the Detect tactic) counters ATT&CK's T1055.001 "Dynamic-link
Library Injection" (a sub-technique of Process Injection, under Defense Evasion,
which adds a Shared Library File artifact).*

Every `def_tech`, `def_artifact` and `off_tech_id` value points back into the
other five domains' `@id` / `d3f:attack-id` fields.

## Useful flags

- `--dry-run` - fetch and compare, write nothing.
- `--domains` - any of `technique tactic artifact weakness offensive-technique
  mapping` (default: all).
- `--api-root` - use a different D3FEND API root (default:
  `https://d3fend.mitre.org`).
- `--timeout`, `--user-agent`, `--base-dir` - see `--help` on either script.
