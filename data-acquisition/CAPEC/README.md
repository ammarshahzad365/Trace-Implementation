# CAPEC Crawlers

Downloads CAPEC (Common Attack Pattern Enumeration and Classification) from
MITRE's [cti GitHub repo](https://github.com/mitre/cti), which publishes the
whole catalog as one STIX 2.1 bundle (`capec/2.1/stix-capec.json`). The objects
are already valid STIX 2.1, so nothing needs converting - unlike the CVE
crawler, which has to turn NVD's own JSON into STIX.

## How this differs from the CVE and ATT&CK crawlers

CAPEC has no pages and no "what changed since X" filter. MITRE only ever
publishes the current full bundle, so both crawlers here download the same
~4-5 MB file every run. Only what happens locally differs:

- **Full crawler**: overwrites the local snapshot with exactly what was
  downloaded. A true resync: objects that are gone upstream are dropped from
  `latest.json`.
- **Incremental crawler**: merges the download into the existing snapshot and
  never drops anything, and writes only the new/changed objects since the last
  run to `delta.json`.

So "incremental" here means less *local* work and a smaller *delta* to read -
not a smaller download, because there is nothing to filter on the server side.

## Quick start

Open PowerShell here and run `.\run.ps1`. Choose `1` (full crawler, for the
first run) or `2` (incremental). Both print live progress - download size,
object counts by type, compare/write steps - then a summary and a JSON report.

Run the full crawler at least once first: the incremental one needs a
`last_successful_fetch` in `manifest.json`.

## Layout

```
data-acquisition/CAPEC/
├── client.py               # shared: bundle fetch + save/merge/compare helpers
├── full_crawler.py         # download, compare, overwrite latest.json
├── incremental_crawler.py  # download, merge into latest.json, write delta.json
├── run.ps1
├── latest.json             # the full CAPEC bundle as stored locally
├── delta.json              # incremental runs only: this run's new/changed objects
└── manifest.json           # last_successful_fetch, mode, counts
```

No API key or rate limiting needed - `raw.githubusercontent.com` is a public
CDN.

## What the data looks like

`latest.json` *is* the STIX bundle:
`{"type": "bundle", "id": "...", "objects": [ ...2666 objects... ]}`. Five types
are mixed in it: `attack-pattern` (615), `course-of-action` (877),
`relationship` (1,172), and one `identity` and one `marking-definition` shared
by everything. An attack pattern (trimmed):

```json
{
  "id": "attack-pattern--94208f8a-...",
  "name": "AJAX Footprinting",
  "external_references": [
    {"external_id": "CAPEC-85", "source_name": "capec", "url": "https://capec.mitre.org/data/definitions/85.html"},
    {"external_id": "CWE-79", "source_name": "cwe", "url": "http://cwe.mitre.org/data/definitions/79.html"}
  ],
  "x_capec_abstraction": "Detailed", "x_capec_likelihood_of_attack": "High", "x_capec_typical_severity": "Low",
  "x_capec_child_of_refs": ["attack-pattern--22a65c6a-..."],
  "x_capec_version": "3.9"
}
```

Two things to know about how links are stored:

- The `external_references` entry with `source_name: "cwe"` is the direct
  CAPEC -> CWE link.
- Links **between attack patterns** (parent/child, peer, can-precede,
  can-follow) live in the custom `x_capec_*_refs` fields shown above, **not** in
  STIX `relationship` objects. All 1,172 `relationship` objects say the same one
  thing: `(course-of-action, "mitigates", attack-pattern)`.

```json
{
  "id": "relationship--000e54be-...",
  "relationship_type": "mitigates",
  "source_ref": "course-of-action--1f048925-...",
  "target_ref": "attack-pattern--d859e461-..."
}
```

`course-of-action` objects are thin: `name` is just a generic `coa-<N>-<M>` id,
and the actual mitigation text is entirely in `description`.

## Useful flags

- `--dry-run` - fetch and compare, write nothing.
- `--source-url` - use a different CAPEC bundle URL (a pinned STIX 2.0 copy, a
  fork, etc.).
- `--timeout`, `--user-agent`, `--base-dir` - see `--help` on either script.
