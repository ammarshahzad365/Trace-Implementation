# Data Storage Report — CVE, CWE, CAPEC, MITRE ATT&CK, MITRE D3FEND

Generated 2026-07-13 by direct inspection of the on-disk state under
`data-acquisition/` in this repo. Every number below (file sizes, record
counts, field names, sample records) was read from the actual files, not
inferred from documentation — see each source's own `README.md` for the
crawler design rationale; this report is about the **data**, not the code.

## 0. At a glance

| Source | Upstream format | Local format | Sharding | Versioning signal | Total on-disk size | Total records |
|---|---|---|---|---|---|---|
| **CVE** | NVD REST JSON | STIX 2.1 `vulnerability` objects (converted) | by year (`records/<year>/`) | none (rolling, no corpus version) | ~2.20 GiB | 364,602 |
| **CWE** | Versioned XML zip | Generic XML→JSON records (`weakness`/`category`/`view`) | flat (single corpus) | `cwe_version` + `cwe_content_date` (from XML root attrs) | ~8.97 MB | 1,450 |
| **CAPEC** | Pre-built STIX 2.1 bundle | STIX 2.1 as-is (no conversion) | flat (single corpus) | `capec_version` (`x_capec_version`) | ~3.87 MB | 2,666 |
| **MITRE ATT&CK** | TAXII 2.1 STIX bundles | STIX 2.1, per domain | by domain (enterprise/mobile/ics), each with a full version history | per-domain TAXII collection + 40/37/26 versioned snapshots | ~53.7 MB (latest only, all domains) | 30,652 (latest, all domains) |
| **MITRE D3FEND** | JSON-LD REST API + inferred-relationship export | JSON-LD records + relationship rows (content-hash keyed) | by entity type (6 domains) | `ontology_version` + `ontology_hash_sha256` (from `/api/version.json`) | ~46 MB | 16,974 |

Four of the five (CVE, CWE, CAPEC, ATT&CK) share one state model: objects keyed
by a stable `id`, diffed by `created`/`modified` timestamp. D3FEND is the
exception — its objects carry no native timestamp at all, so it uses a
content-hash state model instead (see §5 and §6).

---

## 1. CVE (`data-acquisition/CVE/`)

**Upstream**: NVD CVE REST API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`), paginated, rate-limited (5 req/30s without an API key, 50 req/30s with one — `.env` holds `NVD_API_KEY`).

**On-disk layout**: sharded by year, parsed straight out of the CVE ID (`CVE-<year>-<n>`):

```
CVE/
├── manifest.json          # global fetch bookkeeping (NOT year-sharded)
├── full_run.log           # empty (0 bytes) — unused placeholder
└── records/<year>/
    ├── latest.json        # full STIX bundle for that year: {"id": "bundle--...", "objects": [...]}
    └── delta.json         # only present for years touched by the most recent incremental run
```

Years present: **1999–2026** (28 folders). Only **12 years currently have a
`delta.json`** — 2005, 2006, 2009, 2010, 2014, 2015, 2018, 2019, 2020, 2022,
2025, 2026 — because the incremental crawler only writes a delta for years
that actually appear in NVD's `lastModStartDate`/`lastModEndDate` window;
years untouched by that window keep only their existing `latest.json`. The
full crawler, conversely, rewrites every year's `latest.json` and deletes any
stale `delta.json` (a full sync has no "since last time" to report).

**Record shape** — every raw NVD record is converted to a STIX 2.1
`vulnerability` object (`client.py`'s `cve_to_stix`), preserving full NVD
fidelity inside `x_nvd_*` custom properties rather than discarding it:

```json
{
  "created": "1999-12-30T05:00:00.000Z",
  "description": "ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service...",
  "external_references": [
    {"external_id": "CVE-1999-0001", "source_name": "cve", "url": "https://nvd.nist.gov/vuln/detail/CVE-1999-0001"},
    {"source_name": "cve@mitre.org", "url": "http://www.openbsd.org/errata23.html#tcpfix"}
  ],
  "id": "vulnerability--bc9f5fb3-6f23-5604-ab10-c90e78c60857",
  "modified": "2026-06-16T21:47:13.977Z",
  "name": "CVE-1999-0001",
  "spec_version": "2.1",
  "type": "vulnerability",
  "x_nvd_configurations": [ /* raw NVD CPE-applicability nodes, unchanged */ ],
  "x_nvd_cvss": { "cvssMetricV2": [ /* raw NVD metrics, all versions/sources verbatim: v2, v3.1, ssvcV203 */ ] },
  "x_nvd_source_identifier": "cve@mitre.org",
  "x_nvd_vuln_status": "Modified",
  "x_nvd_weaknesses": ["CWE-20"]
}
```

`x_nvd_weaknesses` is the direct **CVE → CWE** link (flattened from NVD's
`weaknesses[].description[].value`, e.g. `["CWE-20"]` or the generic
`"NVD-CWE-noinfo"` label when NVD hasn't assigned a specific CWE).

IDs are deterministic (`uuid5`, not random): `CVE-1999-0001` always hashes to
`vulnerability--bc9f5fb3-6f23-5604-ab10-c90e78c60857`, and each year's bundle
id is stable too (`bundle--ce944051-...` for 1999's `latest.json`), so re-runs
produce byte-identical, diff-friendly output when nothing changed. NVD's
120-day cap on `lastModStartDate`/`lastModEndDate` ranges is handled by
slicing `[last_successful_fetch, now]` into consecutive windows
(`date_windows`, `MAX_LAST_MOD_RANGE_DAYS = 120`).

**`manifest.json`** (global, not year-sharded) tracks `last_successful_fetch`
(the incremental resume cursor), `previous_fetch`, `results_per_page`,
`total_objects_added`/`modified`, and a `years` dict — but only for years
touched by the last run:

```json
{
  "api_root": "https://services.nvd.nist.gov/rest/json/cves/2.0",
  "mode": "incremental",
  "last_successful_fetch": "2026-07-10T18:30:24Z",
  "previous_fetch": "2026-07-10T17:16:42Z",
  "total_objects_added": 46,
  "total_objects_modified": 211,
  "years": {
    "2026": {"delta_object_count": 230, "existing_object_count": 31600, "latest_object_count": 31645, "objects_added": 45, "objects_modified": 185}
  }
}
```

**Scale**: 364,602 CVE records total, ~2.20 GiB across all year files. 2026
alone is 154.28 MB / 31,645 records (partial year, still accumulating);
delta files are tiny relative to their year (2026's delta is 1.05 MB vs.
154.28 MB latest — only the ~230 records actually touched that run).

---

## 2. CWE (`data-acquisition/CWE/`)

**Upstream**: no bulk REST API exists for CWE (`cwe-api.mitre.org` only
supports point lookups) — the only complete export is a versioned XML zip,
`https://cwe.mitre.org/data/xml/cwec_latest.xml.zip`.

**On-disk layout**: flat, single corpus, no sharding:

```
CWE/
├── latest.json     # 8.97 MB — one bundle: {"id": "bundle--...", "type": "bundle", "objects": [1450 records]}
├── delta.json      # currently empty: {"id": "bundle--...", "objects": [], "type": "bundle"}
└── manifest.json
```

**Conversion pipeline**: every `<Weakness>`/`<Category>`/`<View>` XML element
is recursively converted to JSON by `xml_element_to_json`, which strips
underscores from tag names to match MITRE's own REST naming convention
(`Common_Consequences` → `CommonConsequences`). Records mix all three entry
types in one flat `objects` array:

| type | count |
|---|---|
| `weakness` | 969 |
| `category` | 422 |
| `view` | 59 |

**No native `created`/`modified` field exists on a CWE entry** — instead,
each entry carries a `<Content_History>` audit log of every submission/
modification event, and the crawler synthesizes `created` (earliest
submission date) / `modified` (latest event of either kind) from it. This is
why records in the same corpus snapshot can carry very different `modified`
values, unrelated to the corpus-level `cwe_version`/`cwe_content_date`.

**Sample `weakness` record** (CWE-89, SQL Injection) — the deepest/most
complex of the three types, with up to a dozen nested substructures:

```json
{
  "type": "weakness", "id": "CWE-89", "cwe_id": "89",
  "Name": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
  "Abstraction": "Base", "Structure": "Simple", "Status": "Stable",
  "RelatedWeaknesses": {"RelatedWeakness": [{"Nature": "ChildOf", "CWE_ID": "943", "View_ID": "1000"}]},
  "CommonConsequences": {"Consequence": [{"Scope": ["Confidentiality","Integrity","Availability"], "Impact": "Execute Unauthorized Code or Commands"}]},
  "PotentialMitigations": {"Mitigation": [{"Mitigation_ID": "MIT-4", "Strategy": "Libraries or Frameworks"}]},
  "RelatedAttackPatterns": {"RelatedAttackPattern": [{"CAPEC_ID": "108"}, {"CAPEC_ID": "109"}, {"CAPEC_ID": "66"}]},
  "created": "2006-07-19T00:00:00.000Z",
  "modified": "2025-12-11T00:00:00.000Z"
}
```

`RelatedAttackPatterns` is the direct **CWE → CAPEC** link (bare numeric
CAPEC IDs, cross-reference only — no embedded title/description). Present in
336/969 weaknesses. Other substructure prevalence across the 969 weaknesses:
`CommonConsequences` 944, `PotentialMitigations` 671, `DetectionMethods` 499,
`RelatedWeaknesses` 935, `References` 590, `TaxonomyMappings` 638.
`category`/`view` records are structurally much flatter — their only
meaningful nested field is `Relationships`/`Members` → `HasMember` (a list of
member-weakness cross-references), with none of the weakness-only fields.

**`manifest.json`**:

```json
{
  "mode": "incremental",
  "result": {
    "cwe_version": "4.20", "cwe_content_date": "2026-04-30",
    "existing_object_count": 1450, "latest_object_count": 1450, "delta_object_count": 0,
    "latest_modified": "2026-04-30T00:00:00.000Z",
    "object_type_counts": {"category": 422, "view": 59, "weakness": 969}
  }
}
```

`cwe_version`/`cwe_content_date` come straight from the XML root's `Version`/
`Date` attributes — the corpus-level version signal, independent of any
individual entry's synthesized `modified`.

---

## 3. CAPEC (`data-acquisition/CAPEC/`)

**Upstream**: MITRE publishes CAPEC as a pre-built STIX 2.1 bundle in the
`cti` GitHub repo (`raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json`)
— no conversion needed, unlike CVE.

**On-disk layout**: flat, single corpus:

```
CAPEC/
├── latest.json     # 3.87 MB, IS the STIX bundle itself: {"type": "bundle", "id": "...", "objects": [2666]}
├── manifest.json
└── (no delta.json yet — only written once incremental_crawler.py has run)
```

Breakdown of the 2,666 objects by STIX `type`:

| type | count |
|---|---|
| `attack-pattern` | 615 |
| `course-of-action` | 877 |
| `relationship` | 1,172 |
| `identity` | 1 |
| `marking-definition` | 1 |

**Notable finding**: CAPEC's `relationship` objects are **all one kind** —
every single one of the 1,172 relationships is
`(course-of-action, attack-pattern, "mitigates")`. There are **zero**
attack-pattern↔attack-pattern STIX `relationship` objects; that relatedness
(parent/child, peer, can-precede/can-follow) is instead embedded directly on
the attack-pattern object via custom array properties:
`x_capec_child_of_refs`, `x_capec_parent_of_refs`, `x_capec_peer_of_refs`,
`x_capec_can_precede_refs`, `x_capec_can_follow_refs` (553 of 615
attack-patterns carry at least one).

Sample `attack-pattern` (CAPEC-85, AJAX Footprinting) — its
`external_references` are the direct **CAPEC → CWE** link:

```json
{
  "id": "attack-pattern--94208f8a-f779-4be5-a97b-d9ab781a3f5e",
  "name": "AJAX Footprinting",
  "external_references": [
    {"external_id": "CAPEC-85", "source_name": "capec", "url": "https://capec.mitre.org/data/definitions/85.html"},
    {"external_id": "CWE-79", "source_name": "cwe", "url": "http://cwe.mitre.org/data/definitions/79.html"},
    {"external_id": "CWE-20", "source_name": "cwe", "url": "http://cwe.mitre.org/data/definitions/20.html"}
  ],
  "x_capec_abstraction": "Detailed", "x_capec_likelihood_of_attack": "High", "x_capec_typical_severity": "Low",
  "x_capec_child_of_refs": ["attack-pattern--22a65c6a-9498-4e7f-a03a-030ab1c907dc"],
  "x_capec_version": "3.9"
}
```

`course-of-action` objects are sparse (`name` is a generic `coa-<N>-<M>` id —
the actual mitigation text lives in `description`, which contains embedded
XHTML markup). `capec_version()` pulls the corpus version (`"3.9"`) from any
object's `x_capec_version` property — CAPEC has no separate version endpoint.

---

## 4. MITRE ATT&CK (`data-acquisition/mitre-attack/`)

**Upstream**: MITRE's official TAXII 2.1 server
(`https://attack-taxii.mitre.org/api/v21/`), three collections (Enterprise,
Mobile, ICS ATT&CK). This is the only source of the five with a **true
date-filtered incremental fetch** (`added_after` cursor) and the only one with
a **complete locally-vendored version history**, seeded once from a cloned
copy of `mitre/attack-stix-data` at `structured-data/mitre-attack/`.

**On-disk layout**, per domain:

```
mitre-attack/<enterprise|mobile|ics>/
├── history/<version>.json   # every historical release, id-keyed state
├── latest.json              # full current snapshot (STIX bundle)
├── derived.json             # latest.json filtered to a domain-specific type whitelist
├── delta.json               # only written by incremental_crawler.py
└── manifest.json
```

Historical versions on disk: **enterprise 1.0–19.1 (40 files, no gaps)**;
**mobile 1.0–19.1 but missing 11.0/11.1/11.2 (37 files)**; **ics 8.0–19.1, no
gaps (26 files — ICS wasn't a separate domain before release 8.0)**. Early
`enterprise` releases are ~4.7 MB (`1.0.json`); by release 10.0 that's grown
to ~27.8 MB, reflecting the knowledge base's steady growth.

**`latest.json` sizes/counts** (current snapshot per domain):

| domain | size | objects |
|---|---|---|
| enterprise | 45.40 MB | 25,843 |
| mobile | 4.86 MB | 2,635 |
| ics | 3.43 MB | 2,174 |

Enterprise breakdown by type: `relationship` 21,025, `x-mitre-analytic` 1,758,
`attack-pattern` 858, `malware` 729, `x-mitre-detection-strategy` 699,
`course-of-action` 268, `intrusion-set` 189, `x-mitre-data-component` 109,
`tool` 95, `campaign` 56, `x-mitre-data-source` 38, `x-mitre-tactic` 15,
`identity`/`marking-definition`/`x-mitre-collection`/`x-mitre-matrix` 1 each.
ICS uniquely adds **`x-mitre-asset`** (18 objects — physical/logical ICS
assets like PLCs/HMIs that ICS techniques target; this type doesn't exist in
enterprise or mobile).

**`derived.json`** applies a per-domain type whitelist (`DOMAIN_SPECS[...]
["derived_types"]`, 13 types for enterprise/mobile, 14 for ics with
`x-mitre-asset` added) that drops exactly 3 STIX "infrastructure" objects
per domain — `identity`, `marking-definition`, `x-mitre-collection` — while
keeping all substantive content. Enterprise: 25,843 → 25,840 objects (43.48 MB,
8.7% smaller by bytes despite only 3 fewer objects, since the byte savings
also reflect re-serialization).

Sample `attack-pattern` (T1055, Process Injection) and `relationship` — the
flat-bundle-plus-UUID-reference pattern shared with CAPEC:

```json
{
  "id": "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d",
  "name": "Process Injection",
  "external_references": [{"external_id": "T1055", "source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1055"}],
  "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}],
  "x_mitre_platforms": ["Linux", "macOS", "Windows"], "x_mitre_version": "2.0"
}
```
```json
{
  "id": "relationship--0200e185-a06e-470c-af16-814f84f1f6d7",
  "relationship_type": "uses",
  "source_ref": "malware--66637cd6-ae68-4bcd-af82-32f70a854175",
  "target_ref": "attack-pattern--43e7dc91-05b2-474c-b9ac-2ed4fe101f4d"
}
```

**`manifest.json`** is per-domain, keyed by TAXII collection:

```json
{
  "collections": {
    "enterprise-attack": {
      "collection_id": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",
      "last_successful_fetch": "2026-07-10T20:05:55Z",
      "local_object_count": 25843, "remote_object_count": 25843, "up_to_date": true
    }
  }
}
```
`last_successful_fetch` is the resume cursor passed as TAXII's `added_after`
on the next incremental run — the only source among the five with a true
server-side "give me only what changed" query.

---

## 5. MITRE D3FEND (`data-acquisition/mitre-defend/`)

**Upstream**: D3FEND's own "alpha" REST JSON API
(`https://d3fend.mitre.org/api/*`) — no STIX/TAXII, no auth, no stated rate
limit. Six endpoints are tracked, five of them JSON-LD (`{"@graph": [...]}`,
keyed by `@id`) and one a bulk relationship/mapping export shaped like SPARQL
query-results JSON (`{"...": {"type": "uri"/"literal", "value": ...}}` rows,
no natural id).

**On-disk layout**, one folder per entity type:

```
mitre-defend/
├── techniques/{latest.json, delta.json}            271 records, 88 KB
├── tactics/{latest.json, delta.json}                 7 records, 8 KB
├── artifacts/{latest.json, delta.json}              915 records, 336 KB
├── weaknesses/{latest.json, delta.json}             943 records, 632 KB
├── offensive-techniques/{latest.json, delta.json}   835 records, 628 KB
├── mappings/{latest.json, delta.json}            14,003 records, 44 MB
└── manifest.json
```

**This is the only source of the five whose records carry no native
`created`/`modified` timestamp at all** — a D3FEND entity has only `@id`,
`@type`, `rdfs:label`, `d3f:definition`, etc. So instead of the
timestamp-ordering model shared by CVE/CWE/CAPEC/ATT&CK, every record here is
stamped by the crawler itself with `_content_hash` (sha256 of its own raw
fields) and `_first_seen_at` (when this crawler first observed it, carried
forward across runs) — "modified" means the hash changed, not that D3FEND
reports a newer timestamp.

Sample `technique` and `weakness` records — `d3f:cwe-id` is the direct
**D3FEND → CWE** link, `d3f:attack-id` on `offensive-technique` rows is the
direct **D3FEND → ATT&CK** link:

```json
{"@id": "d3f:AccessMediation", "d3f:d3fend-id": "D3-AMED", "rdfs:label": "Access Mediation", "d3f:synonym": "Access Control"}
```
```json
{"@id": "d3f:CWE-119", "d3f:cwe-id": ["CWE-119"], "rdfs:label": ["Improper Restriction of Operations within the Bounds of a Memory Buffer"], "d3f:weakness-of": [{"@id": "d3f:RawMemoryAccessFunction"}]}
```
```json
{"@id": "d3f:T1001", "d3f:attack-id": "T1001", "rdfs:label": "Data Obfuscation"}
```

**The `mappings` domain is the actual payload this project cares most about**
— each of its 14,003 rows is a full defense↔offense trace linking a D3FEND
technique + artifact + tactic to the specific ATT&CK technique + artifact +
tactic it counters:

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

This single row says: *D3FEND's "File Analysis" technique (which analyzes
File artifacts, under the Detect tactic) counters ATT&CK's T1055.001
"Dynamic-link Library Injection" (a sub-technique of T1055 Process Injection,
under Defense Evasion, which adds a Shared Library File artifact)* — every
field needed to trace a full defense-to-offense edge is present in one flat
row, with no join required against the other five endpoints.

**`manifest.json`** carries the corpus version from `/api/version.json`
(the only source besides CWE/ATT&CK-per-domain with an explicit corpus
version+hash), plus per-domain run bookkeeping:

```json
{
  "ontology_version": "1.4.0",
  "ontology_hash_sha256": "81ad2f9920a1954b0b05b04cec9577b3b72c0f7e20fd5a38447b49ca47114a23",
  "release_date": "2026-03-31T00:12:00Z",
  "domains": {"mapping": {"existing_record_count": 14003, "records_added": 0, "records_modified": 0}}
}
```

---

## 6. Intra-source relationships (edges within one source's own data)

Every number below was computed directly against the on-disk `latest.json`
files (not sampled), so these are exhaustive, not illustrative.

### 6.1 CVE — none

CVE records have no internal cross-references at all: no `vulnerability`
object points to another `vulnerability` object. Each CVE stands alone in
`records/<year>/latest.json`; the only edges it carries point *out* of CVE
entirely (§7.1). If you need CVE-to-CVE relatedness (e.g. shared CPEs,
shared CWE) it has to be derived, not read off the record.

### 6.2 CWE — weakness hierarchy + category/view membership

`RelatedWeaknesses.RelatedWeakness[].Nature` (weakness ↔ weakness), exact
distribution across all 969 weaknesses:

| Nature | count |
|---|---|
| `ChildOf` | 1,318 |
| `CanPrecede` | 143 |
| `PeerOf` | 98 |
| `CanAlsoBe` | 27 |
| `Requires` | 13 |
| `StartsWith` | 3 |

Only the child-side of each pair is stored (a weakness records `ChildOf`
pointing at its parent; the parent does not separately record `ParentOf`) —
building a bidirectional graph means adding the inverse edge yourself.
Additionally: `category.Relationships.HasMember` → **4,260** weakness↔category
membership edges, `view.Members.HasMember` → **764** weakness↔view membership
edges (both `{CWE_ID, View_ID}` pairs, view-scoped).

### 6.3 CAPEC — one relationship-object type + five embedded ref arrays

All **1,172** STIX `relationship` objects are the single triple
`(course-of-action, "mitigates", attack-pattern)` — there are zero
attack-pattern↔attack-pattern STIX relationship objects. Attack-pattern
relatedness instead lives in five custom array properties directly on the
`attack-pattern` object: `x_capec_child_of_refs`, `x_capec_parent_of_refs`,
`x_capec_peer_of_refs`, `x_capec_can_precede_refs`, `x_capec_can_follow_refs`
(553/615 attack-patterns carry at least one).

### 6.4 MITRE ATT&CK — the richest intra-source graph of the five

**Relationship objects** — full `(source_type, relationship_type, target_type)`
distribution for the `enterprise` domain (21,025 relationship objects total):

| source → target | relationship_type | count |
|---|---|---|
| malware → attack-pattern | `uses` | 10,342 |
| intrusion-set → attack-pattern | `uses` | 4,546 |
| course-of-action → attack-pattern | `mitigates` | 1,448 |
| campaign → attack-pattern | `uses` | 1,146 |
| tool → attack-pattern | `uses` | 869 |
| x-mitre-detection-strategy → attack-pattern | `detects` | 697 |
| intrusion-set → malware | `uses` | 673 |
| attack-pattern → attack-pattern | `subtechnique-of` | 477 |
| intrusion-set → tool | `uses` | 472 |
| attack-pattern → attack-pattern | `revoked-by` | 149 |
| campaign → malware | `uses` | 91 |
| campaign → tool | `uses` | 81 |
| campaign → intrusion-set | `attributed-to` | 26 |
| intrusion-set → intrusion-set | `revoked-by` | 6 |
| malware → malware / tool | `revoked-by` | 1 / 1 |

**Embedded reference fields** (not STIX relationship objects — these only
show up if you read the object's own fields):
- `attack-pattern.kill_chain_phases[].phase_name` ↔ `x-mitre-tactic.x_mitre_shortname` — technique-to-tactic linkage is a **string match**, not an id reference.
- `x-mitre-matrix.tactic_refs` → ordered list of `x-mitre-tactic` ids (15 for enterprise) — the matrix's tactic ordering.
- `x-mitre-detection-strategy.x_mitre_analytic_refs` → list of `x-mitre-analytic` ids (a detection strategy groups several analytics).
- `x-mitre-analytic.x_mitre_log_source_references[].x_mitre_data_component_ref` → `x-mitre-data-component` id (an analytic cites the telemetry it inspects).

So a full technique's neighborhood in the ATT&CK graph spans two different
linking mechanisms (STIX relationship objects **and** embedded id/string
refs) — a KG ingestion pass needs both, not just the `relationship` objects.

### 6.5 MITRE D3FEND — class hierarchy + weakness-to-artifact

`rdfs:subClassOf` / `rdfs:hasSubClass` (inverse pairs) express ontology class
hierarchy within `techniques`, `tactics` (7/7), `artifacts` (301/915 carry
`hasSubClass`), and `weaknesses` (943/943 carry `subClassOf` — every D3FEND
weakness class sits under a parent in D3FEND's own weakness taxonomy, mirroring
but distinct from CWE's own `ChildOf` hierarchy in §6.2).
`weaknesses.d3f:weakness-of` / `d3f:may-be-weakness-of` (26 + 3 edges,
verified) point a weakness class at the specific **artifact** it's a weakness
of (e.g. `d3f:CWE-119` `weakness-of` `d3f:RawMemoryAccessFunction`) — all 26
targets resolve cleanly into the `artifacts` domain.

**Important limitation for KG building**: the `techniques`, `tactics`, and
`artifacts` domains fetched standalone carry **no relation fields to each
other** (a technique record is just `@id`/`@type`/`d3fend-id`/`label`/
`synonym` — confirmed by a full field-presence sweep across all 271 technique
records, all 7 tactics, and all 915 artifacts). Technique↔tactic↔artifact
relationships exist **only** inside the `mappings` domain (§7.5) — if you
ingest the five entity domains alone you get disconnected vocabularies, not a
graph.

---

## 7. Inter-source (cross-dataset) relationships

This is the exhaustive list — every field on disk, in either direction, that
lets you join two of the five sources, plus the confirmed *absence* of a link
where one doesn't exist. Counts were computed directly against the files, not
estimated.

### 7.1 CVE → CWE (structured)

`vulnerability.x_nvd_weaknesses` — a flat list of CWE ids (`"CWE-20"`) or
NVD's generic fallback labels (`"NVD-CWE-Other"`, `"NVD-CWE-noinfo"`) per CVE
record. One CVE can cite more than one CWE.

### 7.2 CWE → CVE (structured, the concrete reverse of 7.1)

`weakness.ObservedExamples.ObservedExample[]` — `{Description, Link, Reference}`
where `Reference` is a literal `CVE-YYYY-NNNNN` id and `Link` points to
`cve.org`. Verified counts: **582 of 969 weaknesses** carry at least one
observed example, **3,134 example entries** total, **3,126 of which cite an
actual CVE id** (the remainder cite non-CVE advisories). This is a
concrete-instance link, complementary to 7.1's categorical one — a CWE record
names *specific* real-world CVEs that exemplify it.

### 7.3 CWE ↔ CAPEC (structured, both directions present but asymmetric)

- **CWE → CAPEC**: `weakness.RelatedAttackPatterns.RelatedAttackPattern[].CAPEC_ID` — bare numeric CAPEC id, cross-reference only (336/969 weaknesses).
- **CAPEC → CWE**: `attack-pattern.external_references[source_name="cwe"]` — **1,214** such references across 615 attack-patterns (an attack-pattern typically cites several CWEs). This is the denser, more complete direction.

Because both directions exist independently (not one derived from the other
upstream), **do not assume symmetry** — a KG build should reconcile both sets
and expect some CWE↔CAPEC pairs to appear in only one direction.

### 7.4 CAPEC ↔ MITRE ATT&CK (structured, asymmetric — CAPEC's direction is far more complete)

- **CAPEC → ATT&CK**: `attack-pattern.external_references[source_name="ATTACK"]` — **272** references, each carrying the ATT&CK technique id directly as `external_id` (e.g. `"T1195.003"`) plus a `description` and a (dead) `attack.mitre.org/wiki/...` URL.
- **ATT&CK → CAPEC**: `attack-pattern.external_references[source_name="capec"]` — only **36** references across all of `enterprise` — much sparser. Use CAPEC's own references as the primary direction when building this edge.

### 7.5 MITRE D3FEND → CWE, MITRE D3FEND → ATT&CK, and D3FEND's own bridge between them (structured, all join keys verified zero-orphan)

- `weakness.d3f:cwe-id` (943/943 — every D3FEND weakness record's whole reason for existing is to wrap one CWE entry) — resolves 1:1 against CWE ids.
- `offensive-technique.d3f:attack-id` (835/835) — an exact string match against ATT&CK's own `external_references[].external_id` (e.g. `"T1055.001"`), no format conversion needed.
- **`mappings` domain** — the actual defense↔offense relationship graph. Each of the 14,003 rows is a fully-populated (100% field presence, verified across all rows) 6-node path:
  `def_tech —[def_artifact_rel]→ def_artifact`, `def_tech —[def_tactic_rel: always "enables"]→ def_tactic`,
  `off_tech —[off_artifact_rel]→ off_artifact`, `off_tech —[off_tactic_rel: always "enables"]→ off_tactic`,
  plus `off_tech_parent` (the ATT&CK parent technique, when `off_tech` is a sub-technique).
  Distinct node counts inside `mappings`: **149** distinct D3FEND techniques, **74** distinct D3FEND artifacts, **7** distinct D3FEND tactics (matches `tactics/latest.json` exactly), **325** distinct ATT&CK techniques referenced, **172** distinct ATT&CK-side artifacts, **12** distinct ATT&CK tactics.
  Edge-label vocabulary (this *is* the D3FEND relation ontology — use these as your KG's edge types, not generic "relates_to"):
  `def_artifact_rel` — 34 distinct verbs, top ones: `analyzes` (3,381), `filters` (2,828), `modifies` (1,072), `restores` (920), `isolates` (895), `restricts` (540), `deletes` (490), `quarantines` (440), `spoofs` (428), `inventories` (370), `strengthens` (363), `encrypts` (360), `monitors` (341), `hardens` (260), `blocks` (232) — plus 19 more.
  `off_artifact_rel` — 33 distinct verbs, top ones: `modifies` (2,609), `may-modify` (1,881), `produces` (1,681), `creates` (1,501), `accesses` (1,108), `may-create` (978), `uses` (510), `adds` (507), `executes` (409), `loads` (372) — plus 23 more.
  `def_tactic_rel` and `off_tactic_rel` are each a single constant value, `enables`, across all 14,003 rows.
  **Join-key integrity, verified**: every `def_tech` value resolves into `techniques/latest.json`, every `def_artifact` into `artifacts/latest.json`, every `off_tech_id` into `offensive-techniques/latest.json`'s `d3f:attack-id` set — **0 orphans out of 149/74/325 distinct values respectively**. These are reliable foreign keys, not lossy approximations.

### 7.6 Confirmed absent / indirect-only links (equally important for KG scoping)

- **MITRE ATT&CK ↔ CWE**: no structured link exists. A regex sweep for the exact pattern `CWE-\d+` across the entire `enterprise/latest.json` (45.4 MB) returned **zero matches** — the ~30 raw substring hits for "cwe" are incidental (inside unrelated words/citations), not real references. If you need this edge, it must be inferred transitively (ATT&CK technique → D3FEND offensive-technique → D3FEND mapping → D3FEND artifact/weakness → CWE), not read directly.
- **MITRE D3FEND ↔ CAPEC**: no field anywhere in D3FEND references a CAPEC id directly. The only path is transitive: `D3FEND weakness --d3f:cwe-id--> CWE --RelatedAttackPatterns--> CAPEC`.
- The five D3FEND entity domains (`techniques`/`tactics`/`artifacts`) carry no relations to each other outside `mappings` (§6.5) — don't expect a graph from them in isolation.

### 7.7 Unstructured cross-references (present as free text — need IE/NLP, not a JSON field)

These exist and are non-trivial in volume, but require the kind of extraction
pipeline this repo's `Prompts/` folder (`ie.txt`/`et.txt`/`link.txt`) already
seems aimed at, rather than a plain field lookup:

- **MITRE ATT&CK → CVE**: a regex sweep for `CVE-\d{4}-\d+` across
  `enterprise/latest.json` found **175 distinct CVE ids**, appearing in **167**
  objects' `description` text and **229** `external_references` entries
  (citation titles/URLs for security bulletins that happen to name a CVE) —
  e.g. the `attack-pattern` "Compiled HTML File" mentions `CVE-2017-8625` in
  its description. There is no structured `x_mitre_cve` field; this is prose.
- **CAPEC → CVE**: **59 distinct CVE ids** appear in CAPEC attack-pattern
  `description`/`x_capec_example_instances` text (real-world attack examples),
  again unstructured.

### 7.8 Cross-source id-format normalization needed for joins

Not every source spells the same id the same way — a KG ingestion pipeline
needs to normalize before joining:
- **CWE ids**: `"CWE-119"` (with prefix) in CVE's `x_nvd_weaknesses` and
  D3FEND's `d3f:cwe-id`; bare `"119"`/`"CWE_ID": "119"` (no prefix) in CWE's
  own `RelatedAttackPattern.CAPEC_ID`-style fields and CAPEC's
  `external_references[].external_id` for CWE refs.
- **CAPEC ids**: bare number (`"85"`) inside CWE's `RelatedAttackPattern`,
  but `"CAPEC-85"` (prefixed) inside CAPEC's own `external_references`.
- **ATT&CK technique ids**: the one consistent one — `"T1055.001"` format is
  used identically by ATT&CK's own `external_references[].external_id`,
  CAPEC's `ATTACK`-source references, and D3FEND's `d3f:attack-id`/
  `off_tech_id` — no normalization needed for this id across all three
  sources that carry it.

---

## 8. A full 5-source traversal (proof the graph actually connects end-to-end)

Chaining the structured edges above (§7.1–7.5), a single concrete path
touches all five sources without ever leaving a verified, structured field:

```
CVE-2024-37032                                  (CVE, a real llama.cpp path-traversal CVE)
  --x_nvd_weaknesses-->            CWE-23 / CWE-1287     (CVE → CWE, §7.1)
  <--d3f:cwe-id--                  d3f:CWE-23             (D3FEND weakness, §7.5)
  --d3f:weakness-of-->             d3f:<some artifact>    (D3FEND weakness → artifact, §6.5)
  <--def_artifact--                a mappings row         (D3FEND artifact ← mapping row, §7.5)
  --def_tech-->                    a D3FEND technique     (mapping row → D3FEND technique, §7.5)
  --off_tech_id-->                 an ATT&CK technique id (mapping row → ATT&CK technique, §7.5)
  --matches external_id-->         attack-pattern--...    (ATT&CK's own object, §4)
  --relationship (uses)-->         malware / intrusion-set (ATT&CK intra-source graph, §6.4)
```

(This particular CWE-23/CWE-1287 pair was picked because it's the literal
example seen in CWE-20's own `ObservedExamples` entry for `CVE-2024-37032`,
§7.2 — a real, on-disk instance of the chain, not a hypothetical.) The two
weak links in this chain are exactly the two gaps identified in §7.6: there
is no *direct* CWE→D3FEND or ATT&CK→CVE edge, so both hops have to go through
an intermediate source's join key.

## 9. Suggested node/edge schema for a knowledge graph

Node types, one per distinct entity kind actually observed on disk:

| Node label | Source(s) | Key field |
|---|---|---|
| `CVE` | CVE | `name` (`CVE-YYYY-NNNNN`) |
| `CWEWeakness` / `CWECategory` / `CWEView` | CWE | `id` (`CWE-N`) |
| `CAPECAttackPattern` / `CAPECMitigation` | CAPEC | `id` / `external_id` (`CAPEC-N`) |
| `ATTACKTechnique`, `ATTACKMalware`, `ATTACKIntrusionSet`, `ATTACKCampaign`, `ATTACKTool`, `ATTACKTactic`, `ATTACKDataComponent`, `ATTACKAnalytic`, `ATTACKDetectionStrategy`, (`ATTACKAsset` for ICS only) | ATT&CK | `external_references[].external_id` (`T####[.###]`) |
| `D3FENDTechnique`, `D3FENDTactic`, `D3FENDArtifact` | D3FEND | `@id` |

Edge types (source_label —edge_type→ target_label : field it comes from):
- `CVE —HAS_WEAKNESS→ CWEWeakness` (§7.1) / `CWEWeakness —EXEMPLIFIED_BY→ CVE` (§7.2)
- `CWEWeakness —CHILD_OF/CAN_PRECEDE/PEER_OF/CAN_ALSO_BE/REQUIRES/STARTS_WITH→ CWEWeakness` (§6.2)
- `CWECategory|CWEView —HAS_MEMBER→ CWEWeakness` (§6.2)
- `CWEWeakness —RELATED_TO→ CAPECAttackPattern` (union of both §7.3 directions, deduped)
- `CAPECMitigation —MITIGATES→ CAPECAttackPattern` (§6.3) plus `CAPECAttackPattern —CHILD_OF/PARENT_OF/PEER_OF/CAN_PRECEDE/CAN_FOLLOW→ CAPECAttackPattern` (§6.3)
- `CAPECAttackPattern —CORRESPONDS_TO→ ATTACKTechnique` (union of both §7.4 directions, CAPEC's own the primary source)
- `ATTACKMalware|IntrusionSet|Campaign|Tool —USES→ ATTACKTechnique`, `ATTACKCourseOfAction —MITIGATES→ ATTACKTechnique`, `ATTACKDetectionStrategy —DETECTS→ ATTACKTechnique`, `ATTACKTechnique —SUBTECHNIQUE_OF→ ATTACKTechnique`, `— REVOKED_BY→`, `Campaign —ATTRIBUTED_TO→ IntrusionSet` (§6.4, use the exact triple table as the edge-type allowlist)
- `D3FENDWeakness —MAPS_TO→ CWEWeakness` (§7.5), `D3FENDOffensiveTechnique —MAPS_TO→ ATTACKTechnique` (§7.5)
- `D3FENDTechnique —<def_artifact_rel verb>→ D3FENDArtifact`, `D3FENDTechnique —ENABLES→ D3FENDTactic`, `ATTACKTechnique —<off_artifact_rel verb>→ D3FENDArtifact`, `ATTACKTechnique —ENABLES→ D3FENDTactic`, and critically `D3FENDTechnique —COUNTERS→ ATTACKTechnique` (derived: any `mappings` row co-occurring a `def_tech` and `off_tech`) — this last synthetic edge is likely the single most valuable one for a "Trace" defense-to-offense graph, since D3FEND doesn't state it as a single field but it's fully derivable from every mapping row.
- `D3FENDWeakness —WEAKNESS_OF→ D3FENDArtifact` (§6.5)

Treat §7.7's unstructured CVE mentions (ATT&CK, CAPEC) as a **separate,
lower-confidence edge type** (e.g. `MENTIONS`, sourced from IE over free
text) rather than merging them with the structured edges above — they carry
real signal but a different reliability profile.

---

## 10. Cross-cutting design patterns (crawler-level, not data-level)

All five crawlers share:
- **Atomic writes**: every JSON file is written to a `.tmp` sibling then
  `Path.replace()`d into place, and `write_json_file_tracked()` reports
  `"created"`/`"modified"`/`"unchanged"` by diffing serialized text — this is
  what populates the `files` status block in every manifest.
- **`latest.json` + `delta.json` + `manifest.json`** as the universal
  three-file contract, regardless of whether the folder is flat (CWE, CAPEC)
  or sharded (CVE by year, ATT&CK by domain, D3FEND by entity type).
- **Full crawl = overwrite, incremental crawl = merge + delta** — true for
  all five, though the *reason* differs: ATT&CK/CVE have genuine
  date-filtered upstream APIs (so incremental narrows the *fetch*); CWE/CAPEC/
  D3FEND have no such filter (so incremental only narrows the *local diff*,
  fetching the same full data every time).

Where D3FEND diverges is the one place it *had* to: no native timestamps
means no `object_modified_key()`-style ordering is possible, so it's the only
source using content-hash equality instead of "is this newer" as the
definition of "changed."

---

## 11. Consolidated relationship reference (for knowledge graph construction)

Everything below is pulled from §6–§7's verified findings, reorganized into
flat, parser-ready tables — one row per extractable relation, in the shape
`(subject_type, relation, object_type)` plus exactly which field to read it
from. This is the section to work off of when writing the entity/relationship
extraction code; §6–§7 have the narrative reasoning and counts if you need to
double-check something here.

### 11.1 Intra-source relations (edges within one source's own data)

| # | Source | Subject type | Relation | Object type | Field on disk | Count | Notes |
|---|---|---|---|---|---|---|---|
| 1 | CWE | Weakness | `ChildOf` | Weakness | `RelatedWeaknesses.RelatedWeakness[Nature=ChildOf]` | 1,318 | only the child side is stored — add the inverse yourself |
| 2 | CWE | Weakness | `CanPrecede` | Weakness | `RelatedWeaknesses.RelatedWeakness[Nature=CanPrecede]` | 143 | |
| 3 | CWE | Weakness | `PeerOf` | Weakness | `RelatedWeaknesses.RelatedWeakness[Nature=PeerOf]` | 98 | symmetric in meaning, stored one-directionally |
| 4 | CWE | Weakness | `CanAlsoBe` | Weakness | `RelatedWeaknesses.RelatedWeakness[Nature=CanAlsoBe]` | 27 | |
| 5 | CWE | Weakness | `Requires` | Weakness | `RelatedWeaknesses.RelatedWeakness[Nature=Requires]` | 13 | |
| 6 | CWE | Weakness | `StartsWith` | Weakness | `RelatedWeaknesses.RelatedWeakness[Nature=StartsWith]` | 3 | |
| 7 | CWE | Category | `HasMember` | Weakness | `Category.Relationships.HasMember` | 4,260 | scoped by `View_ID` |
| 8 | CWE | View | `HasMember` | Weakness | `View.Members.HasMember` | 764 | scoped by `View_ID` |
| 9 | CAPEC | CourseOfAction | `Mitigates` | AttackPattern | STIX `relationship` object (`source_ref`/`target_ref`) | 1,172 | the only relationship_type CAPEC uses |
| 10 | CAPEC | AttackPattern | `ChildOf` | AttackPattern | `x_capec_child_of_refs` | — | embedded ref array, not a STIX relationship object |
| 11 | CAPEC | AttackPattern | `ParentOf` | AttackPattern | `x_capec_parent_of_refs` | — | 553/615 attack-patterns carry ≥1 of #10–#14 |
| 12 | CAPEC | AttackPattern | `PeerOf` | AttackPattern | `x_capec_peer_of_refs` | — | |
| 13 | CAPEC | AttackPattern | `CanPrecede` | AttackPattern | `x_capec_can_precede_refs` | — | |
| 14 | CAPEC | AttackPattern | `CanFollow` | AttackPattern | `x_capec_can_follow_refs` | — | |
| 15 | ATT&CK | Malware/IntrusionSet/Campaign/Tool | `Uses` | Technique | STIX `relationship` (`relationship_type="uses"`) | 10,342 + 4,546 + 1,146 + 869 | by subject type, enterprise domain |
| 16 | ATT&CK | IntrusionSet | `Uses` | Malware / Tool | STIX `relationship` | 673 / 472 | |
| 17 | ATT&CK | CourseOfAction | `Mitigates` | Technique | STIX `relationship` | 1,448 | |
| 18 | ATT&CK | DetectionStrategy | `Detects` | Technique | STIX `relationship` | 697 | |
| 19 | ATT&CK | Technique | `SubtechniqueOf` | Technique | STIX `relationship` | 477 | |
| 20 | ATT&CK | Technique/IntrusionSet/Malware/Tool | `RevokedBy` | same type | STIX `relationship` | 149 + 6 + 1 + 1 | deprecation/merge pointer |
| 21 | ATT&CK | Campaign | `AttributedTo` | IntrusionSet | STIX `relationship` | 26 | |
| 22 | ATT&CK | Technique | `HasTactic` | Tactic | `kill_chain_phases[].phase_name` == `x-mitre-tactic.x_mitre_shortname` | — | **string match, not an id ref** |
| 23 | ATT&CK | Matrix | `HasTactic` (ordered) | Tactic | `x-mitre-matrix.tactic_refs` | 15 | |
| 24 | ATT&CK | DetectionStrategy | `HasAnalytic` | Analytic | `x_mitre_analytic_refs` | — | |
| 25 | ATT&CK | Analytic | `CitesDataComponent` | DataComponent | `x_mitre_log_source_references[].x_mitre_data_component_ref` | — | |
| 26 | D3FEND | any class | `subClassOf` / `hasSubClass` (inverse) | same domain's class | `rdfs:subClassOf` / `rdfs:hasSubClass` | — | technique/tactic/artifact/weakness ontology hierarchy |
| 27 | D3FEND | Weakness | `WeaknessOf` | Artifact | `d3f:weakness-of` | 26 | all 26 resolve into `artifacts` |
| 28 | D3FEND | Weakness | `MayBeWeaknessOf` | Artifact | `d3f:may-be-weakness-of` | 3 | |

### 11.2 Inter-source (cross-dataset) relations

| # | From (subject) | Relation | To (object) | Field on disk | Direction / reliability | Count |
|---|---|---|---|---|---|---|
| 1 | CVE | `HasWeakness` | CWE | `vulnerability.x_nvd_weaknesses` | structured, CVE→CWE | one list per CVE |
| 2 | CWE | `ExemplifiedBy` | CVE | `weakness.ObservedExamples.ObservedExample[].Reference` | structured, CWE→CVE (concrete instances, not categorical) | 3,126 of 3,134 example entries across 582/969 weaknesses |
| 3 | CWE | `RelatedTo` | CAPEC | `weakness.RelatedAttackPatterns.RelatedAttackPattern[].CAPEC_ID` | structured, CWE→CAPEC | 336/969 weaknesses |
| 4 | CAPEC | `RelatedTo` | CWE | `attack-pattern.external_references[source_name="cwe"]` | structured, CAPEC→CWE (denser direction) | 1,214 refs across 615 attack-patterns |
| 5 | CAPEC | `CorrespondsTo` | ATT&CK Technique | `attack-pattern.external_references[source_name="ATTACK"]` | structured, CAPEC→ATT&CK (primary direction) | 272 refs |
| 6 | ATT&CK | `CorrespondsTo` | CAPEC | `attack-pattern.external_references[source_name="capec"]` | structured, ATT&CK→CAPEC (sparser — prefer #5) | 36 refs |
| 7 | D3FEND Weakness | `MapsTo` | CWE | `weakness.d3f:cwe-id` | structured, 1:1 by construction | 943/943 |
| 8 | D3FEND OffensiveTechnique | `MapsTo` | ATT&CK Technique | `offensive-technique.d3f:attack-id` | structured, exact `T####[.###]` string match | 835/835 |
| 9 | D3FEND Technique | `<def_artifact_rel verb>` | D3FEND Artifact | `mappings.def_tech` / `def_artifact` / `def_artifact_rel` | structured, 0 orphans verified | 14,003 rows, 34 distinct verbs |
| 10 | D3FEND Technique | `Enables` | D3FEND Tactic | `mappings.def_tech` / `def_tactic` | structured, constant verb | 14,003 rows |
| 11 | ATT&CK Technique | `<off_artifact_rel verb>` | D3FEND Artifact | `mappings.off_tech_id` / `off_artifact` / `off_artifact_rel` | structured, 0 orphans verified | 14,003 rows, 33 distinct verbs |
| 12 | ATT&CK Technique | `Enables` | D3FEND Tactic | `mappings.off_tech_id` / `off_tactic` | structured, constant verb | 14,003 rows |
| 13 | D3FEND Technique | `Counters` | ATT&CK Technique | derived: co-occurrence of `def_tech` + `off_tech` in the same `mappings` row | structured but **synthetic** (D3FEND doesn't state it as one field — you derive it) | up to 14,003 pairs (149 × 325 distinct entities involved) |
| 14 | ATT&CK object (any type) | `Mentions` | CVE | free text in `description` / `external_references` | **unstructured — regex/IE required, not a JSON field** | 175 distinct CVE ids across 167+229 hits |
| 15 | CAPEC AttackPattern | `Mentions` | CVE | free text in `description` / `x_capec_example_instances` | **unstructured — regex/IE required** | 59 distinct CVE ids |

### 11.3 Confirmed absent (don't spend time looking for these)

| From | To | Status |
|---|---|---|
| ATT&CK | CWE | No structured field anywhere; a `CWE-\d+` regex over all of `enterprise/latest.json` returns 0 matches. Only reachable transitively via D3FEND (ATT&CK → D3FEND offensive-technique → D3FEND mapping → D3FEND weakness → CWE). |
| D3FEND | CAPEC | No field anywhere. Only reachable transitively via CWE (D3FEND weakness → CWE → CAPEC). |
| D3FEND `technique`/`tactic`/`artifact` (fetched standalone) | each other | No relation fields outside `mappings` — ingest those three domains expecting disconnected vocabularies unless `mappings` is also loaded. |
| CVE | CVE | No CVE-to-CVE relation of any kind exists in this data. |

### 11.4 id-format normalization required before joining (see §7.8 for the full explanation)

| id | prefixed form seen in | bare form seen in |
|---|---|---|
| CWE id | CVE's `x_nvd_weaknesses`, D3FEND's `d3f:cwe-id`, CAPEC's `external_references[source_name="cwe"]` (`"CWE-79"`) | CWE's own `RelatedAttackPattern`/`HasMember`-style fields, sometimes bare `"79"` |
| CAPEC id | CAPEC's own `external_references` (`"CAPEC-85"`) | CWE's `RelatedAttackPattern.CAPEC_ID` (bare `"85"`) |
| ATT&CK technique id | consistent everywhere (`"T1055.001"`) in ATT&CK's own `external_id`, CAPEC's `ATTACK`-source refs, and D3FEND's `d3f:attack-id`/`off_tech_id` | — no normalization needed for this one |
