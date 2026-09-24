# Data Preprocessing (stage 2)

Turns the raw downloads from stage 1 into flat JSON: one `entities.json` and one
`relationships.json` per source, 10 files in total. Standard library only.

## Run it

```bash
py main.py                          # all five sources
py main.py --only cwe capec         # just these
py main.py --skip mitre-defend      # all but this
py CWE/cwe_preprocessing.py         # one source directly
```

Each script finds its input and output folders from its own location, so the
working directory does not matter. `main.py` exits 0 only if every script did.

## What comes out

| Source | Entities | Links | Entity types |
|---|---|---|---|
| `CVE/` | 359,355 | 336,339 | `vulnerability` |
| `mitre-attack/` | 5,659 | 33,105 | technique, malware, intrusion-set, tool, campaign, mitigation, tactic, analytic, detection strategy, data component, asset, matrix |
| `CWE/` | 5,040 | 16,767 | weakness, category, view, platform, mitigation, detection method, consequence |
| `CAPEC/` | 1,492 | 2,155 | attack-pattern, course-of-action |
| `mitre-defend/` | 1,193 | 5,056 | technique, tactic, artifact |

## Rules every output follows

- **Nothing nests.** Every value is a single value or a list of single values.
  Nested source fields are flattened, split into their own records, or dropped.
- **Ids are readable:** `CVE-2021-44228`, `CWE-79`, `CAPEC-85`, `T1055`. Where
  the source used a STIX id, it is kept as `stix_id`.
- **Entities and links are separate files,** and each record's `type` says what
  kind it is.
- **Links across catalogs use the other catalog's own id** (a CVE links to
  `CWE-79`, not to a copy), so stage 3 can join them with no mapping table.
- **Every record has `source`** (`cve`, `cwe`, `capec`, `mitre-attack`,
  `mitre-defend`) **and `collected_at`** (when the crawler fetched it, not when
  this script ran).
- **Re-runs are byte-identical.** Generated ids are `uuid5` hashes of the
  record's content.
- **Text is cleaned the same way everywhere** (`common/`): line endings and odd
  spaces normalised, runs of blank lines collapsed, empty strings dropped, lists
  deduplicated. Markup that is *content* (an XSS payload in a description) is
  left untouched; CWE's and CAPEC's XHTML formatting is flattened to plain text.

## Key decisions per source

**CVE**
- Severity scores are properties on the CVE (`cvss_base_score`, `cvss_version`,
  …), not separate nodes. When a CVE is scored more than once, one winner is
  picked: newest CVSS version, then NVD over vendor, then the higher score.
  Disagreement is kept as `cvss_base_score_min`/`_max` (51,762 CVEs).
- Dropped: 17,958 rejected/empty CVEs; anything derivable from the vector string
  (checked: 0 mismatches when rebuilt); reference URLs; the CPE "affected
  versions" tree (3.1M entries that cannot be flattened without losing meaning);
  NVD's placeholder CWEs (`NVD-CWE-noinfo`).

**CWE**
- Embedded sub-records become their own nodes where they are genuinely shared:
  platforms, mitigations, detection methods and consequences. Per-weakness
  details are copied onto the link, since the same mitigation can read
  differently for different weaknesses.
- Field names are converted to snake_case; alternate terms become an `aliases`
  list (the name all five sources now share).

**CAPEC**
- `external_references` is split: the CAPEC entry gives the `id`, ATT&CK
  entries become links, and CWE entries are dropped as an exact mirror of CWE's
  own links.
- Mirror links are kept one way only (`child_of`, not also `parent_of`).

**MITRE ATT&CK**
- The three domains (enterprise, mobile, ICS) are merged into one set, because
  groups and malware appear in several domains under the same id.
- 226 ids were claimed by two objects upstream (mostly old mitigations reusing a
  technique id). The loser is deleted, never renamed; afterwards every id is
  unique and every link resolves.
- Technique → tactic is derived into `has_tactic` links (ATT&CK stores it only
  as a string match).

**MITRE D3FEND**
- JSON-LD field names are renamed to plain snake_case (`d3f:definition` →
  `description`).
- D3FEND's copies of CWE weaknesses and ATT&CK techniques get no records of
  their own; links point straight at the CWE and ATT&CK ids.
- Its 70 artifact relation names are grouped into 8 buckets per side
  (offensive: accesses, creates, modifies, executes; defensive: observes,
  constrains, hardens, restores). The original name stays on each link as
  `verb`, so nothing is lost.

## Good to know

- A field-by-field provenance report (every type and property, traced to its
  raw field) is in `Trace Paper/reports/DATA_PROVENANCE_REPORT.docx`, outside
  this repo.
- Each `<source>_preprocessing.py` explains its choices in its docstring and
  comments. The longer per-source write-ups (every field kept, renamed or
  dropped, with counts) were removed from this folder on 2026-09-24 and are
  still in git history.
