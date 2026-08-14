# CVE Preprocessing

Reads the raw CVE data (`data-acquisition/CVE/records/<year>/latest.json`,
one file per year) and writes two clean output files.

## Usage

```
py cve_preprocessing.py
```

Optional flags: `--input` (raw records folder) and `--output-dir` (default:
this folder).

## Output

| File | Count | What's in it |
|---|---|---|
| `vulnerabilities.json` | 346,947 | One entry per CVE — description, dates, status, plus its severity scores |
| `external_relationships.json` | 323,027 | `CVE --related-to--> CWE` links, one per weakness type a CVE is classified under |

## What it keeps

Each CVE keeps: `id` (e.g. `"CVE-2021-44228"`), `stix_id`, `type`,
`spec_version`, `created`/`modified` dates, `description`,
`x_nvd_vuln_status`, `x_nvd_source_identifier`.

## Scores are written as labels, not separate records

Every CVE can have severity scores (CVSS) and an exploitation-risk rating
(SSVC). Rather than storing those as their own linked records, they're
written directly onto the CVE as plain fields, prefixed so it's clear which
system they came from:

```json
{
  "id": "CVE-2021-44228",
  "cvss_version": "3.1",
  "cvss_base_score": 10.0,
  "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_source": "nvd@nist.gov",
  "cvss_assessment_type": "Primary",
  "cvss_assessment_count": 1,
  "ssvc_exploitation": "active",
  "ssvc_automatable": "yes",
  "ssvc_technical_impact": "total"
}
```

`cvss_*` = a CVSS severity score. `ssvc_*` = CISA's exploitation-risk rating.
A CVE that was never scored by one of the two just has no fields from it —
no nulls. 1,624 CVEs have no CVSS score at all; 163,212 have an SSVC rating.

### Picking one score when there are several

A CVE can be scored more than once (NVD, plus sometimes a vendor). One
**winner** is picked, in this order: newest CVSS version first (4.0 > 3.1 >
3.0 > 2.0), then NVD's own score over a vendor's, then the higher number.

If scorers disagreed, that's not thrown away — `cvss_assessment_count` says
how many different scores were given, and `cvss_base_score_min` /
`cvss_base_score_max` shows the spread. Both are added only when there's
actually a disagreement (49,236 CVEs, 14.2%).

For SSVC, if a CVE has more than one rating, the newest one wins.

## What's dropped, and why

- Fields that are just a calculation from other fields already kept (e.g. a
  severity word that's derivable from the score) — recomputable, so removed.
- Rejected/empty CVE records (17,655) — no real data in them.
- Reference/bibliography links — they don't point at anything else in this
  dataset.
- CPE "which software versions are affected" data — it's a deeply nested
  structure with no simple way to turn it into a flat link, so it's left out
  entirely (this means the graph can't currently answer "which versions are
  affected").
- The raw `name` field — its value is reused as `id` instead of being kept
  twice.

## Field names are snake_case

The raw data uses camelCase (`baseScore`, `vectorString`). Output fields use
snake_case with a prefix (`cvss_base_score`, `cvss_vector_string`), matching
every other source in this project.
