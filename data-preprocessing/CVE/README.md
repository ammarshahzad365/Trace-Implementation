# CVE Preprocessing

Reads the raw CVE data (`data-acquisition/CVE/records/<year>/latest.json`, one
file per year) and writes two files: `entities.json` and `relationships.json`.

## Usage

```
py cve_preprocessing.py
```

Optional flags: `--input` (the raw records folder) and `--output-dir` (default:
this folder).

## Output

| File | Count | `type` | What's in it |
|---|---|---|---|
| `entities.json` | 359,355 | `vulnerability` | One record per CVE - description, dates, status, and its severity scores |
| `relationships.json` | 336,339 | `relationship` | `CVE --related_to--> CWE` links (`source_name: "cwe"`), one per weakness type the CVE is classified under |

This is the one source where each file holds a single kind of thing: every raw
object is a CVE, and its only link is the CWE classification. Each record still
carries a `type` field anyway, so these files have the same shape as the other
four sources'.

Each CVE keeps `id` (e.g. `"CVE-2021-44228"`), `stix_id`, `type`,
`spec_version`, `created`/`modified`, `description`, `x_nvd_vuln_status` and
`x_nvd_source_identifier`. Field names are snake_case with a prefix
(`cvss_base_score`) where the raw data used camelCase (`baseScore`) - matching
every other source here.

## Scores are properties, not separate records

Severity scores (CVSS) and exploitation-risk ratings (SSVC) sit directly on the
CVE as ordinary fields, prefixed by the system they came from:

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

A CVE that was never scored simply has no fields from that system - no nulls.
1,493 CVEs have no CVSS score at all; 174,306 have an SSVC rating.

### Why not separate score records?

An earlier version gave each assessment its own record plus a
`has_cvss_v*_score` / `has_ssvc_assessment` link - 593,945 of each. That made
severity roughly two thirds of all the records this project produces, to model
something the CVE -> CWE -> CAPEC -> ATT&CK -> D3FEND trace never passes
through, and that is only ever read as a filter or a sort key. Deduplicating
wouldn't have helped: 82.7% of scored CVEs carry exactly one assessment, so the
size came from having a separate record type at all, not from repetition inside
it.

### Picking one score when there are several

A CVE can be scored more than once - by NVD, and sometimes by a vendor. One
winner is chosen, in this order:

1. newest CVSS version (4.0 > 3.1 > 3.0 > 2.0)
2. NVD's own score over a vendor's
3. the higher number
4. earliest position in the input

That order always produces exactly one winner and reads nothing outside the
record itself, so re-runs are byte-identical.

Disagreement isn't thrown away. `cvss_assessment_count` says how many *distinct*
claims were made (a vendor score that just echoes NVD's counts once, not twice),
and `cvss_base_score_min` / `cvss_base_score_max` show the spread. Both are
measured only within the winner's major version, because a v2 and a v3 score
measure different things - that's a change of standard, not a disagreement. They
are only written when a spread exists (51,762 CVEs, 14.4%). For SSVC, the newest
rating by timestamp wins.

## What's dropped, and why

- **Anything derivable from what's kept** - the severity word (from the score),
  the exploitability and impact sub-scores (from the vector), and every enum
  metric already spelled out in the vector string. Checked by rebuilding all
  three from `vectorString` and `baseScore` alone: 0 mismatches across 194,545
  v2, 359,055 v3 and 29,426 v4 records. (v2's five NVD-specific booleans have no
  vector form, so they are kept.)
- **Rejected/empty CVE records** (17,958) - NVD leaves these as shells with no
  CVSS, no CWEs and no product data.
- **Reference links** - they don't point at anything else in this dataset.
- **CPE "which software versions are affected" data** - a nested AND/OR tree
  over 3.1M `cpeMatch` entries with no way to flatten it into links without
  losing meaning. Left out entirely, so nothing here answers "which versions are
  affected".
- **NVD's placeholder CWE labels** (`NVD-CWE-noinfo`, `NVD-CWE-Other`) - not
  real catalog entries, so no link is created for them.
- **The raw `name` field** - its value becomes `id` instead of being stored
  twice.
- **SSVC's `source`/`role`/`version`/`timestamp`** - facts about the scoring
  process, not about the CVE. Only its three decision points are kept.

## Text cleanup

Every string in the output goes through `clean_record()` - whitespace
normalized, empty strings dropped, lists deduplicated, quoted markup left
untouched. The rules are the same for all five sources and are written up once
in [`../README.md`](../README.md#text-cleanup-applied-to-everything).
