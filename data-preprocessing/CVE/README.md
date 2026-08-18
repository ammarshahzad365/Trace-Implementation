# CVE Preprocessing

Reads the raw CVE data (`data-acquisition/CVE/records/<year>/latest.json`, one
file per year) and writes two files: `entities.json` and `relationships.json`.

## Usage

```
py cve_preprocessing.py
```

Optional flags: `--input` (raw records folder) and `--output-dir` (default: this
folder).

## Output

| File | Count | `type` | What's in it |
|---|---|---|---|
| `entities.json` | 359,355 | `vulnerability` | One entry per CVE — description, dates, status, plus its severity scores |
| `relationships.json` | 336,339 | `relationship` | `CVE --related-to--> CWE` links (`source_name: "cwe"`), one per weakness type a CVE is classified under |

This is the one source whose two files each hold a single kind — every raw object
is a STIX `vulnerability`, and its only extracted edge is the CWE classification.
The `type` field is still written on every record, so the files have the same
shape as the other four sources'.

Each CVE keeps `id` (e.g. `"CVE-2021-44228"`), `stix_id`, `type`, `spec_version`,
`created`/`modified`, `description`, `x_nvd_vuln_status` and
`x_nvd_source_identifier`. Field names are snake_case with a prefix
(`cvss_base_score`), where the raw data is camelCase (`baseScore`) — matching
every other source here.

## Scores are written as properties, not separate records

Severity scores (CVSS) and exploitation-risk ratings (SSVC) go directly onto the
CVE as plain fields, prefixed by the system they came from:

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

A CVE never scored by one of the two simply has no fields from it — no nulls.
1,493 CVEs have no CVSS score at all; 174,306 have an SSVC rating.

### Picking one score when there are several

A CVE can be scored more than once (NVD, plus sometimes a vendor). One winner is
picked: newest CVSS version first (4.0 > 3.1 > 3.0 > 2.0), then NVD's own score
over a vendor's, then the higher number, then earliest position in the input.
That order is total and reads only the record's own fields, so reruns are
byte-identical.

Disagreement isn't thrown away — `cvss_assessment_count` says how many *distinct*
claims were made (so a vendor score echoing NVD's counts once, not twice), and
`cvss_base_score_min`/`_max` bracket the spread. Both are measured only within
the winner's major version, since a v2 and a v3 score are readings on different
scales — a change of standard, not a disagreement. They're added only when there
is one (51,762 CVEs, 14.4%). For SSVC, the newest rating by timestamp wins.

## What's dropped, and why

- Fields derivable from ones already kept — the severity word from the score, the
  exploitability/impact sub-scores from the vector, every enum metric already
  spelled out in the vector string. Verified by reconstructing all three from
  `vectorString`/`baseScore` alone: 0 mismatches across 194,545 v2, 359,055 v3 and
  29,426 v4 records. (v2's five NVD-specific booleans have no vector
  representation and are kept.)
- Rejected/empty CVE records (17,958) — NVD leaves them as shells with no CVSS,
  no CWEs and no configurations.
- Reference/bibliography links — they don't point at anything else in this
  dataset.
- CPE "which software versions are affected" data — a nested AND/OR tree over
  3.1M `cpeMatch` entries with no lossless flat edge to extract, so it's left out
  entirely (the graph can't currently answer "which versions are affected").
- NVD's fallback CWE labels (`NVD-CWE-noinfo`, `NVD-CWE-Other`) — not real
  catalog entries, so no edge is emitted for them.
- The raw `name` field — its value becomes `id` rather than being stored twice.
- SSVC's `source`/`role`/`version`/`timestamp` — scoring-process metadata, not a
  fact about the CVE. Only its three decision points are kept.

## Why scores aren't nodes

An earlier pass gave each assessment its own entity plus a `has_cvss_v*_score` /
`has_ssvc_assessment` edge — 593,945 of each, making severity roughly two thirds
of the loaded graph, to model something the CVE → CWE → CAPEC → ATT&CK → D3FEND
trace never traverses and that queries only ever read as a filter or sort key
(`WHERE v.cvss_base_score >= 9.0`). Deduplicating couldn't fix it: 82.7% of
scored CVEs carry exactly one assessment, so the count came from there being a
node class at all, not from redundancy within it.
