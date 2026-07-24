# CVE Preprocessing

Trims the raw CVE bundles (`data-acquisition/CVE/records/<year>/latest.json`,
one STIX 2.1 bundle per year) down to a fixed field whitelist, and splits the
CWE classification field out into a separate relationship file. Unlike
CWE/CAPEC, the CVE crawler shards its output by year rather than writing one
combined `latest.json`, so this script reads every `records/<year>/latest.json`
and writes a single combined output pair.

## Usage

```
py cve_preprocessing.py
```

Optional flags: `--input` (path to the CVE crawler's `records` directory,
default: the CVE crawler's own output) and `--output-dir` (default: this
folder).

## What it does

- Keeps `vulnerability` objects only, each reduced to a whitelist of fields:
  `id`, `type`, `spec_version`, `created`, `modified`, `name`, `description`,
  `x_nvd_vuln_status`, `x_nvd_source_identifier`, `x_nvd_cvss`.
- Drops every record with `x_nvd_vuln_status == "Rejected"` (17,655 records)
  entirely. NVD leaves these as empty shells — no CVSS, no CWEs, no
  configurations, description is just `"Rejected reason: ..."` — so they
  carry no vulnerability data worth keeping.
- Drops `external_references` entirely, on every record. Its first entry is
  always a self-reference (`source_name: "cve"`, `external_id` equal to the
  record's own `name` — redundant) and the rest are bibliographic
  advisory/patch URLs whose `source_name` is the submitting org, not a
  catalog id. None of them point at another entity in this or any other
  bundle, so — like CWE's own `References`/`Notes` fields — there's nothing
  extractable here.
- Drops `x_nvd_configurations` (CPE applicability data) entirely, with no
  replacement. It isn't a flat edge list like every other relationship-shaped
  field in this project — it's a nested AND/OR boolean tree over 3.1M
  `cpeMatch` entries across 427K distinct CPE criteria strings — so there's
  no lossless flat `(source_ref, target_ref)` edge to extract. Out of scope
  for this pass.
- `x_nvd_cvss` stays embedded as an attribute on the vulnerability record —
  like CWE's `PotentialMitigations`/`DetectionMethods`, it's inherently
  per-record scoring data (CVSS v2/v3.0/v3.1/v4.0 + SSVC), not a separately
  reusable entity.
- `x_nvd_weaknesses` (the CVE's CWE classification) is removed from the
  entity record and rebuilt as `external_relationships.json`:
  `CVE-N --related-to--> CWE-N` edges (`source_name: "cwe"`) — the reverse
  direction of CWE's own `CWE-N --related-to--> CVE-N` edges (from
  `RelatedWeaknesses`/`ObservedExamples` in `cwe_preprocessing.py`). Only
  real `CWE-N` ids are extracted; NVD-only fallback labels
  (`NVD-CWE-noinfo`, `NVD-CWE-Other` — 65,916 occurrences) aren't real
  catalog entries and are dropped, not extracted or kept as an attribute.
- Relationship records get a deterministic `relationship--<uuid5>` id,
  seeded from `(source_ref, relationship_type, target_ref)` — reruns against
  the same input produce byte-identical output.

## Output

Two JSON files, each a plain array of records:

| File | Count | Contents |
|---|---|---|
| `vulnerabilities.json` | 346,947 | CVE records — id, name (CVE id), description, created/modified, vuln status, source identifier, raw CVSS/SSVC metrics |
| `external_relationships.json` | 323,027 | `CVE-N --related-to--> CWE-N` edges, `source_name: "cwe"` — id, type, relationship_type, source_ref, target_ref, source_name |
