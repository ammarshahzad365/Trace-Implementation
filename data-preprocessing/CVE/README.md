# CVE Preprocessing

Trims the raw CVE bundles (`data-acquisition/CVE/records/<year>/latest.json`,
one STIX 2.1 bundle per year) down to a fixed field whitelist, fully unnests
`x_nvd_cvss` into its own flat entity files, and splits the CWE
classification field out into a separate relationship file. Unlike
CWE/CAPEC, the CVE crawler shards its output by year rather than writing one
combined `latest.json`, so this script reads every `records/<year>/latest.json`
and writes a single combined set of outputs.

## Usage

```
py cve_preprocessing.py
```

Optional flags: `--input` (path to the CVE crawler's `records` directory,
default: the CVE crawler's own output) and `--output-dir` (default: this
folder).

## What it does

- Keeps `vulnerability` objects only, each reduced to a whitelist of fields:
  `type`, `spec_version`, `created`, `modified`, `description`,
  `x_nvd_vuln_status`, `x_nvd_source_identifier`.
- The record's `id` is its CVE id (`name`, e.g. `"CVE-1999-0001"`) — the
  same convention CAPEC uses for its own `CAPEC-N` ids — not the STIX
  `vulnerability--<uuid>` id the raw bundle assigns. The STIX id is kept
  alongside as `stix_id`. The now-redundant `name` field itself is dropped
  (same call as CAPEC dropping its redundant `capec_id` once `id` became
  `CAPEC-N`). No relationship in this dataset ever referenced the STIX id —
  `external_relationships.json` already keyed off `name` — so this is a
  pure rename, not a rewrite of any edge.
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
- `x_nvd_weaknesses` (the CVE's CWE classification) is removed from the
  entity record and rebuilt as `external_relationships.json`:
  `CVE-N --related-to--> CWE-N` edges (`source_name: "cwe"`) — the reverse
  direction of CWE's own `CWE-N --related-to--> CVE-N` edges (from
  `RelatedWeaknesses`/`ObservedExamples` in `cwe_preprocessing.py`). Only
  real `CWE-N` ids are extracted; NVD-only fallback labels
  (`NVD-CWE-noinfo`, `NVD-CWE-Other` — 65,916 occurrences) aren't real
  catalog entries and are dropped, not extracted or kept as an attribute.

## `x_nvd_cvss` is fully unnested, not kept as an attribute

`x_nvd_cvss` is a container keyed by up to five metric-version names
(`cvssMetricV2`, `cvssMetricV30`, `cvssMetricV31`, `cvssMetricV40`,
`ssvcV203`), each a *list* of scored assessments, each of which nests its
own `cvssData`/`ssvcData` object one level deeper. None of that survives on
the vulnerability record — the whole field is removed and rebuilt as flat
entity files plus `has_cvss_v2_score` / `has_cvss_v3_score` /
`has_cvss_v4_score` / `has_ssvc_assessment` edges in `relationships.json`:

- `cvssMetricV2` → `cvss_v2_scores.json`. Each entry's own fields
  (`source`, `baseSeverity`, `exploitabilityScore`, `impactScore`,
  `acInsufInfo`, `obtainAllPrivilege`, `obtainOtherPrivilege`,
  `obtainUserPrivilege`, `userInteractionRequired`) and its nested
  `cvssData` fields (`version`, `vectorString`, `accessVector`,
  `accessComplexity`, `authentication`, `confidentialityImpact`,
  `integrityImpact`, `availabilityImpact`, `baseScore`) are merged into one
  flat record. The entry's own `type` (`Primary`/`Secondary`) is renamed
  `assessment_type` to avoid colliding with the record's own
  `type: "cvss-v2-score"` discriminator.
- `cvssMetricV30` / `cvssMetricV31` → `cvss_v3_scores.json`, combined into
  one file: the two versions have an identical shape and only ever differ
  in `version`'s own value (`"3.0"` vs `"3.1"`), which stays on the
  flattened record to disambiguate. Fields: `source`, `assessment_type`,
  `exploitabilityScore`, `impactScore`, `version`, `vectorString`,
  `attackVector`, `attackComplexity`, `privilegesRequired`,
  `userInteraction`, `scope`, `confidentialityImpact`, `integrityImpact`,
  `availabilityImpact`, `baseScore`, `baseSeverity`.
- `cvssMetricV40` → `cvss_v4_scores.json`. Base metrics (`version`,
  `vectorString`, `baseScore`, `baseSeverity`, `attackVector`,
  `attackComplexity`, `attackRequirements`, `privilegesRequired`,
  `userInteraction`, `vulnConfidentialityImpact`/`vulnIntegrityImpact`/
  `vulnAvailabilityImpact`, `subConfidentialityImpact`/
  `subIntegrityImpact`/`subAvailabilityImpact`, `exploitMaturity`) and
  supplemental metrics (`Safety`, `Automatable`, `Recovery`, `valueDensity`,
  `vulnerabilityResponseEffort`, `providerUrgency`) are kept. The 14
  environmental-override fields (`confidentialityRequirement`/
  `integrityRequirement`/`availabilityRequirement`,
  `modifiedAttackVector`/`modifiedAttackComplexity`/
  `modifiedAttackRequirements`/`modifiedPrivilegesRequired`/
  `modifiedUserInteraction`, `modifiedVulnConfidentialityImpact`/
  `modifiedVulnIntegrityImpact`/`modifiedVulnAvailabilityImpact`,
  `modifiedSubConfidentialityImpact`/`modifiedSubIntegrityImpact`/
  `modifiedSubAvailabilityImpact`) are dropped entirely — verified
  `NOT_DEFINED` on all 29,426 v4.0 entries in this dataset, pure boilerplate
  NVD never customizes, the same treatment this project already gives other
  always-constant fields (e.g. mitre-attack's always-false
  `revoked`/`x_mitre_deprecated` on relationship records).
- `ssvcV203` → `ssvc_assessments.json`. `source` plus `ssvcData`'s `role`,
  `version`, `timestamp` are kept flat; `ssvcData.id` (a redundant echo of
  the CVE's own id) is dropped; `ssvcData.options` — a list of single-key
  objects, one per decision point (`exploitation`, `automatable`,
  `technicalImpact`) — has each key merged directly onto the flat record
  instead of kept as a nested list.

Every score/assessment record gets a deterministic `<entity-type>--<uuid5>`
id, seeded from the owning CVE id, the raw metric key, the entry's
position, and the entry's own flattened content — reruns against the same
input produce byte-identical output, and a CVE with multiple assessments of
the same metric version (up to 4, e.g. NVD's Primary alongside several
CNA Secondary scores) still gets one distinct record per assessment.

Relationship records (`relationships.json` and `external_relationships.json`)
get a deterministic `relationship--<uuid5>` id, seeded from
`(source_ref, relationship_type, target_ref)` — reruns against the same
input produce byte-identical output.

## Output

Seven JSON files, each a plain array of records:

| File | Count | Contents |
|---|---|---|
| `vulnerabilities.json` | 346,947 | CVE records — id (`CVE-N`), stix_id, description, type, spec_version, created/modified, vuln status, source identifier |
| `cvss_v2_scores.json` | 194,545 | Flattened CVSS v2.0 scores |
| `cvss_v3_scores.json` | 359,055 | Flattened CVSS v3.0/v3.1 scores (`version` disambiguates) |
| `cvss_v4_scores.json` | 29,426 | Flattened CVSS v4.0 scores (environmental-override fields dropped) |
| `ssvc_assessments.json` | 163,361 | Flattened SSVC v2.0.3 triage assessments |
| `relationships.json` | 746,387 | `CVE-N --has_cvss_v2_score/has_cvss_v3_score/has_cvss_v4_score/has_ssvc_assessment--> <score id>` edges — id, type, relationship_type, source_ref, target_ref |
| `external_relationships.json` | 323,027 | `CVE-N --related-to--> CWE-N` edges, `source_name: "cwe"` — id, type, relationship_type, source_ref, target_ref, source_name |
