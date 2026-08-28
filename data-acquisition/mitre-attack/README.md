# MITRE ATT&CK Crawlers

Downloads MITRE ATT&CK from its TAXII 2.1 server and keeps three things in one
place: the scripts, a versioned archive of past releases, and the current
snapshot for each domain.

## Quick start

Open PowerShell in this folder and run:

```powershell
.\run.ps1
```

It asks two questions:

1. **Which crawler?** `1` = historical loader, `2` = full crawler,
   `3` = incremental crawler.
2. **Which domain(s)?** `1` = Enterprise, `2` = Mobile, `3` = ICS, `4` = all.
   You can also give a combination, e.g. `1,3`.

Run the **historical loader first**, so the version archive and the starting
snapshot exist. After any run, each script prints one line per domain: how many
objects were added, changed or removed, and which files it wrote, changed or
left alone.

## The scripts

- `historical_loader.py` - loads every ATT&CK release already sitting in the
  workspace, stores them in the local history archive, and builds the first
  snapshot from the newest one.
- `full_crawler.py` - fetches the complete current dataset, rewrites the latest
  snapshot, and checks whether the local copy was already up to date.
- `incremental_crawler.py` - reads the last successful fetch time from the
  manifest, fetches only new or changed objects, updates the snapshot, and
  writes a delta file.
- `client.py` - shared helper code for all three.
- `run.ps1` - the interactive menu above. It is the only command most people
  need.

## Domain folders

`enterprise/`, `mobile/` and `ics/` each hold:

- `history/` - one file per past ATT&CK release, named by version. Written by
  the historical loader.
- `latest.json` - the current full snapshot for that domain.
- `derived.json` - a filtered copy keeping only the object types used most in
  analysis.
- `manifest.json` - the sync record: source collection, last successful fetch
  time, run mode, and the counts used to work out what changed.
- `delta.json` - the changes from the most recent incremental run. Written only
  by the incremental crawler.

## What the data looks like

Every `latest.json`, `derived.json`, `delta.json` and `history/<version>.json`
is one flat STIX 2.1 bundle: `{"type": "bundle", "id": "...", "objects": [...]}`.

`enterprise/latest.json` alone holds 25,843 objects across a dozen-plus types:
`relationship` (21,025), `x-mitre-analytic` (1,758), `attack-pattern` (858),
`malware` (729), `x-mitre-detection-strategy` (699), `course-of-action` (268),
`intrusion-set` (189), `tool` (95), `campaign` (56), `x-mitre-tactic` (15), plus
one each of `identity`, `marking-definition`, `x-mitre-collection` and
`x-mitre-matrix`. `ics/` also has `x-mitre-asset` (physical and logical ICS
assets), which no other domain has.

A technique, and a relationship tying malware to it (both trimmed):

```json
{
  "id": "attack-pattern--43e7dc91-...",
  "name": "Process Injection",
  "external_references": [{"external_id": "T1055", "source_name": "mitre-attack", "url": "https://attack.mitre.org/techniques/T1055"}],
  "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"}],
  "x_mitre_platforms": ["Linux", "macOS", "Windows"], "x_mitre_version": "2.0"
}
```
```json
{
  "id": "relationship--0200e185-...",
  "relationship_type": "uses",
  "source_ref": "malware--66637cd6-...",
  "target_ref": "attack-pattern--43e7dc91-..."
}
```

The `relationship_type` values in `enterprise` are:

- `uses` - malware, group, campaign or tool -> technique, and group -> malware
  or tool
- `mitigates` - course-of-action -> technique
- `detects` - detection-strategy -> technique
- `subtechnique-of` and `revoked-by` - technique -> technique
- `attributed-to` - campaign -> group

One important gap: **technique-to-tactic is not a relationship object at all.**
It is a string match between `attack-pattern.kill_chain_phases[].phase_name` and
`x-mitre-tactic.x_mitre_shortname`.
