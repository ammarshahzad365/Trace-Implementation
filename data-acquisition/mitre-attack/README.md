# MITRE ATT&CK Crawlers

This folder contains the ATT&CK data acquisition tools.

## Quick Start

1. Open PowerShell in this folder.
2. Run `.
un.ps1`.
3. Type `1`, `2`, or `3` when prompted for which crawler to run.
4. Type `1`, `2`, `3`, `4`, or a comma-separated combination (e.g. `1,3`) when prompted for which domain(s) to sync.

That is the easiest way to use this folder.

Crawler options:

- `1` = historical loader
- `2` = full crawler
- `3` = incremental crawler

Domain options:

- `1` = Enterprise ATT&CK
- `2` = Mobile ATT&CK
- `3` = ICS ATT&CK
- `4` = all domains

After a run finishes, each script prints a one-line summary per domain showing how many objects were added/modified/removed and which output files were created, modified, or left unchanged.

## What this folder does

This folder is the local ATT&CK sync workspace. It keeps three things together:

- the scripts that load and refresh ATT&CK data
- the versioned historical archive
- the current latest-state and delta outputs for each domain

## Layout

### Scripts

- `historical_loader.py` - loads every versioned ATT&CK release already present in the workspace, stores them in the local history archive, and seeds the current snapshot from the newest local release.
- `full_crawler.py` - fetches the complete current ATT&CK dataset, rewrites the latest snapshot, and checks whether the local copy is current.
- `incremental_crawler.py` - reads the last successful fetch time from the manifest, fetches only new or modified objects, updates the latest snapshot, and writes a delta file.
- `client.py` - shared helper code used by all three scripts.
- `run.ps1` - simple interactive launcher that asks which script to run.

### Domain folders

- `enterprise/` - Enterprise ATT&CK outputs.
- `mobile/` - Mobile ATT&CK outputs.
- `ics/` - ICS ATT&CK outputs.

Each domain folder stores:

- `history/` - versioned release archive created by the historical loader. Each file in here is one historical ATT&CK release, named by version.
- `latest.json` - the current canonical STIX bundle for that domain. This is the full latest local snapshot.
- `derived.json` - a filtered bundle that keeps only the ATT&CK object types used most often for analysis.
- `manifest.json` - the sync record for that domain. It tracks the source collection, the last successful fetch time, the run mode, and counts used to decide what changed.
- `delta.json` - the change set from the most recent incremental run. This is written only by the incremental crawler.

## Run

The easiest way to run the tools is with the interactive PowerShell launcher in this folder:

```powershell
Set-Location .\data-acquisition\mitre-attack
.\run.ps1
```

The script will ask you to choose what to run:

- `1` for the historical loader
- `2` for the full crawler
- `3` for the incremental crawler

By default it runs all three domains: Enterprise, Mobile, and ICS.

## Notes

- Run the historical loader first so the version archive and baseline snapshot exist.
- `latest.json` is the full current snapshot.
- `derived.json` is the filtered version for easier analysis.
- `manifest.json` tracks the last successful run so the incremental crawler knows what changed.
- `delta.json` is only written by the incremental crawler.
- The `run.ps1` script is the only command most people need to remember.
