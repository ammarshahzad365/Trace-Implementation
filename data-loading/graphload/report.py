"""The run's own record of what it did.

Written to `data-loading/.cache/load_report.json` (gitignored, like every other
derived artefact in this repo). Holds per-stage results, per-label and per-type
counts, timings, and every warning -- which makes it the thing to diff after a
re-crawl to see what actually changed, rather than re-reading scrollback.
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping


def write(
    path: Path,
    *,
    stages: Mapping[str, object],
    timings: Mapping[str, float],
    warnings: list[str],
    settings_summary: str,
    dry_run: bool,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "target": settings_summary,
        "dry_run": dry_run,
        "timings_seconds": {k: round(v, 1) for k, v in timings.items()},
        "warnings": warnings,
        "stages": stages,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return path
