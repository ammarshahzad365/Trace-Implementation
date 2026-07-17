"""Shared helpers for the top-level data-acquisition orchestrator.

This module does not talk to any upstream API itself. It only knows how to run
each data source's own `full_crawler.py` / `incremental_crawler.py` as a
subprocess with that source's folder as the working directory -- exactly what
running `py -m full_crawler` from inside e.g. `CVE/` would do by hand, just
looped over every source.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

SOURCES: List[Dict[str, str]] = [
    {"key": "cve", "label": "CVE", "folder": "CVE"},
    {"key": "cwe", "label": "CWE", "folder": "CWE"},
    {"key": "capec", "label": "CAPEC", "folder": "CAPEC"},
    {"key": "mitre-attack", "label": "MITRE ATT&CK", "folder": "mitre-attack"},
    {"key": "mitre-defend", "label": "MITRE D3FEND", "folder": "mitre-defend"},
]

SOURCE_KEYS = [source["key"] for source in SOURCES]


def source_folder(base_dir: Path, folder: str) -> Path:
    return base_dir / folder


def run_module(base_dir: Path, folder: str, module: str, extra_args: Sequence[str]) -> Dict[str, Any]:
    """Run `python -m <module>` with `<base_dir>/<folder>` as the working
    directory, streaming its stdout/stderr straight through (each source's own
    crawler already prints its own progress/summary/JSON report)."""
    cwd = source_folder(base_dir, folder)
    command = [sys.executable, "-m", module, *extra_args]
    completed = subprocess.run(command, cwd=str(cwd))
    return {
        "command": " ".join(command),
        "cwd": str(cwd),
        "returncode": completed.returncode,
    }


def format_source_summary_line(label: str, mode: str, returncode: int) -> str:
    status = "ok" if returncode == 0 else f"FAILED (exit {returncode})"
    return f"[data-acquisition] {label} {mode}: {status}"
