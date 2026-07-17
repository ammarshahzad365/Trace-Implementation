"""Top-level incremental crawler.

Runs every data source's own `incremental_crawler.py` in turn (CVE, CWE,
CAPEC, MITRE ATT&CK, MITRE D3FEND), each as a subprocess with that source's
folder as the working directory. This is a thin loop around the same entry
points documented in each source's own README -- it does not duplicate any
fetch/merge/delta logic itself.

Run `full_crawler.py` (this folder's, or each source's own) at least once
before this, the same way each individual source's README requires.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Sequence

import client


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the incremental crawler for every data source under data-acquisition/")
    parser.add_argument(
        "--base-dir",
        default=str(Path(__file__).resolve().parent),
        help="data-acquisition/ directory containing each source's folder",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=client.SOURCE_KEYS,
        default=client.SOURCE_KEYS,
        help="Which sources to run (default: all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Pass --dry-run through to every source's incremental_crawler.py",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="Stop at the first source that fails instead of continuing through the rest",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    base_dir = Path(args.base_dir)
    extra_args = ["--dry-run"] if args.dry_run else []

    selected = [source for source in client.SOURCES if source["key"] in args.sources]
    results: Dict[str, Any] = {}
    for source in selected:
        print(f"[data-acquisition] running incremental crawler for {source['label']} ...")
        result = client.run_module(base_dir, source["folder"], "incremental_crawler", extra_args)
        results[source["key"]] = result
        print(client.format_source_summary_line(source["label"], "incremental", result["returncode"]))
        if result["returncode"] != 0 and args.stop_on_error:
            print(f"ERROR: stopping after {source['label']} failed (--stop-on-error)", file=sys.stderr)
            break

    failed = [key for key, result in results.items() if result["returncode"] != 0]
    output = {
        "mode": "incremental",
        "sources": [source["key"] for source in selected],
        "dry_run": bool(args.dry_run),
        "results": results,
        "failed": failed,
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
