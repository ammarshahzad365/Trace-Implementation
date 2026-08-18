"""Runs every data-preprocessing module in this repo, in order.

Each module (CWE, CAPEC, CVE, mitre-attack, mitre-defend) is a fully
independent script that reads its own domain's raw data from
`data-acquisition/` and writes exactly two files into its own subfolder
here -- `entities.json` and `relationships.json`, ten files in total across
the five modules. Each record's own `type` field distinguishes the kinds
inside those two files. This script doesn't import or share any state
between the modules, it just runs each one's `main()` in a subprocess (via
`sys.executable`, so it's the same interpreter/venv this script itself is
run with) and reports a pass/fail summary at the end. Every module computes
its own default `--input`/`--output-dir` from its own file location, so
this works regardless of the current working directory.

Usage:

    py main.py                              # run every module
    py main.py --only cwe capec             # run just these
    py main.py --skip mitre-defend          # run everything except this

A module's own stdout/stderr streams straight through as it runs, so
progress prints live, the same as running it directly. Exit code is 0 only
if every module that ran exited 0.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent

# (module key, script path relative to this file, human-readable label)
MODULES: Tuple[Tuple[str, str, str], ...] = (
    ("cwe", "CWE/cwe_preprocessing.py", "CWE"),
    ("capec", "CAPEC/capec_preprocessing.py", "CAPEC"),
    ("cve", "CVE/cve_preprocessing.py", "CVE"),
    ("mitre-attack", "mitre-attack/mitre_attack_preprocessing.py", "MITRE ATT&CK"),
    ("mitre-defend", "mitre-defend/mitre_defend_preprocessing.py", "MITRE D3FEND"),
)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    module_keys = [key for key, _, _ in MODULES]
    parser = argparse.ArgumentParser(description="Run every data-preprocessing module")
    parser.add_argument("--only", nargs="+", choices=module_keys, metavar="MODULE", help="Run only these modules (default: all)")
    parser.add_argument("--skip", nargs="+", choices=module_keys, metavar="MODULE", default=(), help="Skip these modules")
    return parser.parse_args(argv)


def selected_modules(args: argparse.Namespace) -> List[Tuple[str, str, str]]:
    chosen = MODULES if args.only is None else tuple(m for m in MODULES if m[0] in args.only)
    return [m for m in chosen if m[0] not in args.skip]


def run_module(key: str, relative_path: str, label: str) -> Tuple[bool, float]:
    script_path = SCRIPT_DIR / relative_path
    print(f"\n=== {label} ({relative_path}) ===", flush=True)
    started = time.monotonic()
    result = subprocess.run([sys.executable, str(script_path)])
    elapsed = time.monotonic() - started
    return result.returncode == 0, elapsed


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    modules = selected_modules(args)

    if not modules:
        print("Nothing to run -- --only/--skip left an empty module list.", file=sys.stderr)
        return 1

    results: List[Tuple[str, bool, float]] = []
    for key, relative_path, label in modules:
        ok, elapsed = run_module(key, relative_path, label)
        results.append((label, ok, elapsed))

    print("\n=== Summary ===")
    total_elapsed = 0.0
    all_ok = True
    for label, ok, elapsed in results:
        status = "OK" if ok else "FAILED"
        print(f"  {status:6} {label:16} {elapsed:6.1f}s")
        total_elapsed += elapsed
        all_ok = all_ok and ok
    print(f"  {'total':23} {total_elapsed:6.1f}s")

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
