"""Loads the preprocessed Trace dataset into Neo4j.

Five stages, each independently runnable. Order is a dependency chain, not a
preference -- see `graphload/stages/__init__.py`.

    py main.py                                   # everything, in order
    py main.py --check                           # can Python reach the database?
    py main.py --dry-run                         # validate and report, write nothing
    py main.py --stage nodes edges --only capec cwe
    py main.py --stage bridges                   # after loading a new source
    py main.py --stage verify                    # read-only counts
    py main.py --limit 500 --dry-run             # fast trial on unfamiliar data
    py main.py --self-check                      # assert the engine/catalog split

Each stage streams its own progress, and the run ends with a pass/fail/timing
summary plus a JSON report in `.cache/load_report.json` -- the same shape
`data-preprocessing/main.py` already uses.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import catalog
from graphload import driver, report, stages
from graphload.config import repo_root, settings
from graphload.context import Context
from graphload.validate import raise_if_fatal


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    keys = [spec.key for spec in catalog.SOURCES]
    parser = argparse.ArgumentParser(
        description="Load the preprocessed Trace dataset into Neo4j",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--stage", nargs="+", choices=stages.ORDER, metavar="STAGE",
        help=f"run only these stages (default: all, in order: {' '.join(stages.ORDER)})",
    )
    parser.add_argument(
        "--only", nargs="+", choices=keys, metavar="SOURCE",
        help="load only these sources (the bridges stage always reads all of them)",
    )
    parser.add_argument(
        "--skip", nargs="+", choices=keys, metavar="SOURCE", default=(),
        help="skip these sources",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="read, validate, route and report without writing anything",
    )
    parser.add_argument(
        "--limit", type=int, default=None, metavar="N",
        help="read at most N records per file (for a fast trial run)",
    )
    parser.add_argument(
        "--batch-size", type=int, default=10_000, metavar="N",
        help="records per transaction (default: 10000)",
    )
    parser.add_argument(
        "--allow-new-labels", action="store_true",
        help="accept a mechanically derived label for a type that is not in "
             "catalog/labels.py, instead of stopping",
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help="ignore the per-source registry cache and rescan",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="report connectivity and what is already in the database, then exit",
    )
    parser.add_argument(
        "--self-check", action="store_true",
        help="verify graphload/ does not import catalog/, then exit",
    )
    return parser.parse_args(argv)


def selected_sources(args: argparse.Namespace):
    chosen = (
        catalog.SOURCES
        if args.only is None
        else tuple(s for s in catalog.SOURCES if s.key in args.only)
    )
    return [s for s in chosen if s.key not in args.skip]


def self_check() -> int:
    """The engine must not depend on the catalog. That is what makes it reusable."""
    root = Path(__file__).resolve().parent / "graphload"
    offenders = []
    for path in sorted(root.rglob("*.py")):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith(("import catalog", "from catalog")):
                offenders.append(f"{path.relative_to(root.parent)}: {stripped}")
    if offenders:
        print("FAILED -- graphload/ imports catalog/, so the engine is no longer reusable:")
        for entry in offenders:
            print(f"  {entry}")
        return 1
    files = len(list(root.rglob("*.py")))
    print(f"OK -- {files} engine files, none importing catalog/")
    print(
        f"OK -- catalog declares {len(catalog.SOURCES)} sources, "
        f"{len(catalog.LABELS)} entity types across {len(catalog.all_labels())} labels, "
        f"{len(catalog.REL_TYPE_OVERRIDES)} relationship-type override(s)"
    )
    return 0


def build_context(args: argparse.Namespace, log) -> Context:
    chosen = selected_sources(args)
    if not chosen:
        raise SystemExit("--only/--skip left no sources to load.")

    root = repo_root()
    missing = [p for spec in catalog.SOURCES for p in spec.missing(root)]
    if missing:
        raise SystemExit(
            "These preprocessed files are missing -- run data-preprocessing/main.py first:\n  - "
            + "\n  - ".join(str(p.relative_to(root)) for p in missing[:10])
        )

    return Context(
        settings=settings(batch_size=args.batch_size),
        repo_root=root,
        all_specs=catalog.SOURCES,
        selected_specs=chosen,
        label_overrides=catalog.LABELS,
        rel_type_overrides=catalog.REL_TYPE_OVERRIDES,
        declared_labels=catalog.all_labels(),
        log=log,
        dry_run=args.dry_run,
        limit=args.limit,
        allow_new_labels=args.allow_new_labels,
        use_cache=not args.no_cache,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if args.self_check:
        return self_check()

    if args.check:
        for key, value in driver.check(settings()).items():
            print(f"  {key:16} {value}")
        return 0

    def log(message: str) -> None:
        print(message, flush=True)

    ctx = build_context(args, log)
    asked_for = set(args.stage) if args.stage else set(stages.ORDER)
    # `verify` reads the database, which a dry run has no business needing: the
    # whole point of --dry-run is to validate the files *before* standing a
    # server up. So it is dropped from the default set, but still honoured when
    # named explicitly -- "check the data, then tell me what is in there" is a
    # reasonable thing to ask for.
    dropped_verify = ctx.dry_run and not args.stage and "verify" in asked_for
    if dropped_verify:
        asked_for.discard("verify")
    to_run = sorted(asked_for, key=stages.ORDER.index)

    print(f"Target: {ctx.settings.redacted}")
    print(f"Sources: {', '.join(s.label for s in ctx.selected_specs)}")
    print(
        f"Stages: {' -> '.join(to_run)}"
        + ("   [DRY RUN -- nothing will be written]" if ctx.dry_run else "")
    )
    if dropped_verify:
        print("       (verify skipped: it reads the database, which a dry run does not need)")
    if ctx.limit:
        print(f"Limit: {ctx.limit:,} records per file")
        print(
            "       expect dangling-endpoint warnings: edges beyond the limit "
            "point at entities that were never read"
        )

    results: dict[str, object] = {}
    timings: dict[str, float] = {}
    failures: list[str] = []

    # A dry run still needs the database if it is going to verify it.
    needs_db = not ctx.dry_run or "verify" in to_run
    connection = driver.connect(ctx.settings) if needs_db else None

    handle = None
    try:
        if connection is not None:
            db = connection.__enter__()
            driver.verify(db, ctx.settings)
            handle = db.session(database=ctx.settings.database)
            handle.__enter__()

        for name in to_run:
            print(f"\n=== {name} ===")
            started = time.monotonic()
            try:
                results[name] = stages.MODULES[name].run(ctx, handle)
            except SystemExit:
                raise
            except Exception as exc:  # noqa: BLE001 -- report which stage, then stop
                failures.append(f"{name}: {type(exc).__name__}: {exc}")
                timings[name] = time.monotonic() - started
                print(f"  FAILED: {type(exc).__name__}: {exc}")
                break
            timings[name] = time.monotonic() - started

            # Gate after every stage that read records, so a bad dataset stops
            # before the next stage compounds it. Note this is after the write,
            # not before: catching a duplicate id without reading every record
            # first is impossible, and reading everything twice would double the
            # slowest part of the load. `--dry-run` is the pass that catches it
            # with nothing written at all.
            if name in ("nodes", "edges", "bridges"):
                raise_if_fatal(ctx.findings, ctx.allow_new_labels)
    finally:
        if handle is not None:
            handle.__exit__(None, None, None)
        if connection is not None:
            connection.__exit__(None, None, None)

    warnings = ctx.findings.warnings()
    if warnings:
        print("\n=== warnings ===")
        for warning in warnings:
            print(f"  {warning}")

    print("\n=== summary ===")
    for name in to_run:
        if name in timings:
            status = "FAILED" if any(f.startswith(name + ":") for f in failures) else "OK"
            print(f"  {status:6} {name:12} {timings[name]:7.1f}s")
    print(f"  {'total':19} {sum(timings.values()):7.1f}s")

    path = report.write(
        ctx.settings.cache_dir / "load_report.json",
        stages=results,
        timings=timings,
        warnings=warnings,
        settings_summary=ctx.settings.redacted,
        dry_run=ctx.dry_run,
    )
    print(f"  report written to {path.relative_to(ctx.repo_root)}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
