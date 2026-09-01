"""Start the ingest API.

    py -m ingest.serve                      # http://127.0.0.1:8000
    py -m ingest.serve --port 8080
    py -m ingest.serve --allow-new-labels   # accept entity types not in catalog/

Binds to 127.0.0.1 by default, deliberately. This endpoint writes to the graph
with no authentication, which is safe over a loopback socket reached through the
same SSH tunnel as Neo4j itself, and is not safe on `0.0.0.0`. `--host` exists
for running behind something that does provide auth; the warning it prints is
meant to be read.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the Trace ingest API")
    parser.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1 (loopback only)")
    parser.add_argument("--port", type=int, default=8000, help="default: 8000")
    parser.add_argument(
        "--allow-new-labels",
        action="store_true",
        help="accept entity types that are not declared in catalog/labels.py, deriving "
        "a label and creating its uniqueness constraint on first use",
    )
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ModuleNotFoundError:
        raise SystemExit(
            "The ingest API needs fastapi and uvicorn:\n"
            "    py -m pip install -r requirements.txt"
        ) from None

    from ingest.api import STATE, app

    STATE["allow_new_labels"] = args.allow_new_labels

    if args.host not in ("127.0.0.1", "localhost"):
        print(
            f"WARNING: binding to {args.host}, so anything that can reach this port can "
            "write to the graph. There is no authentication. Put it behind something "
            "that provides some, or use an SSH tunnel and leave the default.",
            file=sys.stderr,
        )
    if args.allow_new_labels:
        print(
            "NOTE: --allow-new-labels is on. An unrecognised entity type will create a new "
            "label instead of being rejected, which is how a typo becomes a second label "
            "nobody queries.",
            file=sys.stderr,
        )

    print(f"Ingest API on http://{args.host}:{args.port}   (interactive docs at /docs)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
