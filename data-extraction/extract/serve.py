"""Start the extraction API.

    py -m extract.serve                     # http://127.0.0.1:8100
    py -m extract.serve --port 8200

Port 8100 rather than 8000, because the loading stage's ingest API is already on
8000 and this stage talks *to* it. Both are loopback-only for the same reason:
the tunnel that reaches Neo4j reaches these too, and neither has authentication
unless a key is set.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the Trace extraction API")
    parser.add_argument("--host", default="127.0.0.1", help="default: 127.0.0.1 (loopback only)")
    parser.add_argument("--port", type=int, default=8100, help="default: 8100")
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ModuleNotFoundError:
        raise SystemExit(
            "The extraction API needs fastapi, uvicorn and neo4j:\n"
            "    py -m pip install -r requirements.txt"
        ) from None

    from extract.api import app

    if args.host not in ("127.0.0.1", "localhost"):
        print(
            f"WARNING: binding to {args.host}. This endpoint spends GPU time on demand "
            "and writes to the graph. Set EXTRACT_API_KEY, put it behind something that "
            "authenticates, or use an SSH tunnel and leave the default.",
            file=sys.stderr,
        )

    print(f"Extraction API on http://{args.host}:{args.port}   (interactive docs at /docs)")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
