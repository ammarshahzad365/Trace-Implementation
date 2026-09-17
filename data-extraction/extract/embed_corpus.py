"""Give existing nodes an `embedding`, so alignment has something to compare to.

    py -m extract.embed_corpus --labels IntrusionSet,Malware,Tool --dry-run
    py -m extract.embed_corpus --labels IntrusionSet,Malware,Tool
    py -m extract.embed_corpus --all-except Vulnerability

Section 5.2.2 aligns on the `description` attribute, so that is what gets
embedded. Until a label has been through this, alignment for that type finds
nothing, treats every entity as new, and quietly fills the graph with the
duplicates it exists to prevent -- which is why `/extract/health` warns when
there are no vector indexes at all.

## Which labels are worth it

**Not `Vulnerability`.** There are 359,355 of them and they align on their
identifier anyway (`CVE-2021-26855` in a report is a direct hit, no semantics
needed) -- section 5.2.2 makes exactly this point about why `vuln` scores
highest. Embedding them would cost hours to improve nothing.

**Everything else, yes.** Groups, malware, tools and techniques are named in
prose -- "the Hafnium group", "China Chopper" -- and prose is where embeddings
are the only thing that works. That is roughly thirteen thousand nodes and a few
minutes.

## This is the one place that writes

Every other write in this project goes through `ingest/writer.py`. An embedding
is not knowledge, though -- it is an index over knowledge that already exists,
recomputed whenever the model changes -- so it is maintenance, done here, rather
than a record posted through the ingest API.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from extract import graph, llm  # noqa: E402
from extract.align import embedding_text  # noqa: E402
from extract.config import Settings, settings  # noqa: E402

BATCH = 64


def _labels_to_do(handle, requested: str | None, excluded: str | None) -> list[str]:
    present = graph.labels_in_use(handle)
    if requested:
        wanted = [name.strip() for name in requested.split(",") if name.strip()]
        unknown = [name for name in wanted if name not in present]
        if unknown:
            raise SystemExit(
                f"no such label(s) in this graph: {', '.join(unknown)}.\n"
                f"Labels present: {', '.join(present)}"
            )
        return wanted
    skip = {name.strip() for name in (excluded or "").split(",") if name.strip()}
    # The labels the unstructured ontology aligns against go first, so the
    # pipeline becomes usable before the whole corpus is done.
    from extract.ontology import ENTITY_TYPES, PAPER_TYPES

    wanted_first = [ENTITY_TYPES[name].label for name in PAPER_TYPES]
    wanted_first += [e.label for e in ENTITY_TYPES.values() if e.label not in wanted_first]
    priority = [label for label in wanted_first if label in present and label not in skip]
    rest = [name for name in present if name not in skip and name not in priority]
    return priority + rest


def _describable(handle, label: str) -> int:
    """How many nodes of this label have a description worth embedding."""
    return handle.run(
        f"MATCH (n:`{graph.assert_identifier(label, 'node label')}`) "
        "WHERE n.description IS NOT NULL AND size(n.description) > 20 "
        "RETURN count(n) AS total"
    ).single()["total"]


def _ensure_index(handle, label: str, dimensions: int) -> None:
    """Create the vector index, refusing to reuse one of the wrong width.

    A Neo4j vector index fixes its dimensions at creation. Pointing a 1024-wide
    index at a model that emits 4096 does not fail at creation -- it fails on
    every row, with an error that reads like a data problem rather than a
    configuration one.
    """
    name = graph.index_name(label)
    existing = graph.vector_indexes(handle).get(name)
    if existing and existing != dimensions:
        raise SystemExit(
            f"index {name} is {existing}-dimensional but {dimensions} was requested. "
            f"The embedding model changed. Drop it first:\n"
            f"    DROP INDEX {name}\n"
            "then re-run. Every node of this label must then be re-embedded, because "
            "vectors from two different models are not comparable."
        )
    handle.run(
        f"CREATE VECTOR INDEX {name} IF NOT EXISTS "
        f"FOR (n:`{label}`) ON (n.embedding) "
        "OPTIONS {indexConfig: {`vector.dimensions`: $dimensions, "
        "`vector.similarity_function`: 'cosine'}}",
        dimensions=dimensions,
    ).consume()


def embed_label(cfg: Settings, handle, label: str, *, dry_run: bool, redo: bool) -> dict:
    total = _describable(handle, label)
    if not total:
        return {"label": label, "described": 0, "embedded": 0, "note": "no descriptions"}

    clause = "" if redo else "AND n.embedding IS NULL "
    pending = handle.run(
        f"MATCH (n:`{label}`) WHERE n.description IS NOT NULL AND size(n.description) > 20 "
        f"{clause}RETURN count(n) AS total"
    ).single()["total"]

    if dry_run:
        return {"label": label, "described": total, "to_embed": pending, "embedded": 0}

    _ensure_index(handle, label, cfg.embed_dimensions)

    done = 0
    started = time.time()
    while True:
        rows = list(
            handle.run(
                f"MATCH (n:`{label}`) WHERE n.description IS NOT NULL "
                f"AND size(n.description) > 20 {clause}"
                "RETURN n.id AS id, n.name AS name, n.description AS description LIMIT $limit",
                limit=BATCH,
            )
        )
        if not rows:
            break
        # Name plus description, built by the same function alignment uses for
        # the other side of the comparison. See `align.embedding_text` for the
        # measurement that made this necessary.
        vectors = llm.embed(
            cfg, [embedding_text(row["name"], row["description"]) for row in rows]
        )
        if vectors and len(vectors[0]) != cfg.embed_dimensions:
            raise SystemExit(
                f"{cfg.embed_model} returned {len(vectors[0])}-dimensional vectors but "
                f"EMBED_DIMENSIONS is {cfg.embed_dimensions}. Set it to "
                f"{len(vectors[0])} and drop any index already built at the old width."
            )
        # The label is essential: `MATCH (n {id: ...})` without one has no index
        # to use and scans every node in the store, per row. Measured here, that
        # turned a 100/s embedder into a 4/s pipeline.
        payload = [{"id": row["id"], "vector": vector} for row, vector in zip(rows, vectors)]
        handle.execute_write(
            lambda tx, rows_=payload: tx.run(
                f"UNWIND $rows AS row MATCH (n:`{label}` {{id: row.id}}) "
                "CALL db.create.setNodeVectorProperty(n, 'embedding', row.vector)",
                rows=rows_,
            ).consume()
        )
        done += len(rows)
        rate = done / max(time.time() - started, 0.001)
        print(f"  {label}: {done}/{pending}  ({rate:.0f}/s)", flush=True)
        # `redo` rewrites vectors that already exist, so the "still null" query
        # would never drain -- stop once every pending row has been handled.
        if redo and done >= pending:
            break

    return {"label": label, "described": total, "embedded": done}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--labels", help="comma-separated labels to embed")
    parser.add_argument(
        "--all-except",
        default="Vulnerability",
        help="embed every label but these (default: Vulnerability, which aligns by identifier)",
    )
    parser.add_argument("--dry-run", action="store_true", help="count only, write nothing")
    parser.add_argument(
        "--redo", action="store_true", help="re-embed nodes that already have a vector"
    )
    args = parser.parse_args(argv)

    cfg = settings()
    print(f"{cfg.embed_model} at {cfg.ollama_url}, {cfg.embed_dimensions} dimensions")

    with graph.session(cfg) as handle:
        labels = _labels_to_do(handle, args.labels, args.all_except)
        print(f"labels: {', '.join(labels)}\n")
        results = [
            embed_label(cfg, handle, label, dry_run=args.dry_run, redo=args.redo)
            for label in labels
        ]

    print("\n--- summary ---")
    for row in results:
        described = row.get("described", 0)
        if args.dry_run:
            print(f"  {row['label']:28} {described:>7} described, {row.get('to_embed', 0):>7} to embed")
        else:
            print(f"  {row['label']:28} {described:>7} described, {row['embedded']:>7} embedded")
    graph.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
