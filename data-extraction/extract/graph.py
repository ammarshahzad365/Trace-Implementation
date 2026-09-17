"""Read-only access to the knowledge graph.

Alignment and the retrieval repository both have to ask what the graph already
contains, and neither question fits through the ingest API -- it has no read
endpoint, and a vector search over 13,000 candidates is not something to put
behind HTTP. So this stage opens its own Bolt session.

**Read-only is a rule, not a description.** Every write in this project goes
through `ingest/writer.py`, so that a record produced here is indistinguishable
from one produced by a batch load. Nothing in this module runs a query that
writes, and `embed_corpus.py` is the single deliberate exception -- a one-off
maintenance script that adds `embedding` properties, which is graph plumbing
rather than knowledge.

## Why one query per label

`MATCH (n {id: $id})` with no label uses no index: Neo4j has no cross-label
property index, so it scans the store. `ingest/writer.py` solves this by running
one indexed lookup per declared label, and `lookup` here does the same thing for
the same reason.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Iterable, Iterator, Sequence

from neo4j import GraphDatabase, Session

from .config import Settings

# Spelled out rather than `\w`, which a linter will suggest: Python's `\w` is
# Unicode-aware and would admit any letter in any script, and this pattern is an
# injection guard on a string that gets interpolated into Cypher. ASCII is the
# point. Matches `graphload/naming.py`, which guards the same thing.
_IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")

_driver = None


def assert_identifier(name: str, what: str) -> str:
    """Refuse to interpolate anything that is not a bare Cypher identifier.

    Labels cannot be query parameters, so they are interpolated -- and every one
    of them originates in `catalog/labels.py` or in a label read back from the
    database, never in a document. This is the belt to that braces.
    """
    if not _IDENTIFIER.match(name):
        raise ValueError(f"{what} {name!r} cannot be interpolated into Cypher safely")
    return name


@contextmanager
def session(cfg: Settings) -> Iterator[Session]:
    """A session on a process-wide driver. The driver pools connections itself."""
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(
            cfg.neo4j_uri,
            auth=(cfg.neo4j_user, cfg.neo4j_password),
            # Before the first embedding run, no node has an `embedding`
            # property, so every `WHERE n.embedding IS NULL` draws an
            # UNRECOGNIZED "property key does not exist" notification -- one per
            # label, each a paragraph long. They are correct and useless, and
            # they bury the progress output. Only this class is silenced;
            # deprecation and performance notifications still come through.
            notifications_disabled_classifications=["UNRECOGNIZED"],
        )
        _driver.verify_connectivity()
    with _driver.session(database=cfg.neo4j_database) as handle:
        yield handle


def close() -> None:
    """Let the API shut its driver down cleanly."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None


def index_name(label: str) -> str:
    """One vector index per label, named predictably so both stages agree."""
    return f"{assert_identifier(label, 'node label').lower()}_embedding"


def lookup(handle: Session, ids: Iterable[str]) -> dict[str, dict]:
    """id -> {id, label, name, description} for ids that exist.

    Used by the regex short-circuit: a document naming `S0066` tells us the id
    but not whether it is malware or a tool, because ATT&CK shares that id space.
    The graph already knows, so ask it rather than guessing.
    """
    wanted = sorted({str(i) for i in ids})
    if not wanted:
        return {}
    rows = handle.run(
        "MATCH (n) WHERE n.id IN $ids "
        "RETURN n.id AS id, labels(n)[0] AS label, n.name AS name, "
        "n.description AS description",
        ids=wanted,
    )
    return {row["id"]: dict(row) for row in rows}


def by_exact_name(handle: Session, labels: Sequence[str], name: str) -> dict | None:
    """The node of one of these labels whose name equals `name`, ignoring case.

    A cheap, high-precision alignment step that sits between identifiers and
    embeddings. "PowerShell" in a report and ATT&CK's S0194 `PowerShell` are the
    same thing, and no embedding of a one-line description should be needed to
    say so -- measured, the description "Used for discovery" was too thin and
    the embedding search missed it. Within a single type an exact name is about
    as unambiguous as an identifier.
    """
    wanted = name.strip().lower()
    if not wanted:
        return None
    for label in labels:
        rows = handle.run(
            f"MATCH (n:`{assert_identifier(label, 'node label')}`) "
            "WHERE toLower(n.name) = $name "
            "RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 2",
            name=wanted,
        ).data()
        # Two nodes with the same name in one label is a tie we should not
        # break silently; fall through to the embedding path instead.
        if len(rows) == 1:
            return rows[0]
    return None


def by_name_overlap(handle: Session, labels: Sequence[str], name: str) -> list[dict]:
    """Nodes of these labels whose name is inside `name`, or contains it.

    The candidates for `align._name_contained`, which applies the word-boundary
    and length rules; this only narrows ~10,000 nodes to a handful with a
    substring test. Fetched by name rather than taken from the embedding
    search because the embedding search can miss them: "Cobalt Strike beacon:
    bundled with ShadowPad" retrieved ShadowPad and not Cobalt Strike.
    """
    wanted = name.strip().lower()
    if len(wanted) < 3:
        return []
    found: list[dict] = []
    for label in labels:
        found.extend(
            handle.run(
                f"MATCH (n:`{assert_identifier(label, 'node label')}`) "
                "WHERE n.name IS NOT NULL AND ("
                "  $name CONTAINS toLower(n.name) OR toLower(n.name) CONTAINS $name) "
                "RETURN n.id AS id, n.name AS name, n.description AS description LIMIT 10",
                name=wanted,
            ).data()
        )
    return found


def labels_in_use(handle: Session) -> list[str]:
    rows = handle.run("CALL db.labels() YIELD label RETURN label ORDER BY label")
    return [row["label"] for row in rows]


def vector_indexes(handle: Session) -> dict[str, int]:
    """Existing vector indexes -> their dimensions, so callers can check width."""
    rows = handle.run(
        "SHOW VECTOR INDEXES YIELD name, labelsOrTypes, options "
        "RETURN name, labelsOrTypes, options"
    )
    found: dict[str, int] = {}
    for row in rows:
        config = (row.get("options") or {}).get("indexConfig") or {}
        dimensions = config.get("vector.dimensions")
        if dimensions:
            found[row["name"]] = int(dimensions)
    return found


def similar(
    handle: Session, label: str, vector: Sequence[float], *, k: int = 20
) -> list[dict]:
    """Top `k` nodes of one label by vector similarity, with **raw cosine**.

    Neo4j does not return raw cosine. For a cosine index it returns
    `(1 + cos) / 2`, squashed into 0..1, so a raw cosine of 0.9 arrives as 0.95.
    Converting here, once, is the difference between TRACE's threshold meaning
    what the paper says and quietly meaning 0.8 -- which would merge entities
    that are merely related, and the merges would look plausible.
    """
    rows = handle.run(
        "CALL db.index.vector.queryNodes($index, $k, $vector) YIELD node, score "
        "RETURN node.id AS id, node.name AS name, node.description AS description, score",
        index=index_name(label),
        k=k,
        vector=list(vector),
    )
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "cosine": 2.0 * row["score"] - 1.0,
        }
        for row in rows
    ]


def neighbours(handle: Session, ids: Sequence[str], *, limit: int = 15) -> list[dict]:
    """A few edges around these nodes, as reference material for the prompt.

    Section 3.2.2's retrieval repository holds "previously extracted nodes *and
    triples*". Showing the model how entities in this neighbourhood are usually
    connected is the triple half of that.
    """
    if not ids:
        return []
    rows = handle.run(
        "MATCH (a)-[r]->(b) WHERE a.id IN $ids OR b.id IN $ids "
        "RETURN a.name AS source, type(r) AS relation, b.name AS target LIMIT $limit",
        ids=list(ids),
        limit=limit,
    )
    return [dict(row) for row in rows]
