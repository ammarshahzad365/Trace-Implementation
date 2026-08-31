"""Uniqueness constraints, one per node label.

This is the single most consequential thing in the whole loader, and it has to
happen before any relationship is written. Every edge row names its endpoints by
id, so loading 393,418 relationships means 786,836 lookups of the form "find
the node with this id". Backed by the index a constraint creates, each is an
instant seek. Unbacked, each is a scan of a several-hundred-thousand-node label
-- the difference between a load measured in minutes and one measured in hours.

A constraint also does the second job it is actually named for: it makes it
impossible for two records to quietly fuse into one node by sharing an id.
`validate.py` checks for that in Python too, so the failure is reported with both
offending records rather than as a driver exception, but the constraint is the
backstop that holds even for data this loader never saw.

`await_indexes` blocks until every index is ONLINE. Neo4j builds them in the
background, and an index that is still POPULATING is not used by the planner --
so skipping this wait silently gives you the unbacked-scan performance you just
paid to avoid.
"""

from __future__ import annotations

from typing import Iterable

from neo4j import Session

from .naming import assert_identifier


def constraint_name(label: str) -> str:
    return f"{label.lower()}_id_unique"


def create_constraints(handle: Session, labels: Iterable[str]) -> list[str]:
    created = []
    for label in sorted(set(labels)):
        assert_identifier(label, "node label")
        name = constraint_name(label)
        handle.run(
            f"CREATE CONSTRAINT {name} IF NOT EXISTS "
            f"FOR (n:`{label}`) REQUIRE n.id IS UNIQUE"
        ).consume()
        created.append(name)
    return created


def await_indexes(handle: Session, timeout_seconds: int = 600) -> None:
    handle.run("CALL db.awaitIndexes($timeout)", timeout=timeout_seconds).consume()
