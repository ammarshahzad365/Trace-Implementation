"""Opening (and sanity-checking) the Neo4j connection.

`check()` exists so `py main.py --check` can answer "can Python reach the
database, with these credentials, and is it empty or not" in one second --
before anyone spends twenty minutes streaming a gigabyte of JSON at a server
that was never listening.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from neo4j import Driver, GraphDatabase, Session
from neo4j.exceptions import AuthError, ServiceUnavailable

from .config import Settings


@contextmanager
def connect(settings: Settings) -> Iterator[Driver]:
    driver = GraphDatabase.driver(settings.uri, auth=(settings.user, settings.password))
    try:
        yield driver
    finally:
        driver.close()


@contextmanager
def session(driver: Driver, settings: Settings) -> Iterator[Session]:
    with driver.session(database=settings.database) as handle:
        yield handle


def check(settings: Settings) -> dict[str, object]:
    """Verify connectivity and report what's already in the database."""
    try:
        with connect(settings) as driver:
            driver.verify_connectivity()
            with session(driver, settings) as handle:
                version = handle.run(
                    "CALL dbms.components() YIELD name, versions, edition "
                    "RETURN name, versions[0] AS version, edition"
                ).single()
                nodes = handle.run("MATCH (n) RETURN count(n) AS c").single()["c"]
                rels = handle.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
                labels = handle.run("CALL db.labels() YIELD label RETURN count(label) AS c").single()["c"]
    except AuthError as exc:
        raise SystemExit(f"Neo4j rejected the credentials for {settings.redacted}: {exc}") from exc
    except ServiceUnavailable as exc:
        raise SystemExit(
            f"Cannot reach Neo4j at {settings.uri}: {exc}\n"
            "Is the container running? `docker compose --env-file ../.env up -d`"
        ) from exc

    return {
        "target": settings.redacted,
        "server": f"{version['name']} {version['version']} ({version['edition']})",
        "nodes": nodes,
        "relationships": rels,
        "labels": labels,
    }
