"""Opening (and sanity-checking) the Neo4j connection.

`check()` exists so `py main.py --check` can answer "can Python reach the
database, with these credentials, and is it empty or not" in about a second --
before anyone spends twenty minutes streaming half a gigabyte of JSON at a
server that was never listening.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from neo4j import Driver, GraphDatabase, Session
from neo4j.exceptions import AuthError, ClientError, ServiceUnavailable

from .config import Settings

# Every way the driver says "I could not get in", rather than "the query was
# wrong". `AuthError` covers a plain bad password, but repeated attempts trip
# `Neo.ClientError.Security.AuthenticationRateLimit`, which arrives as a bare
# ClientError -- and if that one is not caught, the retry loop someone wrote to
# wait for a container to come up ends in 40 lines of driver stack trace.
CONNECTION_ERRORS = (AuthError, ClientError, ServiceUnavailable)


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


def unreachable(exc: Exception, settings: Settings) -> SystemExit:
    """Turn a driver exception into an explanation rather than a stack trace.

    Both of these are ordinary situations -- a typo in the password, a database
    that is not up yet -- and neither is worth 40 lines of neo4j internals.
    """
    if isinstance(exc, AuthError):
        return SystemExit(f"Neo4j rejected the credentials for {settings.redacted}: {exc}")
    if isinstance(exc, ClientError) and "AuthenticationRateLimit" in str(exc.code or ""):
        return SystemExit(
            f"Neo4j is rate-limiting authentication for {settings.redacted} after too many "
            "failed attempts. Wait a few seconds and try again with the right password.\n"
            "A container started against an existing data volume keeps that volume's "
            "original password -- NEO4J_AUTH only applies to a database being created for "
            "the first time. See data-loading/README.md, 'Starting a database'."
        )
    if isinstance(exc, ClientError):
        return SystemExit(f"Neo4j refused the connection to {settings.redacted}: {exc}")
    return SystemExit(
        f"Cannot reach Neo4j at {settings.uri}: {exc}\n"
        "Is the database running, and is NEO4J_URI pointing at it? See "
        "data-loading/README.md, 'Starting a database'.\n"
        "To validate the data without a database at all, use --dry-run."
    )


def verify(driver: Driver, settings: Settings) -> None:
    """Connectivity check that explains itself when it fails."""
    try:
        driver.verify_connectivity()
    except CONNECTION_ERRORS as exc:
        raise unreachable(exc, settings) from exc


def check(settings: Settings) -> dict[str, object]:
    """Verify connectivity and report what is already in the database."""
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
                labels = handle.run(
                    "CALL db.labels() YIELD label RETURN count(label) AS c"
                ).single()["c"]
    except CONNECTION_ERRORS as exc:
        raise unreachable(exc, settings) from exc

    return {
        "target": settings.redacted,
        "server": f"{version['name']} {version['version']} ({version['edition']})",
        "nodes": nodes,
        "relationships": rels,
        "labels": labels,
    }
