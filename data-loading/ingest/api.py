"""The HTTP API: three endpoints over the same engine the batch loader uses.

    GET  /health     is it up, is Neo4j reachable, what is in the graph
    GET  /schema     which fields are required, and which types are already known
    POST /ingest     add or update entities and relationships

`/docs` serves an interactive page (FastAPI's built-in Swagger UI) where a
request can be filled in and sent from the browser, which is usually the fastest
way to add a handful of records without writing any client code.

## Why one endpoint rather than two

Entities and relationships arrive together and are written **entities first**,
because a relationship can only attach to nodes that exist. Splitting them into
`POST /entities` and `POST /relationships` would push that ordering onto the
caller, and getting it wrong would look like data loss -- the relationships
would be silently skipped as dangling. One endpoint makes the correct order the
only order.

## What this does not do

It does not preprocess, and it does not gate `type` against a fixed list. This
is the door unstructured extraction writes through -- an APT report or a paper
will keep naming entity types this project has never seen -- so the only things
required are the fields the graph itself cannot do without (see `Entity` and
`Relationship` below). Whatever other fields a record carries become properties
under those names, exactly as in `graphload/properties.py`. It is the same
contract as the files under `data-preprocessing/`, which means anything valid
there is valid here, and vice versa.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from neo4j import GraphDatabase
from pydantic import BaseModel, ConfigDict, Field

import catalog
from graphload.config import settings
from graphload.properties import PropertyError
from graphload.schema import await_indexes, create_constraints

from .writer import IngestError, write_entities, write_relationships

# Both mean "the request was wrong", so both are a 422 rather than a 500:
# IngestError for a missing required field, PropertyError for a value Neo4j
# cannot store. The latter is raised deep inside graphload and is easy to let
# fall through to the catch-all, which would blame the server for the caller's
# nested object.
BAD_REQUEST = (IngestError, PropertyError)

STATE: dict[str, Any] = {}


class Entity(BaseModel):
    """One node. `id`, `type` and `source` are required; every other field is a
    plain property, under whatever name the caller sends it.

    `type` is not limited to a fixed list -- post anything and it becomes a
    label (`threat-actor` -> `ThreatActor`), which is what makes this endpoint
    usable for entities an LLM extractor names for the first time, not just the
    five catalogs this project started with. `source` stays required rather
    than optional: entity alignment tells two same-named nodes apart by *who
    asserted them*, and a record with no source is unidentifiable in exactly
    the way alignment needs to resolve. `collected_at` is not required -- if
    the record doesn't carry one, the API stamps the current time itself.
    """

    model_config = ConfigDict(extra="allow")
    id: str = Field(examples=["CVE-2026-99999"])
    type: str = Field(examples=["vulnerability"], description="Any value; unrecognised types derive their own label.")
    source: str = Field(
        description="Who or what asserted this record -- a catalog name or a document id.",
        examples=["apt-report-2026-114"],
    )


class Relationship(BaseModel):
    """One relationship. Endpoints are ids of nodes that must already exist.

    `id`, `relationship_type`, `source_ref`, `target_ref` and `source` are
    required for the same reasons as on `Entity`; `collected_at` is stamped
    automatically if omitted.
    """

    model_config = ConfigDict(extra="allow")
    id: str = Field(examples=["relationship--my-unique-id-1"])
    relationship_type: str = Field(examples=["related_to"])
    source_ref: str = Field(examples=["CVE-2026-99999"])
    target_ref: str = Field(examples=["CWE-79"])
    source: str = Field(
        description="Who or what asserted this relationship -- a catalog name or a document id.",
        examples=["apt-report-2026-114"],
    )


class IngestRequest(BaseModel):
    entities: list[Entity] = []
    relationships: list[Relationship] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = settings()
    driver = GraphDatabase.driver(cfg.uri, auth=(cfg.user, cfg.password))
    driver.verify_connectivity()
    # The batch loader creates these in stage 1. The API may well be the first
    # thing to touch an empty database, so it ensures them too -- an endpoint
    # lookup without an index is a full scan.
    with driver.session(database=cfg.database) as handle:
        create_constraints(handle, catalog.all_labels())
        await_indexes(handle)
    STATE["driver"], STATE["cfg"] = driver, cfg
    yield
    driver.close()


app = FastAPI(
    title="Trace knowledge graph - ingest API",
    description=__doc__,
    version="1.0.0",
    lifespan=lifespan,
)


def _session():
    cfg = STATE["cfg"]
    return STATE["driver"].session(database=cfg.database)


@app.get("/health")
def health() -> dict:
    """Liveness plus what is currently in the graph."""
    try:
        with _session() as handle:
            nodes = handle.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            rels = handle.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
    except Exception as exc:  # noqa: BLE001 -- surfaced as a 503, not a stack trace
        raise HTTPException(503, f"Neo4j unreachable: {exc}") from exc
    return {"status": "ok", "database": STATE["cfg"].redacted, "nodes": nodes, "relationships": rels}


@app.get("/schema")
def schema() -> dict:
    """What a record must carry, plus the types already known and in use."""
    with _session() as handle:
        in_use = [
            row["t"]
            for row in handle.run("CALL db.relationshipTypes() YIELD relationshipType AS t RETURN t")
        ]
    return {
        "entity_required_fields": ["id", "type", "source"],
        "relationship_required_fields": [
            "id",
            "relationship_type",
            "source_ref",
            "target_ref",
            "source",
        ],
        "auto_filled_if_omitted": ["collected_at"],
        "known_entity_types": dict(sorted(catalog.LABELS.items())),
        "relationship_types_in_use": sorted(in_use),
        "note": (
            "known_entity_types is a reference, not a gate: any 'type' value is accepted "
            "and derives its own label (e.g. 'threat-actor' -> 'ThreatActor') the same way "
            "an unrecognised one would from data-preprocessing/. 'relationship_type' is "
            "likewise free-form and is uppercased. Every field not listed above is a plain "
            "property, under whatever name the caller sends it."
        ),
    }


@app.post("/ingest")
def ingest(request: IngestRequest) -> dict:
    """Add or update records. Entities are written first, then relationships.

    Re-posting the same record updates it rather than duplicating it, because
    both are MERGEd on `id`. Note that properties are *replaced*, not merged, so
    a field left out of a later post is removed from the node -- send the whole
    record, not a patch.
    """
    if not request.entities and not request.relationships:
        raise HTTPException(400, "Nothing to do: both 'entities' and 'relationships' are empty.")

    declared = catalog.all_labels()
    try:
        with _session() as handle:
            entity_result = (
                write_entities(
                    handle,
                    [e.model_dump() for e in request.entities],
                    label_overrides=catalog.LABELS,
                    declared_labels=declared,
                )
                if request.entities
                else {"written": 0, "by_label": {}}
            )
            rel_result = (
                write_relationships(
                    handle,
                    [r.model_dump() for r in request.relationships],
                    rel_type_overrides=catalog.REL_TYPE_OVERRIDES,
                    declared_labels=sorted(set(declared) | set(entity_result["by_label"])),
                )
                if request.relationships
                else {"written": 0, "by_type": {}, "skipped_dangling": 0, "dangling": []}
            )
    except BAD_REQUEST as exc:
        raise HTTPException(422, str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"{type(exc).__name__}: {exc}") from exc

    return {"entities": entity_result, "relationships": rel_result}
