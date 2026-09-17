"""The HTTP surface: post a document, poll the job, review, then commit.

    GET  /extract/health         is Ollama up, are the models pulled, is the graph reachable
    POST /extract                submit a document; returns a job id straight away
    GET  /extract/jobs           recent jobs, newest first
    GET  /extract/{job_id}       progress, then the finished proposal
    POST /extract/file           upload a .txt and get entities + relationships back in one response
    POST /extract/{job_id}/commit   write it, optionally minus records you rejected

`/docs` serves the interactive page, the same way the ingest API does.

## Why committing is a separate call

The model is right most of the time, which is exactly what makes reviewing worth
the extra step: the failures are a minority and they are not obvious in
aggregate. The proposal shows every decision -- what matched what and at what
similarity, which sentence justified each edge, what was dropped, what the
ontology could not place -- and `drop_ids` lets you remove the wrong ones before
anything is written. Extraction that wrote directly would put the reviewing
after the damage.

## Why this writes over HTTP rather than importing the writer

Stages in this repo do not import each other. `ingest/api.py` calls itself "the
door unstructured extraction writes through", and going through that door means
records from here are validated, labelled and MERGEd by exactly the code that
handles a batch load -- there is no second write path to keep in step.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from . import graph, jobs, llm, ontology, pipeline
from .config import Settings, settings

STATE: dict[str, Any] = {}


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """Same optional shared secret as the ingest API, for the same reasons.

    Unset is right for the loopback-plus-SSH-tunnel deployment. Set is right
    anywhere the port is reachable, because this endpoint spends GPU time on
    demand and then writes to the graph.
    """
    import os
    import secrets

    expected = os.environ.get("EXTRACT_API_KEY") or os.environ.get("INGEST_API_KEY")
    if not expected:
        return
    given = (authorization or "").removeprefix("Bearer ")
    if not secrets.compare_digest(given, expected):
        raise HTTPException(401, "Missing or invalid 'Authorization: Bearer <key>' header")


class ExtractRequest(BaseModel):
    text: str = Field(description="The document, as plain text. Convert PDFs before posting.")
    source: str = Field(
        description=(
            "Who asserted this -- a document id, which lands on every record "
            "produced from it. TRACE section 3.2.4 requires it."
        ),
        examples=["apt-report-2026-114"],
    )
    genre: str = Field(
        default="apt-report",
        description=f"One of: {', '.join(sorted(ontology.GENRES))}",
        examples=["apt-report"],
    )
    title: str = Field(default="", description="Used by the relevance check on papers.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = settings()
    STATE["cfg"] = cfg
    STATE["jobs"] = jobs.JobStore(cfg.jobs_dir, workers=cfg.workers)
    yield
    STATE["jobs"].shutdown()
    graph.close()


app = FastAPI(
    title="Trace knowledge graph - extraction API",
    description=__doc__,
    version="1.0.0",
    lifespan=lifespan,
)


def _cfg() -> Settings:
    return STATE["cfg"]


def _store() -> jobs.JobStore:
    return STATE["jobs"]


@app.get("/extract/health")
def health() -> dict:
    """Everything this stage depends on, checked separately so failures localise."""
    cfg = _cfg()
    report: dict[str, Any] = {"config": cfg.redacted}

    try:
        installed = llm.installed_models(cfg)
        report["ollama"] = "ok"
        report["models_installed"] = installed
        missing = [
            model
            for model in (cfg.extract_model, cfg.embed_model)
            # Ollama reports `qwen3:32b` as `qwen3:32b`, but a tag without an
            # explicit version arrives as `name:latest`.
            if model not in installed and f"{model}:latest" not in installed
        ]
        report["models_missing"] = missing
    except llm.LLMError as exc:
        report["ollama"] = f"unreachable: {exc}"

    try:
        with graph.session(cfg) as handle:
            counts = handle.run(
                "MATCH (n) RETURN count(n) AS nodes"
            ).single()["nodes"]
            indexes = graph.vector_indexes(handle)
        report["graph"] = "ok"
        report["nodes"] = counts
        report["vector_indexes"] = indexes
        if not indexes:
            report["warning"] = (
                "no vector indexes, so alignment cannot find existing nodes and "
                "every entity will look new -- run `py -m extract.embed_corpus`"
            )
    except Exception as exc:  # noqa: BLE001 -- reported, not raised
        report["graph"] = f"unreachable: {exc}"

    return report


def _start_job(*, text: str, source: str, genre: str, title: str) -> jobs.Job:
    """Validate, then hand the document to the pipeline on a worker thread.

    Both submission endpoints go through here, so a document posted as JSON and
    one uploaded as a file run the identical pipeline and land in the same job
    store -- which is what lets `/commit` treat them the same afterwards.
    """
    if genre not in ontology.GENRES:
        raise HTTPException(
            422, f"unknown genre {genre!r}; expected one of {sorted(ontology.GENRES)}"
        )
    if not text.strip():
        raise HTTPException(422, "the document is empty")
    if not source.strip():
        raise HTTPException(422, "'source' is required -- it is what tells records apart")

    cfg = _cfg()
    store = _store()

    def work(job: jobs.Job) -> dict:
        with graph.session(cfg) as handle:
            proposal = pipeline.run(
                cfg,
                handle,
                text=text,
                source=source,
                genre=genre,
                title=title,
                progress=store.progress(job.id),
            )
        return proposal.as_dict()

    return store.submit(source=source, genre=genre, title=title, work=work)


@app.post("/extract", dependencies=[Depends(require_api_key)], status_code=202)
def submit(request: ExtractRequest) -> dict:
    """Queue a document. Returns a job id; poll `GET /extract/{job_id}`."""
    job = _start_job(
        text=request.text, source=request.source, genre=request.genre, title=request.title
    )
    return {"job_id": job.id, "status_url": f"/extract/{job.id}", "status": job.status}


# Files are read as UTF-8 first because that is what nearly every text file is;
# the fallback exists for the odd Windows-1252 export, which would otherwise
# fail on the first curly quote.
_ENCODINGS = ("utf-8", "utf-8-sig", "cp1252", "latin-1")
_TEXT_SUFFIXES = (".txt", ".md", ".text")
_MAX_UPLOAD = 5 * 1024 * 1024


def _decode_upload(name: str, raw: bytes) -> str:
    if not raw:
        raise HTTPException(422, f"{name!r} is empty")
    if len(raw) > _MAX_UPLOAD:
        raise HTTPException(413, f"{name!r} is {len(raw)} bytes; the limit is {_MAX_UPLOAD}")
    if b"\x00" in raw[:4096]:
        raise HTTPException(
            422,
            f"{name!r} does not look like a text file (it contains NUL bytes). "
            "Convert PDFs and Word documents to plain text before uploading.",
        )
    for encoding in _ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise HTTPException(422, f"{name!r} could not be decoded as text")


@app.post("/extract/file", dependencies=[Depends(require_api_key)])
def extract_file(
    file: UploadFile = File(description="A plain-text document (.txt). Convert PDFs first."),
    source: str = Form(
        default="",
        description="Document id stamped on every record. Defaults to the file name.",
    ),
    genre: str = Form(default="apt-report", description=f"One of: {', '.join(sorted(ontology.GENRES))}"),
    title: str = Form(default="", description="Used by the relevance check on papers."),
    timeout: int = Form(default=1800, description="Seconds to wait before giving up (the job keeps running)."),
) -> dict:
    """Upload a text file and get the extracted entities and relationships back
    in the same response.

    This is `POST /extract` with the waiting done for you. It runs the identical
    pipeline and the result is also stored as a job, so the returned `job_id`
    works with `POST /extract/{job_id}/commit` exactly as before. A long document
    can take minutes; if `timeout` passes first, the response says so and the
    job id lets you collect the result later from `GET /extract/{job_id}`.
    """
    name = file.filename or "upload"
    if not name.lower().endswith(_TEXT_SUFFIXES):
        raise HTTPException(
            415, f"{name!r}: only {', '.join(_TEXT_SUFFIXES)} files are accepted. Convert PDFs first."
        )
    text = _decode_upload(name, file.file.read())
    document_id = source.strip() or Path(name).stem

    job = _start_job(text=text, source=document_id, genre=genre, title=title)
    settled = _store().wait(job.id, timeout=max(1, timeout))

    if settled is None:
        raise HTTPException(500, f"job {job.id} vanished while waiting")
    if settled.status in (jobs.QUEUED, jobs.RUNNING):
        return {
            "job_id": job.id,
            "status": settled.status,
            "progress": settled.progress,
            "note": f"still running after {timeout}s; fetch the result from /extract/{job.id}",
        }
    if settled.status == jobs.SKIPPED:
        return {"job_id": job.id, "status": settled.status, "reason": settled.error}
    if settled.status != jobs.DONE or not settled.proposal:
        raise HTTPException(500, f"extraction {settled.status}: {settled.error}")

    proposal = settled.proposal
    return {
        "job_id": job.id,
        "status": settled.status,
        "source": document_id,
        "genre": genre,
        "entities": proposal["entities"],
        "relationships": proposal["relationships"],
        "aligned": proposal["aligned"],
        "near_misses": proposal["near_misses"],
        "dropped": proposal["dropped"],
        "other": proposal["other"],
        "new_relations": proposal.get("new_relations", []),
        "stats": proposal["stats"],
        "commit_url": f"/extract/{job.id}/commit",
    }


@app.get("/extract/jobs")
def recent_jobs(limit: int = 50) -> dict:
    return {"jobs": [job.summary() for job in _store().recent(limit)]}


@app.get("/extract/{job_id}")
def job_status(job_id: str) -> dict:
    job = _store().get(job_id)
    if job is None:
        raise HTTPException(404, f"no job {job_id!r}")
    from dataclasses import asdict

    return asdict(job)


@app.post("/extract/{job_id}/commit", dependencies=[Depends(require_api_key)])
def commit(job_id: str, drop_ids: list[str] = Body(default=[], embed=True)) -> dict:
    """Write a finished proposal through the ingest API.

    `drop_ids` removes records by id before writing -- the point of reviewing.
    Dropping an entity also drops any relationship that touches it, because an
    edge to a node that was never written would dangle.
    """
    store = _store()
    job = store.get(job_id)
    if job is None:
        raise HTTPException(404, f"no job {job_id!r}")
    if job.status == jobs.COMMITTED:
        raise HTTPException(409, f"job {job_id} was already committed")
    if job.status != jobs.DONE or not job.proposal:
        raise HTTPException(409, f"job {job_id} is {job.status}, not {jobs.DONE}")

    unwanted = set(drop_ids)
    entities = [e for e in job.proposal["entities"] if e["id"] not in unwanted]
    kept = {e["id"] for e in entities}
    dropped_entity_ids = {e["id"] for e in job.proposal["entities"]} - kept

    relationships = [
        r
        for r in job.proposal["relationships"]
        if r["id"] not in unwanted
        and r["source_ref"] not in dropped_entity_ids
        and r["target_ref"] not in dropped_entity_ids
    ]

    if not entities and not relationships:
        raise HTTPException(400, "nothing left to write once drop_ids is applied")

    result = _post_ingest(_cfg(), {"entities": entities, "relationships": relationships})
    store.update(job_id, status=jobs.COMMITTED, commit_result=result)
    return {
        "written": result,
        "dropped_by_request": len(unwanted),
        "entities_sent": len(entities),
        "relationships_sent": len(relationships),
    }


def _post_ingest(cfg: Settings, payload: dict) -> dict:
    """One POST to the loading stage. Its errors are surfaced, not swallowed."""
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if cfg.ingest_api_key:
        headers["Authorization"] = f"Bearer {cfg.ingest_api_key}"
    request = urllib.request.Request(
        f"{cfg.ingest_url}/ingest", data=body, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:1000]
        raise HTTPException(502, f"the ingest API rejected this: {exc.code} {detail}") from exc
    except urllib.error.URLError as exc:
        raise HTTPException(
            502,
            f"cannot reach the ingest API at {cfg.ingest_url} ({exc.reason}). "
            "Is `py -m ingest.serve` running in data-loading?",
        ) from exc
