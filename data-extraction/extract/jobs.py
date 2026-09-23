"""Extraction runs as a job, because it takes minutes and HTTP does not wait.

A twenty-page APT report is fifteen chunks, each an extraction call, plus batched
relation checks, plus an alignment call per ambiguous name. That is minutes of
GPU time. Holding an HTTP connection open for it would hit a timeout in every
client, proxy and browser between here and the caller, and the work would be
lost with no way to ask what happened.

So `POST /extract` returns an id immediately and the work happens on a thread.
`GET /extract/{id}` says how far along it is and, when finished, hands back the
proposal.

**Finished jobs are written to disk.** An in-memory dict alone would lose a
twenty-minute extraction to an API restart, and the result is the expensive part
-- a job is worth keeping precisely because reproducing it costs GPU time.
Running jobs are not resumed after a restart; they are marked `interrupted` when
they are next read, because a half-finished extraction cannot be trusted and is
cheaper to re-run than to reason about.

**One worker by default.** Two documents extracting at once share one GPU,
finish no sooner together than one after the other, and make both look hung.
"""

from __future__ import annotations

import json
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

QUEUED = "queued"
RUNNING = "running"
#: Stage A finished and the draft is waiting for a human. Settled, not busy:
#: it can sit here for hours, and it must survive an API restart.
AWAITING_REVIEW = "awaiting_review"
#: Stage B is running, on a job that was reviewed.
ALIGNING = "aligning"
DONE = "done"
FAILED = "failed"
SKIPPED = "skipped"
COMMITTED = "committed"
INTERRUPTED = "interrupted"

#: Statuses where a worker thread is meant to exist. A job found in one of
#: these after a restart was orphaned by it -- see `_load`. Everything else is
#: settled and gets written to disk on every update.
BUSY = (QUEUED, RUNNING, ALIGNING)


def _now() -> str:
    """The format `data-acquisition/*/client.py` stamps: seconds, `Z`."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class Job:
    id: str
    source: str
    genre: str
    title: str = ""
    status: str = QUEUED
    progress: str = "waiting for a worker"
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    #: Stage A's output, once it exists. Kept after alignment too, so the
    #: review that produced a proposal stays inspectable.
    draft: dict | None = None
    proposal: dict | None = None
    commit_result: dict | None = None
    error: str | None = None

    def summary(self) -> dict:
        """What `GET /extract/jobs` lists -- everything but the bulky parts."""
        data = asdict(self)
        proposal = data.pop("proposal")
        draft = data.pop("draft")
        data["stats"] = (proposal or {}).get("stats") or (draft or {}).get("counts")
        return data


class JobStore:
    """Thread-safe job registry with a disk copy of every finished result."""

    def __init__(self, directory: Path, workers: int = 1) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=max(1, workers), thread_name_prefix="extract")

    # -- storage -----------------------------------------------------------

    def _path(self, job_id: str) -> Path:
        return self.directory / f"{job_id}.json"

    def _persist(self, job: Job) -> None:
        # Written whole then renamed, so a reader never sees half a file and a
        # crash mid-write cannot corrupt a finished result.
        temporary = self._path(job.id).with_suffix(".tmp")
        temporary.write_text(json.dumps(asdict(job), indent=2), encoding="utf-8")
        temporary.replace(self._path(job.id))

    def _load(self, job_id: str) -> Job | None:
        path = self._path(job_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        job = Job(**data)
        # A job recorded as busy cannot be busy: this process has no thread for
        # it, so the API was restarted underneath it. `awaiting_review` is
        # deliberately not in that set -- parking across a restart is the point
        # of persisting it, and its draft is complete.
        if job.status in BUSY:
            job.status = INTERRUPTED
            job.error = "the API restarted while this job was running; submit it again"
        return job

    # -- lifecycle ---------------------------------------------------------

    def submit(
        self,
        *,
        source: str,
        genre: str,
        title: str,
        work: Callable[[Job], dict],
        field_name: str = "proposal",
        settles_at: str = DONE,
    ) -> Job:
        """Register a job and hand `work` to the pool. Returns immediately.

        `field_name` and `settles_at` are what let one store carry both halves
        of the pipeline: stage A settles at `awaiting_review` with its output in
        `draft`, stage B at `done` with its output in `proposal`.
        """
        job = Job(id=uuid.uuid4().hex[:12], source=source, genre=genre, title=title)
        with self._lock:
            self._jobs[job.id] = job
        self._persist(job)
        self._pool.submit(self._run, job, work, RUNNING, field_name, settles_at)
        return job

    def resume(
        self,
        job_id: str,
        work: Callable[[Job], dict],
        *,
        busy_status: str = ALIGNING,
        field_name: str = "proposal",
        settles_at: str = DONE,
    ) -> Job | None:
        """Run more work on a job that already exists.

        Stage B is not a new job: it belongs to the document that was already
        extracted, and keeping it on the same id is what lets `/commit` and the
        review page follow one thing from upload to graph.
        """
        job = self.get(job_id)
        if job is None:
            return None
        with self._lock:
            self._jobs[job_id] = job
        self._pool.submit(self._run, job, work, busy_status, field_name, settles_at)
        return job

    def _run(
        self,
        job: Job,
        work: Callable[[Job], dict],
        busy_status: str = RUNNING,
        field_name: str = "proposal",
        settles_at: str = DONE,
    ) -> None:
        self.update(job.id, status=busy_status, progress="starting")
        try:
            produced = work(job)
        except Exception as exc:  # noqa: BLE001 -- recorded on the job, not raised into the pool
            # The traceback goes to the job rather than to a log nobody reads:
            # whoever submitted the document is the one who needs to see why it
            # failed, and they are looking at `GET /extract/{id}`.
            self.update(
                job.id,
                status=_status_for(exc),
                progress="finished",
                error=f"{type(exc).__name__}: {exc}",
                traceback_text=traceback.format_exc(),
            )
            return
        self.update(job.id, status=settles_at, progress="finished", **{field_name: produced})

    def update(self, job_id: str, *, traceback_text: str | None = None, **fields) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            for key, value in fields.items():
                setattr(job, key, value)
            job.updated_at = _now()
            snapshot = Job(**asdict(job))
        if traceback_text:
            (self.directory / f"{job_id}.traceback.txt").write_text(
                traceback_text, encoding="utf-8"
            )
        # Persist only settled states: progress ticks several times a second and
        # rewriting a megabyte of proposal each time would cost more than the
        # extraction. `awaiting_review` is settled and so is written -- that is
        # what lets a parked review survive a restart.
        if snapshot.status not in BUSY:
            self._persist(snapshot)

    def progress(self, job_id: str) -> Callable[[str], None]:
        """A callback the pipeline can report into without knowing about jobs."""

        def report(message: str) -> None:
            self.update(job_id, progress=message)

        return report

    # -- reading -----------------------------------------------------------

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            job = self._jobs.get(job_id)
        return job or self._load(job_id)

    def wait(self, job_id: str, timeout: float) -> Job | None:
        """Block until the job settles or `timeout` seconds pass.

        For the synchronous endpoint: the caller wants the answer in the same
        HTTP response, so someone has to sit and wait, and it is cheaper for the
        server to do it than for a client to poll. Polling the store rather than
        joining the future keeps the job store's own bookkeeping (status,
        progress, persistence) the single source of truth.
        """
        deadline = time.monotonic() + timeout
        while True:
            job = self.get(job_id)
            if job is None or job.status not in BUSY:
                return job
            if time.monotonic() >= deadline:
                return job
            time.sleep(0.5)

    def recent(self, limit: int = 50) -> list[Job]:
        """Newest first, in memory and on disk, without duplicates."""
        with self._lock:
            jobs = dict(self._jobs)
        for path in self.directory.glob("*.json"):
            job_id = path.stem
            if job_id not in jobs:
                loaded = self._load(job_id)
                if loaded:
                    jobs[job_id] = loaded
        return sorted(jobs.values(), key=lambda job: job.created_at, reverse=True)[:limit]

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def _status_for(exc: Exception) -> str:
    """An irrelevant paper is an outcome, not a failure -- keep them apart."""
    from .pipeline import Irrelevant

    return SKIPPED if isinstance(exc, Irrelevant) else FAILED
