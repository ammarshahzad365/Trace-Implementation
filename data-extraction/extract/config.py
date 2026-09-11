"""Settings, read from the repo-root `.env` the same way every other stage does.

This duplicates `data-loading/graphload/config.py`'s tiny `.env` reader rather
than importing it, and that is deliberate. The stages in this repo do not import
each other -- `data-preprocessing/` does not import `data-acquisition/`, they
meet through files on disk -- and this stage meets `data-loading/` through its
HTTP API instead. Thirty lines of duplication is the price of being able to run,
move or break one stage without touching another, which is the same trade the
loader already made by not depending on python-dotenv.

Two connections are configured here, and they are not the same thing:

- **`ingest_url`** is where finished records are *written*: `POST /ingest` on the
  loading API, which `ingest/api.py` describes as the door unstructured
  extraction writes through. Nothing in this stage writes to Neo4j itself.
- **`neo4j_*`** is a **read-only** connection used by alignment and by the
  retrieval repository, both of which need to ask what the graph already knows.
  Reading cannot go through the ingest API because it has no read endpoint, and
  a vector search is not something HTTP should be in the middle of.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# bge-m3 emits 1024 floats. A Neo4j vector index fixes its dimensions at
# creation and cannot be re-pointed at a model of a different width, so changing
# the embedder means rebuilding the indexes -- `embed_corpus.py` checks this
# rather than letting Neo4j reject every row with a confusing error.
DEFAULT_EMBED_DIMENSIONS = 1024


@lru_cache(maxsize=1)
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def load_dotenv() -> dict[str, str]:
    values: dict[str, str] = {}
    env_path = repo_root() / ".env"
    if not env_path.exists():
        return values
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def setting(name: str, default: str | None = None) -> str | None:
    """Real environment first, then `.env`, then the default."""
    if name in os.environ:
        return os.environ[name]
    return load_dotenv().get(name, default)


@dataclass(frozen=True)
class Settings:
    ollama_url: str
    extract_model: str
    embed_model: str
    embed_dimensions: int
    align_threshold: float
    workers: int
    think: bool
    timeout: int
    ingest_url: str
    ingest_api_key: str | None
    neo4j_uri: str
    neo4j_user: str
    neo4j_password: str
    neo4j_database: str
    jobs_dir: Path

    @property
    def redacted(self) -> str:
        return (
            f"extract={self.extract_model} embed={self.embed_model} "
            f"ollama={self.ollama_url} ingest={self.ingest_url}"
        )


def settings() -> Settings:
    """Read fresh each call -- cheap, and lets a test set an env var and re-ask."""
    password = setting("NEO4J_PASSWORD")
    if not password:
        raise SystemExit(
            "NEO4J_PASSWORD is not set. Alignment has to read the existing graph. "
            "Add it to the repo-root .env file or export it for this shell."
        )
    return Settings(
        ollama_url=(setting("OLLAMA_URL", "http://127.0.0.1:11434") or "").rstrip("/"),
        extract_model=setting("EXTRACT_MODEL", "qwen3:32b"),
        embed_model=setting("EMBED_MODEL", "bge-m3"),
        embed_dimensions=int(setting("EMBED_DIMENSIONS", str(DEFAULT_EMBED_DIMENSIONS))),
        # TRACE section 5.2.2 sets theta to 0.9, but tuned it for *their*
        # sentence-transformer. Cosine scales are not comparable across embedding
        # models, so this is a starting point to recalibrate with
        # `eval/calibrate.py`, not a constant to trust. See the README.
        align_threshold=float(setting("ALIGN_THRESHOLD", "0.9")),
        # One by default: two documents extracting at once share one GPU, finish
        # no sooner, and make both look hung.
        workers=int(setting("EXTRACT_WORKERS", "1")),
        # Reasoning models think before answering. Measured on this server, the
        # same extraction took 11.8s thinking and 4.7s not, with an identical
        # answer -- so off by default. See `llm.py` for when to turn it back on.
        think=(setting("EXTRACT_THINK", "false") or "").lower() in ("1", "true", "yes"),
        timeout=int(setting("OLLAMA_TIMEOUT", "600")),
        ingest_url=(setting("INGEST_URL", "http://127.0.0.1:8000") or "").rstrip("/"),
        ingest_api_key=setting("INGEST_API_KEY"),
        neo4j_uri=setting("NEO4J_URI", "bolt://localhost:7687"),
        neo4j_user=setting("NEO4J_USER", "neo4j"),
        neo4j_password=password,
        neo4j_database=setting("NEO4J_DATABASE", "neo4j"),
        jobs_dir=repo_root() / "data-extraction" / ".cache" / "jobs",
    )
