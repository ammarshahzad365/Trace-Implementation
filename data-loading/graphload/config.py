"""Connection settings and paths, read from the repo-root `.env`.

No third-party dotenv dependency -- the file is four `KEY=value` lines and a
real environment variable always wins over it, so exporting `NEO4J_URI` for one
run works without editing anything.

`repo_root()` walks up from this file rather than trusting the working
directory, so every path in `catalog/` can be written relative to the repo root
and the loader can be run from anywhere -- the same property
`data-preprocessing/`'s modules already have.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


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
    uri: str
    user: str
    password: str
    database: str
    batch_size: int
    cache_dir: Path

    @property
    def redacted(self) -> str:
        return f"{self.user}@{self.uri} (database: {self.database})"


def settings(batch_size: int = 10_000) -> Settings:
    password = setting("NEO4J_PASSWORD")
    if not password:
        raise SystemExit(
            "NEO4J_PASSWORD is not set. Add it to the repo-root .env file "
            "(see data-loading/README.md) or export it for this shell."
        )
    return Settings(
        uri=setting("NEO4J_URI", "bolt://localhost:7687"),
        user=setting("NEO4J_USER", "neo4j"),
        password=password,
        database=setting("NEO4J_DATABASE", "neo4j"),
        batch_size=batch_size,
        cache_dir=Path(__file__).resolve().parents[1] / ".cache",
    )
