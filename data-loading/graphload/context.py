"""Everything a stage needs, assembled once.

A stage is a function `run(ctx, handle) -> dict`. Keeping the wiring in one
object means a stage never reaches for global state, which is what lets any of
them run alone (`--stage bridges`) or against a subset of sources
(`--only capec cwe`).

`all_specs` and `selected_specs` are both here on purpose. Node and local-edge
loading act on the selection; the registry and the bridge stage need *every*
source, because a cross-source edge cannot resolve its far endpoint otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .config import Settings
from .registry import Registry
from .spec import SourceSpec
from .validate import Findings


@dataclass
class Context:
    settings: Settings
    repo_root: Path
    all_specs: Sequence[SourceSpec]
    selected_specs: Sequence[SourceSpec]
    label_overrides: Mapping[str, str]
    rel_type_overrides: Mapping[str, str]
    declared_labels: Sequence[str]
    log: Callable[[str], None]
    dry_run: bool = False
    limit: int | None = None
    allow_new_labels: bool = False
    use_cache: bool = True
    findings: Findings = field(default_factory=Findings)
    registry: Registry = field(default_factory=Registry)
    covered_sources: set[str] = field(default_factory=set)

    @property
    def selected_keys(self) -> set[str]:
        return {spec.key for spec in self.selected_specs}

    def spec(self, key: str) -> SourceSpec:
        for candidate in self.all_specs:
            if candidate.key == key:
                return candidate
        raise KeyError(key)

    def sync_duplicates(self) -> None:
        """Surface the registry's duplicate ids as a findings gate."""
        self.findings.duplicate_ids = list(self.registry.duplicates)
