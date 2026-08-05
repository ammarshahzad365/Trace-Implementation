"""The gates that stop a bad load before it starts.

Some problems are cheap to catch here and expensive to notice later, once
1.1M nodes are already in the store:

- **A duplicate id** is the worst of them. Two records sharing an id don't
  error -- they `MERGE` into a single node whose properties are a blend of two
  unrelated things, and nothing downstream ever looks wrong.
- **An unmapped type** must fail loudly rather than have a label invented for
  it, because an invented label is how a future ATT&CK release quietly ends up
  with half its techniques under `AttackTechnique` and half under something
  else. `--allow-new-labels` turns this into a warning *and reports every name
  it derived*, for when you're deliberately loading something new.
- **A property collision** after prefix stripping would silently drop a field.
- **A leftover `related-to`** means a cross-reference shape appeared that
  `catalog/bridges.py` has no rule for. Since the whole point of the bridge
  rules is that `RELATED_TO` stops existing, one surviving is a modelling gap,
  not a cosmetic one.

Dangling endpoints are the deliberate exception: **reported, counted, and
skipped, but never fatal.** They're not always a bug in the data. This dataset
has exactly four, all correct citations -- CWE names four CVEs as observed
examples that NVD either rejected or never published. The right behaviour is to
say so and decline to invent them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from .registry import Duplicate


@dataclass
class Findings:
    duplicate_ids: list[Duplicate] = field(default_factory=list)
    missing_id: list[str] = field(default_factory=list)
    missing_type: list[str] = field(default_factory=list)
    unmapped_types: dict[str, int] = field(default_factory=dict)
    derived_labels: dict[str, str] = field(default_factory=dict)
    property_collisions: list[str] = field(default_factory=list)
    dangling: list[tuple[str, str, str, str]] = field(default_factory=list)
    leftover_related_to: dict[str, int] = field(default_factory=dict)

    def fatal(self, allow_new_labels: bool = False) -> list[str]:
        problems: list[str] = []
        if self.duplicate_ids:
            shown = ", ".join(
                f"{d.id} ({d.first[1]}/{d.first[0]} vs {d.second[1]}/{d.second[0]})"
                for d in self.duplicate_ids[:5]
            )
            problems.append(
                f"{len(self.duplicate_ids)} duplicate entity id(s) -- these would merge "
                f"two records into one node: {shown}"
                + (" ..." if len(self.duplicate_ids) > 5 else "")
            )
        if self.missing_id:
            problems.append(f"{len(self.missing_id)} record(s) with no id: {self.missing_id[:5]}")
        if self.missing_type:
            problems.append(f"{len(self.missing_type)} record(s) with no type: {self.missing_type[:5]}")
        if self.unmapped_types and not allow_new_labels:
            listed = ", ".join(f"{t} (x{n})" for t, n in sorted(self.unmapped_types.items()))
            problems.append(
                f"{len(self.unmapped_types)} type(s) have no label in catalog/labels.py: {listed}. "
                "Add them there, or re-run with --allow-new-labels to accept the derived name."
            )
        if self.property_collisions:
            problems.append(
                "property name collisions after prefix stripping: "
                + "; ".join(self.property_collisions)
            )
        if self.leftover_related_to:
            listed = ", ".join(f"{k} (x{v})" for k, v in sorted(self.leftover_related_to.items()))
            problems.append(
                "these 'related-to' edge shapes have no rule in catalog/bridges.py, so they "
                f"would load as an untyped RELATED_TO: {listed}"
            )
        return problems

    def warnings(self) -> list[str]:
        out = []
        if self.dangling:
            shown = ", ".join(f"{s} -{r}-> {t}" for s, r, t, _ in self.dangling[:4])
            out.append(
                f"{len(self.dangling)} edge endpoint(s) resolve to no entity; those edges are "
                f"skipped, not invented: {shown}" + (" ..." if len(self.dangling) > 4 else "")
            )
        if self.derived_labels:
            listed = ", ".join(f"{t} -> {l}" for t, l in sorted(self.derived_labels.items()))
            out.append(f"labels derived automatically (no override in catalog/labels.py): {listed}")
        return out


def report_lines(findings: Findings, allow_new_labels: bool) -> tuple[list[str], list[str]]:
    return findings.fatal(allow_new_labels), findings.warnings()


def raise_if_fatal(findings: Findings, allow_new_labels: bool) -> None:
    problems = findings.fatal(allow_new_labels)
    if problems:
        raise SystemExit(
            "Refusing to load. "
            + str(len(problems))
            + " blocking problem(s):\n  - "
            + "\n  - ".join(problems)
        )
