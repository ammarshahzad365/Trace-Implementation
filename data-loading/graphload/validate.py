"""The gates that stop a bad load before it goes further.

Some problems are cheap to catch here and expensive to notice later, once
several hundred thousand nodes are already in the store:

- **A duplicate id** is the worst of them. Two records sharing an id do not
  error -- they `MERGE` into a single node whose properties are a blend of two
  unrelated things, and nothing downstream ever looks wrong.
- **An unmapped type** must fail loudly rather than have a label invented for
  it, because an invented label is how a future ATT&CK release quietly ends up
  with half its techniques under `AttackTechnique` and half under something
  else. `--allow-new-labels` turns this into a warning *and reports every name
  it derived*, for when you are deliberately loading something new.
- **A record with no id or no type** cannot become a node at all.

Dangling endpoints are the deliberate exception: **reported, counted and
skipped, but never fatal.** They are not always a bug in the data -- a catalog
can legitimately cite an id another catalog rejected or never published. The
right behaviour is to say so and decline to invent the missing node, which is
also the only behaviour consistent with a loader that does not preprocess.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .registry import Duplicate


@dataclass
class Findings:
    duplicate_ids: list[Duplicate] = field(default_factory=list)
    missing_id: list[str] = field(default_factory=list)
    missing_type: list[str] = field(default_factory=list)
    unmapped_types: dict[str, int] = field(default_factory=dict)
    derived_labels: dict[str, str] = field(default_factory=dict)
    dangling: list[tuple[str, str, str, str]] = field(default_factory=list)

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
            problems.append(
                f"{len(self.missing_type)} record(s) with no type: {self.missing_type[:5]}"
            )
        if self.unmapped_types and not allow_new_labels:
            listed = ", ".join(f"{t} (x{n})" for t, n in sorted(self.unmapped_types.items()))
            problems.append(
                f"{len(self.unmapped_types)} type(s) have no label in catalog/labels.py: {listed}. "
                "Add them there, or re-run with --allow-new-labels to accept the derived name."
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
            listed = ", ".join(f"{t} -> {label}" for t, label in sorted(self.derived_labels.items()))
            out.append(f"labels derived automatically (no entry in catalog/labels.py): {listed}")
        return out


def raise_if_fatal(findings: Findings, allow_new_labels: bool) -> None:
    problems = findings.fatal(allow_new_labels)
    if problems:
        raise SystemExit(
            f"Refusing to load. {len(problems)} blocking problem(s):\n  - "
            + "\n  - ".join(problems)
        )
