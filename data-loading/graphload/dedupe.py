"""Making one arrow out of one fact, however many catalogs assert it.

Edge rows arrive with an id their own preprocessor invented. That's exactly
right when the row is the only record of its fact, and exactly wrong when it
isn't -- two catalogs describing the same relationship produce two different
ids, and `MERGE`-ing on id then creates two parallel arrows between the same two
nodes. Any query that walks that path silently counts it twice.

A `CanonicalRule` says "these input shapes are all the same fact": it names the
output relationship type, its canonical direction, and which
`(relationship_type, source label, target label)` triples map onto it -- in
either direction. Matching rows are rewritten to the canonical direction and
given a deterministic id derived from `(type, source, target)`, so every one of
them lands on the same arrow no matter which file it came from or which stage
loads it.

Verified against this dataset, the rules in `catalog/bridges.py` cover:

- **1,079** `child_of` pairs asserted by *both* CWE and D3FEND.
- **~4,400** cross-catalog `related-to` pairs asserted from both ends
  (CVE<->CWE, CAPEC<->CWE, CAPEC<->ATT&CK), which are also retyped from one
  vague `RELATED_TO` into three directional types.
- **158** `child_of` pairs and **376** `introduced_in`/`has_log_source` pairs
  recorded more than once inside a single catalog (CWE repeats a parent/child
  fact once per view it appears in).

`union_properties` is what makes the collapse non-destructive: instead of the
last write winning, those properties accumulate as a set-like list (see
`batch.py`). `asserted_by` is unioned on *every* edge, so the graph always
answers "which of my five catalogs claimed this".

Deliberately **not** collapsed, though they do repeat their endpoint pair:
`counters` (293 pairs) and `uses_data_component` (57). Both carry several
*correlated* attributes -- which defensive artifact, acted on how, bridging to
which offensive artifact -- and unioning each into its own list would destroy
which value pairs with which. There, a repeated pair is genuinely a second
distinct justification, so it stays a second arrow.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Iterable, Mapping

# Fixed namespace so a canonical edge id is stable across runs and machines --
# the same property `data-preprocessing/`'s own uuid5 ids have.
NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


@dataclass(frozen=True)
class CanonicalRule:
    """One fact that more than one row may describe."""

    rel_type: str
    source_label: str
    target_label: str
    matches: tuple[tuple[str, str, str], ...]
    union_properties: tuple[str, ...] = ()

    def key(self) -> tuple[str, str, str]:
        return (self.rel_type, self.source_label, self.target_label)


@dataclass
class Canonicalizer:
    """Applies a set of rules to edge rows. Rows matching nothing pass through."""

    rules: tuple[CanonicalRule, ...]
    provenance_property: str = "asserted_by"
    _forward: dict[tuple[str, str, str], CanonicalRule] = field(default_factory=dict)
    _reverse: dict[tuple[str, str, str], CanonicalRule] = field(default_factory=dict)
    collapsed: int = 0

    def __post_init__(self) -> None:
        for rule in self.rules:
            for rel_type, source_label, target_label in rule.matches:
                triple = (rel_type, source_label, target_label)
                if (source_label, target_label) == (rule.source_label, rule.target_label):
                    self._forward[triple] = rule
                elif (target_label, source_label) == (rule.source_label, rule.target_label):
                    self._reverse[triple] = rule
                else:
                    raise ValueError(
                        f"rule {rule.rel_type}: match {triple} is neither the canonical "
                        f"direction ({rule.source_label} -> {rule.target_label}) nor its reverse"
                    )

    def union_properties_for(self, rel_type: str, source_label: str, target_label: str) -> tuple[str, ...]:
        for rule in self.rules:
            if rule.key() == (rel_type, source_label, target_label):
                extra = tuple(p for p in rule.union_properties if p != self.provenance_property)
                return (self.provenance_property,) + extra
        return (self.provenance_property,)

    def apply(
        self,
        *,
        rel_type: str,
        source_id: str,
        target_id: str,
        source_label: str,
        target_label: str,
        edge_id: str,
    ) -> tuple[str, str, str, str, str, str, bool]:
        """-> (rel_type, source_id, target_id, source_label, target_label, edge_id, canonicalized)"""
        triple = (rel_type, source_label, target_label)
        rule = self._forward.get(triple)
        if rule is not None:
            new_id = canonical_id(rule.rel_type, source_id, target_id)
            self.collapsed += 1
            return (rule.rel_type, source_id, target_id, rule.source_label, rule.target_label, new_id, True)

        rule = self._reverse.get(triple)
        if rule is not None:
            new_id = canonical_id(rule.rel_type, target_id, source_id)
            self.collapsed += 1
            return (rule.rel_type, target_id, source_id, rule.source_label, rule.target_label, new_id, True)

        return (rel_type, source_id, target_id, source_label, target_label, edge_id, False)


def canonical_id(rel_type: str, source_id: str, target_id: str) -> str:
    seed = f"{source_id}|{rel_type}|{target_id}"
    return f"relationship--{uuid.uuid5(NAMESPACE, seed)}"


def declared_rel_types(rules: Iterable[CanonicalRule]) -> set[str]:
    return {rule.rel_type for rule in rules}


def split_union_values(
    props: Mapping[str, object], union_names: Iterable[str]
) -> tuple[dict[str, object], dict[str, list]]:
    """Move union-property values out of `props` into a `u` map of lists.

    Every union property must be present as a list for every row in a batch --
    `[] + null` would fail server-side -- so absent ones become `[]`.
    """
    plain = dict(props)
    unions: dict[str, list] = {}
    for name in union_names:
        value = plain.pop(name, None)
        if value is None:
            unions[name] = []
        elif isinstance(value, list):
            unions[name] = value
        else:
            unions[name] = [value]
    return plain, unions
