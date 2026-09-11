"""The vocabulary an LLM is allowed to use, and how it maps onto this graph.

TRACE defines a **separate, small** schema for unstructured text rather than
reusing the structured catalogs' 34 relationship types: entity types tailored per
genre (section 3.1.1) and a fixed set of triple patterns (section 3.1.2,
evaluated in Figure 2). This module is that schema, in one place, because three
different stages need to agree on it -- the extraction prompt offers these types,
relation validation forms pairs from these patterns, and alignment searches
within one of these types.

## Why the list is closed

The prompt is limited; `POST /ingest` is not, and stays exactly as open as
`ingest/serve.py` says it is. The limit exists for three reasons:

1. **Alignment only works within a type.** It compares against the top-20 nodes
   *of the same type*. If the model is free to invent type names, one threat
   actor arrives as `group`, `threat-actor` and `apt-group` from three reports,
   lands in three separate search spaces, and alignment never fires -- producing
   exactly the duplicates alignment exists to prevent.
2. **Relation validation needs patterns to form pairs from.** "Combine the nodes
   based on the predefined relationship schema" is not possible without a schema.
3. **Per-type F1 needs a closed set.** Table 4's macro-F1 averages F1 per entity
   type; an open set makes the paper's own metric uncomputable.

`OTHER` is the escape hatch: a model may say "this is something else, and here
is what I would call it". Those are reported and **not** written, which turns
"what does the fixed ontology miss?" into a number instead of a worry.

## The mapping trap

The paper's `technique` means an *attack* technique. In this repo
`catalog/labels.py` maps the bare type `technique` to `DefensiveTechnique`,
because that is D3FEND's word for its own entries. The two cross over, so the
paper's names are translated here once, explicitly, and nowhere else.
"""

from __future__ import annotations

import re
from typing import Iterable, NamedTuple

OTHER = "other"

# The genres section 3.1.1 names. The value is what the extraction prompt calls
# the document, which the model does read -- "an APT report" primes differently
# from "a document".
GENRES: dict[str, str] = {
    "apt-report": "an APT (advanced persistent threat) report",
    "repair-notice": "a vendor repair notice or security advisory",
    "paper": "an academic paper on attack or defense techniques",
}

# Section 3.1.1 gives the APT-report set explicitly -- "vulnerabilities",
# "tools", "techniques", "groups", "assets". The other two genres follow the
# same logic applied to what section 3.1.2 says those genres discuss: a repair
# notice is about a flaw and its fix, a paper is about a technique and a defence.
ENTITY_TYPES_BY_GENRE: dict[str, tuple[str, ...]] = {
    "apt-report": ("vuln", "technique", "tool", "group", "asset"),
    "repair-notice": ("vuln", "mitigation", "asset", "technique"),
    "paper": ("vuln", "technique", "tool", "asset", "mitigation", "defend_technique"),
}

# What each paper-name means, in the prompt's own words. Sharp boundaries here
# are the only defence against the paper's own stated limitation -- tools being
# misclassified as techniques (Limitations, second bullet).
TYPE_DEFINITIONS: dict[str, str] = {
    "vuln": "a specific software or hardware flaw, named or with a CVE identifier",
    "technique": "an offensive method or behaviour an attacker performs (what they do, not what they use)",
    "tool": "a named piece of software, malware or utility used by an attacker (what they use, not what they do)",
    "group": "a named threat actor, APT group or intrusion set",
    "asset": "a system, device or component that is targeted or affected",
    "mitigation": "a defensive measure that reduces or removes a vulnerability",
    "defend_technique": "a named defensive technique or countermeasure a defender performs",
}

# Paper's name -> the `type` value `data-preprocessing/` emits, whose label
# `catalog/labels.py` then fixes. Note `technique`/`defend_technique` crossing
# over; that is the trap described above.
REPO_TYPE: dict[str, str] = {
    "vuln": "vulnerability",
    "technique": "attack-technique",
    "tool": "tool",
    "group": "intrusion-set",
    "asset": "x-mitre-asset",
    "mitigation": "attack-mitigation",
    "defend_technique": "technique",
}

# The Neo4j label each of those becomes. `catalog/labels.py` is the authority and
# this repeats seven of its entries, because a stage does not import another
# stage -- but they must agree, or alignment searches a label that holds nothing
# and every entity looks new. `py -m extract.check --labels` verifies it against
# the live graph rather than trusting this table.
REPO_LABEL: dict[str, str] = {
    "vuln": "Vulnerability",
    "technique": "AttackTechnique",
    "tool": "Tool",
    "group": "IntrusionSet",
    "asset": "Asset",
    "mitigation": "AttackMitigation",
    "defend_technique": "DefensiveTechnique",
}

# The labels alignment *searches* for each paper type -- a superset of where a
# new one is *written*. The paper's `tool` is one concept ("a named piece of
# software ... used by an attacker") but ATT&CK splits it: Mimikatz and PsExec
# are `Tool`, while China Chopper, Cobalt Strike and PlugX are `Malware`. A
# report says "deployed China Chopper" and the model rightly calls it a tool;
# searching `Tool` alone would never find S0020. Checked against the live graph
# on 2026-09-10.
ALIGN_LABELS: dict[str, tuple[str, ...]] = {
    "vuln": ("Vulnerability",),
    "technique": ("AttackTechnique",),
    "tool": ("Tool", "Malware"),
    "group": ("IntrusionSet",),
    "asset": ("Asset",),
    "mitigation": ("AttackMitigation",),
    "defend_technique": ("DefensiveTechnique",),
}


class Pattern(NamedTuple):
    source: str
    relation: str
    target: str


# What each relation means, in the validation prompt's words. The paper leaves
# them undefined, and an undefined `discovers` got confirmed on the evidence
# "the group exploited CVE-2021-26855" -- exploiting is not discovering. There is
# no `exploits` in Figure 2, so the honest answer is a stricter judge, not a
# looser relation.
RELATION_DEFINITIONS: dict[str, str] = {
    "discovers": "the technique is how the vulnerability was found or identified (not merely exploited)",
    "uses": "the technique is carried out with, or by means of, the tool",
    "causes": "the vulnerability leads to compromise, damage or impact on the asset",
    "mitigated_by": "the mitigation reduces, blocks or fixes the vulnerability",
    "targets": "the technique (or defensive technique) is directed at the asset",
    "used_by": "the group exploited or leveraged the vulnerability in its operations",
}


# Exactly the triple patterns Figure 2 evaluates. Section 3.1.2 also lists
# `reflects` and `solves` in prose, but the paper gives them no pattern and no
# evaluation anywhere, so they are deliberately absent -- see the README.
TRIPLE_PATTERNS: tuple[Pattern, ...] = (
    Pattern("technique", "discovers", "vuln"),
    Pattern("technique", "uses", "tool"),
    Pattern("vuln", "causes", "asset"),
    Pattern("vuln", "mitigated_by", "mitigation"),
    Pattern("technique", "targets", "asset"),
    Pattern("vuln", "used_by", "group"),
    Pattern("defend_technique", "targets", "asset"),
)

# Identifiers that name a node directly, sampled from what `data-preprocessing/`
# actually emits rather than from the paper: CVE-1999-0001, CWE-5, CAPEC-85,
# T1003.008, TA0009, M1036, G1028, S0066, C0028, A0008, AN0001, DC0103, DET0210.
#
# Two things to note. `S####` is shared by `malware` and `tool`, so a match tells
# us the id but *not* the type -- which is why `find_identifiers` returns ids
# only and the caller resolves the label from the graph. And D3FEND is absent on
# purpose: its ids in this graph are CamelCase names (`AccessMediation`), not the
# `D3-PLA` form the paper's Figure 3 shows, and a CamelCase word cannot be told
# from ordinary prose by a regex. Defensive techniques therefore reach their node
# through embedding alignment or not at all.
_IDENTIFIER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    re.compile(r"\bCWE-\d{1,4}\b", re.I),
    re.compile(r"\bCAPEC-\d{1,4}\b", re.I),
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    re.compile(r"\bTA\d{4}\b"),
    re.compile(r"\bM\d{4}\b"),
    re.compile(r"\bG\d{4}\b"),
    re.compile(r"\bS\d{4}\b"),
    re.compile(r"\bC\d{4}\b"),
    re.compile(r"\bA\d{4}\b"),
    re.compile(r"\bAN\d{4}\b"),
    re.compile(r"\bDC\d{4}\b"),
    re.compile(r"\bDET\d{4}\b"),
)

# Words that label a serial number without being part of it, so that "Item 3"
# and "Ref. 44" count as serials while "Exchange Server 2019" does not.
_FILLER_WORDS = frozenset(
    {"no", "nr", "num", "number", "item", "entry", "ref", "reference", "id", "sn", "serial"}
)
_WORDS = re.compile(r"[A-Za-z]+")


def entity_types(genre: str) -> tuple[str, ...]:
    """The types the prompt offers for this genre. Unknown genre is a caller bug."""
    try:
        return ENTITY_TYPES_BY_GENRE[genre]
    except KeyError:
        raise ValueError(
            f"unknown genre {genre!r}; expected one of {', '.join(sorted(GENRES))}"
        ) from None


def patterns_for(genre: str) -> tuple[Pattern, ...]:
    """Triple patterns whose *both* ends are types this genre extracts.

    Derived rather than listed a second time: a pattern naming a type the genre
    never produces could never match anything, and a hand-kept second table is
    one more thing to fall out of step with `ENTITY_TYPES_BY_GENRE`.
    """
    allowed = set(entity_types(genre))
    return tuple(p for p in TRIPLE_PATTERNS if p.source in allowed and p.target in allowed)


def repo_type(paper_type: str) -> str:
    """`technique` -> `attack-technique`. Raises rather than guessing."""
    try:
        return REPO_TYPE[paper_type]
    except KeyError:
        raise ValueError(f"{paper_type!r} is not a type in the unstructured ontology") from None


def repo_label(paper_type: str) -> str:
    """`technique` -> `AttackTechnique`, the label a *new* node of this type gets."""
    try:
        return REPO_LABEL[paper_type]
    except KeyError:
        raise ValueError(f"{paper_type!r} is not a type in the unstructured ontology") from None


def align_labels(paper_type: str) -> tuple[str, ...]:
    """The labels alignment searches for this type. `tool` -> Tool and Malware."""
    try:
        return ALIGN_LABELS[paper_type]
    except KeyError:
        raise ValueError(f"{paper_type!r} is not a type in the unstructured ontology") from None


def paper_type_for_label(label: str) -> str | None:
    """Reverse of `ALIGN_LABELS`: which paper type does a graph label belong to?"""
    for paper_type, labels in ALIGN_LABELS.items():
        if label in labels:
            return paper_type
    return None


def find_identifiers(text: str) -> list[str]:
    """Every standardised identifier in `text`, uppercased, in first-seen order.

    Type is deliberately not inferred -- `S0066` could be malware or a tool, and
    the graph already knows which. The caller looks the id up and adopts
    whatever label it finds.
    """
    seen: dict[str, None] = {}
    for pattern in _IDENTIFIER_PATTERNS:
        for match in pattern.finditer(text):
            seen.setdefault(match.group(0).upper(), None)
    return list(seen)


def is_serial_only(name: str) -> bool:
    """Is this name just a number with decoration -- `SN-4471`, `#12`, `Item 3`?

    Section 3.2.3 drops nodes whose names "only contain serial numbers without
    valid information", but only when they are also isolated, so a false positive
    here is survivable and a false negative merely leaves a dull node in place.

    The hard part is that `CVE-2021-26855` is also mostly digits and is the
    opposite of uninformative -- so a name that parses as a standard identifier
    is never a serial. After that the test is simply whether any meaningful word
    remains once filler is removed.

    Written as a scan rather than one regex on purpose: the obvious pattern
    nests two unbounded character classes and backtracks super-linearly, and
    these names ultimately come from documents we did not write.
    """
    stripped = name.strip()
    if not stripped or not any(character.isdigit() for character in stripped):
        return False
    if find_identifiers(stripped):
        return False
    # Any word that is not filler makes it a name. An earlier version required
    # the surviving letters to exceed three, which dropped `7-Zip` -- a real
    # tool -- as a serial. Keeping a dull node is cheaper than losing a real one.
    return not any(word.lower() not in _FILLER_WORDS for word in _WORDS.findall(stripped))


def all_types() -> Iterable[str]:
    """Every paper-name in the ontology, for prompts and for eval bookkeeping."""
    return REPO_TYPE.keys()
