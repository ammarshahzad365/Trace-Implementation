"""The vocabulary an LLM is allowed to use, and how it maps onto this graph.

Two lists live here, and they are closed to different degrees.

**Entity types** are closed: the types TRACE tailors per genre (section 3.1.1),
plus `other` as an escape that is reported and never written. The reasons are
below. **Relation types** are the graph's own vocabulary -- every relationship
type the structured catalogs loaded, measured on the live graph, plus the seven
patterns of Figure 2 -- with a proposed new name allowed only when nothing in
that vocabulary expresses what the text says. New names *are* written. The
model is told to resolve into an existing type first, and the pipeline records
which relations came out as new so the cost of the vocabulary is a number in
every proposal, not a guess.

This module is that schema, in one place, because three stages need to agree
on it -- the extraction prompt offers these types, relation extraction offers
these relations, and alignment searches within one of these types.

## Why the entity list is closed

The prompt is limited; `POST /ingest` is not, and stays exactly as open as
`ingest/serve.py` says it is. The limit exists for three reasons:

1. **Alignment only works within a type.** It compares against the top-20 nodes
   *of the same type*. If the model is free to invent type names, one threat
   actor arrives as `group`, `threat-actor` and `apt-group` from three reports,
   lands in three separate search spaces, and alignment never fires -- producing
   exactly the duplicates alignment exists to prevent.
2. **Per-type F1 needs a closed set.** Table 4's macro-F1 averages F1 per entity
   type; an open set makes the paper's own metric uncomputable.
3. **Types are where the graph's labels come from.** A type the loader has never
   seen becomes a label with no index and no existing nodes to join.

`OTHER` is the escape hatch: a model may say "this is something else, and here
is what I would call it". Those are reported and **not** written, which turns
"what does the fixed ontology miss?" into a number instead of a worry.

## Why the relation list is the graph's, not just the paper's

The paper's seven patterns (Figure 2) have no `group uses tool`, yet "Volt
Typhoon uses Mimikatz" is the commonest sentence in an APT report -- and the
graph already holds 1,159 such edges from ATT&CK (`USES` IntrusionSet -> Tool /
Malware). Restricting extracted text to seven patterns would make a report say
less than the catalog it sits next to. So the offered vocabulary is what the
graph holds, the paper's seven added, and a new name permitted only as a last
resort -- decided 2026-09-11.

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


# What each relation means, in the prompts' words, with the direction. The paper
# leaves its own undefined, and an undefined `discovers` got confirmed on the
# evidence "the group exploited CVE-2021-26855" -- exploiting is not discovering.
#
# Two groups. `REPORT_RELATIONS` are the ones whose both ends are types the
# extractor produces: the paper's six names plus the graph's relations between
# extractable types. These are offered to the model. `CATALOG_RELATIONS` are
# the rest of what the structured sources loaded: relations between weaknesses,
# artifacts, analytics, platforms -- node types the extractor never emits, so
# between extracted entities they can never be right. They were offered at
# first, with a warning, because the user wanted the whole vocabulary
# available; measured on a tool-lineage text the model used `has_analytic`
# three times for tool -> tool (verification rejected all three) and proposed
# no new name at all. An enum entry that cannot be correct is a distractor, so
# they are known to the pipeline -- `is_known_relation`, and a proposed name
# that equals one is that one -- but not offered. The day the entity types
# grow to include, say, weaknesses, the graph patterns below are where the
# corresponding relations get promoted. Definitions follow each source's own
# meaning (CWE, CAPEC, ATT&CK, D3FEND). Measured on the live graph 2026-09-11
# with `MATCH (a)-[r]->(b) RETURN type(r), labels(a)[0], labels(b)[0]`.
REPORT_RELATIONS: dict[str, str] = {
    # The paper's six (seven patterns; `targets` appears twice).
    "discovers": "the technique is how the vulnerability was found or identified (not merely exploited)",
    "uses": "the subject makes use of the object as an instrument: a group uses a tool or a technique; a tool carries out a technique; a technique is performed with a tool. Never for an asset -- a device or system that is attacked or compromised is 'targets'",
    "causes": "the vulnerability leads to compromise, damage or impact on the asset",
    "mitigated_by": "the mitigation reduces, blocks or fixes the vulnerability",
    "targets": "the technique, defensive technique or group is directed at, attacks or compromises the asset",
    "used_by": "the group exploited or leveraged the vulnerability in its operations",
    # The graph's, between extractable types.
    "mitigates": "the mitigation reduces or blocks the attack technique",
    "counters": "the defensive technique counters or defeats the attack technique",
    "subtechnique_of": "the technique is a more specific form of the parent technique",
    "attributed_to": "the activity or campaign is attributed to the group",
    "detects": "the defensive technique or detection method detects the attack technique",
}

CATALOG_RELATIONS: dict[str, str] = {
    # ATT&CK
    "has_tactic": "the technique serves the tactic (its goal, e.g. initial access, persistence)",
    "revoked_by": "the catalog entry was retired and replaced by the other (ATT&CK bookkeeping)",
    "accesses": "the attack technique accesses the artifact (a file, process, credential, network traffic ...)",
    "creates": "the attack technique creates the artifact",
    "executes": "the attack technique executes the artifact",
    "modifies": "the attack technique modifies the artifact",
    # D3FEND
    "hardens": "the defensive technique hardens the artifact",
    "observes": "the defensive technique observes or monitors the artifact",
    "constrains": "the defensive technique constrains or restricts the artifact",
    "restores": "the defensive technique restores the artifact",
    "enables": "the defensive technique enables the defensive tactic",
    "has_analytic": "the detection strategy is made up of the analytic",
    "uses_data_component": "the analytic reads the data component (a log, a sensor ...)",
    "weakness_of": "the weakness is a weakness of the artifact",
    # CWE / CAPEC
    "child_of": "the weakness, attack pattern or artifact is a more specific form of the other",
    "peer_of": "the two weaknesses or attack patterns are peers",
    "can_precede": "the weakness or attack pattern can come before the other in a chain",
    "can_also_be": "the weakness can also be classified as the other weakness",
    "requires": "the weakness requires the other weakness to be present",
    "starts_with": "the weakness chain starts with the other weakness",
    "has_consequence": "the weakness leads to the consequence (e.g. denial of service)",
    "has_detection_method": "the weakness can be found by the detection method",
    "has_mitigation": "the weakness is reduced by the mitigation",
    "has_observed_example": "the weakness has the vulnerability as a real observed example",
    "has_member": "the category or view contains the weakness",
    "applies_to_platform": "the weakness applies to the platform (a language, OS or technology)",
}

# Also in the graph and also not offered, for a sharper reason than the
# catalog ones: NVD's `related_to` *does* sit between an extractable type and
# a weakness, and it is a cross-reference, not a statement. Offered, it became
# the fallback for everything -- "shares code with" and "bundled with" both
# came back as `related_to` -- which is exactly the outcome the `other` route
# exists to prevent.
UNOFFERED_RELATIONS: dict[str, str] = {
    "related_to": "the catalogs' generic cross-reference; never produced from text",
}

RELATION_DEFINITIONS: dict[str, str] = {
    **REPORT_RELATIONS,
    **CATALOG_RELATIONS,
    **UNOFFERED_RELATIONS,
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

# The graph's own patterns between extractable types, as loaded from ATT&CK and
# D3FEND. Shown to the model as the typical direction of each relation; not
# enforced, because the user chose an open relation vocabulary and the
# verification step judges each relation on the text anyway.
GRAPH_PATTERNS: tuple[Pattern, ...] = (
    Pattern("group", "uses", "tool"),
    Pattern("group", "uses", "technique"),
    Pattern("tool", "uses", "technique"),
    Pattern("mitigation", "mitigates", "technique"),
    Pattern("defend_technique", "counters", "technique"),
    Pattern("technique", "subtechnique_of", "technique"),
    Pattern("technique", "targets", "asset"),
)

# A proposed relation name the writer will accept as a Neo4j relationship type
# once uppercased: snake_case, letters and digits, sensible length.
_RELATION_NAME = re.compile(r"^[a-z][a-z0-9_]{1,40}$")

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
    """The paper's and the graph's patterns whose *both* ends this genre extracts.

    Derived rather than listed a second time: a pattern naming a type the genre
    never produces could never match anything, and a hand-kept second table is
    one more thing to fall out of step with `ENTITY_TYPES_BY_GENRE`. Shown to
    the model as the typical direction of each relation.
    """
    allowed = set(entity_types(genre))
    seen: dict[Pattern, None] = {}
    for pattern in (*TRIPLE_PATTERNS, *GRAPH_PATTERNS):
        if pattern.source in allowed and pattern.target in allowed:
            seen.setdefault(pattern, None)
    return tuple(seen)


def relation_names() -> tuple[str, ...]:
    """Every relation the model may pick by name -- see `REPORT_RELATIONS`."""
    return tuple(REPORT_RELATIONS)


def orient(source_type: str, relation: str, target_type: str) -> tuple[bool, str]:
    """Does a known pattern fix this relation's direction and name?

    Returns (swap, relation). The schema, not the model, owns direction:
    `used_by` is vuln -> group, and a model that returns `APT41 used_by
    CVE-2021-44228` has the fact right and the arrow wrong (measured once in
    three test documents). When the reversed pair is a known pattern and the
    given one is not, swap. Two retypings on top, because the definitions say
    so and the model did not always listen: `uses` with an asset as object is
    `targets` ("Volt Typhoon uses Fortinet devices" survived two prompt
    rules), and `uses` with a vulnerability as object is `used_by` the other
    way round -- the ProxyLogon test returned both `HAFNIUM uses CVE-…` and
    `CVE-… used_by HAFNIUM` for one sentence, which is one fact under two
    names until this folds them.
    """
    if relation == "uses" and target_type == "asset":
        relation = "targets"
    if relation == "uses" and target_type == "vuln" and source_type == "group":
        return True, "used_by"
    patterns = {*TRIPLE_PATTERNS, *GRAPH_PATTERNS}
    forward = Pattern(source_type, relation, target_type) in patterns
    backward = Pattern(target_type, relation, source_type) in patterns
    return (backward and not forward), relation


def normalise_relation(name: str) -> str | None:
    """`Exfiltrates To` -> `exfiltrates_to`; None if nothing usable remains.

    A proposed name reaches Neo4j as a relationship type (uppercased by the
    writer), so it must be an identifier. Anything else -- an empty string, a
    sentence, punctuation -- is refused here rather than written as a type
    nobody will ever query.
    """
    cleaned = re.sub(r"[^a-z0-9]+", "_", name.strip().lower()).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned if _RELATION_NAME.match(cleaned) else None


def is_known_relation(name: str) -> bool:
    return name in RELATION_DEFINITIONS


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
