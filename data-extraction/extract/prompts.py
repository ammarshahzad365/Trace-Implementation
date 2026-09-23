"""The five prompts, each with the JSON Schema that constrains its answer.

Keeping prompt text and schema together is deliberate: they are one contract. A
prompt that asks for a field the schema forbids produces a confusing failure, and
the two drift apart immediately if they live in different files.

The schemas do real work here, not decoration. Ollama constrains decoding to the
schema, so:

- the extraction and relation schemas leave `type` and `relation` as free
  strings on purpose -- `ontology.py` explains why an enum with an `other`
  escape does not work under constrained decoding -- and the code
  canonicalises the names afterwards;
- the relation schema's `source`/`target` enums contain only the entities found
  in that chunk, so a relation cannot name an entity that was never extracted;
- the alignment schema's `match_id` enum contains only the candidate ids that
  were actually shown, so the judge cannot hallucinate a node id -- the one
  failure that would silently point an edge at the wrong entity.

## On the few-shot examples

Section 3.2.2 attributes the paper's 7.8% margin over the baselines to few-shot
plus RAG, so the examples are not filler. They are chosen to teach the one
distinction the paper names as its own biggest error source (Limitations): a
**tool** is a thing you use, a **technique** is a thing you do. Every example
below contains one of each, in a sentence where confusing them is tempting.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from .ontology import (
    ENTITY_GROUPS,
    GENRES,
    RELATION_DEFINITIONS,
    RELATION_GROUPS,
    Pattern,
    typical_patterns,
)

_SYSTEM = (
    "You are a careful cybersecurity analyst building a knowledge graph. "
    "You extract only what the text actually states. You never guess, never "
    "infer from background knowledge, and never invent identifiers. If the text "
    "does not say something, it is not there."
)


# --------------------------------------------------------------------------
# 1. Is this paper about security at all? (section 3.2.2)
# --------------------------------------------------------------------------

RELEVANCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "relevant": {"type": "boolean"},
        "reason": {"type": "string"},
    },
    "required": ["relevant", "reason"],
}


def relevance_prompt(title: str, abstract: str) -> tuple[str, str]:
    """Binary classifier over title and abstract only -- the paper's screen.

    Only papers get this. APT reports and repair notices are security documents
    by construction (section 3.2.2 says they "are sourced from annual disclosures
    and periodic product updates"), so paying a model call to confirm it would be
    a tax on every document to catch nothing.
    """
    user = (
        "Decide whether this paper contains extractable cybersecurity knowledge: "
        "concrete attack techniques, vulnerabilities, tools, threat actors, "
        "assets or defensive measures.\n\n"
        "Answer true for offensive or defensive security research. Answer false "
        "for papers that merely mention security in passing, and for work in "
        "other fields.\n\n"
        f"TITLE: {title}\n\nABSTRACT: {abstract}"
    )
    return _SYSTEM, user


# --------------------------------------------------------------------------
# 2. Step one: find the candidate nodes (section 3.2.2)
# --------------------------------------------------------------------------


def extraction_schema() -> dict[str, Any]:
    """`type` is a free string on purpose -- see `ontology` on why not an enum.
    `pipeline._extract_nodes` canonicalises it: an offered name or alias
    becomes that type, anything else becomes a new type."""
    return {
        "type": "object",
        "properties": {
            "nodes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                    },
                    "required": ["type", "name", "description"],
                },
            }
        },
        "required": ["nodes"],
    }


# Worked examples. Each teaches a distinction the model gets wrong without it:
# a tool is a thing you use, a technique is a thing you do (the paper's own
# biggest error source); a victim organisation is an identity, not an asset;
# an address the malware talks to is infrastructure, not a tool.
_EXAMPLES: tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...] = (
    (
        "The operators deployed China Chopper to maintain access, then used "
        "DLL side-loading to execute their payload against the Exchange server.",
        (
            ("malware", "China Chopper", "Web shell deployed to maintain access"),
            ("attack-technique", "DLL side-loading", "Used to execute the payload"),
            ("asset", "Exchange server", "System targeted by the payload execution"),
        ),
    ),
    (
        "APT41 exploited CVE-2021-26855 against law firms in the region. Microsoft "
        "recommends restricting web-based content as a mitigation.",
        (
            ("intrusion-set", "APT41", "Threat group exploiting the vulnerability for initial access"),
            ("vulnerability", "CVE-2021-26855", "Vulnerability exploited to gain initial access"),
            ("identity", "law firms", "Victim organisations targeted in the region"),
            ("course-of-action", "Restrict web-based content", "Recommended by Microsoft against this exploitation"),
        ),
    ),
    (
        "The implant beacons to 45.77.12.9 over HTTPS and drops a second stage, "
        "svchost.exe, signed with a stolen certificate.",
        (
            ("ipv4-addr", "45.77.12.9", "Command-and-control address the implant beacons to"),
            ("file", "svchost.exe", "Second-stage payload dropped by the implant"),
            ("x509-certificate", "stolen certificate", "Used to sign the second stage"),
        ),
    ),
    (
        "Process lineage analysis detects the abuse of elevation control by "
        "comparing parent and child process trees on the affected hosts.",
        (
            ("defensive-technique", "Process lineage analysis", "Detects elevation control abuse via process trees"),
            ("attack-technique", "Abuse of elevation control", "Detected by comparing parent and child process trees"),
            ("asset", "Affected hosts", "Where the process trees are compared"),
        ),
    ),
)


def _examples() -> str:
    blocks: list[str] = []
    for text, nodes in _EXAMPLES:
        lines = "\n".join(
            f'  {{"type": "{t}", "name": "{n}", "description": "{d}"}}' for t, n, d in nodes
        )
        blocks.append(f'Text: "{text}"\nNodes:\n{lines}')
    return "EXAMPLES\n\n" + "\n\n".join(blocks) + "\n"


def _type_catalogue() -> str:
    return "\n".join(
        f"  {heading}:\n"
        + "\n".join(f"    {entity.name}: {entity.definition}" for entity in group)
        for heading, group in ENTITY_GROUPS
    )


def extraction_prompt(
    genre: str, chunk_text: str, reference_nodes: Sequence[dict] = ()
) -> tuple[str, str]:
    """Type catalogue, worked examples, retrieved neighbours, then the text.

    The catalogue is every type the graph or STIX knows, grouped with the
    common ones first, and the rule that a new type is written only when none
    of them describes the thing. Decided 2026-09-17; the paper's closed list
    of five to six per genre is `ontology.PAPER_TYPES`, kept for scoring.
    """
    reference = ""
    if reference_nodes:
        # The RAG half of section 3.2.2: show how this project already names
        # things, so the model reuses an existing spelling instead of coining a
        # near-duplicate that alignment then has to repair.
        listed = "\n".join(
            f"  {node['type']}: {node['name']}" for node in reference_nodes
        )
        reference = (
            "\nENTITIES ALREADY IN THE KNOWLEDGE GRAPH, related to this text. "
            "If the text refers to one of these, use its exact name:\n"
            f"{listed}\n"
        )

    user = (
        f"Extract cybersecurity entities from this excerpt of {GENRES[genre]}.\n\n"
        f"ENTITY TYPES. Copy the type name exactly as written here:\n{_type_catalogue()}\n\n"
        "  If the text names something clearly important that NONE of these types "
        "describes, write a new short lowercase type name with hyphens (for example "
        "victim-sector, cryptocurrency-wallet). Use an existing type whenever its "
        "definition fits; do not invent a type for a synonym of one.\n\n"
        "RULES\n"
        "  - Extract only entities the text actually names.\n"
        "  - Use the text's own name for each entity. Do not expand, translate or "
        "normalise it.\n"
        "  - The description must say what this text says about the entity, in one "
        "sentence. Do not add knowledge from elsewhere.\n"
        "  - A tool or malware is a thing that is used. A technique is a thing that is "
        "done. Sort them by that question alone.\n"
        "  - A victim organisation or sector is an identity; the machine attacked is an "
        "asset; an address or server the attacker operates is infrastructure.\n"
        "  - Skip anything named only by a number with no meaning.\n\n"
        f"{_examples()}"
        f"{reference}\n"
        f"TEXT\n{chunk_text}"
    )
    return _SYSTEM, user


# --------------------------------------------------------------------------
# 3. Step two, first half: which relations does the text state, and of what
#    type? (section 3.2.2, with the graph's and STIX's vocabulary)
# --------------------------------------------------------------------------


def relation_schema(entity_labels: Sequence[str]) -> dict[str, Any]:
    """`source`/`target` are enums of the entities shown, so a relation cannot
    name something never extracted. `relation` is a free string on purpose.

    It was an enum of the vocabulary plus `other` first, and under constrained
    decoding the model never once chose `other`: for two tools that share code
    it tried `uses`, `subtechnique_of` and `targets` in turn rather than reach
    the escape value. A free string lets it copy a known name or write a new
    one in the same breath; `ontology.normalise_relation` then folds case and
    punctuation, and whatever is not a known name is new. The prompt carries
    the vocabulary; the code does the canonicalising the enum used to do.
    """
    return {
        "type": "object",
        "properties": {
            "relations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "source": {"enum": list(entity_labels)},
                        "relation": {"type": "string"},
                        "target": {"enum": list(entity_labels)},
                        "evidence": {"type": "string"},
                    },
                    "required": ["source", "relation", "target", "evidence"],
                },
            }
        },
        "required": ["relations"],
    }


def _relation_catalogue() -> str:
    return "\n".join(
        f"  {heading}:\n"
        + "\n".join(f"    {name}: {meaning}" for name, meaning in group.items())
        for heading, group in RELATION_GROUPS
    )


def relation_prompt(
    genre: str, entities: Sequence[tuple[str, str, str]], chunk_text: str
) -> tuple[str, str]:
    """Propose relations among the entities of one chunk.

    `entities` is (label, type, description). The label is what the schema's
    enums use, so it must be unique per entity -- the caller makes it
    `name (type)`.

    The vocabulary is every relation the graph holds and every STIX 2.1
    relationship, grouped with the common ones first, and the rule that an
    existing name wins whenever its definition genuinely fits. Typical directions are shown only for the types present in this
    chunk, because the full table is 185 rows.
    """
    listed = "\n".join(
        f"  {label} -- {type_name}: {description}" if description else f"  {label} -- {type_name}"
        for label, type_name, description in entities
    )
    present = {type_name for _, type_name, _ in entities}
    typical = "; ".join(
        f"{p.source} --{p.relation}--> {p.target}"
        for p in typical_patterns()
        if p.source in present and p.target in present
    )
    user = (
        f"Find every relationship that THIS TEXT states between the entities below. "
        f"The text is an excerpt of {GENRES[genre]}.\n\n"
        f"ENTITIES FOUND IN THIS TEXT (use these labels exactly)\n{listed}\n\n"
        f"RELATION TYPES. Copy one of these names exactly whenever its definition "
        f"genuinely describes the relationship:\n{_relation_catalogue()}\n"
        + (f"  Typical directions for the types present: {typical}\n\n" if typical else "\n")
        + "  If the text states a relationship that none of the types above describes -- for "
        "example two tools that share code, are bundled together, or one succeeds another -- "
        "write a NEW short lowercase snake_case name as the relation (shares_code_with, "
        "successor_of, bundled_with, ...). Do not stretch an existing type to avoid this: "
        "a relationship with the wrong type is worse than a new type.\n\n"
        "RULES\n"
        "  - Report only relationships the text states. Quote the sentence in 'evidence'; "
        "it must mention both entities.\n"
        "  - Two entities in the same sentence is not a relationship. The text must connect them.\n"
        "  - Direction matters: 'source' is the subject of the relation as defined above "
        "('source' beacons_to 'target' means the malware is the source and the server the target).\n"
        "  - A victim system, organisation or place is never 'used'. Something attacked, "
        "exploited or compromised is 'targets'.\n"
        "  - One relationship per pair and type; do not repeat.\n"
        "  - If the text states nothing between these entities, return an empty list.\n\n"
        f"TEXT\n{chunk_text}"
    )
    return _SYSTEM, user


# --------------------------------------------------------------------------
# 4. Step two, second half: does the text state this relation? (section 3.2.2)
# --------------------------------------------------------------------------

VALIDATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "holds": {"type": "boolean"},
                    "evidence": {"type": "string"},
                },
                "required": ["index", "holds", "evidence"],
            },
        }
    },
    "required": ["results"],
}


def validation_prompt(
    candidates: Sequence[tuple[int, str, Pattern, str]],
    context: str,
    descriptions: dict[str, str] | None = None,
) -> tuple[str, str]:
    """Judge a batch of candidate triples against the text that produced them.

    Batched rather than one call per pair because the pair count grows with the
    square of the node count, and the context is identical for every pair in a
    chunk -- sending it once per pair would be the dominant cost of the whole
    pipeline.

    `candidates` is (index, source name, pattern, target name). `descriptions`
    maps a name to what the extractor said about it, and is shown beside each
    name: a technique the model itself paraphrased as "Network proxy" means
    nothing on its own, and without the description the model confirmed
    "Network proxy uses Mimikatz" on a sentence about credential dumping --
    because the actor does use Mimikatz, somewhere. The description is what
    ties the relation to *this* technique rather than to the actor in general.
    """
    descriptions = descriptions or {}

    def show(name: str) -> str:
        detail = descriptions.get(name, "").strip()
        return f"{name} ({detail})" if detail else name

    listed = "\n".join(
        f"  {index}. {show(source)} --[{pattern.relation}]--> {show(target)}"
        for index, source, pattern, target in candidates
    )
    used = sorted({pattern.relation for _, _, pattern, _ in candidates})
    # A name outside the vocabulary was proposed by the model itself in the
    # first half of step two; the judge sees it flagged as such and takes its
    # meaning from the words.
    meanings = "\n".join(
        f"  {relation}: "
        + RELATION_DEFINITIONS.get(
            relation, "a new relation proposed for this document; judge it by its plain meaning"
        )
        for relation in used
    )
    user = (
        "For each candidate relationship below, decide whether THIS TEXT states "
        "it. Answer for every candidate, using its number.\n\n"
        f"WHAT THE RELATIONS MEAN\n{meanings}\n\n"
        "  holds = true only if the text asserts this relationship. Quote the "
        "sentence that says so in 'evidence'. The quoted sentence must name "
        "both entities; a sentence about only one of them is not evidence.\n"
        "  holds = false if the text does not say it, even when you believe it is "
        "true in reality. Leave 'evidence' empty.\n\n"
        "Two entities appearing in the same sentence is not a relationship. The "
        "text must actually connect them. And the relationship must hold for the "
        "entity as described in brackets: that the actor uses a tool somewhere in "
        "the document does not mean every technique uses it.\n\n"
        f"CANDIDATES\n{listed}\n\n"
        f"TEXT\n{context}"
    )
    return _SYSTEM, user


# --------------------------------------------------------------------------
# 5. Are these the same real-world entity? (section 5.2.2)
# --------------------------------------------------------------------------


def alignment_schema(candidate_ids: Sequence[str]) -> dict[str, Any]:
    """`match_id` is an enum of the offered ids plus null -- nothing else fits."""
    return {
        "type": "object",
        "properties": {
            "match_id": {"enum": [*candidate_ids, None]},
            "reason": {"type": "string"},
        },
        "required": ["match_id", "reason"],
    }


def alignment_prompt(
    *, name: str, entity_type: str, description: str, candidates: Sequence[dict]
) -> tuple[str, str]:
    """Zero-shot, as section 5.2.2 specifies, over candidates already above theta.

    The model is the *second* filter, not the first. Everything it sees has
    already passed a similarity threshold, so the question is narrow: of these
    few, which one is the same thing, if any.
    """
    listed = "\n".join(
        f"  id: {candidate['id']}\n  name: {candidate['name']}\n"
        f"  description: {candidate.get('description', '') or '(none)'}\n"
        for candidate in candidates
    )
    user = (
        "Does the new entity refer to the same real-world thing as one of the "
        "existing entities?\n\n"
        "Threat actors, malware and tools are often known by several names, so "
        "different names can still be the same entity. But a different tool or "
        "group that merely has a similar purpose is NOT the same entity, and "
        "neither are versions, variants or family members. Match on what the new "
        "entity IS, not on what its description mentions: a tool described as "
        "'bundled with X' or 'used alongside X' is not X. If none matches, "
        "answer null -- a wrong match is worse than a missed one, because it "
        "merges two things that are not the same.\n\n"
        f"NEW ENTITY\n  type: {entity_type}\n  name: {name}\n"
        f"  description: {description or '(none)'}\n\n"
        f"EXISTING ENTITIES OF THE SAME TYPE\n{listed}"
    )
    return _SYSTEM, user


def compact(value: object) -> str:
    """Small helper for putting structures in prompts without pretty-print noise."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
