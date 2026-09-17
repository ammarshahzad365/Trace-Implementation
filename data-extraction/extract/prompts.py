"""The five prompts, each with the JSON Schema that constrains its answer.

Keeping prompt text and schema together is deliberate: they are one contract. A
prompt that asks for a field the schema forbids produces a confusing failure, and
the two drift apart immediately if they live in different files.

The schemas do real work here, not decoration. Ollama constrains decoding to the
schema, so:

- the extraction schema's `type` enum makes a type outside `ontology.py`
  **unrepresentable**, which is what lets the prompt stop policing vocabulary and
  spend its words on telling the types apart instead;
- the relation schema's `source`/`target` enums contain only the entities found
  in that chunk, so a relation cannot name an entity that was never extracted,
  and its `relation` enum is the graph's vocabulary plus `other` -- a known type
  cannot be misspelt into a new one;
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
    GENRES,
    OTHER,
    RELATION_DEFINITIONS,
    TYPE_DEFINITIONS,
    Pattern,
    entity_types,
    patterns_for,
    relation_names,
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


def extraction_schema(genre: str) -> dict[str, Any]:
    """`type` is an enum, so an eighth type cannot be decoded into existence."""
    allowed = list(entity_types(genre)) + [OTHER]
    return {
        "type": "object",
        "properties": {
            "nodes": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": allowed},
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "other_type": {"type": "string"},
                    },
                    "required": ["type", "name", "description"],
                },
            }
        },
        "required": ["nodes"],
    }


# Worked examples as data, so they can be filtered to the genre's own types.
# An example demonstrating a type the schema then forbids teaches the model
# something it cannot do -- which is what happened before this was filtered: an
# APT-report prompt showed `mitigation`, the enum did not allow it, and the
# model dutifully filed a real mitigation under `other`.
_EXAMPLES: tuple[tuple[str, tuple[tuple[str, str, str], ...]], ...] = (
    (
        "The operators deployed China Chopper to maintain access, then used "
        "DLL side-loading to execute their payload against the Exchange server.",
        (
            ("tool", "China Chopper", "Web shell deployed to maintain access"),
            ("technique", "DLL side-loading", "Used to execute the payload"),
            ("asset", "Exchange server", "System targeted by the payload execution"),
        ),
    ),
    (
        "APT41 exploited CVE-2021-26855 to gain initial access. Microsoft "
        "recommends restricting web-based content as a mitigation.",
        (
            ("group", "APT41", "Threat actor exploiting the vulnerability for initial access"),
            ("vuln", "CVE-2021-26855", "Vulnerability exploited to gain initial access"),
            ("mitigation", "Restrict web-based content", "Recommended by Microsoft against this exploitation"),
        ),
    ),
    (
        "Process lineage analysis detects the abuse of elevation control by "
        "comparing parent and child process trees on the affected hosts.",
        (
            ("defend_technique", "Process lineage analysis", "Detects elevation control abuse via process trees"),
            ("technique", "Abuse of elevation control", "Detected by comparing parent and child process trees"),
            ("asset", "Affected hosts", "Where the process trees are compared"),
        ),
    ),
)


def _examples_for(genre: str) -> str:
    """Render the examples, keeping only nodes of types this genre may return."""
    allowed = set(entity_types(genre))
    blocks: list[str] = []
    for text, nodes in _EXAMPLES:
        kept = [(t, n, d) for t, n, d in nodes if t in allowed]
        # An example that would show fewer than two node types teaches little;
        # skip it rather than show a lopsided one.
        if len({t for t, _, _ in kept}) < 2:
            continue
        lines = "\n".join(
            f'  {{"type": "{t}", "name": "{n}", "description": "{d}"}}' for t, n, d in kept
        )
        blocks.append(f'Text: "{text}"\nNodes:\n{lines}')
    return "EXAMPLES\n\n" + "\n\n".join(blocks) + "\n"


def extraction_prompt(
    genre: str, chunk_text: str, reference_nodes: Sequence[dict] = ()
) -> tuple[str, str]:
    """Type definitions, worked examples, retrieved neighbours, then the text."""
    types = entity_types(genre)
    definitions = "\n".join(f"  {name}: {TYPE_DEFINITIONS[name]}" for name in types)

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
        f"ENTITY TYPES -- use only these:\n{definitions}\n"
        f"  {OTHER}: something clearly important that fits none of the types above; "
        f"put what you would call it in 'other_type'\n\n"
        "RULES\n"
        "  - Extract only entities the text actually names.\n"
        "  - Use the text's own name for each entity. Do not expand, translate or "
        "normalise it.\n"
        "  - The description must say what this text says about the entity, in one "
        "sentence. Do not add knowledge from elsewhere.\n"
        "  - A tool is a thing that is used. A technique is a thing that is done. "
        "Sort them by that question alone.\n"
        "  - Skip anything named only by a number with no meaning.\n\n"
        f"{_examples_for(genre)}"
        f"{reference}\n"
        f"TEXT\n{chunk_text}"
    )
    return _SYSTEM, user


# --------------------------------------------------------------------------
# 3. Step two, first half: which relations does the text state, and of what
#    type? (section 3.2.2, with the graph's vocabulary rather than seven patterns)
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


def relation_prompt(
    genre: str, entities: Sequence[tuple[str, str, str]], chunk_text: str
) -> tuple[str, str]:
    """Propose relations among the entities of one chunk.

    `entities` is (label, paper type, description). The label is what the
    schema's enums use, so it must be unique per entity -- the caller makes it
    `name (type)`.

    The vocabulary offered is `ontology.relation_names()` -- the graph's
    relations between extractable types plus the paper's -- and `other` as the
    route for anything it cannot express, with the rule that an existing type
    wins whenever its definition genuinely fits. That is the user's decision of
    2026-09-11: resolve into what the graph already says before adding to what
    it can say. Offering the catalogs' other 26 relations as well was tried and
    measured; see `ontology.CATALOG_RELATIONS` for why they are not here.
    """
    listed = "\n".join(
        f"  {label} -- {paper_type}: {description}" if description else f"  {label} -- {paper_type}"
        for label, paper_type, description in entities
    )
    offered = "\n".join(f"  {name}: {RELATION_DEFINITIONS[name]}" for name in relation_names())
    typical = "; ".join(
        f"{p.source} --{p.relation}--> {p.target}" for p in patterns_for(genre)
    )
    user = (
        f"Find every relationship that THIS TEXT states between the entities below. "
        f"The text is an excerpt of {GENRES[genre]}.\n\n"
        f"ENTITIES FOUND IN THIS TEXT (use these labels exactly)\n{listed}\n\n"
        f"RELATION TYPES the knowledge graph already uses. Copy one of these names exactly "
        f"whenever its definition genuinely describes the relationship:\n{offered}\n"
        f"  Typical directions: {typical}\n\n"
        "  If the text states a relationship that none of the types above describes -- for "
        "example two tools that share code, are bundled together, or one succeeds another -- "
        "write a NEW short lowercase snake_case name as the relation (shares_code_with, "
        "successor_of, bundled_with, communicates_with, ...). Do not stretch an existing "
        "type to avoid this: a relationship with the wrong type is worse than a new type.\n\n"
        "RULES\n"
        "  - Report only relationships the text states. Quote the sentence in 'evidence'; "
        "it must mention both entities.\n"
        "  - Two entities in the same sentence is not a relationship. The text must connect them.\n"
        "  - Direction matters: 'source' is the subject of the relation as defined above "
        "('source' used_by 'target' means the vulnerability is the source and the group the target).\n"
        "  - An asset (a device, system, product or organisation) is never 'used'. Something "
        "attacked, exploited or compromised is 'targets'.\n"
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
