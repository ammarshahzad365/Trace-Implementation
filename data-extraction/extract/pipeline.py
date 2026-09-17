"""The whole of Algorithm 1 lines 8-17, for one document.

    cleanse -> screen -> (relevance) -> chunk -> extract nodes -> validate
    relations -> filter -> standardise -> align -> proposal

The output is a **proposal**, not a write. Every model decision it contains is
visible before anything reaches the graph -- which entity matched what and at
what similarity, which relation survived validation and on what sentence, what
was dropped, and what the fixed ontology could not place. `jobs.py` stores it and
`api.py` serves it; committing is a separate, explicit call.

## Two-step extraction (section 3.2.2)

Step one asks *what entities are here*. Step two has two halves: the model is
shown the entities of a chunk and the graph's relation vocabulary and asked
which relations the text states between them -- an existing type if one fits,
a proposed name only if none does -- and then every proposed relation goes back
to the model in a separate call asking whether the text actually states it,
with the sentence demanded as evidence. Splitting it this way is the paper's
design and it matters: a model asked for entities and relations in a single
breath will cheerfully assert a relation because it is true in the world, not
because the document said it. Asking separately, with the sentence demanded as
evidence, is what makes the edges traceable.

Before 2026-09-11 the first half was not a model call at all: the code formed
every pair that fit one of the paper's seven patterns. That made `group uses
tool` -- the commonest statement in an APT report, and 1,159 edges in the graph
already -- unrepresentable. The vocabulary is now the graph's; see ontology.py.

## Where the cost goes

One proposal call per chunk, then verification batched ten relations to a
request, grouped by chunk so the context is sent once. The verification pass is
what keeps the wider vocabulary honest: opening what a relation may be *called*
does not loosen what counts as evidence for it.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Callable, Sequence

from neo4j import Session

from . import align, chunking, cleanse, graph, llm, ontology, prompts
from .align import Candidate
from .config import Settings

_NAMESPACE = uuid.NAMESPACE_URL
VALIDATION_BATCH = 10

Progress = Callable[[str], None]


class Irrelevant(Exception):
    """A paper the relevance classifier rejected. Not an error -- an outcome."""


@dataclass
class Proposal:
    """What the pipeline produced, ready for review and then for `POST /ingest`."""

    entities: list[dict] = field(default_factory=list)
    relationships: list[dict] = field(default_factory=list)
    aligned: list[dict] = field(default_factory=list)
    near_misses: list[dict] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)
    new_types: list[dict] = field(default_factory=list)
    new_relations: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "entities": self.entities,
            "relationships": self.relationships,
            "aligned": self.aligned,
            "near_misses": self.near_misses,
            "dropped": self.dropped,
            "new_types": self.new_types,
            "new_relations": self.new_relations,
            "stats": self.stats,
        }


def _extract_nodes(
    cfg: Settings, genre: str, chunk: chunking.Chunk, reference: Sequence[dict]
) -> list[Candidate]:
    """The model writes a type name; `ontology.normalise_type` makes it an
    offered type (directly or through an alias) or a new one. A name that
    normalises to nothing usable is dropped with the node."""
    system, user = prompts.extraction_prompt(genre, chunk.text, reference)
    answer = llm.chat_json(
        cfg, system=system, user=user, schema=prompts.extraction_schema()
    )
    found: list[Candidate] = []
    for node in answer.get("nodes", []):
        name = str(node.get("name", "")).strip()
        type_name = ontology.normalise_type(str(node.get("type", "")))
        if not name or type_name is None:
            continue
        # A node named by its own type word -- "campaign", "the actor" -- is
        # the model labelling a mention it could not name; it carries no
        # identity, and once aligned it lands on whichever real campaign the
        # embedding likes (measured: "campaign" -> "Indian Critical
        # Infrastructure Intrusions" at 0.55).
        if ontology.normalise_type(name) in (type_name, ontology.repo_type(type_name)):
            continue
        found.append(
            Candidate(
                paper_type=type_name,
                name=name,
                description=str(node.get("description", "")).strip(),
            )
        )
    return found


def _identifier_candidates(handle: Session, text: str) -> list[Candidate]:
    """Entities named by a standard identifier, whether or not the model saw them.

    Section 3.2.2's "target regularization": `CVE-2021-26855` is unambiguous, so
    a regex is strictly better than a model at finding it. The graph supplies the
    type, because `S0066` could be malware or a tool and only the graph knows.

    Every label the graph holds now maps to an offered type, so a `CWE-79`
    landing on `Weakness` is a candidate like any other; the skip below is for
    a label this module has never heard of.
    """
    identifiers = ontology.find_identifiers(text)
    if not identifiers:
        return []
    found: list[Candidate] = []
    for node in graph.lookup(handle, identifiers).values():
        paper_type = ontology.paper_type_for_label(node.get("label"))
        if not paper_type:
            continue
        found.append(
            Candidate(
                paper_type=paper_type,
                name=node["id"],
                description=node.get("description") or node.get("name") or "",
            )
        )
    return found


def _retrieve_reference(
    cfg: Settings,
    handle: Session,
    chunk_text: str,
    genre: str,
    indexes: dict[str, int],
    seeds: Sequence[Candidate],
    *,
    per_type: int = 3,
) -> list[dict]:
    """Section 3.2.2's retrieval repository: what this graph already calls things.

    Identifier hits are the precise part. The rest is the chunk embedded once
    and searched against each of the genre's labels, so that a passage about
    "the Hafnium group" is shown `HAFNIUM` before the model names it -- the
    cheapest possible nudge toward the spelling alignment will later have to
    match. Loose on purpose: the prompt says "if the text refers to one of
    these", so an irrelevant neighbour costs a few tokens and nothing else.
    """
    reference = [{"type": seed.paper_type, "name": seed.name} for seed in seeds]
    # Each indexed label once, under the type it primarily belongs to; with
    # every graph label now offerable that is ~20 small vector queries per
    # chunk. `genre` no longer narrows the types.
    searchable: list[tuple[str, str]] = []
    seen_labels: set[str] = set()
    for paper_type in ontology.entity_types():
        for label in ontology.align_labels(paper_type):
            if label in seen_labels or graph.index_name(label) not in indexes:
                continue
            if ontology.paper_type_for_label(label) != paper_type:
                continue
            seen_labels.add(label)
            searchable.append((paper_type, label))
    if not searchable:
        return reference
    vector = llm.embed(cfg, [chunk_text[:2000]])[0]
    seen = {(row["type"], row["name"]) for row in reference}
    for paper_type, label in searchable:
        for row in graph.similar(handle, label, vector, k=per_type):
            entry = (paper_type, row["name"])
            if row["name"] and entry not in seen:
                seen.add(entry)
                reference.append({"type": paper_type, "name": row["name"]})
    return reference


def _merge(candidates: Sequence[Candidate]) -> dict[str, Candidate]:
    """Collapse repeats across chunks, keeping the richest description.

    The same entity named in four chunks must be aligned once, not four times --
    both to save three model calls and because four separate alignments could
    disagree with each other.
    """
    merged: dict[str, Candidate] = {}
    for candidate in candidates:
        existing = merged.get(candidate.key)
        if existing is None:
            merged[candidate.key] = candidate
        elif len(candidate.description) > len(existing.description):
            existing.description = candidate.description
    return merged


def _propose_relations(
    cfg: Settings,
    genre: str,
    per_chunk: Sequence[set[str]],
    merged: dict[str, Candidate],
    chunks: Sequence[chunking.Chunk],
    progress: Progress | None,
) -> tuple[list[tuple[str, ontology.Pattern, str, int]], int]:
    """(source key, pattern, target key, chunk index) for every relation the
    model proposes, plus how many proposals were refused for an unusable name.

    The model is shown the graph's relation types and writes one of their
    names, or a new one when none fits. Every name is normalised to
    snake_case; if what remains is not an identifier -- an empty string, a
    sentence -- the relation is dropped here rather than written as a type
    nobody could query. A name that equals a known type is that type; any
    other is new, and `_assemble` lists it under `new_relations`.
    """
    proposals: list[tuple[str, ontology.Pattern, str, int]] = []
    seen: set[tuple[str, str, str]] = set()
    unnamed = 0

    for index, keys in enumerate(per_chunk):
        present = [merged[key] for key in keys if key in merged]
        if len(present) < 2:
            continue
        if progress:
            progress(f"finding relations, chunk {index + 1} of {len(chunks)}")
        # Labels must be unique for the enum and unambiguous to map back:
        # "PowerShell (tool)" and "PowerShell (technique)" are different entities.
        by_label = {f"{c.name} ({c.paper_type})": c for c in present}
        shown = [
            (label, c.paper_type, c.description[:160]) for label, c in by_label.items()
        ]
        system, user = prompts.relation_prompt(genre, shown, chunks[index].text)
        answer = llm.chat_json(
            cfg, system=system, user=user, schema=prompts.relation_schema(list(by_label))
        )
        for row in answer.get("relations", []):
            read = _read_relation(row, by_label)
            if isinstance(read, str):
                unnamed += read == "unnamed"
                continue
            source, relation, target = read
            signature = (source.key, relation, target.key)
            if signature not in seen:
                seen.add(signature)
                pattern = ontology.Pattern(source.paper_type, relation, target.paper_type)
                proposals.append((source.key, pattern, target.key, index))
    return proposals, unnamed


def _read_relation(
    row: dict, by_label: dict[str, Candidate]
) -> tuple[Candidate, str, Candidate] | str:
    """One proposed relation as (source, relation, target), or why it is unusable."""
    source = by_label.get(str(row.get("source", "")))
    target = by_label.get(str(row.get("target", "")))
    if source is None or target is None:
        return "unknown entity"  # the enum makes this unreachable; belt and braces
    if source.key == target.key:
        return "self-relation"
    # A known name, or a new one -- the same normalisation decides which, so
    # `Uses`, `USES` and `uses` are one relation and `shares code with` is a
    # well-formed new one. See `prompts.relation_schema` for why this is not
    # an enum.
    relation = ontology.normalise_relation(str(row.get("relation", "")))
    if relation is None:
        return "unnamed"
    swap, relation = ontology.orient(source.paper_type, relation, target.paper_type)
    if swap:
        source, target = target, source
    return source, relation, target




_STOPWORDS = frozenset(
    "the and for with from that this into over used uses using through their "
    "them then than which while where about after before other actor actors "
    "group attack attacker attackers target targets targeted system systems".split()
)


def _refers_generically(evidence: str, type_name: str) -> bool:
    """Does the evidence refer to an entity of this type by a generic noun or
    a pronoun -- "the group", "the campaign", "it"?"""
    if type_name in ontology.ACTOR_TYPES:
        return bool(_GENERIC_ACTOR.search(evidence) or _PRONOUN.search(evidence))
    if type_name in _CAMPAIGN_TYPES:
        return bool(_GENERIC_CAMPAIGN.search(evidence) or _PRONOUN.search(evidence))
    return False


def _content_words(text: str) -> set[str]:
    """Content words as six-letter stems, so "Exfiltration" and "exfiltrated"
    count as the same word -- the overlap test between a paraphrased name and
    the evidence sentence was failing on exactly that inflection."""
    return {
        word[:6]
        for word in re.findall(r"[a-z][a-z0-9-]{3,}", text.lower())
        if word not in _STOPWORDS
    }


# How a report refers back to the actor or the campaign it is about, after
# naming it once. Actor words resolve among actor-type entities, campaign
# words among campaigns, pronouns among either -- so "the group" never
# resolves to a campaign that happened to be named more recently.
_GENERIC_ACTOR = re.compile(
    r"\b(?:the|this|that)\s+(?:threat\s+)?(?:actors?|group|adversary|adversaries|attackers?|operators?|intruders?|intrusion set)\b",
    re.I,
)
_GENERIC_CAMPAIGN = re.compile(r"\b(?:the|this|that)\s+(?:campaign|operation|activity|intrusions?)\b", re.I)
_PRONOUN = re.compile(r"\b(?:it|its|they|their)\b", re.I)
_CAMPAIGN_TYPES = frozenset({"campaign"})


def _named_in(evidence: str, candidate: Candidate, *, antecedent: bool = False) -> bool:
    """Does the evidence sentence actually concern this entity?

    For a concrete entity -- a tool, a group, a CVE, an asset -- that means its
    name (or its longest word) appears in the sentence, so "the FRP tool" still
    counts for "Fast Reverse Proxy (FRP)".

    A technique is different: the model paraphrases it ("Network proxy" for
    "proxies all of its traffic"), so its name is not in the text. What *is* in
    the text is the sentence the description came from, so the test is lexical
    overlap between the technique's description and the evidence. Measured on
    one report before this: 54 of 90 pairs confirmed, most of them one
    technique paired with every tool in the document on a sentence that named
    the tool and had nothing to do with the technique.

    `antecedent` handles the one coreference a report relies on: it names its
    actor, then says "the actor", "the group", "it". When this group is the
    group most recently named before the evidence sentence, such a reference
    means it, and counts as naming it. Measured on the Volt Typhoon advisory:
    without this, 11 of 21 correctly proposed relations were rejected, every
    one on a sentence beginning "The actor ..." or "It ...". A first version
    allowed it only when the group was the *only* group in the chunk; on the
    ProxyLogon text, which names ToddyCat two paragraphs after "tracks as
    Hafnium. The group exploited ...", that dropped 7 of 9 relations. Nearest
    antecedent is the rule a reader applies, and it fails only where a reader
    would hesitate too.
    """
    haystack = evidence.lower()
    if antecedent and _refers_generically(evidence, candidate.paper_type):
        return True
    if candidate.paper_type in ontology.PARAPHRASED_TYPES:
        wanted = _content_words(candidate.description) | _content_words(candidate.name)
        if not wanted:
            return True
        shared = wanted & _content_words(evidence)
        return len(shared) >= 2 or len(shared) >= 0.4 * len(wanted)
    name = candidate.name.lower()
    if name in haystack:
        return True
    words = sorted(re.findall(r"[a-z0-9][a-z0-9.-]{3,}", name), key=len, reverse=True)
    return any(word in haystack for word in words[:2])


def _accepted(
    answer: dict,
    batch: Sequence[tuple[str, ontology.Pattern, str]],
    merged: dict[str, Candidate],
    chunk_text: str = "",
    groups: Sequence[Candidate] = (),
) -> list[tuple[str, ontology.Pattern, str, str]]:
    """The rows of one validation answer that confirm a relation.

    Defensive about the index because it is the one field the schema cannot
    constrain to a valid range -- a model can return `"index": 47` for a batch of
    ten, and attaching that evidence to whatever pair happened to be there would
    be worse than dropping it. And the evidence must name the concrete entities
    it is supposed to be evidence for; see `_named_in`. `groups` are the group
    candidates present in this chunk, for resolving "the actor".
    """
    kept: list[tuple[str, ontology.Pattern, str, str]] = []
    for row in answer.get("results", []):
        position = row.get("index")
        if not row.get("holds") or not isinstance(position, int):
            continue
        if not 0 <= position < len(batch):
            continue
        source, pattern, target = batch[position]
        evidence = str(row.get("evidence", ""))[:1000]
        if not evidence.strip():
            continue
        actors = [g for g in groups if g.paper_type in ontology.ACTOR_TYPES]
        campaigns = [g for g in groups if g.paper_type in _CAMPAIGN_TYPES]
        antecedents = {
            _antecedent_group(chunk_text, evidence, actors),
            _antecedent_group(chunk_text, evidence, campaigns),
        }
        if not all(
            _named_in(evidence, merged[key], antecedent=key in antecedents)
            for key in (source, target)
        ):
            continue
        kept.append((source, pattern, target, evidence))
    return kept


def _antecedent_group(chunk_text: str, evidence: str, groups: Sequence[Candidate]) -> str | None:
    """The key of the group most recently named before `evidence` in the chunk.

    Locates the evidence by its opening words (the model sometimes elides the
    middle of a long sentence with "..."), then takes the group whose name --
    or longest word, so "the Hafnium actor" finds HAFNIUM -- last appears
    before that point. If the evidence cannot be found, or names a group
    itself, the answer is the last group named anywhere before the end of the
    chunk that the evidence could be in -- which for a single-group chunk is
    simply that group, and for a multi-group one is a guess the caller should
    not need, because the evidence then usually names its actor outright.
    """
    if not groups:
        return None
    text = chunk_text.lower()
    opening = evidence.strip().lower().replace("…", "...").split("...")[0].strip()[:60]
    position = text.find(opening) if opening else -1
    before = text[:position] if position >= 0 else text
    best_key, best_at = None, -1
    for group in groups:
        name = group.name.lower()
        words = sorted(re.findall(r"[a-z0-9][a-z0-9.-]{3,}", name), key=len, reverse=True)
        at = max((before.rfind(needle) for needle in (name, *words[:1])), default=-1)
        if at > best_at:
            best_key, best_at = group.key, at
    return best_key if best_at >= 0 else None


def _validate_pairs(
    cfg: Settings,
    pairs: Sequence[tuple[str, ontology.Pattern, str, int]],
    merged: dict[str, Candidate],
    chunks: Sequence[chunking.Chunk],
    per_chunk: Sequence[set[str]],
    progress: Progress | None,
) -> list[tuple[str, ontology.Pattern, str, str]]:
    """Ask the model which candidate triples the text actually states."""
    confirmed: list[tuple[str, ontology.Pattern, str, str]] = []
    # Group by chunk so each request carries one context rather than many.
    by_chunk: dict[int, list[tuple[str, ontology.Pattern, str]]] = {}
    for source, pattern, target, index in pairs:
        by_chunk.setdefault(index, []).append((source, pattern, target))

    done = 0
    for index, group in by_chunk.items():
        groups_here = [
            merged[key]
            for key in per_chunk[index]
            if key in merged and merged[key].paper_type in (ontology.ACTOR_TYPES | _CAMPAIGN_TYPES)
        ]
        for start in range(0, len(group), VALIDATION_BATCH):
            batch = group[start : start + VALIDATION_BATCH]
            numbered = [
                (position, merged[source].name, pattern, merged[target].name)
                for position, (source, pattern, target) in enumerate(batch)
            ]
            descriptions = {
                merged[key].name: merged[key].description[:120]
                for source, _, target in batch
                for key in (source, target)
            }
            system, user = prompts.validation_prompt(
                numbered, chunks[index].text, descriptions
            )
            answer = llm.chat_json(
                cfg, system=system, user=user, schema=prompts.VALIDATION_SCHEMA
            )
            confirmed.extend(
                _accepted(answer, batch, merged, chunks[index].text, groups_here)
            )
            done += len(batch)
            if progress:
                progress(f"checking relations, {done} of {len(pairs)}")
    return confirmed


def run(
    cfg: Settings,
    handle: Session,
    *,
    text: str,
    source: str,
    genre: str,
    title: str = "",
    progress: Progress | None = None,
) -> Proposal:
    """Extract, validate, filter, align. Returns a proposal; writes nothing."""

    def step(message: str) -> None:
        if progress:
            progress(message)

    step("cleansing")
    body = cleanse.cleanse(text)
    cleanse.screen(body)

    if genre == "paper":
        step("checking relevance")
        # Section 3.2.2 screens papers on title and abstract before spending any
        # GPU on the body. The abstract is approximated by the opening, which is
        # what a converted PDF gives us.
        system, user = prompts.relevance_prompt(title or "(untitled)", body[:3000])
        verdict = llm.chat_json(
            cfg, system=system, user=user, schema=prompts.RELEVANCE_SCHEMA
        )
        if not verdict.get("relevant"):
            raise Irrelevant(str(verdict.get("reason", "no reason given")))

    chunks = chunking.chunk(body)
    all_candidates: list[Candidate] = []
    per_chunk: list[set[str]] = []
    indexes = graph.vector_indexes(handle)

    for chunk in chunks:
        step(f"extracting, {chunk.label} of {len(chunks)}")
        seeds = _identifier_candidates(handle, chunk.text)
        reference = _retrieve_reference(cfg, handle, chunk.text, genre, indexes, seeds[:10])
        found = _extract_nodes(cfg, genre, chunk, reference)
        found.extend(seeds)
        per_chunk.append({candidate.key for candidate in found})
        all_candidates.extend(found)

    merged = _merge(all_candidates)

    pairs, unnamed = _propose_relations(cfg, genre, per_chunk, merged, chunks, progress)
    confirmed = _validate_pairs(cfg, pairs, merged, chunks, per_chunk, progress)

    # Section 3.2.3: drop nodes that are both isolated and named only by a serial
    # number. Both conditions -- a lone node with a real name is knowledge.
    connected = {key for source, _, target, _ in confirmed for key in (source, target)}
    dropped: list[dict] = []
    survivors: dict[str, Candidate] = {}
    for key, candidate in merged.items():
        if key not in connected and ontology.is_serial_only(candidate.name):
            dropped.append(
                {
                    "name": candidate.name,
                    "type": candidate.paper_type,
                    "why": "isolated, and named only by a serial number",
                }
            )
        else:
            survivors[key] = candidate
    merged = survivors
    # Nothing needs re-filtering here: a dropped key was by definition absent
    # from `connected`, so no confirmed relation can refer to it.

    step("aligning")
    alignment = align.align(cfg, handle, list(merged.values()), progress=progress)
    final_id = {
        decision.candidate.key: decision.final_id for decision in alignment.decisions
    }

    return _assemble(
        cfg,
        source=source,
        alignment=alignment,
        confirmed=confirmed,
        final_id=final_id,
        dropped=dropped,
        counts={
            "characters": len(body),
            "chunks": len(chunks),
            "candidates": len(merged),
            "relations_proposed": len(pairs),
            "relations_unnamed": unnamed,
        },
    )


def _assemble(
    cfg: Settings,
    *,
    source: str,
    alignment: align.Result,
    confirmed: Sequence[tuple[str, ontology.Pattern, str, str]],
    final_id: dict[str, str],
    dropped: list[dict],
    counts: dict,
) -> Proposal:
    """Turn decisions into the record shapes `POST /ingest` accepts."""
    proposal = Proposal()

    # An aligned entity is NOT written -- see align.py. Writing it would replace
    # a real node's properties with the handful a model produced.
    for decision in alignment.fresh:
        candidate = decision.candidate
        record = {
            "id": decision.final_id,
            "type": ontology.repo_type(candidate.paper_type),
            "_type_name": candidate.paper_type,
            "source": source,
            "name": candidate.name,
            "description": candidate.description,
            "extracted_by": cfg.extract_model,
        }
        proposal.entities.append(record)
        # The near-miss travels in the proposal, not on the record: it is review
        # information, and would otherwise become a property on the node.
        proposal.near_misses.append(
            {
                "name": candidate.name,
                "type": candidate.paper_type,
                "closest_name": decision.matched_name,
                "cosine": round(decision.cosine, 4) if decision.cosine is not None else None,
                "why_new": decision.reason,
            }
        )

    for decision in alignment.matched:
        proposal.aligned.append(
            {
                "name": decision.candidate.name,
                "type": decision.candidate.paper_type,
                "matched_id": decision.final_id,
                "matched_name": decision.matched_name,
                "cosine": round(decision.cosine, 4) if decision.cosine is not None else None,
                "method": decision.method,
                "reason": decision.reason,
            }
        )

    seen_edges: set[str] = set()
    new_relations: dict[str, dict] = {}
    for source_key, pattern, target_key, evidence in confirmed:
        start, end = final_id.get(source_key), final_id.get(target_key)
        if not start or not end or start == end:
            continue
        # Minted from the *final* endpoints so that re-running the document after
        # alignment moved an endpoint still produces one edge, not two.
        edge_id = uuid.uuid5(_NAMESPACE, f"trace-extract:{start}:{pattern.relation}:{end}")
        # Four "X routers" that all aligned to one Routers node are one edge.
        # MERGE would collapse them on write anyway; the preview should not
        # show four.
        if str(edge_id) in seen_edges:
            continue
        seen_edges.add(str(edge_id))
        proposal.relationships.append(
            {
                "id": f"relationship--{edge_id}",
                "relationship_type": pattern.relation,
                "source_ref": start,
                "target_ref": end,
                "source": source,
                "evidence": evidence,
                "extracted_by": cfg.extract_model,
            }
        )
        # A relation type the graph does not hold yet is review information:
        # what the vocabulary could not express. It is written -- the user's
        # decision -- but listed so it is seen first.
        if not ontology.is_known_relation(pattern.relation):
            entry = new_relations.setdefault(
                pattern.relation,
                {"relation": pattern.relation, "count": 0, "example": evidence[:200]},
            )
            entry["count"] += 1

    proposal.dropped = dropped
    # Likewise an entity type outside the offered vocabulary: written, and
    # listed with examples so the reviewer sees what the model coined.
    new_types: dict[str, dict] = {}
    for record in proposal.entities:
        if not ontology.is_known_type(record["_type_name"]):
            entry = new_types.setdefault(
                record["_type_name"], {"type": record["_type_name"], "count": 0, "examples": []}
            )
            entry["count"] += 1
            if len(entry["examples"]) < 3:
                entry["examples"].append(record["name"])
    for record in proposal.entities:
        del record["_type_name"]
    proposal.new_types = list(new_types.values())
    proposal.new_relations = list(new_relations.values())
    relation_counts: dict[str, int] = {}
    for record in proposal.relationships:
        relation_counts[record["relationship_type"]] = (
            relation_counts.get(record["relationship_type"], 0) + 1
        )
    proposal.stats = {
        **counts,
        "relations_confirmed": len(confirmed),
        "relation_types": relation_counts,
        "entities_new": len(proposal.entities),
        "entities_aligned": len(proposal.aligned),
        "aligned_by_identifier": sum(
            1 for decision in alignment.matched if decision.method == "identifier"
        ),
        "aligned_by_embedding": sum(
            1 for decision in alignment.matched if decision.method == "embedding"
        ),
        "no_vector_index": sum(
            1 for decision in alignment.decisions if decision.method == "no-index"
        ),
        "new_types": len(proposal.new_types),
        "new_relation_types": len(proposal.new_relations),
        "dropped": len(dropped),
        "threshold": cfg.align_threshold,
        "extract_model": cfg.extract_model,
        "embed_model": cfg.embed_model,
    }
    return proposal
