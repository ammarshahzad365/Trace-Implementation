"""Section 3.2.4 and 5.2.2: is this entity already in the graph, or is it new?

Without this step every report mints its own "Hafnium" and the graph fills with
duplicates -- one holding ATT&CK's edges, one per report holding three each, none
connected to the others. The cross-source paths the project exists for would
still be absent while the data was technically all present.

The paper's procedure, in order:

1. encode the `description` of the new entity and of its same-type counterparts;
2. take the top 20 by similarity;
3. below theta, it is new; at or above theta, ask an LLM which one it is;
4. redirect every edge of the new entity onto the match.

Three things this module adds, all of them forced by the data rather than chosen:

**Identifiers first.** Section 5.2.2 notes that `vuln` scores highest precisely
because its identifiers are regular: "If two descriptions share the same ID, they
match directly without semantic textual similarity." A document naming
`CVE-2021-26855` needs no model and no embedding, and the id space of this graph
is wider than CVEs -- `T1190`, `M1051`, `G1028` are all direct hits.

**The threshold is not the paper's number.** `graph.similar` returns raw cosine,
but 0.9 was tuned for TRACE's own sentence-transformer, and cosine scales are not
comparable between embedding models. `cfg.align_threshold` is therefore a
starting point to be recalibrated per embedder -- see `eval/calibrate.py` and the
README.

**A match means the extracted node is discarded, not written.** Section 5.2.2
replaces "the original node's properties in the extracted list with those of the
matched node", so the graph's version wins. That is also the only safe move
here: `ingest/writer.py` MERGEs with `SET n = props`, which *replaces* every
property, so writing an aligned entity would overwrite a real CVE's CVSS scores
and dates with the four fields a model produced. Only the edges survive.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Sequence

from neo4j import Session

from . import graph, llm, ontology, prompts
from .config import Settings

# Same namespace `data-preprocessing/` uses for its own deterministic ids, so
# re-running a document produces the same id rather than a second node.
_NAMESPACE = uuid.NAMESPACE_URL


@dataclass
class Candidate:
    """One entity the extractor found, before we know whether it already exists."""

    paper_type: str
    name: str
    description: str = ""
    other_type: str | None = None

    @property
    def key(self) -> str:
        """Identity *within this document*: same type and name means same thing."""
        return f"{self.paper_type}:{self.name.strip().lower()}"

    def minted_id(self) -> str:
        """A stable id of our own, in the STIX shape the graph already uses.

        Section 3.2.4 asks for consistent ID prefixes; `intrusion-set--<uuid5>`
        matches what ATT&CK data in this graph already looks like. Derived from
        type and name so the same entity in a re-run lands on the same id.
        """
        repo_type = ontology.repo_type(self.paper_type)
        return f"{repo_type}--{uuid.uuid5(_NAMESPACE, f'trace-extract:{self.key}')}"


@dataclass
class Decision:
    """What happened to one candidate, and why -- the preview shows all of this."""

    candidate: Candidate
    final_id: str
    matched: bool
    method: str  # identifier | embedding | new | no-index
    matched_name: str | None = None
    cosine: float | None = None
    reason: str = ""


@dataclass
class Result:
    decisions: list[Decision] = field(default_factory=list)
    #: minted id -> the id an existing node already has, for edge redirection.
    rewrites: dict[str, str] = field(default_factory=dict)

    @property
    def matched(self) -> list[Decision]:
        return [d for d in self.decisions if d.matched]

    @property
    def fresh(self) -> list[Decision]:
        return [d for d in self.decisions if not d.matched]


def embedding_text(name: str, description: str | None) -> str:
    """What gets embedded, on both sides of the comparison.

    Section 5.2.2 embeds the `description` attribute. Measured here with
    `bge-m3`, that alone is not enough: the extracted description of Hafnium
    ("state-sponsored group attributed to intrusions against on-premises Exchange
    Server") is a one-line paraphrase that fits a dozen APTs, and ATT&CK's
    HAFNIUM ranked *fourth* behind APT17 and UNC2452 at cosine 0.537. With the
    name prepended it ranked first at 0.630 with a clear margin. The name is
    where the identity lives; the description is context. `embed_corpus.py` uses
    the same function so the two sides are built identically.
    """
    name = (name or "").strip()
    description = (description or "").strip()
    if name and description:
        return f"{name}: {description}"
    return name or description


def _identifier_hit(candidate: Candidate, known: dict[str, dict]) -> dict | None:
    """Does this candidate's name contain an identifier that exists in the graph?"""
    for identifier in ontology.find_identifiers(candidate.name):
        node = known.get(identifier)
        if node:
            return node
    return None


def align(
    cfg: Settings,
    handle: Session,
    candidates: Sequence[Candidate],
    *,
    threshold: float | None = None,
    progress=None,
) -> Result:
    """Decide new-or-existing for every candidate, in the paper's order."""
    theta = cfg.align_threshold if threshold is None else threshold
    result = Result()
    if not candidates:
        return result

    # One lookup for every identifier mentioned by any candidate, rather than one
    # query per candidate. `S0066` resolves to whatever label the graph gives it,
    # because ATT&CK shares that id space between malware and tools.
    identifiers = {
        identifier
        for candidate in candidates
        for identifier in ontology.find_identifiers(candidate.name)
    }
    known = graph.lookup(handle, identifiers)
    indexes = graph.vector_indexes(handle)

    for position, candidate in enumerate(candidates):
        if progress:
            progress(f"aligning {position + 1} of {len(candidates)}")

        # 1. A standardised identifier is its own alignment.
        node = _identifier_hit(candidate, known)
        if node:
            result.decisions.append(
                Decision(
                    candidate=candidate,
                    final_id=node["id"],
                    matched=True,
                    method="identifier",
                    matched_name=node.get("name"),
                    cosine=1.0,
                    reason="the name contains an identifier that already names this node",
                )
            )
            result.rewrites[candidate.minted_id()] = node["id"]
            continue

        minted = candidate.minted_id()

        # 1b. An exact name within the same type. Between the identifier step
        # and the embedding step in precision, and far cheaper than either
        # model call. See `graph.by_exact_name` for the case that motivated it.
        same_name = graph.by_exact_name(
            handle, ontology.align_labels(candidate.paper_type), candidate.name
        )
        if same_name:
            result.decisions.append(
                Decision(
                    candidate=candidate,
                    final_id=same_name["id"],
                    matched=True,
                    method="name",
                    matched_name=same_name["name"],
                    cosine=1.0,
                    reason="an existing node of this type has exactly this name",
                )
            )
            result.rewrites[minted] = same_name["id"]
            continue

        labels = [
            label
            for label in ontology.align_labels(candidate.paper_type)
            if graph.index_name(label) in indexes
        ]

        # 2. No vector index for this type means no candidates can be found.
        # Degrade to "new" and say so, rather than failing the whole job.
        if not labels:
            result.decisions.append(
                Decision(
                    candidate=candidate,
                    final_id=minted,
                    matched=False,
                    method="no-index",
                    reason=(
                        f"no vector index on {ontology.align_labels(candidate.paper_type)}; "
                        "run embed_corpus.py or alignment cannot see existing nodes"
                    ),
                )
            )
            continue

        # 3. Embed and fetch the top 20 of the same type. "Same type" can span
        # two labels (tool -> Tool and Malware), so search each and merge.
        vector = llm.embed(cfg, [embedding_text(candidate.name, candidate.description)])[0]
        nearby = sorted(
            (row for label in labels for row in graph.similar(handle, label, vector, k=20)),
            key=lambda row: row["cosine"],
            reverse=True,
        )[:20]
        above = [row for row in nearby if row["cosine"] >= theta]

        if not above:
            # Record the near-miss. Whether theta is right for this embedder is
            # only visible if every "new" verdict says how close it came.
            closest = nearby[0] if nearby else None
            result.decisions.append(
                Decision(
                    candidate=candidate,
                    final_id=minted,
                    matched=False,
                    method="new",
                    matched_name=closest["name"] if closest else None,
                    cosine=closest["cosine"] if closest else None,
                    reason=(
                        f"nothing of this type reached theta={theta:.2f}"
                        + (
                            f"; closest was {closest['name']} ({closest['id']}) at {closest['cosine']:.3f}"
                            if closest
                            else ""
                        )
                    ),
                )
            )
            continue

        # 4. The model picks among the survivors, or declines.
        system, user = prompts.alignment_prompt(
            name=candidate.name,
            entity_type=candidate.paper_type,
            description=candidate.description,
            candidates=above,
        )
        answer = llm.chat_json(
            cfg,
            system=system,
            user=user,
            schema=prompts.alignment_schema([row["id"] for row in above]),
        )
        match_id = answer.get("match_id")
        reason = str(answer.get("reason", ""))[:400]

        if not match_id:
            result.decisions.append(
                Decision(
                    candidate=candidate,
                    final_id=minted,
                    matched=False,
                    method="new",
                    matched_name=above[0]["name"],
                    cosine=above[0]["cosine"],
                    reason=f"above theta but the model rejected every candidate: {reason}",
                )
            )
            continue

        chosen = next(row for row in above if row["id"] == match_id)
        result.decisions.append(
            Decision(
                candidate=candidate,
                final_id=match_id,
                matched=True,
                method="embedding",
                matched_name=chosen["name"],
                cosine=chosen["cosine"],
                reason=reason,
            )
        )
        result.rewrites[minted] = match_id

    return result
