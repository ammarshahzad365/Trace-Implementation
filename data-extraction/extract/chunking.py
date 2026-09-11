"""Cutting a document into pieces a model can read in one go.

An APT report is tens of thousands of characters and the extraction prompt also
carries type definitions, worked examples and retrieved reference nodes. Feeding
the whole document at once either overflows the context window or -- worse,
because it is silent -- pushes the instructions far enough from the end that the
model starts drifting from the schema.

Three rules, each paying for itself:

- **Split on blank lines first.** A paragraph is the unit an author wrote; cutting
  mid-paragraph strands the subject of a sentence in the previous chunk, and
  "the group then deployed it" is unextractable without "it".
- **Overlap.** A sentence spanning a boundary would otherwise be seen twice in
  halves and understood neither time. Duplicate entities across overlapping
  chunks cost nothing -- `pipeline.py` merges by (type, name) before alignment.
- **Split long paragraphs on sentences.** A wall-of-text paragraph longer than
  the chunk size still has to be cut somewhere, and a sentence end is the least
  damaging place.

The sizes are characters rather than tokens on purpose: counting tokens means
carrying the model's tokenizer, and the margin here is wide enough that the
approximation never matters.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# ~4,000 characters is roughly 1,000 tokens, leaving most of even a modest
# context window for the prompt's own scaffolding and the model's answer.
DEFAULT_SIZE = 4_000
DEFAULT_OVERLAP = 200

_PARAGRAPH = re.compile(r"\n\s*\n")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+")


class Chunk(NamedTuple):
    index: int
    text: str

    @property
    def label(self) -> str:
        """For job progress: humans count from one."""
        return f"chunk {self.index + 1}"


def _split_oversized(paragraph: str, size: int) -> list[str]:
    """Cut one over-long paragraph at sentence ends, hard-cutting only if forced."""
    pieces: list[str] = []
    current = ""
    for sentence in _SENTENCE_END.split(paragraph):
        if current and len(current) + len(sentence) + 1 > size:
            pieces.append(current)
            current = sentence
        elif current:
            current = f"{current} {sentence}"
        else:
            current = sentence
        # A single sentence longer than the chunk size is pathological -- a
        # minified script, a base64 blob -- so cut it bluntly rather than
        # letting one piece grow without bound.
        while len(current) > size:
            pieces.append(current[:size])
            current = current[size:]
    if current:
        pieces.append(current)
    return pieces


def chunk(
    text: str, *, size: int = DEFAULT_SIZE, overlap: int = DEFAULT_OVERLAP
) -> list[Chunk]:
    """Split into overlapping pieces of at most `size` characters.

    A document shorter than `size` comes back as a single chunk, which is the
    common case for a repair notice.
    """
    if size <= 0:
        raise ValueError("chunk size must be positive")
    if overlap >= size:
        raise ValueError("overlap must be smaller than the chunk size")

    text = text.strip()
    if not text:
        return []

    units: list[str] = []
    for paragraph in _PARAGRAPH.split(text):
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        units.extend(_split_oversized(paragraph, size) if len(paragraph) > size else [paragraph])

    chunks: list[str] = []
    current = ""
    for unit in units:
        if current and len(current) + len(unit) + 2 > size:
            chunks.append(current)
            # Carry the tail forward so a boundary-spanning sentence is whole
            # somewhere. Cut the tail at a space so the overlap never starts
            # mid-word.
            tail = current[-overlap:] if overlap else ""
            space = tail.find(" ")
            current = f"{tail[space + 1:]}\n\n{unit}" if space != -1 else unit
        else:
            current = f"{current}\n\n{unit}" if current else unit
    if current:
        chunks.append(current)

    return [Chunk(index, piece) for index, piece in enumerate(chunks)]
