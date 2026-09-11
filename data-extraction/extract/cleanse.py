"""Section 3.2.3's first half: make the text safe, then decide if it is worth reading.

Two small jobs that both happen before a model sees anything.

**Cleansing.** The paper names `\\\\` and `--` as characters that "cause graph
anomalies". The underlying problem is not those two glyphs; it is that text
lifted out of a PDF carries ligatures, soft hyphens, non-breaking spaces and
zero-width joiners that survive all the way into a node name, where they make
two visually identical names unequal -- and alignment compares names. Normalising
here is cheaper than debugging a duplicate node later.

**Screening.** Section 3.2.2 puts "a preliminary screening process to validate
the presence of required content" before extraction. A PDF that converted to
three lines of headers, or a page of references, costs a minute of GPU time to
learn nothing from. This is the cheap structural check; the *semantic* check --
"is this paper about security at all?" -- is a model call and lives in
`pipeline.py`, because section 3.2.2 applies it only to papers.
"""

from __future__ import annotations

import re
import unicodedata

# Characters that look like nothing but compare as something.
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Quotes and dashes have several Unicode spellings each; a name extracted from
# one document should equal the same name from another.
_PUNCTUATION = {
    ord("‘"): "'", ord("’"): "'", ord("‚"): "'", ord("‛"): "'",
    ord("“"): '"', ord("”"): '"', ord("„"): '"', ord("‟"): '"',
    ord("‐"): "-", ord("‑"): "-", ord("‒"): "-", ord("–"): "-",
    ord("—"): "-", ord("―"): "-", ord("−"): "-",
    ord(" "): " ", ord(" "): " ", ord(" "): " ",
}

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MANY_BLANKS = re.compile(r"\n{3,}")
_TRAILING_SPACE = re.compile(r"[ \t]+$", re.M)
# A line break inside a sentence, which PDF extraction inserts at every line of
# the original layout. Joining these back matters because chunking splits on
# blank lines and the model reads whole sentences better than ragged ones.
_SOFT_WRAP = re.compile(r"(?<=[a-z,;])\n(?=[a-z])")

MIN_CHARACTERS = 400
MIN_WORDS = 80


class ScreenedOut(ValueError):
    """The document has nothing worth sending to a model, and why."""


def cleanse(text: str) -> str:
    """Normalise text so that equal-looking names are equal strings."""
    # NFKC folds ligatures (`ﬁ` -> `fi`) and full-width forms, both of which turn
    # up in PDF text and neither of which should produce a distinct entity.
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH).translate(_PUNCTUATION)
    text = _CONTROL.sub(" ", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = _SOFT_WRAP.sub(" ", text)
    text = _TRAILING_SPACE.sub("", text)
    text = _MANY_BLANKS.sub("\n\n", text)
    return text.strip()


def screen(text: str) -> None:
    """Raise `ScreenedOut` if this is not a document, structurally speaking.

    Deliberately generous. The job is to catch a failed PDF conversion or an
    empty paste, not to judge subject matter -- a wrong rejection here costs a
    whole document silently, while a wrong acceptance costs one minute of GPU.
    """
    if len(text) < MIN_CHARACTERS:
        raise ScreenedOut(
            f"only {len(text)} characters after cleansing (need {MIN_CHARACTERS}). "
            "If this was a PDF, the conversion probably produced little text."
        )
    words = text.split()
    if len(words) < MIN_WORDS:
        raise ScreenedOut(f"only {len(words)} words after cleansing (need {MIN_WORDS}).")
    # Text that is mostly not letters is a table of hashes, a base64 blob or a
    # reference list -- all of which extract badly and slowly.
    letters = sum(character.isalpha() for character in text)
    if letters / max(len(text), 1) < 0.5:
        raise ScreenedOut(
            f"only {letters / len(text):.0%} of the characters are letters; this looks "
            "like tabular or encoded data rather than prose."
        )
