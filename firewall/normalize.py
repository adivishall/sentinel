"""Input normalisation & validation for untrusted spans.

A lexical detector is trivially bypassed if the attacker writes "іgnore" with a
Cyrillic 'і', or pads text with zero-width joiners. Before any detection runs we:
  - reject inputs that are not usable (empty / oversized),
  - Unicode-normalise (NFKC) so full-width and compatibility forms collapse,
  - strip zero-width / control characters,
  - fold a table of common homoglyphs to their ASCII look-alike.

This is defence-in-depth for Layer 2 and the first line of edge-case handling.
"""

from __future__ import annotations

import re
import unicodedata

MAX_LEN = 20_000  # a dispute narrative longer than this is not a real submission

# Common confusable homoglyphs -> ASCII. Not exhaustive; covers the cheap attacks.
_HOMOGLYPHS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",  # Cyrillic
    " і": "i",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ן": "l",
    "Ι": "I",
    "ο": "o",  # Greek/other
    "𝗂": "i",
    "ｇ": "g",
    "ⅼ": "l",
    "ǃ": "!",
}
_ZERO_WIDTH = re.compile(r"[​-‏‪-‮⁠﻿]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class InvalidSubmission(ValueError):
    """Raised when input cannot be processed (empty or oversized)."""


def validate(text: object) -> str:
    """Type/size gate. Raises InvalidSubmission on unusable input."""
    if not isinstance(text, str):
        raise InvalidSubmission(f"expected str, got {type(text).__name__}")
    if not text.strip():
        raise InvalidSubmission("empty submission")
    if len(text) > MAX_LEN:
        raise InvalidSubmission(f"submission too large ({len(text)} > {MAX_LEN} chars)")
    return text


def normalize(text: str) -> str:
    """Canonicalise untrusted text so evasion by unicode tricks fails.
    Idempotent: normalize(normalize(x)) == normalize(x)."""
    text = _ZERO_WIDTH.sub("", text)
    text = _CONTROL.sub("", text)
    text = "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)
    text = unicodedata.normalize("NFKC", text)
    return text


def prepare(text: object) -> str:
    """validate + normalize in one call."""
    return normalize(validate(text))
