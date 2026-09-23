"""Input validation and canonicalisation for untrusted spans.

A lexical detector is trivially bypassed if the attacker writes "іgnore" with a
Cyrillic 'і', pads text with zero-width joiners, or uses full-width letters.
Before any detection runs we:

  - reject inputs that are not usable (wrong type / empty / oversized),
  - strip zero-width and control characters,
  - fold a table of common homoglyphs to their ASCII look-alike,
  - Unicode-normalise (NFKC) so full-width and compatibility forms collapse.

``normalize_report`` also *counts* how much folding was needed, which is itself
a signal (``unicode_obfuscation``) -- honest text rarely needs it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

MAX_LEN = 20_000  # a narrative longer than this is not a real submission

# Common confusable homoglyphs -> ASCII. Not exhaustive; covers the cheap attacks.
HOMOGLYPHS = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",  # Cyrillic
    "і": "i",
    "ѕ": "s",
    "һ": "h",
    "ԁ": "d",
    "ј": "j",
    "ן": "l",
    "Ι": "I",
    "ο": "o",
    "ν": "v",  # Greek / other
    "𝗂": "i",
    "ｇ": "g",
    "ⅼ": "l",
    "ǃ": "!",
}
_ZERO_WIDTH = re.compile("[​-‏‪-‮⁠﻿]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FULLWIDTH_OR_LIGATURE = re.compile("[＀-￯ﬀ-ﬆ]")


class InvalidSubmission(ValueError):
    """Raised when input cannot be processed (wrong type, empty or oversized)."""


@dataclass(frozen=True)
class NormalizationReport:
    text: str
    zero_width_removed: int
    homoglyphs_folded: int
    compat_forms_folded: int

    @property
    def obfuscation_count(self) -> int:
        return self.zero_width_removed + self.homoglyphs_folded + self.compat_forms_folded

    @property
    def changed(self) -> bool:
        return self.obfuscation_count > 0


def validate(text: object) -> str:
    """Type/size gate. Raises InvalidSubmission on unusable input."""
    if not isinstance(text, str):
        raise InvalidSubmission(f"expected str, got {type(text).__name__}")
    if not text.strip():
        raise InvalidSubmission("empty submission")
    if len(text) > MAX_LEN:
        raise InvalidSubmission(f"submission too large ({len(text)} > {MAX_LEN} chars)")
    return text


def normalize_report(text: str) -> NormalizationReport:
    zw = len(_ZERO_WIDTH.findall(text))
    text = _ZERO_WIDTH.sub("", text)
    text = _CONTROL.sub("", text)
    homo = sum(1 for ch in text if ch in HOMOGLYPHS)
    text = "".join(HOMOGLYPHS.get(ch, ch) for ch in text)
    compat = len(_FULLWIDTH_OR_LIGATURE.findall(text))
    text = unicodedata.normalize("NFKC", text)
    return NormalizationReport(text, zw, homo, compat)


def normalize(text: str) -> str:
    """Canonicalise untrusted text so evasion by unicode tricks fails.
    Idempotent: normalize(normalize(x)) == normalize(x)."""
    return normalize_report(text).text


def prepare(text: object) -> str:
    """validate + normalize in one call."""
    return normalize(validate(text))
