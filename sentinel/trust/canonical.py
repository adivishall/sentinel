"""Canonical JSON: exactly one byte string for every value that may be signed.

A signature covers bytes, so signer and verifier must agree on the bytes of a value
without negotiation. The profile is deliberately narrow and refuses what is ambiguous
instead of normalising it:

- objects with string keys, sorted by code point; no insignificant whitespace; UTF-8;
- integers within +/-(2**53 - 1) (the range every JSON implementation reads exactly);
- no floats, NaN or Infinity (money is integer minor units; ``50000.0`` and ``5e4`` are
  the same number with different bytes);
- on input, a duplicated key is an error (two parsers could each keep a different one);
- no lone surrogates; nesting at most ``MAX_DEPTH`` deep.

Strings are not Unicode-normalised: ``é`` precomposed and decomposed are different
statements, and a signature over one does not cover the other.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_SAFE_INT = 2**53 - 1
MAX_DEPTH = 16
MAX_BYTES = 64 * 1024


class CanonicalError(ValueError):
    """The value has no canonical form (and so cannot be signed or verified)."""


def _check(v: object, path: str, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError(f"{path}: nested deeper than {MAX_DEPTH}")
    if v is None or isinstance(v, bool):
        return
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError as e:
            raise CanonicalError(f"{path}: not valid UTF-8 text ({e.reason})") from None
        return
    if isinstance(v, int):
        if not -MAX_SAFE_INT <= v <= MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer outside +/-(2**53 - 1)")
        return
    if isinstance(v, float):
        raise CanonicalError(f"{path}: floats have no canonical form; use integers or strings")
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise CanonicalError(f"{path}: object key {k!r} is not a string")
            _check(k, f"{path}.<key>", depth + 1)
            _check(x, f"{path}.{k}", depth + 1)
        return
    if isinstance(v, (list, tuple)):
        for i, x in enumerate(v):
            _check(x, f"{path}[{i}]", depth + 1)
        return
    raise CanonicalError(f"{path}: {type(v).__name__} is not a JSON value")


def canonical_json(value: object) -> bytes:
    _check(value, "$", 0)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: object) -> str:
    """SHA-256 of the canonical form."""
    return sha256_hex(canonical_json(value))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise CanonicalError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _no_float(s: str) -> Any:
    raise CanonicalError(f"float {s!r} has no canonical form")


def _no_constant(s: str) -> Any:
    raise CanonicalError(f"{s} is not JSON")


def strict_loads(data: str | bytes, *, max_bytes: int = MAX_BYTES) -> Any:
    """Parse JSON that is to be verified. Refuses what ``canonical_json`` could not have
    produced -- duplicate keys, floats, NaN / Infinity, over-large or over-deep input --
    so the parsed value re-serialises to the bytes a signer meant."""
    raw = data.encode("utf-8") if isinstance(data, str) else data
    if len(raw) > max_bytes:
        raise CanonicalError(f"input is {len(raw)} bytes; the limit is {max_bytes}")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_float=_no_float,
            parse_constant=_no_constant,
        )
    except CanonicalError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise CanonicalError(f"not canonical JSON: {e}") from None
    _check(value, "$", 0)
    return value
