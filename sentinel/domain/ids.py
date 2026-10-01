"""Identifier and hashing helpers.

Identifiers are opaque strings with a readable prefix (``TX-``, ``CASE-``,
``DEC-``). ``content_hash`` is the one way untrusted prose is ever referenced by
persisted records: as a SHA-256, never as text.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import UTC, datetime


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def content_hash(value: object, length: int = 16) -> str:
    """Stable SHA-256 prefix of any JSON-serialisable value (sorted keys)."""
    if isinstance(value, str):
        raw = value.encode("utf-8", "replace")
    else:
        raw = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:length]


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


# A record id a caller may name: ASCII letters, digits and . _ -, 1-64 characters (the same
# grammar a signed statement's subject uses). Whitespace, case tricks via Unicode (U+2011,
# fullwidth letters) and NFKC-foldable look-alikes are refused, so two spellings of one
# stored id cannot be two subjects for the execution ledger.
RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def check_record_id(value: object, what: str = "record id") -> str:
    if not isinstance(value, str) or not RECORD_ID.match(value):
        raise ValueError(f"{what} {value!r} is not a record id (letters, digits, . _ -; 1-64)")
    return value
