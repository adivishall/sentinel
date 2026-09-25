"""Identifier and hashing helpers.

Identifiers are opaque strings with a readable prefix (``TX-``, ``CASE-``,
``DEC-``). ``content_hash`` is the one way untrusted prose is ever referenced by
persisted records: as a SHA-256, never as text.
"""

from __future__ import annotations

import hashlib
import json
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
