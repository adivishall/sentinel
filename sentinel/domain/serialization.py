"""Uniform dataclass <-> dict conversion used by the API, audit, storage and CLI.

One canonical wire form for every domain object keeps the API, the console, the
audit trail and the tests looking at the same shape.
"""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any


def to_dict(obj: Any) -> Any:
    """Recursively convert dataclasses / enums / tuples / sets to plain JSON types."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        out: dict[str, Any] = {}
        for f in dataclasses.fields(obj):
            out[f.name] = to_dict(getattr(obj, f.name))
        return out
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): to_dict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_dict(v) for v in obj]
    if isinstance(obj, (set, frozenset)):
        return sorted(to_dict(v) for v in obj)
    return obj
