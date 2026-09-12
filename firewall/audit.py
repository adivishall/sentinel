"""Append-only structured audit trail.

Every firewall decision emits one audit event so a decision can be reconstructed
after the fact: what entered, what was untrusted, what was detected, what facts
the adjudicator used, and what final effect occurred.

Privacy: we store a **hash** of the raw submission, never the prose itself, plus
the structured (already non-sensitive) facts. Events are JSON lines, appended to
``$SENTINEL_AUDIT_LOG`` (default ``eval/results/audit.jsonl``). Recording is
best-effort -- a logging failure must never change or block a decision.
"""

from __future__ import annotations

import json
import os
import threading

from firewall.logging_config import get_logger

_log = get_logger("firewall.audit")
_lock = threading.Lock()

DEFAULT_PATH = "eval/results/audit.jsonl"


def _path() -> str:
    return os.environ.get("SENTINEL_AUDIT_LOG", DEFAULT_PATH)


def record(event: dict) -> str:
    """Append one audit event; return its audit_id. Never raises."""
    audit_id = event.get("audit_id", "")
    try:
        path = _path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        line = json.dumps(event, default=str, sort_keys=True)
        with _lock, open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as e:  # pragma: no cover - best effort
        _log.warning("audit write failed", extra={"detail": str(e)})
    return audit_id


def read_all(path: str | None = None) -> list[dict]:
    """Read back all audit events (for the console viewer / tests)."""
    p = path or _path()
    if not os.path.exists(p):
        return []
    out = []
    with open(p, encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:  # pragma: no cover
                    continue
    return out
