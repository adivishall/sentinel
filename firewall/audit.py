"""Append-only structured audit trail.

Every firewall decision emits one audit event so a decision can be reconstructed
after the fact: what entered, what was untrusted, what was detected, what facts
the adjudicator used, and what final effect occurred.

Privacy: the persisted audit stores a **hash** of the raw submission, never the
prose itself. Even the small matched-trigger snippets that L2 detection produces
for explainability are redacted to a hash before writing (see ``_redact``), so no
raw untrusted text -- not even a substring -- lands on disk. The structured facts
that reach the adjudicator come from the bank's own records and are retained.
Events are JSON lines, appended to ``$SENTINEL_AUDIT_LOG`` (default
``eval/results/audit.jsonl``). Recording is best-effort -- a logging failure must
never change or block a decision.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import threading

from firewall.logging_config import get_logger

_log = get_logger("firewall.audit")
_lock = threading.Lock()

DEFAULT_PATH = "eval/results/audit.jsonl"


def _path() -> str:
    return os.environ.get("SENTINEL_AUDIT_LOG", DEFAULT_PATH)


def _redact(obj: object) -> object:
    """Recursively replace any ``span`` string (a raw matched snippet of untrusted
    text) with a hash + length, so the persisted audit never contains raw prose
    while still letting an auditor confirm which trigger fired."""
    if isinstance(obj, dict):
        out: dict = {}
        for k, v in obj.items():
            if k == "span" and isinstance(v, str):
                out["span_sha256"] = hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()[:16]
                out["span_len"] = len(v)
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    return obj


def record(event: dict) -> str:
    """Append one audit event; return its audit_id. Never raises."""
    audit_id = event.get("audit_id", "")
    try:
        path = _path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        redacted = _redact(copy.deepcopy(event))
        line = json.dumps(redacted, default=str, sort_keys=True)
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
