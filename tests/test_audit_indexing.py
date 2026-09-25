"""Indexed audit lookups, tail/at, and exported checkpoints."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from sentinel.audit.chain import AuditChain, Checkpoint, JsonlBackend, MemoryBackend

T0 = datetime(2026, 9, 1, 12, 0)


def _iso(days: float = 0, hours: float = 0) -> str:
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


# ---- audit: indexed lookups, tail, checkpoints ---------------------------------------------
@pytest.mark.parametrize("backend_factory", [MemoryBackend, "jsonl"])
def test_indexed_lookup_tail_and_at(tmp_path, backend_factory):
    backend = (
        JsonlBackend(str(tmp_path / "a.jsonl")) if backend_factory == "jsonl" else backend_factory()
    )
    ch = AuditChain(backend)
    for i in range(6):
        ch.append(actor="s", workflow="dispute", action="DENY", decision_id=f"DEC-{i}")
    assert ch.backend.count() == 6
    assert [e.sequence for e in ch.tail(2)] == [4, 5] and ch.at(3).decision_id == "DEC-3"
    assert ch.get("DEC-4").sequence == 4 and ch.get(ch.at(1).event_id).sequence == 1
    assert ch.get("nope") is None and ch.at(99) is None
    reopened = AuditChain(type(backend)(backend.path) if backend_factory == "jsonl" else backend)
    assert len(reopened) == 6 and reopened.head == ch.head and reopened.get("DEC-2").sequence == 2


def test_checkpoint_detects_consistent_rewrite_and_truncation(tmp_path):
    key = b"k" * 32
    ch = AuditChain(MemoryBackend())
    for i in range(4):
        ch.append(actor="s", workflow="w", action="A", decision_id=f"D{i}")
    cp = ch.checkpoint(key)
    assert cp.signed and ch.verify_checkpoint(cp, key).ok
    # a consistently rewritten chain verifies on its own but not against the checkpoint
    rewritten = AuditChain(MemoryBackend())
    for i in range(4):
        rewritten.append(actor="s", workflow="w", action="ALLOW", decision_id=f"D{i}")
    assert rewritten.verify().ok
    v = rewritten.verify_checkpoint(cp, key)
    assert not v.ok and any("rewritten" in p for p in v.problems)
    # truncation below the checkpointed length
    short = AuditChain(MemoryBackend())
    for i in range(2):
        short.append(actor="s", workflow="w", action="A", decision_id=f"D{i}")
    assert any("truncated" in p for p in short.verify_checkpoint(cp, key).problems)
    # wrong key / edited checkpoint / unsigned
    assert not ch.verify_checkpoint(cp, b"other").ok
    edited = Checkpoint.from_dict({**cp.to_dict(), "length": 3})
    assert not ch.verify_checkpoint(edited, key).ok
    unsigned = ch.checkpoint(None)
    assert not unsigned.signed and ch.verify_checkpoint(unsigned).ok
    assert json.loads(json.dumps(unsigned.to_dict()))["signature"] is None
