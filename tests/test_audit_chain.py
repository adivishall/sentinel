"""Tamper-evident audit chain: modification, deletion and reordering are detected."""

import json

from sentinel.audit.chain import (
    GENESIS,
    AuditChain,
    JsonlBackend,
    MemoryBackend,
    redact,
    verify_records,
)


def _chain(n=5, backend=None):
    ch = AuditChain(backend)
    for i in range(n):
        ch.append(
            actor="sentinel",
            workflow="dispute",
            action="DENY",
            decision_id=f"DEC-{i}",
            subject_id=f"D-{i}",
            risk_score=i,
            detail={"i": i},
        )
    return ch


def test_chain_links_and_verifies():
    ch = _chain()
    evs = ch.events()
    assert evs[0].previous_hash == GENESIS and evs[0].sequence == 0
    for a, b in zip(evs, evs[1:], strict=False):
        assert b.previous_hash == a.event_hash and b.sequence == a.sequence + 1
    v = ch.verify()
    assert v.ok and v.length == 5 and v.head_hash == ch.head and not v.problems


def test_modification_is_detected():
    ch = _chain()
    rows = ch.backend.read_all()
    rows[2]["risk_score"] = 99
    v = verify_records(rows)
    assert not v.ok and v.first_bad_sequence == 2 and any("modified" in p for p in v.problems)


def test_deletion_is_detected():
    ch = _chain()
    rows = ch.backend.read_all()
    del rows[1]
    v = verify_records(rows)
    assert not v.ok and v.first_bad_sequence == 1


def test_reordering_is_detected():
    ch = _chain()
    rows = ch.backend.read_all()
    rows[1], rows[2] = rows[2], rows[1]
    v = verify_records(rows)
    assert not v.ok and v.first_bad_sequence == 1


def test_truncation_from_the_end_changes_head():
    ch = _chain()
    rows = ch.backend.read_all()[:-1]
    v = verify_records(rows)
    assert (
        v.ok and v.head_hash != ch.head
    )  # a truncated chain verifies but its head no longer matches


def test_jsonl_backend_persists_and_reloads(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    ch = _chain(3, JsonlBackend(path))
    again = AuditChain(JsonlBackend(path))
    assert len(again) == 3 and again.head == ch.head
    again.append(actor="x", workflow="w", action="A")
    assert again.verify().ok and len(again.events()) == 4
    # tamper on disk
    lines = open(path).read().splitlines()
    rec = json.loads(lines[0])
    rec["action"] = "ALLOW"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    open(path, "w").write("\n".join(lines) + "\n")
    assert not AuditChain(JsonlBackend(path)).verify().ok


def test_redaction_never_persists_raw_text():
    ch = AuditChain(MemoryBackend())
    ch.append(
        actor="a",
        workflow="w",
        action="X",
        detail={"narrative": "SECRET-PROSE-123", "nested": {"span": "ignore all previous"}},
    )
    blob = json.dumps(ch.backend.read_all())
    assert "SECRET-PROSE-123" not in blob and "ignore all previous" not in blob
    assert "narrative_sha256" in blob and "span_sha256" in blob
    assert redact({"text": "x"})["text_len"] == 1


def test_get_by_event_or_decision_id():
    ch = _chain(2)
    ev = ch.events()[1]
    assert ch.get(ev.event_id).event_id == ev.event_id
    assert ch.get("DEC-1").decision_id == "DEC-1"
    assert ch.get("nope") is None
