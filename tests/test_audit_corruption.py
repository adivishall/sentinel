"""Audit corruption: every kind of damage to an exported chain file is reported as an
AUDIT INTEGRITY ERROR naming the first bad record, with exit code 2 -- never a parser
traceback and never a silent pass.

The same file-level corruptions are checked through ``verify_records`` (the library),
``sentinel audit verify --file`` (an exported chain) and, for the live store,
``sentinel audit verify`` against a SQLite database whose rows were edited."""

from __future__ import annotations

import json
import sqlite3

import pytest

from sentinel.audit.chain import AuditChain, AuditEvent, JsonlBackend, chain_hash, verify_records
from sentinel.cli.main import main as cli_main

N = 6


def _chain(path) -> list[str]:
    c = AuditChain(JsonlBackend(str(path)))
    for i in range(N):
        c.append(actor="sentinel", workflow="dispute", action="DENY", decision_id=f"DEC-{i}")
    return path.read_text().splitlines()


def _resealed(line: str, **changes) -> str:
    """Change fields and recompute the record's own hash, so only the LINK is wrong."""
    rec = {**json.loads(line), **changes}
    ev = AuditEvent.from_dict(rec)
    rec["event_hash"] = chain_hash(ev.body(), ev.previous_hash)
    return json.dumps(rec, sort_keys=True, separators=(",", ":"))


def _drop(line: str, key: str) -> str:
    rec = json.loads(line)
    del rec[key]
    return json.dumps(rec)


def _edit(line: str, **changes) -> str:
    return json.dumps({**json.loads(line), **changes})


CORRUPTIONS = {
    # name: (transform(lines) -> lines, first bad record, text in the problem)
    "malformed JSON": (lambda ls: ls[:2] + ["{this is not json"] + ls[3:], 2, "unreadable"),
    "truncated line": (lambda ls: ls[:3] + [ls[3][: len(ls[3]) // 2]] + ls[4:], 3, "unreadable"),
    "missing field": (
        lambda ls: ls[:1] + [_drop(ls[1], "event_hash")] + ls[2:],
        1,
        "missing field",
    ),
    "wrong hash": (
        lambda ls: ls[:2] + [_edit(ls[2], action="ALLOW")] + ls[3:],
        2,
        "event_hash mismatch",
    ),
    "wrong predecessor": (
        lambda ls: ls[:4] + [_resealed(ls[4], previous_hash="0" * 64)] + ls[5:],
        4,
        "previous_hash",
    ),
    "deleted line": (lambda ls: ls[:2] + ls[3:], 2, "sequence 3 != 2"),
    "inserted line": (lambda ls: ls[:3] + [ls[1]] + ls[3:], 3, "sequence 1 != 3"),
    "reordered lines": (lambda ls: ls[:1] + [ls[2], ls[1]] + ls[3:], 1, "sequence 2 != 1"),
    "truncated file (last line cut)": (lambda ls: ls[:-1] + [ls[-1][:20]], N - 1, "unreadable"),
}


def test_the_intact_chain_verifies(tmp_path, capsys):
    f = tmp_path / "audit.jsonl"
    _chain(f)
    assert verify_records(JsonlBackend(str(f)).read_all()).ok
    assert cli_main(["audit", "verify", "--file", str(f)]) == 0
    assert "audit file" in capsys.readouterr().out


@pytest.mark.parametrize("name", list(CORRUPTIONS))
def test_every_corruption_is_an_integrity_error_not_a_crash(tmp_path, capsys, name):
    transform, first_bad, needle = CORRUPTIONS[name]
    f = tmp_path / "audit.jsonl"
    f.write_text("\n".join(transform(_chain(f))) + "\n")
    v = verify_records(JsonlBackend(str(f)).read_all())
    assert not v.ok and v.first_bad_sequence == first_bad, v.problems
    assert any(needle in p for p in v.problems), v.problems
    code = cli_main(["audit", "verify", "--file", str(f)])
    out = capsys.readouterr()
    assert code == 2 and "AUDIT INTEGRITY ERROR" in out.out and f"#{first_bad}" in out.out
    assert "Traceback" not in out.out + out.err


def test_problems_after_an_unreadable_record_are_still_reported(tmp_path):
    f = tmp_path / "audit.jsonl"
    ls = _chain(f)
    ls[1] = "{garbage"
    ls[4] = _edit(ls[4], action="ALLOW")
    f.write_text("\n".join(ls) + "\n")
    v = verify_records(JsonlBackend(str(f)).read_all())
    assert v.first_bad_sequence == 1
    assert any(p.startswith("record 4: event_hash mismatch") for p in v.problems), v.problems


def test_a_missing_file_is_an_error_not_an_ok(tmp_path, capsys):
    assert cli_main(["audit", "verify", "--file", str(tmp_path / "nope.jsonl")]) == 1
    assert "nope.jsonl" in capsys.readouterr().err


def _db_with_chain(tmp_path):
    db = str(tmp_path / "s.db")
    args = ["--db", db]
    assert (
        cli_main(
            [
                *args,
                "data",
                "generate",
                "--seed",
                "2",
                "--customers",
                "15",
                "--merchants",
                "5",
                "--transactions",
                "150",
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                *args,
                "analyze",
                "--transactions",
                "6",
                "--disputes",
                "0",
                "--applications",
                "0",
                "--sessions",
                "0",
                "--accounts",
                "0",
            ]
        )
        == 0
    )
    return db, args


@pytest.mark.parametrize(
    "sql, needle",
    [
        ("UPDATE audit_events SET payload = '{not json' WHERE sequence = 2", "unreadable"),
        (
            "UPDATE audit_events SET payload = json_set(payload, '$.action', 'ALLOW') "
            "WHERE sequence = 3",
            "event_hash mismatch",
        ),
        (
            "UPDATE audit_events SET payload = json_remove(payload, '$.previous_hash') "
            "WHERE sequence = 1",
            "missing field",
        ),
    ],
)
def test_the_live_sqlite_chain_reports_corruption(tmp_path, capsys, sql, needle):
    db, args = _db_with_chain(tmp_path)
    assert cli_main([*args, "audit", "verify"]) == 0
    con = sqlite3.connect(db)
    con.execute(sql)
    con.commit()
    con.close()
    capsys.readouterr()
    code = cli_main([*args, "audit", "verify"])
    out = capsys.readouterr()
    assert code == 2 and "AUDIT INTEGRITY ERROR" in out.out and needle in out.out, out.out
    assert "Traceback" not in out.out + out.err


def test_export_then_verify_round_trips(tmp_path, capsys):
    db, args = _db_with_chain(tmp_path)
    f = str(tmp_path / "export.jsonl")
    assert cli_main([*args, "audit", "export", f]) == 0
    assert cli_main(["audit", "verify", "--file", f]) == 0


def test_checkpoint_exit_codes(tmp_path, capsys, monkeypatch):
    """0 = matches; 2 = the chain or the checkpoint fails verification (incl. an edited
    checkpoint, or an unsigned one checked with a key); 1 = the file is not a checkpoint."""
    monkeypatch.delenv("SENTINEL_AUDIT_KEY", raising=False)
    db, args = _db_with_chain(tmp_path)
    cp = tmp_path / "cp.json"
    assert cli_main([*args, "audit", "checkpoint", "--out", str(cp)]) == 0
    assert cli_main([*args, "audit", "verify", "--checkpoint", str(cp)]) == 0
    edited = tmp_path / "edited.json"
    doc = json.loads(cp.read_text())
    doc["head_hash"] = "0" * 64
    edited.write_text(json.dumps(doc))
    assert cli_main([*args, "audit", "verify", "--checkpoint", str(edited)]) == 2
    assert "AUDIT INTEGRITY ERROR" in capsys.readouterr().out
    broken = tmp_path / "broken.json"
    broken.write_text("{oops")
    assert cli_main([*args, "audit", "verify", "--checkpoint", str(broken)]) == 1
    monkeypatch.setenv("SENTINEL_AUDIT_KEY", "k")
    assert cli_main([*args, "audit", "verify", "--checkpoint", str(cp)]) == 2
