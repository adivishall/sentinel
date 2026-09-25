"""Release-candidate hardening: the findings of the final hostile review, pinned.

1. The authoritative evaluate routes and CLI commands never run an older policy
   version or a different risk model on request (a what-if is not an authorization);
   ``tests/test_evaluation_authority.py`` pins the structural rule behind it.
2. A case is resolved only by a recorded human decision.
3. The audit chain reports an unreadable record, an inserted record, a broken link
   and tampered index columns; refuses to append onto an inconsistent store; and a
   checkpoint names the record it disagrees with.
4. Replay compares the STORED decision (anchored to its audit event) with the
   recomputed one and reports a stored record that disagrees with the chain.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
import urllib.request

import pytest

from sentinel.api.server import make_server
from sentinel.app import SentinelApp
from sentinel.audit.chain import (
    AuditChain,
    AuditIntegrityError,
    Checkpoint,
    JsonlBackend,
    MemoryBackend,
)
from sentinel.cases.service import CaseService, InvalidTransition
from sentinel.cli.main import main as cli_main
from sentinel.data.store import SentinelStore, SqliteAuditBackend
from sentinel.decision.workflows import RunOptions
from sentinel.domain.enums import CaseStatus
from sentinel.replay.engine import ReplayOverrides
from sentinel.risk import scoring

LEDGER_REFUNDED = {
    "amount": 18000,
    "delivery_status": "not_delivered",
    "policy_auto_limit": 50000,
    "refund_state": "refunded",
}
CLAIM = "My order never arrived, it never came, please refund."


@pytest.fixture(scope="module")
def app():
    a = SentinelApp.demo(seed=42, customers=50, merchants=10, transactions=600)
    a.analyze(transactions=15, disputes=8, applications=4, sessions=6, accounts=3)
    return a


@pytest.fixture(scope="module")
def server(app):
    httpd = make_server(app, "127.0.0.1", 0)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _post(url, obj):
    req = urllib.request.Request(
        url,
        data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.status, json.loads(resp.read())


# ---- 1. what-if switches are not authorizations ---------------------------------------------
def test_policy_version_override_would_pay_a_second_refund_so_the_api_refuses_it(server, app):
    # The defect: dispute-refund@v1 has no block-already-refunded rule.
    b = app.evaluate_dispute(CLAIM, LEDGER_REFUNDED, options=RunOptions(policy_version=1))
    assert b.decision.executed_capability is not None  # what the override would do ...
    assert not b.decision.authoritative and app.store.decision(b.decision.decision_id) is None
    latest = app.evaluate_dispute(CLAIM, LEDGER_REFUNDED)
    assert latest.decision.final_action.value == "DENY" and not latest.decision.executed
    code, body = _post(
        server + "/v1/disputes/evaluate",
        {"narrative": CLAIM, "ledger": LEDGER_REFUNDED, "options": {"policy_version": 1}},
    )
    assert code == 403 and "policy_version" in body["error"]
    code, body = _post(
        server + "/v1/transactions/evaluate",
        {
            "transaction_id": app.store.transactions(limit=1)[0].transaction_id,
            "options": {"risk_model": "txn-1.0"},
        },
    )
    assert code == 403 and "risk_model" in body["error"]
    # the same body without the override is accepted
    code, body = _post(
        server + "/v1/disputes/evaluate", {"narrative": CLAIM, "ledger": LEDGER_REFUNDED}
    )
    assert code == 200 and body["final_action"] == "DENY" and body["policy"]["version"] >= 3
    # replay keeps the what-if
    code, body = _post(
        server + "/v1/replay", {"decision_id": body["decision_id"], "policy_version": 1}
    )
    assert code == 200 and body["replayed"]["policy"] == "dispute-refund@v1"


def test_cli_authoritative_commands_refuse_what_if_switches(tmp_path, capsys):
    db = str(tmp_path / "s.db")
    assert (
        cli_main(
            [
                "--db",
                db,
                "data",
                "generate",
                "--seed",
                "1",
                "--customers",
                "20",
                "--merchants",
                "6",
                "--transactions",
                "200",
            ]
        )
        == 0
    )
    tid = SentinelApp.open(db).store.transactions(limit=1)[0].transaction_id
    for flag in (["--policy-version", "1"], ["--risk-model", "txn-1.0"], ["--unguarded"]):
        with pytest.raises(SystemExit) as e:  # the flags do not exist on this command
            cli_main(["--db", db, "transaction", "evaluate", tid, *flag])
        assert e.value.code == 2 and "unrecognized arguments" in capsys.readouterr().err
    assert cli_main(["--db", db, "transaction", "evaluate", tid]) == 0
    # the simulator keeps the switches; its what-if side is never recorded
    assert (
        cli_main(
            ["--db", db, "security", "attack", "--scenario", "direct_injection", "--unguarded"]
        )
        == 0
    )


# ---- 2. only a human resolves a case ------------------------------------------------------------
def test_a_status_transition_cannot_resolve_a_case(server, app):
    svc = CaseService()
    from sentinel.domain.enums import Workflow

    c = svc.open_manual(Workflow.DISPUTE, "manual", ("account:A",))
    c = svc.transition(c.case_id, CaseStatus.INVESTIGATING, actor="analyst")
    with pytest.raises(InvalidTransition):
        svc.transition(c.case_id, CaseStatus.RESOLVED, actor="an-agent")
    c = svc.record_human_decision(c.case_id, reviewer="senior", outcome="deny")
    assert c.status is CaseStatus.RESOLVED and c.human_decisions
    code, created = _post(
        server + "/v1/cases", {"case_type": "dispute", "title": "t", "entities": ["account:A"]}
    )
    code, body = _post(
        server + f"/v1/cases/{created['case_id']}/transition",
        {"status": "RESOLVED", "actor": "agent"},
    )
    assert code == 409 and "human decision" in body["error"]


# ---- 3. audit chain -----------------------------------------------------------------------------
def _chain(backend):
    ch = AuditChain(backend)
    for i in range(5):
        ch.append(actor="t", workflow="dispute", action="ALLOW", decision_id=f"DEC-{i}")
    assert ch.verify().ok
    return ch


def test_unreadable_record_is_reported_not_raised(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    _chain(JsonlBackend(path))
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[2] = "{not json"
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    v = AuditChain(JsonlBackend(path)).verify()
    assert not v.ok and v.first_bad_sequence == 2 and "unreadable" in v.problems[0]
    db = str(tmp_path / "audit.db")
    store = SentinelStore(db)
    _chain(SqliteAuditBackend(store))
    c = sqlite3.connect(db)
    c.execute("UPDATE audit_events SET payload = '{broken' WHERE sequence = 3")
    c.commit()
    c.close()
    v = AuditChain(SqliteAuditBackend(SentinelStore(db))).verify()
    assert not v.ok and v.first_bad_sequence == 3 and "unreadable" in v.problems[0]


def test_inserted_record_and_broken_link_are_named(tmp_path):
    path = str(tmp_path / "audit.jsonl")
    _chain(JsonlBackend(path))
    rows = [json.loads(ln) for ln in open(path, encoding="utf-8").read().splitlines()]
    inserted = dict(rows[1])
    inserted["event_id"] = "AUD-forged"
    rows.insert(2, inserted)
    open(path, "w", encoding="utf-8").write("\n".join(json.dumps(r) for r in rows) + "\n")
    v = AuditChain(JsonlBackend(path)).verify()
    assert not v.ok and v.first_bad_sequence == 2 and any("sequence" in p for p in v.problems)
    rows = [json.loads(ln) for ln in open(path, encoding="utf-8").read().splitlines()]
    del rows[2]
    rows[3]["previous_hash"] = "f" * 64
    open(path, "w", encoding="utf-8").write("\n".join(json.dumps(r) for r in rows) + "\n")
    v = AuditChain(JsonlBackend(path)).verify()
    assert not v.ok and v.first_bad_sequence == 3 and any("chain broken" in p for p in v.problems)


def test_sqlite_index_columns_are_cross_checked_against_the_hashed_record(tmp_path):
    db = str(tmp_path / "audit.db")
    store = SentinelStore(db)
    ch = _chain(SqliteAuditBackend(store))
    full = ch.backend.read_all()
    assert ch.backend.find(event_id=str(full[3]["event_id"])) == full[3]
    assert ch.backend.find(decision_id="DEC-2") == full[2]
    assert ch.backend.at(4) == full[4]
    c = sqlite3.connect(db)
    c.execute("UPDATE audit_events SET decision_id = 'DEC-9' WHERE sequence = 2")  # redirect
    c.commit()
    c.close()
    fresh = AuditChain(SqliteAuditBackend(SentinelStore(db)))
    assert fresh.verify().ok  # payloads are intact ...
    with pytest.raises(AuditIntegrityError):  # ... but the lookup path notices the redirect
        fresh.backend.find(decision_id="DEC-9")
    with pytest.raises(AuditIntegrityError):
        fresh.at(2)
    c = sqlite3.connect(db)
    c.execute("UPDATE audit_events SET event_hash = 'ab' WHERE sequence = 4")  # tail index
    c.commit()
    c.close()
    with pytest.raises(AuditIntegrityError):  # opening the chain reads the tail through the check
        AuditChain(SqliteAuditBackend(SentinelStore(db)))


def test_append_fails_closed_on_every_backend_when_the_store_was_edited(tmp_path):
    mem = MemoryBackend()
    ch = _chain(mem)
    mem._rows.pop(1)  # deleted underneath the live chain
    with pytest.raises(AuditIntegrityError):
        ch.append(actor="t", workflow="dispute", action="ALLOW")
    path = str(tmp_path / "audit.jsonl")
    ch = _chain(JsonlBackend(path))
    rows = open(path, encoding="utf-8").read().splitlines()
    open(path, "w", encoding="utf-8").write("\n".join(rows[:-1]) + "\n")
    ch.backend._offsets = None  # the live chain re-reads the edited file
    with pytest.raises(AuditIntegrityError):
        ch.append(actor="t", workflow="dispute", action="ALLOW")


def test_checkpoint_failures_name_a_record_and_cover_keys(tmp_path):
    ch = _chain(MemoryBackend())
    good = ch.checkpoint()
    assert ch.verify_checkpoint(good).ok
    ch.append(actor="t", workflow="dispute", action="ALLOW")  # extending after a checkpoint is fine
    assert ch.verify_checkpoint(good).ok
    wrong_head = Checkpoint(good.length, "0" * 64, good.created_at)
    v = ch.verify_checkpoint(wrong_head)
    assert not v.ok and v.first_bad_sequence == good.length - 1 and "rewritten" in v.problems[0]
    short = AuditChain(MemoryBackend())
    short.append(actor="t", workflow="dispute", action="ALLOW")
    v = short.verify_checkpoint(good)
    assert not v.ok and v.first_bad_sequence == 1 and "truncated" in v.problems[0]
    key = b"k"
    signed = ch.checkpoint(key)
    assert ch.verify_checkpoint(signed, key).ok
    v = ch.verify_checkpoint(signed, None)
    assert not v.ok and "no key" in v.problems[0]
    v = ch.verify_checkpoint(ch.checkpoint(None), key)
    assert not v.ok and "unsigned" in v.problems[0]
    edited = Checkpoint(
        signed.length, signed.head_hash, "2000-01-01T00:00:00", signature=signed.signature
    )
    v = ch.verify_checkpoint(edited, key)
    assert not v.ok and "signature" in v.problems[0]


def test_cli_and_api_report_tampering(tmp_path, capsys, server, app):
    db = str(tmp_path / "t.db")
    assert (
        cli_main(
            [
                "--db",
                db,
                "data",
                "generate",
                "--seed",
                "3",
                "--customers",
                "20",
                "--merchants",
                "6",
                "--transactions",
                "200",
            ]
        )
        == 0
    )
    assert (
        cli_main(
            [
                "--db",
                db,
                "analyze",
                "--transactions",
                "5",
                "--disputes",
                "2",
                "--applications",
                "1",
                "--sessions",
                "1",
                "--accounts",
                "1",
            ]
        )
        == 0
    )
    assert cli_main(["--db", db, "audit", "verify"]) == 0
    c = sqlite3.connect(db)
    row = c.execute("SELECT payload FROM audit_events WHERE sequence = 1").fetchone()[0]
    p = json.loads(row)
    p["risk_score"] = 99
    c.execute("UPDATE audit_events SET payload = ? WHERE sequence = 1", (json.dumps(p),))
    c.commit()
    c.close()
    assert cli_main(["--db", db, "audit", "verify"]) == 2
    assert "TAMPERED" in capsys.readouterr().out
    # API: the shared demo app is intact
    s, body = _get(server + "/v1/audit/verify")
    assert s == 200 and body["ok"] is True and body["first_bad_sequence"] is None


# ---- 4. replay compares the stored decision -----------------------------------------------------
def test_replay_diffs_the_stored_decision_and_reports_engine_drift(app):
    b = app.evaluate_dispute(CLAIM, {"amount": 18000, "delivery_status": "not_delivered"})
    did = b.decision.decision_id
    n = len(app.runtime.audit)
    r = app.replay(did, ReplayOverrides())
    assert r.decision_diff == [] and not r.changed and not r.engine_drift
    assert r.replayed_decision.decision_id != did  # ids are never compared
    assert len(app.runtime.audit) == n + 1
    ev = app.runtime.audit.tail(1)[0]
    assert ev.kind == "replay" and ev.subject_id == r.replay_id and ev.decision_id == did
    assert app.audit_event(did)["kind"] != "replay"  # the decision's own event is still first
    r_pol = app.replay(did, ReplayOverrides(policy_version=1))
    assert any(d["field"] == "policy" and d["after"].endswith("@v1") for d in r_pol.decision_diff)
    # tamper with the stored record: the audit event anchors the recorded side, and the
    # disagreement is reported rather than trusted (tests/test_replay_integrity.py)
    stored = app.store.decision(did)
    recorded_score = stored["risk_score"]
    stored["risk_score"] = 99
    c = app.store._conn
    c.execute("UPDATE decisions SET payload = ? WHERE decision_id = ?", (json.dumps(stored), did))
    c.commit()
    r2 = app.replay(did, ReplayOverrides())
    assert r2.original["risk_score"] == recorded_score and not r2.record_verified
    assert any("risk_score" in i and "99" in i for i in r2.record_issues)
    assert "does not match its audit event" in r2.explanation


def test_replay_risk_model_change_is_explicit(app):
    t = app.store.transactions(limit=1)[0]
    b = app.evaluate_transaction(t.transaction_id)
    r = app.replay(
        b.decision.decision_id, ReplayOverrides(risk_model=scoring.TRANSACTION_V1.version)
    )
    assert {"field": "risk_model", "before": "txn-2.0", "after": "txn-1.0"} in r.decision_diff
    assert r.versions["risk_model"] == {"recorded": "txn-2.0", "replay": "txn-1.0"}
    assert "txn-1.0" in " ".join(r.overrides) and r.record_verified
