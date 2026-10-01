"""Asymmetric audit checkpoints and external anchoring (issue #17).

INV-AUDIT-1  Audit corruption is detected.
INV-AUDIT-2  A consistent rewrite of history is detectable only where an external
             checkpoint covers it: before the latest anchored checkpoint it is an
             anchor_mismatch; after it, nothing can tell -- and the report says so.

The checkpoint is signed with Ed25519 by a key whose only purpose is audit checkpoints;
the verifier holds the public key, so verifying cannot forge (the HMAC checkpoint could).
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sentinel.audit.anchor import (
    ANCHORED,
    MISMATCH,
    NOT_ANCHORED,
    AnchorError,
    DirectoryAnchor,
    JsonlAnchor,
    anchoring,
    checkpoint_digest,
    sign_checkpoint_statement,
)
from sentinel.audit.chain import AuditChain, AuditEvent, JsonlBackend, chain_hash
from sentinel.trust import crypto
from sentinel.trust.keys import AUDIT_CHECKPOINT, FACTS, TrustedKey, TrustStore

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def _key(purpose=AUDIT_CHECKPOINT, issuer="audit-notary", **kw):
    private = crypto.generate()
    pub = crypto.public_raw(private)
    key = TrustedKey(
        key_id=crypto.key_id(pub),
        issuer=issuer,
        public_key=pub,
        purpose=purpose,
        scopes=frozenset({"*"}),
        not_before=NOW - timedelta(days=1),
        **kw,
    )
    return private, key


def _chain(path, n=6) -> AuditChain:
    c = AuditChain(JsonlBackend(str(path)))
    for i in range(n):
        c.append(actor="sentinel", workflow="dispute", action="DENY", decision_id=f"DEC-{i}")
    return c


def _records(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def _write(path, records):
    path.write_text(
        "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records)
    )


def _rewrite(path, at: int, **changes):
    """A storage attacker's consistent rewrite: change event ``at`` and recompute every
    hash from there, so the chain verifies on its own."""
    recs = _records(path)
    recs[at] = {**recs[at], **changes}
    prev = recs[at - 1]["event_hash"] if at else "0" * 64
    for r in recs[at:]:
        r["previous_hash"] = prev
        r["event_hash"] = chain_hash(AuditEvent.from_dict(r).body(), prev)
        prev = r["event_hash"]
    _write(path, recs)


def _publish(path, anchor, private, signer="audit-notary"):
    held = anchor.all()
    stmt = sign_checkpoint_statement(
        private,
        signer=signer,
        records=_records(path),
        previous=held[-1] if held else None,
        issued_at=NOW,
    )
    anchor.publish(stmt)
    return stmt


@pytest.fixture()
def setup(tmp_path):
    log = tmp_path / "audit.jsonl"
    _chain(log, 4)
    private, key = _key()
    anchor = DirectoryAnchor(tmp_path / "anchor")
    _publish(log, anchor, private)  # checkpoint 1 covers events 0..3
    c = AuditChain(JsonlBackend(str(log)))
    for i in (4, 5):
        c.append(actor="sentinel", workflow="dispute", action="DENY", decision_id=f"DEC-{i}")
    return log, anchor, private, TrustStore.empty().with_key(key)


def test_the_chain_is_anchored_through_the_checkpoint(setup):
    log, anchor, _, trust = setup
    a = anchoring(_records(log), anchor, trust)
    assert a.status == ANCHORED and a.covered_length == 4 and a.unanchored_events == 2
    assert a.for_event(3) == ANCHORED and a.for_event(4) == NOT_ANCHORED
    assert a.to_dict()["latest_checkpoint"]["checkpoint_sequence"] == 1


def test_no_anchor_means_not_anchored(tmp_path):
    log = tmp_path / "audit.jsonl"
    _chain(log)
    a = anchoring(_records(log), None, TrustStore.empty())
    assert a.status == NOT_ANCHORED and a.for_event(0) == NOT_ANCHORED


def test_inv_audit_1_corruption_below_a_checkpoint_is_detected(setup):
    log, anchor, _, trust = setup
    recs = _records(log)
    recs[1]["action"] = "ALLOW"  # edited, not resealed
    _write(log, recs)
    assert not AuditChain(JsonlBackend(str(log))).verify().ok
    a = anchoring(recs, anchor, trust)
    assert a.status == MISMATCH and a.for_event(5) == MISMATCH


def test_inv_audit_2_a_rewrite_before_the_checkpoint_is_detected(setup):
    """Half A: the rewrite passes the chain's own check and fails against the anchor."""
    log, anchor, _, trust = setup
    _rewrite(log, 2, action="ALLOW")
    assert AuditChain(JsonlBackend(str(log))).verify().ok  # self-consistent again
    a = anchoring(_records(log), anchor, trust)
    assert a.status == MISMATCH
    assert any("does not recompute to the signed head" in r for r in a.reasons)


def test_inv_audit_2_a_rewrite_after_the_checkpoint_cannot_be_detected(setup):
    """Half B, stated honestly: events after the latest anchored checkpoint are covered
    by nothing, so their consistent rewrite passes -- and they are reported as
    not_anchored, never as anchored. Anchoring protects from the moment of anchoring."""
    log, anchor, private, trust = setup
    _rewrite(log, 4, action="ALLOW")
    a = anchoring(_records(log), anchor, trust)
    assert a.status == ANCHORED and a.covered_length == 4
    assert a.for_event(4) == NOT_ANCHORED and a.unanchored_events == 2
    _publish(log, anchor, private)  # the forged tail is anchored from now on
    assert anchoring(_records(log), anchor, trust).for_event(4) == ANCHORED


@pytest.mark.parametrize(
    "who, why",
    [
        ({"purpose": FACTS}, "not trusted to sign audit checkpoints"),
        ({"issuer": "someone-else"}, "belongs to someone-else"),
    ],
)
def test_only_an_audit_checkpoint_key_counts(tmp_path, who, why):
    log = tmp_path / "audit.jsonl"
    _chain(log)
    private, key = _key(**who)
    anchor = DirectoryAnchor(tmp_path / "anchor")
    _publish(log, anchor, private)
    a = anchoring(_records(log), anchor, TrustStore.empty().with_key(key))
    assert a.status == MISMATCH and any(why in r for r in a.reasons)


def test_an_unknown_checkpoint_key_is_a_mismatch_and_a_revoked_one_retires(setup):
    """A revoked key's checkpoints no longer count -- but they are not tampering: the
    chain is not_anchored (with a note) until a current key re-anchors it."""
    log, anchor, _, trust = setup
    (key,) = trust.keys.values()
    assert "unknown signer" in anchoring(_records(log), anchor, TrustStore.empty()).reasons[0]
    revoked = TrustStore.empty().with_key(replace(key, revoked_at=NOW, revocation_reason="leaked"))
    a = anchoring(_records(log), anchor, revoked)
    assert a.status == NOT_ANCHORED and "revoked since" in a.notes[0] and not a.reasons


def test_an_edited_checkpoint_file_is_a_mismatch(setup):
    log, anchor, _, trust = setup
    (f,) = sorted(anchor.path.glob("cp-*.json"))
    os.chmod(f, 0o644)
    stmt = json.loads(f.read_text())
    stmt["length"] = 3  # shrink what it covers
    f.write_text(json.dumps(stmt))
    a = anchoring(_records(log), anchor, trust)
    assert a.status == MISMATCH and "does not verify" in a.reasons[0]


def test_the_anchor_is_append_only(setup):
    log, anchor, private, _ = setup
    held = anchor.all()
    again = sign_checkpoint_statement(
        private, signer="audit-notary", records=_records(log), previous=None, issued_at=NOW
    )
    with pytest.raises(AnchorError, match="not next"):
        anchor.publish(again)  # a second "checkpoint 1"
    unlinked = dict(
        sign_checkpoint_statement(
            private, signer="audit-notary", records=_records(log), previous=held[-1], issued_at=NOW
        ),
        previous_checkpoint="0" * 64,
    )
    with pytest.raises(AnchorError, match="link"):
        anchor.publish(unlinked)
    stmt = _publish(log, anchor, private)
    assert stmt["previous_checkpoint"] == checkpoint_digest(held[-1])
    f = sorted(anchor.path.glob("cp-*.json"))[-1]
    with pytest.raises(FileExistsError):
        os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL)


def test_a_jsonl_anchor_works_the_same_way(tmp_path):
    log = tmp_path / "audit.jsonl"
    _chain(log)
    private, key = _key()
    anchor = JsonlAnchor(tmp_path / "anchor.jsonl")
    _publish(log, anchor, private)
    trust = TrustStore.empty().with_key(key)
    assert anchoring(_records(log), anchor, trust).status == ANCHORED
    _rewrite(log, 0, action="ALLOW")
    assert anchoring(_records(log), anchor, trust).status == MISMATCH


def test_a_checkpoint_for_another_chain_does_not_cover_this_one(tmp_path):
    a_log, b_log = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _chain(a_log)
    c = AuditChain(JsonlBackend(str(b_log)))
    for i in range(6):
        c.append(actor="sentinel", workflow="dispute", action="ALLOW", decision_id=f"X-{i}")
    private, key = _key()
    anchor = DirectoryAnchor(tmp_path / "anchor")
    _publish(a_log, anchor, private)
    a = anchoring(_records(b_log), anchor, TrustStore.empty().with_key(key))
    assert a.status == MISMATCH and "another chain" in a.reasons[0]


# ---- the application ---------------------------------------------------------------------------
def _app_with_anchor(tmp_path):
    from sentinel.app import SentinelApp

    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    private, key = _key()
    app.runtime.trust = app.runtime.trust.with_key(key)
    app.anchor = DirectoryAnchor(tmp_path / "anchor")
    return app, private


def test_the_app_publishes_records_and_replays_anchoring(tmp_path):
    from sentinel.replay.engine import ReplayOverrides

    app, private = _app_with_anchor(tmp_path)
    d = app.store.all_disputes()[0]
    b = app.evaluate_dispute("", dispute_id=d.dispute_id)
    stmt = app.publish_checkpoint(private, "audit-notary")
    assert app.audit_anchoring().unanchored_events == 0  # the publication record is not a gap
    published = [e for e in app.runtime.audit.events() if e.action == "CHECKPOINT_PUBLISHED"]
    assert published and published[-1].detail["digest"] == checkpoint_digest(stmt)
    assert app.audit_anchoring().status == ANCHORED
    r = app.replay(b.decision.decision_id, ReplayOverrides())
    assert r.anchoring["decision_event"] == ANCHORED and r.record_verified
    assert app.system_info()["audit"]["anchor"] == app.anchor.name  # cheap: no re-verify


def test_deleting_the_newest_anchored_checkpoint_is_visible(tmp_path):
    app, private = _app_with_anchor(tmp_path)
    app.evaluate_dispute("", dispute_id=app.store.all_disputes()[0].dispute_id)
    app.publish_checkpoint(private, "audit-notary")
    app.publish_checkpoint(private, "audit-notary")
    newest = sorted(app.anchor.path.glob("cp-*.json"))[-1]
    os.chmod(newest, 0o644)
    newest.unlink()
    a = app.audit_anchoring()
    assert a.status == MISMATCH and any("does not hold" in r for r in a.reasons)


def test_a_rewritten_decision_event_fails_replay_verification(tmp_path):
    from sentinel.replay.engine import ReplayOverrides

    app, private = _app_with_anchor(tmp_path)
    d = app.store.all_disputes()[0]
    b = app.evaluate_dispute("", dispute_id=d.dispute_id)
    app.publish_checkpoint(private, "audit-notary")
    # a storage attacker rewrites the decision's event and reseals the whole chain
    rows = app.store._rows("SELECT sequence, payload FROM audit_events ORDER BY sequence")
    recs = [json.loads(r["payload"]) for r in rows]
    at = next(i for i, r in enumerate(recs) if r["decision_id"] == b.decision.decision_id)
    recs[at]["risk_score"] = 1
    prev = recs[at - 1]["event_hash"] if at else "0" * 64
    for r in recs[at:]:
        r["previous_hash"] = prev
        r["event_hash"] = chain_hash(AuditEvent.from_dict(r).body(), prev)
        prev = r["event_hash"]
        app.store._exec(
            "UPDATE audit_events SET payload = ?, previous_hash = ?, event_hash = ? "
            "WHERE sequence = ?",
            (json.dumps(r), r["previous_hash"], r["event_hash"], r["sequence"]),
        )
    assert app.verify_audit().ok  # the chain alone cannot tell
    r = app.replay(b.decision.decision_id, ReplayOverrides())
    assert r.anchoring["decision_event"] == MISMATCH and not r.record_verified


def test_the_cli_signs_anchors_and_verifies(tmp_path, capsys):
    from sentinel.cli.main import main

    db, key, trust = tmp_path / "s.db", tmp_path / "cp.pem", tmp_path / "trust.json"
    anchor = tmp_path / "anchor"
    assert (
        main(
            [
                "trust",
                "keygen",
                "--issuer",
                "audit-notary",
                "--purpose",
                "audit-checkpoint",
                "--key-out",
                str(key),
                "--trust-out",
                str(trust),
            ]
        )
        == 0
    )
    from sentinel.app import SentinelApp

    seeded = SentinelApp.open(str(db))
    seeded.generate_dataset(3, 10, 4, 80)
    seeded.evaluate_dispute("", dispute_id=seeded.store.all_disputes()[0].dispute_id)
    seeded.store.close()
    base = ["--db", str(db), "--trust-store", str(trust)]
    assert (
        main(
            [
                *base,
                "audit",
                "checkpoint",
                "--sign-key",
                str(key),
                "--signer",
                "audit-notary",
                "--anchor",
                str(anchor),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main([*base, "audit", "verify", "--anchor", str(anchor)]) == 0
    assert "anchored through" in capsys.readouterr().out
    # right after an honest checkpoint nothing is unanchored (its publication record is not)
    assert main([*base, "audit", "verify", "--anchor", str(anchor), "--require-anchored"]) == 0
    capsys.readouterr()
    assert main([*base, "--json", "audit", "verify", "--anchor", str(anchor)]) == 0
    assert json.loads(capsys.readouterr().out)["anchoring"]["status"] == "anchored"
    later = SentinelApp.open(str(db))
    later.evaluate_dispute("", dispute_id=later.store.all_disputes()[1].dispute_id)
    later.store.close()
    assert main([*base, "audit", "verify", "--anchor", str(anchor), "--require-anchored"]) == 3


# ---- regressions: the adversarial review of #17 ------------------------------------------------
def test_r1_no_checkpoint_is_signed_over_a_broken_chain(setup):
    log, anchor, private, _ = setup
    recs = _records(log)
    recs[-1]["action"] = "ALLOW"  # one byte, not resealed
    _write(log, recs)
    with pytest.raises(AnchorError, match="does not verify from event #5"):
        _publish(log, anchor, private)
    assert len(anchor.all()) == 1  # nothing was written to the append-only anchor
    with pytest.raises(AnchorError, match="not a checkpoint statement"):
        anchor.publish({"checkpoint_sequence": 2, "head_hash": None})


def test_r1_the_app_refuses_to_checkpoint_a_chain_that_disagrees_with_its_anchor(tmp_path):
    app, private = _app_with_anchor(tmp_path)
    app.evaluate_dispute("", dispute_id=app.store.all_disputes()[0].dispute_id)
    app.publish_checkpoint(private, "audit-notary")
    newest = sorted(app.anchor.path.glob("cp-*.json"))[-1]
    os.chmod(newest, 0o644)
    newest.unlink()  # the anchor lost a checkpoint the chain says it published
    with pytest.raises(ValueError, match="refusing to checkpoint"):
        app.publish_checkpoint(private, "audit-notary")


def test_r2_a_checkpoint_job_in_another_process_does_not_break_the_server(tmp_path):
    """The job appends CHECKPOINT_PUBLISHED from its own process; the server's chain
    adopts records that link to its head instead of failing every decision."""
    from sentinel.app import SentinelApp
    from sentinel.data.store import SentinelStore

    db = str(tmp_path / "s.db")
    server = SentinelApp.open(db)
    server.generate_dataset(3, 10, 4, 80)
    ids = [d.dispute_id for d in server.store.all_disputes()]
    server.evaluate_dispute("", dispute_id=ids[0])
    private, key = _key()
    job = SentinelApp(SentinelStore(db))  # the scheduled job: another connection
    job.runtime.trust = job.runtime.trust.with_key(key)
    job.anchor = DirectoryAnchor(tmp_path / "anchor")
    job.publish_checkpoint(private, "audit-notary")
    b = server.evaluate_dispute("", dispute_id=ids[1])  # used to raise AuditIntegrityError
    assert b.audit_event is not None and server.verify_audit().ok


def test_r2_records_that_do_not_link_are_still_refused(tmp_path):
    from sentinel.audit.chain import AuditIntegrityError
    from sentinel.data.store import SentinelStore, SqliteAuditBackend

    store = SentinelStore(str(tmp_path / "s.db"))
    chain = AuditChain(SqliteAuditBackend(store))
    for i in range(3):
        chain.append(actor="sentinel", workflow="dispute", action="DENY", decision_id=f"D-{i}")
    other = AuditChain(SqliteAuditBackend(store))  # another writer, its own view
    other.append(actor="sentinel", workflow="system", action="X", kind="system")
    chain.append(actor="sentinel", workflow="dispute", action="DENY")  # adopts the linked one
    rec = store._rows("SELECT payload FROM audit_events WHERE sequence = 4")[0]["payload"]
    forged = {**json.loads(rec), "sequence": 5, "event_id": "AUD-forged", "previous_hash": "f" * 64}
    store._exec(
        "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
        (
            5,
            "AUD-forged",
            None,
            "f" * 64,
            forged["event_hash"],
            forged["timestamp"],
            json.dumps(forged),
        ),
    )
    with pytest.raises(AuditIntegrityError):
        chain.append(actor="sentinel", workflow="dispute", action="DENY")


def test_r3_removing_the_latest_publication_record_is_a_mismatch(tmp_path):
    app, private = _app_with_anchor(tmp_path)
    app.evaluate_dispute("", dispute_id=app.store.all_disputes()[0].dispute_id)
    app.publish_checkpoint(private, "audit-notary")
    assert app.audit_anchoring().status == ANCHORED
    last = app.store._rows("SELECT MAX(sequence) AS s FROM audit_events")[0]["s"]
    app.store._exec("DELETE FROM audit_events WHERE sequence = ?", (last,))
    a = app.audit_anchoring()
    assert a.status == MISMATCH and any("publication record is missing" in r for r in a.reasons)


def test_r4_re_anchoring_after_a_key_is_revoked(setup):
    log, anchor, old, trust = setup
    (old_key,) = trust.keys.values()
    new, new_key = _key(issuer="audit-notary-2")
    rotated = (
        TrustStore.empty()
        .with_key(replace(old_key, revoked_at=NOW, revocation_reason="compromised"))
        .with_key(new_key)
    )
    _publish(log, anchor, new, signer="audit-notary-2")
    a = anchoring(_records(log), anchor, rotated)
    assert a.status == ANCHORED and a.covered_length == 6 and a.notes


def test_r8_an_integrity_failure_outranks_require_anchored(tmp_path, capsys):
    from sentinel.cli.main import main

    log = tmp_path / "audit.jsonl"
    _chain(log)
    private, key = _key()
    anchor = DirectoryAnchor(tmp_path / "anchor")
    _publish(log, anchor, private)
    trust = tmp_path / "trust.json"
    trust.write_text(TrustStore.empty().with_key(key).dumps())
    base = ["--trust-store", str(trust), "audit", "verify", "--file", str(log)]
    where = str(anchor.path)
    # a library-built chain records no publication: the --file check asks for one
    assert main([*base, "--anchor", where]) == 2
    _rewrite(log, 1, action="ALLOW")
    assert main([*base, "--anchor", where, "--require-anchored"]) == 2  # never masked by 3
    capsys.readouterr()
    assert main(["audit", "verify", "--anchor", where, "--checkpoint", str(log)]) != 0
    assert "two different checks" in capsys.readouterr().err


def test_r9_a_non_utf8_byte_in_a_jsonl_anchor_is_a_mismatch_not_an_error(tmp_path):
    log = tmp_path / "audit.jsonl"
    _chain(log)
    private, key = _key()
    anchor = JsonlAnchor(tmp_path / "anchor.jsonl")
    _publish(log, anchor, private)
    with open(anchor.path, "ab") as fh:
        fh.write(b"\xff\xfe{bad\n")
    a = anchoring(_records(log), anchor, TrustStore.empty().with_key(key))
    assert a.status == MISMATCH and "unreadable" in a.reasons[0]


def test_r10_an_unreadable_anchor_entry_names_no_path(tmp_path):
    log = tmp_path / "audit.jsonl"
    _chain(log)
    private, key = _key()
    anchor = DirectoryAnchor(tmp_path / "anchor")
    _publish(log, anchor, private)
    (anchor.path / "cp-00000002-x.json").mkdir()
    a = anchoring(_records(log), anchor, TrustStore.empty().with_key(key))
    assert a.status == MISMATCH and str(tmp_path) not in " ".join(a.reasons)


def test_r12_a_relabelled_sequence_breaks_the_chain(setup):
    log, anchor, _, trust = setup
    recs = _records(log)
    recs[5]["sequence"] = 0
    recs[5]["event_hash"] = chain_hash(
        AuditEvent.from_dict(recs[5]).body(), recs[5]["previous_hash"]
    )
    _write(log, recs)
    a = anchoring(_records(log), anchor, trust)
    assert a.for_event(0) == ANCHORED  # event #0 is genuinely covered
    assert a.unanchored_events == 2  # the relabelled one is not "covered" by its claim


@pytest.mark.parametrize("field", ["head_hash", "chain_id"])
def test_the_anchor_refuses_a_digest_with_a_trailing_newline(tmp_path, field):
    """``$`` also matches before a final newline; digests are full matches."""
    log = tmp_path / "audit.jsonl"
    _chain(log, 3)
    private, _ = _key()
    stmt = sign_checkpoint_statement(
        private, signer="audit-notary", records=_records(log), previous=None, issued_at=NOW
    )
    stmt[field] += "\n"
    with pytest.raises(AnchorError, match="SHA-256"):
        DirectoryAnchor(tmp_path / "anchor").publish(stmt)
