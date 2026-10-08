"""A backtest is many replays with the same guarantees: every row equals ``app.replay`` for
that decision, nothing recorded changes, exactly one audit event is added, unreplayable
decisions are counted with their reason, and the report is deterministic."""

from __future__ import annotations

import json

import pytest

from sentinel.app import SentinelApp
from sentinel.cli.main import main
from sentinel.domain.enums import FactKind
from sentinel.domain.ids import new_id
from sentinel.replay.backtest import LOOSENING, TIGHTENING, backtest
from sentinel.replay.engine import ReplayOverrides
from tests.records import ledger as complete

CLAIM = "My order never arrived, please refund."
# the documented replay example: denied by block-already-refunded (v3+), which v1 did not have
REFUNDED = {
    "amount": 18000,
    "delivery_status": "not_delivered",
    "policy_auto_limit": 50000,
    "refund_state": "refunded",
}
SUPPORTED = {"amount": 12000, "delivery_status": "not_delivered", "policy_auto_limit": 50000}
OVER_LIMIT = {"amount": 90000, "delivery_status": "not_delivered", "policy_auto_limit": 50000}

# the fields a replay reports for a decision, compared row by row with the backtest
REPLAY_FIELDS = (
    "original",
    "replayed",
    "changed",
    "decision_diff",
    "drift",
    "record_verified",
    "policy_drift",
    "original_drift",
    "versions",
    "facts",
    "policy_release",
)


@pytest.fixture()
def app():
    a = SentinelApp.demo(seed=11, customers=30, merchants=6, transactions=300)
    for over in (REFUNDED, SUPPORTED, OVER_LIMIT, SUPPORTED):
        env = a.issuer.sign(FactKind.DISPUTE_LEDGER, new_id("DSP"), complete(**over))
        a.evaluate_dispute(CLAIM, envelope=env)
    for t in a.store.all_transactions()[:3]:
        a.evaluate_transaction(t.transaction_id)
    return a


def _history(app, events: int | None = None):
    """Everything a backtest must leave alone: decisions, snapshots, replay records and
    the audit events that existed before it (the first ``events`` of the chain), as
    stored."""
    rows = app.store._rows("SELECT decision_id, payload, snapshot FROM decisions ORDER BY 1")
    chain = [e.to_dict() for e in app.runtime.audit.events()]
    return (
        [tuple(r) for r in rows],
        json.dumps(app.store.replays(10_000), sort_keys=True, default=str),
        json.dumps(chain if events is None else chain[:events], sort_keys=True),
    )


def _row_of(result):
    d = result.to_dict()
    return {k: d[k] for k in REPLAY_FIELDS}


def test_every_backtest_row_equals_app_replay_for_that_decision(app):
    for ov in (
        ReplayOverrides(policy_version=1),
        ReplayOverrides(rule_values={"review-over-auto-limit": 1}),
        ReplayOverrides(risk_model="disp-1.0"),
    ):
        report = app.backtest(ov, workflow="dispute")
        assert report.replayed == 4 and not report.unreplayable
        for o in report.outcomes:
            r = app.replay(o.decision_id, ov)
            assert _row_of(r) == _row_of(app._replay(o.decision_id, ov))
            assert (o.recorded, o.candidate) == (
                r.original["final_action"],
                r.replayed["final_action"],
            )
            assert (o.executed_recorded, o.executed_candidate) == (
                r.original["executed_capability"],
                r.replayed["executed_capability"],
            )
            assert o.changed == r.changed and list(o.diffs) == r.decision_diff
            assert list(o.drift) == r.drift
            assert (list(o.rules_recorded), list(o.rules_candidate)) == (
                r.original["matched_rules"],
                r.replayed["matched_rules"],
            )


def test_the_known_example_is_loosening_and_an_over_limit_refund_is_tightening(app):
    report = app.backtest(ReplayOverrides(policy_version=1), workflow="dispute")
    loose = report.loosening
    assert len(loose) == 1 and loose[0].direction == LOOSENING
    assert (loose[0].recorded, loose[0].candidate) == ("DENY", "ALLOW")
    assert loose[0].executed_recorded is None
    assert loose[0].executed_candidate == "APPROVE_REFUND"
    assert "block-already-refunded" in loose[0].rules_recorded
    assert report.rules_removed["block-already-refunded"] == 1
    assert report.transitions == {"DENY -> ALLOW": 1}
    assert report.summary()["loosening_ids"] == [loose[0].decision_id]
    # the reverse: a threshold that sends every refund to a human
    report = app.backtest(
        ReplayOverrides(rule_values={"review-over-auto-limit": 1}), workflow="dispute"
    )
    tight = report.tightening
    assert tight and all(o.direction == TIGHTENING for o in tight)
    assert all(o.executed_recorded == "APPROVE_REFUND" for o in tight)
    assert all(o.executed_candidate is None for o in tight)
    assert not report.loosening
    assert report.rules_added["review-over-auto-limit"] >= len(tight)


def test_inv_backtest_1_a_backtest_never_changes_history_and_records_exactly_one_event(app):
    app.replay(
        app.store.decisions(workflow="dispute", limit=1)[0]["decision_id"], ReplayOverrides()
    )
    n = len(app.runtime.audit)
    before = _history(app, n)
    report = app.backtest(ReplayOverrides(policy_version=1))
    assert report.loosening  # it did real work
    assert _history(app, n) == before  # nothing recorded changed; the chain only grew
    assert app.verify_audit().ok
    added = app.runtime.audit.events()[n:]
    assert len(added) == 1
    (ev,) = added
    assert (ev.kind, ev.action, ev.actor, ev.workflow) == (
        "backtest",
        "BACKTEST",
        "sentinel",
        "system",
    )
    assert ev.subject_id == report.backtest_id and ev.decision_id is None
    assert ev.detail == report.summary()
    # counts and ids, never prose or a stored row
    assert set(ev.detail) == set(report.summary())
    assert all(not isinstance(v, str) or len(v) < 80 for v in ev.detail["overrides"])
    # a backtest over one workflow names it
    n = len(app.runtime.audit)
    app.backtest(ReplayOverrides(policy_version=1), workflow="dispute")
    assert len(app.runtime.audit) == n + 1 and app.runtime.audit.events()[-1].workflow == "dispute"


def test_a_what_if_app_backtests_without_recording(app):
    """The pure function writes nothing at all, whoever calls it."""
    before = _history(app)
    report = backtest(app, ReplayOverrides(policy_version=1))
    assert report.replayed and _history(app) == before


def test_unreplayable_decisions_are_counted_with_a_reason(app):
    # a rule the other workflows' policies do not have: every one of their decisions is
    # unreplayable, named, and the dispute decisions still replay
    report = app.backtest(ReplayOverrides(rule_values={"review-repeat-disputer": 1}))
    assert report.considered == 7 and report.replayed == 4 and len(report.unreplayable) == 3
    assert all("has no rule(s) ['review-repeat-disputer']" in u.reason for u in report.unreplayable)
    assert sum(report.unreplayable_reasons.values()) == 3
    assert report.summary()["unreplayable"] == 3
    # a stored snapshot that no longer matches its audit event is not replayed: its recorded
    # side cannot be trusted
    did = report.outcomes[0].decision_id
    snap = app.store.decision_snapshot(did)
    snap["amount"] = int(snap["amount"]) + 1
    c = app.store._conn
    c.execute("UPDATE decisions SET snapshot = ? WHERE decision_id = ?", (json.dumps(snap), did))
    c.commit()
    report = app.backtest(ReplayOverrides(policy_version=1), workflow="dispute")
    assert report.replayed == 3
    (u,) = report.unreplayable
    assert u.decision_id == did
    assert u.reason.startswith("the record does not match its audit event: ")
    assert "snapshot does not match the hash" in u.reason


def test_an_anchor_mismatch_makes_every_decision_unreplayable(app, tmp_path):
    """When the chain disagrees with its anchored checkpoints, the history is not a
    basis for anything: every decision is unreplayable, with that reason."""
    from datetime import UTC, datetime, timedelta

    from sentinel.audit.anchor import DirectoryAnchor
    from sentinel.audit.chain import AuditEvent, chain_hash
    from sentinel.trust import crypto
    from sentinel.trust.keys import AUDIT_CHECKPOINT, TrustedKey

    private = crypto.generate()
    pub = crypto.public_raw(private)
    key = TrustedKey(
        key_id=crypto.key_id(pub),
        issuer="audit-notary",
        public_key=pub,
        purpose=AUDIT_CHECKPOINT,
        scopes=frozenset({"*"}),
        not_before=datetime.now(UTC) - timedelta(days=1),
    )
    app.runtime.trust = app.runtime.trust.with_key(key)
    app.anchor = DirectoryAnchor(tmp_path / "anchor")
    app.publish_checkpoint(private, "audit-notary")
    assert app.backtest(ReplayOverrides(policy_version=1)).replayed == 7
    # a storage attacker rewrites one event below the checkpoint and reseals the chain
    rows = app.store._rows("SELECT sequence, payload FROM audit_events ORDER BY sequence")
    recs = [json.loads(r["payload"]) for r in rows]
    at = next(i for i, r in enumerate(recs) if r.get("kind") == "decision")
    recs[at]["risk_score"] = int(recs[at]["risk_score"]) + 1
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
    report = app.backtest(ReplayOverrides(policy_version=1))
    assert report.replayed == 0 and len(report.unreplayable) == 7
    assert all("anchored checkpoints" in u.reason for u in report.unreplayable)


def test_the_report_is_deterministic(app):
    a = app.backtest(ReplayOverrides(policy_version=1)).to_dict()
    b = app.backtest(ReplayOverrides(policy_version=1)).to_dict()
    for d in (a, b):
        d.pop("backtest_id")
        d.pop("created_at")
    assert a == b
    assert [o["decision_id"] for o in a["outcomes"]] == sorted(
        o["decision_id"] for o in a["outcomes"]
    )


def test_a_backtest_needs_a_policy_candidate_and_bounded_inputs(app):
    with pytest.raises(ValueError, match="needs a candidate"):
        app.backtest(ReplayOverrides())
    with pytest.raises(ValueError, match="policy version, a risk model or rule thresholds"):
        app.backtest(ReplayOverrides(ai_recommendation="approve_refund"))
    with pytest.raises(ValueError, match="policy version, a risk model or rule thresholds"):
        app.backtest(ReplayOverrides(policy_version=1, controls=frozenset()))
    with pytest.raises(ValueError, match="unknown workflow"):
        app.backtest(ReplayOverrides(policy_version=1), workflow="refunds")
    for limit in (0, -1, 10_001, True):
        with pytest.raises(ValueError, match="limit"):
            app.backtest(ReplayOverrides(policy_version=1), limit=limit)
    with pytest.raises(ValueError, match="no policy has a version 99"):
        app.backtest(ReplayOverrides(policy_version=99))
    assert len(app.runtime.audit.events()) == len(
        [e for e in app.runtime.audit.events() if e.kind != "backtest"]
    )  # a refused backtest records nothing
    assert app.backtest(ReplayOverrides(policy_version=1), limit=2).considered == 2


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "s.db")
    base = ["--db", path]
    assert (
        main(
            [
                *base,
                "data",
                "generate",
                "--seed",
                "42",
                "--customers",
                "40",
                "--merchants",
                "8",
                "--transactions",
                "500",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                *base,
                "analyze",
                "--transactions",
                "5",
                "--disputes",
                "6",
                "--applications",
                "2",
                "--sessions",
                "2",
                "--accounts",
                "2",
            ]
        )
        == 0
    )
    return path


def _run(capsys, *argv):
    code = main(list(argv))
    return code, capsys.readouterr().out


def test_cli_backtest_reports_and_gates_on_loosening(db, capsys):
    code, out = _run(
        capsys, "--db", db, "replay", "backtest", "--policy-version", "1", "--workflow", "dispute"
    )
    assert (
        code == 0
        and out.startswith("Backtest BACKTEST-")
        and "LOOSENING (would newly execute):" in out
    )
    assert "6 decisions considered, 6 replayed, 0 not replayable" in out
    code, out = _run(capsys, "--db", db, "--json", "replay", "backtest", "--policy-version", "1")
    assert code == 0
    report = json.loads(out)
    assert report["considered"] == 17 and report["replayed"] == 17
    assert set(report) >= {
        "loosening",
        "tightening",
        "changes",
        "outcomes",
        "not_replayable",
        "directions",
    }
    # a dispute-only rule on every workflow: the other workflows are unreplayable, named
    code, out = _run(
        capsys,
        "--db",
        db,
        "replay",
        "backtest",
        "--rule",
        "review-repeat-disputer=1",
        "--limit",
        "20",
    )
    assert code == 0 and "not replayable: 11" in out and "has no rule(s)" in out
    # the gate: a candidate that would newly execute fails the command
    code, out = _run(
        capsys,
        "--db",
        db,
        "--json",
        "replay",
        "backtest",
        "--policy-version",
        "1",
        "--workflow",
        "dispute",
    )
    loosening = json.loads(out)["loosening"]
    code, _ = _run(
        capsys,
        "--db",
        db,
        "replay",
        "backtest",
        "--policy-version",
        "1",
        "--workflow",
        "dispute",
        "--fail-on-loosening",
    )
    assert code == (3 if loosening else 0)
    code, _ = _run(
        capsys,
        "--db",
        db,
        "replay",
        "backtest",
        "--rule",
        "review-over-auto-limit=1",
        "--workflow",
        "dispute",
        "--fail-on-loosening",
    )
    assert code == 0  # tightening never fails the gate
    code, out = _run(capsys, "--db", db, "replay", "backtest", "--policy-version", "99")
    assert code == 1
    # every backtest above is one audit event; the chain still verifies
    code, out = _run(
        capsys, "--db", db, "audit", "list", "--json", "--action", "BACKTEST", "--limit", "50"
    )
    assert code == 0 and len(json.loads(out)) == 6
    assert main(["--db", db, "audit", "verify"]) == 0
