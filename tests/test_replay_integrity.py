"""Replay is trustworthy only if it cannot falsely report equivalence.

The recorded side of a replay is anchored to the decision's audit event (tamper-evident)
and the stored input snapshot is checked against the SHA-256 that event recorded. A
replay reports the policy, risk model and engine version on each side, reports policy
drift and engine drift, and never overwrites the decision it replays."""

from __future__ import annotations

import json

import pytest

from sentinel import __version__
from sentinel.app import SentinelApp
from sentinel.decision import composer
from sentinel.domain.enums import FactKind, FinalAction
from sentinel.domain.ids import new_id
from sentinel.replay import engine as replay_engine
from sentinel.replay.engine import ReplayOverrides

CLAIM = "My order never arrived, please refund."
REFUNDED = {
    "amount": 18000,
    "delivery_status": "not_delivered",
    "policy_auto_limit": 50000,
    "refund_state": "refunded",
}
SUPPORTED = {"amount": 12000, "delivery_status": "not_delivered", "policy_auto_limit": 50000}


@pytest.fixture()
def app():
    return SentinelApp.demo(seed=11, customers=30, merchants=6, transactions=300)


def _decide(app, ledger):
    """A decision on the ledger as its issuer (the demo app's) signs it: replay is about
    decisions made on verified facts."""
    env = app.issuer.sign(FactKind.DISPUTE_LEDGER, new_id("DSP"), ledger)
    return app.evaluate_dispute(CLAIM, envelope=env)


def _raw(app, did):
    r = app.store._one("SELECT payload, snapshot FROM decisions WHERE decision_id = ?", (did,))
    return r["payload"], r["snapshot"]


def _rewrite(app, did, *, payload=None, snapshot=None):
    c = app.store._conn
    if payload is not None:
        c.execute(
            "UPDATE decisions SET payload = ? WHERE decision_id = ?", (json.dumps(payload), did)
        )
    if snapshot is not None:
        c.execute(
            "UPDATE decisions SET snapshot = ? WHERE decision_id = ?", (json.dumps(snapshot), did)
        )
    c.commit()


def test_same_inputs_no_diff_and_every_version_named(app):
    did = _decide(app, SUPPORTED).decision.decision_id
    r = app.replay(did, ReplayOverrides())
    assert r.decision_id == did  # the recorded decision, not the re-derivation's fresh id
    assert app.store.replays(1)[0]["decision_id"] == did
    assert r.decision_diff == [] and not r.changed and r.record_verified
    assert not r.engine_drift and not r.policy_drift
    assert r.versions["engine"] == {"recorded": __version__, "replay": __version__}
    assert r.versions["policy"]["recorded"] == r.versions["policy"]["replay"]
    assert r.versions["risk_model"] == {"recorded": "disp-1.0", "replay": "disp-1.0"}
    assert r.original["final_action"] == "ALLOW" and r.replayed["final_action"] == "ALLOW"


def test_changed_policy_is_an_explicit_diff(app):
    did = _decide(app, REFUNDED).decision.decision_id  # v3: DENY
    r = app.replay(did, ReplayOverrides(policy_version=1))
    diff = {d["field"]: (d["before"], d["after"]) for d in r.decision_diff}
    assert diff["policy"][1] == "dispute-refund@v1"
    assert diff["final_action"] == ("DENY", "ALLOW") and r.changed
    assert r.versions["policy"] == {"recorded": "dispute-refund@v3", "replay": "dispute-refund@v1"}
    assert app.store.decision(did)["final_action"] == "DENY"  # the original is untouched


def test_changed_engine_is_an_explicit_diff_and_named(app, monkeypatch):
    did = _decide(app, SUPPORTED).decision.decision_id
    real = composer._final_action

    def changed_engine(*a, **k):
        action, why = real(*a, **k)
        return (
            (FinalAction.REQUIRE_HUMAN_REVIEW, "changed engine")
            if action is FinalAction.ALLOW
            else (action, why)
        )

    monkeypatch.setattr(composer, "_final_action", changed_engine)
    monkeypatch.setattr(replay_engine, "__version__", "9.9.9")
    r = app.replay(did, ReplayOverrides())
    assert r.engine_drift and r.record_verified
    assert {"field": "final_action", "before": "ALLOW", "after": "REQUIRE_HUMAN_REVIEW"} in (
        r.decision_diff
    )
    assert "engine has changed" in r.explanation
    assert r.versions["engine"] == {"recorded": __version__, "replay": "9.9.9"}


def test_later_changes_to_source_records_do_not_change_a_replay(app):
    """Replay runs on the snapshot taken at decision time, not on today's records."""
    t = app.store.transactions(limit=1)[0]
    did = app.evaluate_transaction(t.transaction_id).decision.decision_id
    c = app.store._conn
    c.execute(
        "UPDATE transactions SET amount = amount * 50 WHERE transaction_id = ?", (t.transaction_id,)
    )
    c.commit()
    r = app.replay(did, ReplayOverrides())
    assert r.decision_diff == [] and r.record_verified


def test_an_edited_snapshot_is_detected_not_replayed_as_truth(app):
    did = _decide(app, REFUNDED).decision.decision_id  # DENY
    _, snap = _raw(app, did)
    snap = json.loads(snap)
    snap["facts"]["refund_state"] = "none"  # rewrite history: 'it was never refunded'
    _rewrite(app, did, snapshot=snap)
    r = app.replay(did, ReplayOverrides())
    assert not r.record_verified
    assert any("snapshot does not match" in i for i in r.record_issues)
    assert r.original["final_action"] == "DENY"  # the audit event's action, not a re-derivation


def test_a_consistent_rewrite_of_decision_and_snapshot_cannot_fake_equivalence(app):
    """Edit the stored decision AND its snapshot so they agree with each other: the replay
    still disagrees with the audit chain and says so."""
    did = _decide(app, SUPPORTED).decision.decision_id  # ALLOW, executed
    payload, snap = (json.loads(x) for x in _raw(app, did))
    snap["facts"]["delivery_status"] = "delivered"
    snap["reconciliation"]["verdict"] = "UNSUPPORTED"
    payload["final_action"], payload["executed_capability"] = "DENY", None
    _rewrite(app, did, payload=payload, snapshot=snap)
    r = app.replay(did, ReplayOverrides())
    assert not r.record_verified and len(r.record_issues) >= 2
    assert r.original["final_action"] == "ALLOW" and r.original["executed_capability"]
    assert r.replayed["final_action"] == "DENY" and r.changed  # the edit shows up as a change


def test_no_audit_event_means_unverified(app, monkeypatch):
    did = _decide(app, SUPPORTED).decision.decision_id
    monkeypatch.setattr(app.runtime.audit, "get", lambda _id: None)
    r = app.replay(did, ReplayOverrides())
    assert not r.record_verified and "no audit event" in r.record_issues[0]


def test_replay_never_overwrites_the_original(app):
    did = _decide(app, REFUNDED).decision.decision_id
    before = _raw(app, did)
    n = app.store.count("decisions")
    for ov in (
        ReplayOverrides(),
        ReplayOverrides(policy_version=1),
        ReplayOverrides(controls=frozenset()),
        ReplayOverrides(ai_recommendation="approve_refund"),
    ):
        app.replay(did, ov)
    assert _raw(app, did) == before and app.store.count("decisions") == n
    assert len(app.store.replays(50)) >= 4
    assert app.verify_audit().ok


def test_api_replay_exposes_versions_and_integrity(app):
    import threading
    import urllib.request

    from sentinel.api.server import make_server

    did = _decide(app, REFUNDED).decision.decision_id
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{httpd.server_address[1]}/v1/replay",
            json.dumps({"decision_id": did, "policy_version": 1}).encode(),
            {"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read())
    finally:
        httpd.shutdown()
    assert body["record_verified"] is True and body["record_issues"] == []
    assert set(body["versions"]) == {"policy", "risk_model", "engine"}
    assert (
        body["original"]["final_action"] == "DENY" and body["replayed"]["final_action"] == "ALLOW"
    )
    assert {"engine_drift", "policy_drift", "decision_diff", "explanation"} <= set(body)
