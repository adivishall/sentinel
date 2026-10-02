"""Replay: same events, evidence, policy version and risk configuration -> an
identical result; a different version or configuration -> an explained diff with
policy_drift / engine_drift / decision_diff."""

from __future__ import annotations

from sentinel.app import SentinelApp
from sentinel.decision.composer import compose
from sentinel.decision.snapshot import restore, snapshot
from sentinel.decision.workflows import DisputeRequest, RunOptions, Runtime, run_dispute
from sentinel.domain.enums import Capability, FactsSource
from sentinel.policy import DEFAULT_REGISTRY
from sentinel.replay.engine import ReplayEngine, ReplayOverrides
from sentinel.security.provenance import UntrustedContent

LEDGER = {
    "amount": 18_000,
    "delivery_status": "not_delivered",
    "policy_auto_limit": 50_000,
    "prior_disputes_90d": 0,
}


def _summary(d):
    return (
        d.final_action,
        d.policy.outcome,
        d.policy.version,
        d.policy.policy_hash,
        d.policy.matched_rules,
        d.authorization.status,
        d.executed_capability,
        d.evidence_verdict,
        d.risk_score,
        d.blocked_by,
    )


def test_same_snapshot_same_configuration_is_bit_for_bit_identical_in_outcome():
    rt = Runtime(persist=False)
    b = run_dispute(rt, DisputeRequest(UntrustedContent("My order never arrived."), LEDGER, "D"))
    snap = snapshot(b.inputs)
    outs = {_summary(compose(restore(snap, DEFAULT_REGISTRY))) for _ in range(5)}
    assert len(outs) == 1 and next(iter(outs)) == _summary(b.decision)
    eng = ReplayEngine(DEFAULT_REGISTRY)
    r1 = eng.replay(b.decision, snap, ReplayOverrides())
    r2 = eng.replay(b.decision, snap, ReplayOverrides())
    assert r1.replayed == r2.replayed and not r1.changed and not r1.policy_drift
    assert not r1.engine_drift and r1.decision_diff == []
    assert r1.to_dict()["decision_diff"] == [] and r1.to_dict()["engine_drift"] is False


def test_different_policy_version_and_risk_model_explain_their_difference():
    app = SentinelApp.demo(seed=42, customers=50, merchants=10, transactions=600)
    t = next(x for x in app.store.transactions(limit=100) if x.label == "fraud:account_takeover")
    b = app.evaluate_transaction(t, options=RunOptions(skip_agent=True))
    r_model = app.replay(b.decision.decision_id, ReplayOverrides(risk_model="txn-1.0"))
    assert r_model.replayed["risk_score"] != r_model.original["risk_score"]
    assert any(d["field"] == "risk_score" for d in r_model.decision_diff)
    assert "risk model -> txn-1.0" in r_model.overrides and "txn-1.0" in r_model.explanation
    r_pol = app.replay(b.decision.decision_id, ReplayOverrides(policy_version=1))
    assert r_pol.replayed["policy"] == "transaction-authorization@v1"
    assert not r_pol.policy_drift  # pinning a version is a choice, not drift
    stored = app.store.replay(r_pol.replay_id)
    assert stored["policy_drift"] is False and stored["original_drift"] is False


def test_replay_with_model_override_reports_no_change_and_no_drift():
    rt = Runtime(persist=False)
    b = run_dispute(
        rt,
        DisputeRequest(
            UntrustedContent("never arrived"),
            LEDGER,
            "D",
            facts_source=FactsSource.SYSTEM_OF_RECORD,
        ),
    )
    r = ReplayEngine(DEFAULT_REGISTRY).replay(
        b.decision,
        snapshot(b.inputs),
        ReplayOverrides(ai_recommendation="release_funds", ai_capability=Capability.RELEASE_FUNDS),
    )
    assert r.replayed["final_action"] == r.original["final_action"] == "ALLOW"
    assert r.replayed["executed_capability"] == "APPROVE_REFUND"  # the workflow's, not the model's
    assert [d["field"] for d in r.decision_diff] == ["ai_recommendation"]
    assert not r.changed and not r.policy_drift and not r.engine_drift
