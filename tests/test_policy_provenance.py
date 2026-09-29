"""Provenance-aware policy and capability floors (issue #12).

INV-PROV-2  A decision requiring verified evidence cannot execute using unverified facts:
            facts below a capability's floor never execute it, under any policy version,
            and facts whose verification failed are never approved by anyone.

Plus the regressions for the structured-channel bypasses the trust audit found:
caller-chosen FREEZE_ACCOUNT on stored sessions, out-of-vocabulary values that disabled a
BLOCK rule, and caller-controlled time (backdating, the ISO-separator string compare).
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from sentinel.app import SentinelApp
from sentinel.cases.rules import CaseTrigger
from sentinel.cases.service import CaseService, ReviewerNotAuthorized
from sentinel.decision.composer import FULL, DecisionInputs, compose, policy_context
from sentinel.decision.workflows import DisputeRequest, RunOptions, Runtime, run_dispute
from sentinel.domain.entities import Account
from sentinel.domain.enums import (
    ActorKind,
    AuthorizationStatus,
    Capability,
    CasePriority,
    CaseStatus,
    EvidenceVerdict,
    FactKind,
    FactsSource,
    FinalAction,
    PolicyOutcome,
    ProvenanceStatus,
    Workflow,
)
from sentinel.evidence.reconcile import reconcile_dispute
from sentinel.policy import DEFAULT_REGISTRY
from sentinel.policy.engine import PolicyEvaluationError, evaluate
from sentinel.policy.models import CONTEXT_FIELDS
from sentinel.security import capabilities
from sentinel.security.gateway import GATEWAY
from sentinel.security.provenance import UntrustedContent
from sentinel.security.trust_boundary import DisputeFacts, UntrustedText
from sentinel.trust import local, untrusted
from sentinel.trust.issuer import Issuer
from sentinel.trust.keys import TrustStore
from tests.records import ledger

CLAIM = "My order never arrived after three weeks."
SUPPORTING = ledger(amount=18000, delivery_status="not_delivered", refund_state="none")
ISSUER = Issuer.ephemeral("core-ledger")
TRUST = TrustStore.empty().with_key(ISSUER.key)


def _signed(ledger, rid="D-1"):
    return DisputeRequest(
        UntrustedContent(CLAIM), {}, rid, envelope=ISSUER.sign(FactKind.DISPUTE_LEDGER, rid, ledger)
    )


def _rt(**kw):
    return Runtime(persist=False, trust=TRUST, **kw)


# ---- INV-PROV-2: under every policy version ------------------------------------------------
@pytest.mark.parametrize("version", DEFAULT_REGISTRY.versions("dispute-refund"))
def test_inv_prov_2_unverified_facts_never_execute_under_any_policy_version(version):
    opts = RunOptions(policy_version=version)
    unsigned = run_dispute(_rt(), DisputeRequest(UntrustedContent(CLAIM), SUPPORTING, "D-1"), opts)
    assert unsigned.decision.provenance.status is ProvenanceStatus.UNTRUSTED
    assert not unsigned.decision.executed, version
    signed = run_dispute(_rt(), _signed(SUPPORTING), opts)
    assert signed.decision.executed, version  # the same facts, signed, are approved


def _inputs(provenance, verdict=EvidenceVerdict.SUPPORTED, policy=None):
    """Inputs with the reconciliation forced to SUPPORTED -- as if something bypassed
    ``reconcile._gate`` -- so only the registry floor stands between them and execution."""
    facts = DisputeFacts.from_ledger(SUPPORTING)
    rec = replace(reconcile_dispute(UntrustedText(CLAIM).claim(), facts), verdict=verdict)
    return DecisionInputs(
        Workflow.DISPUTE,
        "dispute",
        "D-1",
        18000,
        Capability.APPROVE_REFUND,
        {**facts.as_policy_facts(), "account_risk_score": 0},
        rec,
        GATEWAY.inspect(UntrustedContent(CLAIM)),
        policy or DEFAULT_REGISTRY.get("dispute-refund", 1),  # v1: no provenance rules
        controls=FULL,
        claim_type="non_receipt",
        provenance=provenance,
    )


@pytest.mark.parametrize(
    "status, expected",
    [
        (ProvenanceStatus.UNTRUSTED, AuthorizationStatus.PENDING_HUMAN),
        (ProvenanceStatus.EXPIRED, AuthorizationStatus.PENDING_HUMAN),
        (ProvenanceStatus.SUPERSEDED, AuthorizationStatus.PENDING_HUMAN),
        (ProvenanceStatus.INVALID, AuthorizationStatus.DENIED),
        (ProvenanceStatus.REVOKED, AuthorizationStatus.DENIED),
        (None, AuthorizationStatus.DENIED),  # no provenance at all: fail closed
    ],
)
def test_inv_prov_2_the_registry_floor_holds_even_if_evidence_says_supported(status, expected):
    prov = (
        None
        if status is None
        else replace(untrusted(FactKind.DISPUTE_LEDGER, "D-1", {}), status=status)
    )
    d = compose(_inputs(prov))
    assert d.authorization.status is expected and not d.executed
    ok = compose(_inputs(local(FactKind.DISPUTE_LEDGER, "D-1", SUPPORTING)))
    assert ok.authorization.status is AuthorizationStatus.GRANTED and ok.executed


def test_every_consequential_capability_has_a_floor():
    for cap, spec in capabilities.REGISTRY.items():
        if spec.consequential:
            assert spec.min_fact_provenance is ProvenanceStatus.TRUSTED_LOCAL, cap
    rows = {r["capability"]: r for r in capabilities.matrix()}
    assert rows["APPROVE_REFUND"]["min_fact_provenance"] == "TRUSTED_LOCAL"
    assert rows["READ_ACCOUNT"]["min_fact_provenance"] is None


def test_the_policy_context_always_names_the_provenance():
    assert "facts_provenance" in CONTEXT_FIELDS
    ctx = policy_context(_inputs(local(FactKind.DISPUTE_LEDGER, "D-1", SUPPORTING)))
    assert ctx["facts_provenance"] == "TRUSTED_LOCAL"
    assert policy_context(_inputs(None))["facts_provenance"] == "NONE"


# ---- the policy: declarative requirements ----------------------------------------------------
def test_a_failed_signature_is_blocked_by_policy():
    """A statement that does not verify is never decided on (it fails safe); a stored row
    that disagrees with its statement is decided on the row -- and the policy BLOCKs it."""
    forged = Issuer.ephemeral("core-ledger").sign(FactKind.DISPUTE_LEDGER, "D-1", SUPPORTING)
    b = run_dispute(_rt(), DisputeRequest(UntrustedContent(CLAIM), {}, "D-1", envelope=forged))
    assert b.decision.provenance.status is ProvenanceStatus.INVALID and not b.decision.executed
    stored = SentinelApp.demo(seed=7, customers=30, merchants=6, transactions=300)
    d = next(
        x
        for x in stored.store.all_disputes()
        if stored.evaluate_dispute(dispute_id=x.dispute_id).decision.final_action
        is not FinalAction.BLOCK
    )
    stored.store._conn.execute(
        "UPDATE disputes SET amount = amount + 1 WHERE dispute_id = ?", (d.dispute_id,)
    )
    stored.store._conn.commit()
    t = stored.evaluate_dispute(dispute_id=d.dispute_id)
    assert t.decision.provenance.status is ProvenanceStatus.INVALID
    assert "block-failed-fact-provenance" in t.decision.policy.matched_rules
    assert t.decision.final_action is FinalAction.DENY and not t.decision.executed


@pytest.mark.parametrize(
    "amount, source, executes",
    [
        (20_000, "local", True),  # an unsigned stored record may pay a small refund
        (30_000, "local", False),  # above 25,000 it needs the signed statement
        (30_000, "signed", True),
        (49_000, "signed", True),
    ],
)
def test_high_value_money_movement_needs_the_signed_statement(amount, source, executes):
    ledger = {**SUPPORTING, "amount": amount}
    req = (
        DisputeRequest(
            UntrustedContent(CLAIM), ledger, "D-1", facts_source=FactsSource.SYSTEM_OF_RECORD
        )
        if source == "local"
        else _signed(ledger)
    )
    b = run_dispute(_rt(), req)
    assert b.decision.executed is executes, b.decision.policy.matched_rules
    if not executes:
        assert "review-high-value-unsigned-facts" in b.decision.policy.matched_rules


# ---- human review: who establishes unverified facts ------------------------------------------
def _case_for(status):
    svc = CaseService()
    d = compose(_inputs(replace(local(FactKind.DISPUTE_LEDGER, "D-1", {}), status=status)))
    c = svc.open(CaseTrigger("test", CasePriority.P2, "t"), d)
    if c.status is not CaseStatus.WAITING_HUMAN:
        c = svc.transition(c.case_id, CaseStatus.WAITING_HUMAN, actor="analyst")
    return svc, c


def test_a_human_may_establish_unverified_facts_but_nobody_approves_failed_ones():
    svc, c = _case_for(ProvenanceStatus.UNTRUSTED)
    ok, why = svc.approval(c, "HUMAN_REVIEWER")
    assert ok and "facts UNTRUSTED" in why
    for status in (ProvenanceStatus.INVALID, ProvenanceStatus.REVOKED):
        svc, c = _case_for(status)
        for role in ("HUMAN_REVIEWER", "SENIOR_REVIEWER"):
            ok, why = svc.approval(c, role)
            assert not ok and status.value in why
        with pytest.raises(ReviewerNotAuthorized):
            svc.record_human_decision(c.case_id, reviewer="alice", outcome="approve")


# ---- regressions: the structured-channel bypasses ------------------------------------------
@pytest.fixture(scope="module")
def app():
    return SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)


def test_a_caller_cannot_freeze_an_account_by_asking(app):
    """The audit: FREEZE_ACCOUNT requested on stored sessions executed 17 of 20 times."""
    from sentinel.api.server import build_routes

    r = build_routes(app)
    fn, params = r.match("POST", "/v1/accounts/evaluate")
    for s in app.store.sessions(limit=20):
        d = fn({}, {"session_id": s.session_id, "requested_capability": "FREEZE_ACCOUNT"}, params)
        assert d["executed_capability"] is None, s.session_id
        assert d["evidence_verdict"] == "INSUFFICIENT"


def test_a_payout_change_the_session_recorded_is_still_human_only(app):
    s = next(x for x in app.store.sessions(limit=5000) if "payout_change" in x.events)
    b = app.evaluate_account(s.session_id)
    assert b.decision.requested_capability is Capability.CHANGE_PAYOUT and not b.decision.executed


@pytest.mark.parametrize("value", ["REFUNDED", "Refunded", "refunded ", "reversed-ish"])
def test_an_out_of_vocabulary_value_cannot_disable_a_block_rule(value):
    """The audit: refund_state "REFUNDED" got ALLOW + APPROVE_REFUND (a double refund)."""
    for req in (
        DisputeRequest(UntrustedContent(CLAIM), {**SUPPORTING, "refund_state": value}, "D-1"),
        _signed({**SUPPORTING, "refund_state": value}),
    ):
        b = run_dispute(_rt(), req)
        assert not b.decision.executed
        assert b.decision.final_action is FinalAction.REQUIRE_HUMAN_REVIEW  # fail safe
        assert "not one of" in b.reconciliation.explanation


def test_the_engine_itself_fails_closed_on_an_unknown_value():
    pol = DEFAULT_REGISTRY.get("dispute-refund", 3)
    ctx = policy_context(_inputs(local(FactKind.DISPUTE_LEDGER, "D-1", SUPPORTING), policy=pol))
    ctx["refund_state"] = "REFUNDED"
    with pytest.raises(PolicyEvaluationError, match="outside the vocabulary"):
        evaluate(pol, ctx)


def test_status_at_compares_instants_not_strings():
    a = Account("A", "C", "2026-01-01", status="frozen", status_since="2026-08-15T00:00:00")
    assert a.status_at("2026-08-15 10:00:00") == "frozen"  # was "active" by string compare
    assert a.status_at("2026-08-14T23:59:59") == "active"
    assert a.status_at("2026-08-15T10:00:00+05:30") == "frozen"
    assert a.status_at("not a time") == "frozen"  # unreadable: the stricter answer


def test_a_backdated_caller_transaction_is_assessed_as_of_now():
    """The audit: a caller-supplied transaction backdated before an account's freeze got
    ALLOW + APPROVE_TRANSACTION. Its timestamp no longer chooses the point-in-time view."""
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    t0 = app.store.transactions(limit=1)[0]
    since = "2026-08-15T00:00:00"
    app.store._conn.execute(  # the account was frozen on 15 August
        "UPDATE accounts SET status = 'frozen', status_since = ? WHERE account_id = ?",
        (since, t0.account_id),
    )
    app.store._conn.commit()
    app._world = None
    for ts in ("2026-08-10T12:00:00", "2026-08-15 10:00:00", "2020-01-01T00:00:00"):
        body = replace(t0, transaction_id="TX-BACKDATED", amount=1200, timestamp=ts)
        b = app.evaluate_transaction(body)
        assert b.decision.provenance.status is ProvenanceStatus.UNTRUSTED, ts
        assert not b.decision.executed, ts
        assert "block-frozen-account" in b.decision.policy.matched_rules, ts


def test_an_unknown_account_is_not_an_active_one():
    """An account the store does not hold was read as status "unknown", which no rule named
    -- so no rule on account_status fired. It now fails safe."""
    pol = DEFAULT_REGISTRY.get("transaction-authorization")
    ctx = {k: v for k, v in policy_context(_inputs(None)).items()}
    ctx.update({"account_status": "unknown", "merchant_risk_level": "LOW"})
    with pytest.raises(PolicyEvaluationError, match="outside the vocabulary"):
        evaluate(pol, ctx)


def test_a_legacy_case_without_recorded_provenance_is_not_approvable():
    svc, c = _case_for(ProvenanceStatus.TRUSTED_LOCAL)
    legacy = replace(c, facts_provenance=None)
    ok, why = svc.approval(legacy, "SENIOR_REVIEWER")
    assert not ok and "unknown provenance" in why


def test_a_human_approval_is_checked_with_the_system_floor_skipped():
    """For the SYSTEM actor the floor holds unverified facts for a human; for a human it
    does not -- establishing them is what the human is for."""
    for actor, expected in (
        (ActorKind.SYSTEM, AuthorizationStatus.PENDING_HUMAN),
        (ActorKind.HUMAN_REVIEWER, AuthorizationStatus.GRANTED),
    ):
        a = capabilities.authorize(
            Capability.APPROVE_REFUND,
            actor=actor,
            amount=1000,
            policy_outcome=PolicyOutcome.ALLOW,
            evidence_supported=True,
            workflow=Workflow.DISPUTE,
            facts_provenance=ProvenanceStatus.UNTRUSTED,
        )
        assert a.status is expected, actor


# ---- idempotency: a capability runs once per subject -------------------------------------
def test_re_evaluating_a_record_that_already_executed_does_not_execute_again():
    """The provenance review: every re-evaluation of the same record recorded another
    executed decision (a second refund on the same dispute)."""
    app = SentinelApp.demo(seed=7, customers=30, merchants=6, transactions=300)
    d, first = next(
        (x, b)
        for x in app.store.all_disputes()
        if (b := app.evaluate_dispute(dispute_id=x.dispute_id)).decision.executed
    )
    again = app.evaluate_dispute(dispute_id=d.dispute_id)
    assert not again.decision.executed and again.decision.final_action is FinalAction.DENY
    assert first.decision.decision_id in again.decision.authorization.reason
    env = app.issuer.sign(FactKind.DISPUTE_LEDGER, "DSP-ONCE", SUPPORTING)
    assert app.evaluate_dispute(CLAIM, envelope=env).decision.executed
    assert not app.evaluate_dispute(CLAIM, envelope=env).decision.executed  # same statement


def test_the_execution_ledger_survives_a_restart(tmp_path):
    from sentinel.data.store import SentinelStore

    db = str(tmp_path / "s.db")
    issuer = Issuer.ephemeral("core-ledger")
    env = issuer.sign(FactKind.DISPUTE_LEDGER, "DSP-R", SUPPORTING)
    assert (
        SentinelApp(SentinelStore(db), issuer=issuer)
        .evaluate_dispute(CLAIM, envelope=env)
        .decision.executed
    )
    reopened = SentinelApp(SentinelStore(db), issuer=issuer)
    assert not reopened.evaluate_dispute(CLAIM, envelope=env).decision.executed


def test_two_concurrent_requests_execute_once():
    import threading

    app = SentinelApp.demo(seed=7, customers=30, merchants=6, transactions=300)
    env = app.issuer.sign(FactKind.DISPUTE_LEDGER, "DSP-RACE", SUPPORTING)
    results: list[bool] = []
    barrier = threading.Barrier(8)

    def go() -> None:
        barrier.wait()
        results.append(app.evaluate_dispute(CLAIM, envelope=env).decision.executed)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count(True) == 1, results


def test_a_human_approval_is_an_execution_too():
    svc_rt = Runtime(trust=TRUST)  # recording: its case service claims executions
    b = run_dispute(svc_rt, _signed({**SUPPORTING, "amount": 60_000}, "DSP-H"))  # over the limit
    assert b.case is not None and not b.decision.executed
    c = svc_rt.cases.transition(b.case.case_id, CaseStatus.INVESTIGATING, actor="analyst")
    c = svc_rt.cases.record_human_decision(c.case_id, reviewer="alice", outcome="approve")
    assert c.resolution == "approve"
    # the refund was paid by the human's approval: the system does not pay it again
    again = run_dispute(svc_rt, _signed({**SUPPORTING, "amount": 60_000}, "DSP-H"))
    assert not again.decision.executed and "case:" in again.decision.authorization.reason
