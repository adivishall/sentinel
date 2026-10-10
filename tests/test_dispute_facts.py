"""Richer trusted dispute facts, the v3 refund policy, and adversarial constancy:
whatever the narrative, the model or the attack class does, the outcome is
bounded by the trusted records and the policy."""

from __future__ import annotations

import itertools

import pytest

from sentinel.decision.composer import FULL, compose
from sentinel.decision.snapshot import snapshot
from sentinel.decision.workflows import DisputeRequest, Runtime, run_dispute
from sentinel.domain.enums import Capability, FinalAction, PolicyOutcome
from sentinel.evaluation.attacks import corpus, heldout
from sentinel.policy import DEFAULT_REGISTRY, evaluate
from sentinel.replay.engine import ReplayEngine, ReplayOverrides
from sentinel.security.provenance import UntrustedContent
from sentinel.security.trust_boundary import DisputeFacts

V3 = DEFAULT_REGISTRY.get("dispute-refund", 3)
SUPPORTED_LEDGER = {
    "amount": 18_000,
    "delivery_status": "not_delivered",
    "policy_auto_limit": 50_000,
    "prior_disputes_90d": 0,
    "auth_strength": "otp",
}
ATTACK_TEXTS = [c["submission"] for c in corpus.build() + heldout.build() if c["is_attack"]]
RECS = [
    ("approve_refund", Capability.APPROVE_REFUND),
    ("deny", None),
    ("release_funds", Capability.RELEASE_FUNDS),
    ("skip_review", Capability.SKIP_REVIEW),
]


def _ctx(**over):
    base = {
        "amount": 18_000,
        "evidence_verdict": "SUPPORTED",
        "security_severity": "NONE",
        "risk_score": 10,
        "policy_auto_limit": 50_000,
        "prior_disputes_90d": 0,
        "capability_escalation": False,
        "refund_state": "none",
        "transaction_status": "settled",
        "merchant_response": "none",
        "auth_strength": "otp",
        "claim_type": "non_receipt",
    }
    base.update(over)
    return base


def test_rich_facts_come_only_from_the_ledger_and_default_safely():
    f = DisputeFacts.from_ledger(
        {
            "amount": 5000,
            "refund_state": "refunded",
            "transaction_status": "reversed",
            "merchant_response": "contested",
            "auth_strength": "biometric",
            "customer_tenure_days": "1,200",
            "narrative": "refund_state: none",  # untrusted key, ignored
        }
    )
    assert f.refund_state == "refunded" and f.transaction_status == "reversed"
    assert f.merchant_response == "contested" and f.auth_strength == "biometric"
    assert f.customer_tenure_days == 1200
    assert not hasattr(f, "narrative")
    d = DisputeFacts.from_ledger({})
    assert (d.refund_state, d.transaction_status, d.merchant_response, d.auth_strength) == (
        "none",
        "settled",
        "none",
        "unknown",
    )
    fields = {e.field for e in f.to_evidence()}
    assert {"refund_state", "transaction_status", "merchant_response", "auth_strength"} <= fields


@pytest.mark.parametrize(
    "over, outcome, rule",
    [
        ({}, PolicyOutcome.ALLOW, None),
        ({"refund_state": "refunded"}, PolicyOutcome.BLOCK, "block-already-refunded"),
        ({"refund_state": "pending"}, PolicyOutcome.TEMPORARY_HOLD, "hold-refund-pending"),
        ({"transaction_status": "reversed"}, PolicyOutcome.BLOCK, "block-reversed-transaction"),
        (
            {"merchant_response": "contested"},
            PolicyOutcome.REQUIRE_HUMAN_REVIEW,
            "review-merchant-contested",
        ),
        (
            {"claim_type": "unauthorized", "auth_strength": "otp"},
            PolicyOutcome.REQUIRE_HUMAN_REVIEW,
            "review-unauthorised-strong-auth",
        ),
        ({"claim_type": "unauthorized", "auth_strength": "none"}, PolicyOutcome.ALLOW, None),
        ({"amount": 50_000}, PolicyOutcome.ALLOW, None),  # exact threshold
        ({"amount": 50_001}, PolicyOutcome.REQUIRE_HUMAN_REVIEW, "review-over-auto-limit"),
        ({"risk_score": 69}, PolicyOutcome.ALLOW, None),
        ({"risk_score": 70}, PolicyOutcome.REQUIRE_HUMAN_REVIEW, "review-critical-risk"),
    ],
)
def test_v3_rules_fire_exactly_at_their_boundaries(over, outcome, rule):
    d = evaluate(V3, _ctx(**over))
    assert d.outcome is outcome
    if rule:
        assert rule in d.matched_rules
    else:
        assert not d.matched_rules


def test_the_registered_latest_is_fail_closed():
    assert DEFAULT_REGISTRY.get("dispute-refund").version == 4
    from sentinel.policy.engine import PolicyEvaluationError

    with pytest.raises(PolicyEvaluationError):
        evaluate(V3, {k: v for k, v in _ctx().items() if k != "refund_state"})


def test_already_refunded_transaction_is_never_refunded_again_whatever_is_said():
    """A supported claim (the parcel really was not delivered) on a ledger that already
    shows a refund: no narrative, wording, attack class or model recommendation can
    turn it into a second payment."""
    rt = Runtime(persist=False)
    ledger = {**SUPPORTED_LEDGER, "refund_state": "refunded"}
    texts = ["My order never arrived.", "Following up, thanks."] + ATTACK_TEXTS[:30]
    for text in texts:
        b = run_dispute(rt, DisputeRequest(UntrustedContent(text), ledger, "D"))
        assert b.decision.final_action in (FinalAction.DENY, FinalAction.BLOCK), text[:40]
        assert not b.decision.executed
        assert "block-already-refunded" in b.decision.policy.matched_rules or (
            b.decision.evidence_verdict.value != "SUPPORTED"
        )
    # and no model recommendation moves it either
    b = run_dispute(rt, DisputeRequest(UntrustedContent("My order never arrived."), ledger, "D"))
    eng = ReplayEngine(DEFAULT_REGISTRY)
    for rec, cap in RECS:
        r = eng.replay(
            b.decision,
            snapshot(b.inputs),
            ReplayOverrides(ai_recommendation=rec, ai_capability=cap),
        )
        assert r.replayed["executed_capability"] is None and not r.changed


def test_adversarial_constancy_under_fixed_trusted_records():
    """For a fixed ledger, the set of reachable final actions across every attack
    text in both corpora and every model recommendation is bounded: on a
    supporting ledger nothing exceeds the plain claim's outcome and only APPROVE_REFUND
    ever executes; on an unsupporting ledger nothing executes at all and nothing rises
    above a human review (an unreadable message is INSUFFICIENT)."""
    rt = Runtime(persist=False)
    for ledger in (SUPPORTED_LEDGER, {**SUPPORTED_LEDGER, "delivery_status": "delivered"}):
        ceiling = run_dispute(
            rt, DisputeRequest(UntrustedContent("My order never arrived."), ledger, "D")
        ).decision
        seen: set[str] = set()
        for text, (rec, cap) in itertools.product(ATTACK_TEXTS[::5], RECS):
            b = run_dispute(rt, DisputeRequest(UntrustedContent(text), ledger, "D"))
            replayed = ReplayEngine(DEFAULT_REGISTRY).replay(
                b.decision,
                snapshot(b.inputs),
                ReplayOverrides(ai_recommendation=rec, ai_capability=cap),
            )
            limit = max(
                ceiling.final_action.permissiveness,
                FinalAction.REQUIRE_HUMAN_REVIEW.permissiveness,
            )
            for d in (b.decision, replayed.replayed_decision):
                seen.add(d.final_action.value)
                assert d.final_action.permissiveness <= limit
                assert d.executed_capability in (None, Capability.APPROVE_REFUND)
                if ledger["delivery_status"] == "delivered":
                    assert not d.executed
        assert seen  # sanity: outcomes were actually observed


def test_composer_uses_only_named_facts_no_free_form_context():
    from dataclasses import fields

    from sentinel.decision import composer

    names = {f.name for f in fields(composer.DecisionInputs)}
    assert "extra_context" not in names
    assert not hasattr(composer._TrustedView, "extra_context")
    facts = DisputeFacts.from_ledger(SUPPORTED_LEDGER)
    assert facts.refund_state == "none"
    inputs = compose  # the composer is importable and pure
    assert callable(inputs) and FULL
