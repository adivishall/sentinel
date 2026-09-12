"""Layer-4 capability policy engine tests (explicit ALLOW / REVIEW / BLOCK)."""

from agents.tools import Effect
from firewall import limits
from firewall.limits import PolicyOutcome


def test_refund_over_limit_requires_human_review():
    e = Effect("approve_refund", 200000, "ok", irreversible=True)
    d = limits.evaluate(e, {"policy_auto_limit": 50000})
    assert d.outcome is PolicyOutcome.REQUIRE_HUMAN_REVIEW
    assert d.effect.action == "escalate"
    assert d.rule == "refund_over_auto_limit"
    assert "exceeds" in d.reason


def test_refund_within_limit_allowed():
    e = Effect("approve_refund", 20000, "ok", irreversible=True)
    d = limits.evaluate(e, {"policy_auto_limit": 50000})
    assert d.outcome is PolicyOutcome.ALLOW
    assert d.effect is e  # unchanged


def test_non_refund_effect_allowed():
    e = Effect("deny", 0, "no basis")
    d = limits.evaluate(e, {"policy_auto_limit": 50000})
    assert d.outcome is PolicyOutcome.ALLOW


def test_high_risk_merchant_requires_review():
    e = Effect("approve_merchant", 0, "ok", irreversible=True)
    d = limits.evaluate(e, {"mcc_risk": "high"})
    assert d.outcome is PolicyOutcome.REQUIRE_HUMAN_REVIEW
    assert d.effect.action == "escalate"


def test_enforce_backwards_compatible_tuple():
    e = Effect("approve_refund", 200000, "ok", irreversible=True)
    eff, reason = limits.enforce(e, {"policy_auto_limit": 50000})
    assert eff.action == "escalate" and reason and reason.startswith("capability_limit")


def test_reversible_refund_not_gated():
    # A non-irreversible approve is not money-out; policy leaves it alone.
    e = Effect("approve_refund", 999999, "ok", irreversible=False)
    d = limits.evaluate(e, {"policy_auto_limit": 50000})
    assert d.outcome is PolicyOutcome.ALLOW
