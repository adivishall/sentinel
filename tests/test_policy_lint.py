"""Policy linter and exhaustive policy boundary checks."""

from __future__ import annotations

import pytest

from sentinel.domain.enums import ActorKind, AuthorizationStatus, Capability, PolicyOutcome
from sentinel.policy import DEFAULT_REGISTRY, evaluate, lint
from sentinel.policy.engine import PolicyEvaluationError
from sentinel.policy.loader import policy_from_dict
from sentinel.security import capabilities


def _doc(rules, **over):
    base = {
        "policy_id": "t",
        "version": 1,
        "workflow": "dispute",
        "default_outcome": "ALLOW",
        "effective_from": "2026-01-01",
        "required_fields": ["account_status", "amount"],
        "rules": rules,
    }
    base.update(over)
    return base


def test_shipped_policies_lint_clean():
    for p in DEFAULT_REGISTRY.all():
        assert lint(p) == [], (p.key, lint(p))


@pytest.mark.parametrize(
    "rules, over, needle",
    [
        (
            [
                {
                    "id": "a",
                    "when": [
                        {"field": "amount", "op": ">", "value": 100},
                        {"field": "amount", "op": "<", "value": 50},
                    ],
                    "outcome": "BLOCK",
                }
            ],
            {},
            "empty numeric range",
        ),
        (
            [
                {
                    "id": "a",
                    "when": [
                        {"field": "account_status", "op": "==", "value": "frozen"},
                        {"field": "account_status", "op": "==", "value": "active"},
                    ],
                    "outcome": "BLOCK",
                }
            ],
            {},
            "contradictory",
        ),
        (
            [
                {
                    "id": "a",
                    "when": [
                        {"field": "amount", "op": ">", "value": 1},
                        {"field": "amount", "op": ">", "value": 1},
                    ],
                    "outcome": "BLOCK",
                }
            ],
            {},
            "duplicate condition",
        ),
        (
            [
                {
                    "id": "a",
                    "when": [{"field": "amount", "op": ">", "value": 1}],
                    "outcome": "BLOCK",
                },
                {
                    "id": "b",
                    "when": [{"field": "amount", "op": ">", "value": 1}],
                    "outcome": "REQUIRE_HUMAN_REVIEW",
                },
            ],
            {},
            "same conditions",
        ),
        (
            [{"id": "a", "when": [{"field": "amount", "op": ">", "value": 1}], "outcome": "ALLOW"}],
            {},
            "never changes",
        ),
        (
            [{"id": "a", "when": [{"field": "amount", "op": ">", "value": 1}], "outcome": "BLOCK"}],
            {"effective_from": ""},
            "effective_from",
        ),
        ([], {}, "no rules"),
    ],
)
def test_linter_reports_each_configuration_problem(rules, over, needle):
    findings = lint(policy_from_dict(_doc(rules, **over)))
    assert any(needle in f for f in findings), findings


def test_conflicting_rules_resolve_to_the_most_severe_deterministically():
    p = policy_from_dict(
        _doc(
            [
                {
                    "id": "allow-ish",
                    "when": [{"field": "amount", "op": ">", "value": 0}],
                    "outcome": "STEP_UP",
                },
                {
                    "id": "review",
                    "when": [{"field": "amount", "op": ">", "value": 0}],
                    "outcome": "REQUIRE_HUMAN_REVIEW",
                },
                {
                    "id": "block",
                    "when": [{"field": "account_status", "op": "==", "value": "frozen"}],
                    "outcome": "BLOCK",
                },
            ]
        )
    )
    d = evaluate(p, {"amount": 1, "account_status": "frozen"})
    assert d.outcome is PolicyOutcome.BLOCK and set(d.matched_rules) == {
        "allow-ish",
        "review",
        "block",
    }
    d2 = evaluate(p, {"amount": 1, "account_status": "active"})
    assert d2.outcome is PolicyOutcome.REQUIRE_HUMAN_REVIEW


def test_malformed_field_values_never_match_and_missing_fields_fail_closed():
    p = policy_from_dict(
        _doc(
            [
                {
                    "id": "big",
                    "when": [{"field": "amount", "op": ">", "value": 50000}],
                    "outcome": "BLOCK",
                }
            ]
        )
    )
    for bad in ("999999", None, [], {}, True, float("nan")):
        # a malformed number cannot silently disable the BLOCK rule: evaluation fails closed
        # (the composer turns this into a human review, never an ALLOW)
        with pytest.raises(PolicyEvaluationError, match="wrong type"):
            evaluate(p, {"amount": bad, "account_status": "active"})
    assert evaluate(p, {"amount": 999_999, "account_status": "active"}).outcome.value == "BLOCK"
    with pytest.raises(PolicyEvaluationError):
        evaluate(p, {"account_status": "active"})


@pytest.mark.parametrize(
    "cap, actor, outcome, supported, expect",
    [
        (
            Capability.APPROVE_REFUND,
            ActorKind.SYSTEM,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.GRANTED,
        ),
        (
            Capability.APPROVE_REFUND,
            ActorKind.AI_AGENT,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.DENIED,
        ),
        (
            Capability.APPROVE_REFUND,
            ActorKind.SYSTEM,
            PolicyOutcome.ALLOW,
            False,
            AuthorizationStatus.DENIED,
        ),
        (
            Capability.APPROVE_REFUND,
            ActorKind.SYSTEM,
            PolicyOutcome.BLOCK,
            True,
            AuthorizationStatus.DENIED,
        ),
        (
            Capability.APPROVE_REFUND,
            ActorKind.SYSTEM,
            PolicyOutcome.REQUIRE_HUMAN_REVIEW,
            True,
            AuthorizationStatus.PENDING_HUMAN,
        ),
        (
            Capability.RELEASE_FUNDS,
            ActorKind.SYSTEM,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.DENIED,
        ),
        (
            Capability.RELEASE_FUNDS,
            ActorKind.SENIOR_REVIEWER,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.GRANTED,
        ),
        (
            Capability.UNFREEZE_ACCOUNT,
            ActorKind.HUMAN_REVIEWER,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.GRANTED,
        ),
        (
            Capability.SKIP_REVIEW,
            ActorKind.SENIOR_REVIEWER,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.DENIED,
        ),
        (
            Capability.CLOSE_CASE,
            ActorKind.AI_AGENT,
            PolicyOutcome.ALLOW,
            True,
            AuthorizationStatus.DENIED,
        ),
        (
            Capability.READ_ACCOUNT,
            ActorKind.AI_AGENT,
            PolicyOutcome.ALLOW,
            False,
            AuthorizationStatus.GRANTED,
        ),
        (None, ActorKind.EXTERNAL, PolicyOutcome.BLOCK, False, AuthorizationStatus.GRANTED),
    ],
)
def test_authorization_matrix(cap, actor, outcome, supported, expect):
    a = capabilities.authorize(
        cap, actor=actor, amount=1000, policy_outcome=outcome, evidence_supported=supported
    )
    assert a.status is expect, a.reason


@pytest.mark.parametrize(
    "amount, expect",
    [(50_000, AuthorizationStatus.GRANTED), (50_001, AuthorizationStatus.PENDING_HUMAN)],
)
def test_human_review_threshold_boundary(amount, expect):
    a = capabilities.authorize(
        Capability.APPROVE_REFUND,
        actor=ActorKind.SYSTEM,
        amount=amount,
        policy_outcome=PolicyOutcome.ALLOW,
        evidence_supported=True,
    )
    assert a.status is expect


def test_unknown_actor_or_capability_is_rejected_at_the_type_boundary():
    with pytest.raises(ValueError):
        ActorKind("ROOT")
    with pytest.raises(ValueError):
        Capability("GRANT_ALL")
