"""Policy-as-code: schema validation, deterministic evaluation, versioning."""

import json

import pytest

from sentinel.domain.enums import PolicyOutcome, Workflow
from sentinel.policy import (
    DEFAULT_REGISTRY,
    PolicyRegistry,
    PolicyValidationError,
    evaluate,
    load_policy,
)
from sentinel.policy.engine import PolicyEvaluationError
from sentinel.policy.loader import policy_from_dict
from sentinel.policy.models import Condition, Policy, Rule


def _doc(**over):
    base = {
        "policy_id": "t",
        "version": 1,
        "workflow": "dispute",
        "description": "x",
        "rules": [
            {
                "id": "r1",
                "when": [{"field": "amount", "op": ">", "value": 50000}],
                "outcome": "REQUIRE_HUMAN_REVIEW",
                "reason": "big",
            },
            {
                "id": "r2",
                "when": [{"field": "security_severity", "op": "==", "value": "CRITICAL"}],
                "outcome": "BLOCK",
                "reason": "sec",
            },
        ],
    }
    base.update(over)
    return base


def test_builtin_policies_load_and_validate():
    keys = [p.key for p in DEFAULT_REGISTRY.all()]
    assert {"dispute-refund@v1", "dispute-refund@v2", "dispute-refund@v3"} <= set(keys)
    assert DEFAULT_REGISTRY.versions("dispute-refund") == [1, 2, 3]
    assert DEFAULT_REGISTRY.get("dispute-refund").version == 3  # latest by default
    covered = {p.workflow for p in DEFAULT_REGISTRY.all()}
    assert covered == set(Workflow) - {Workflow.AI_SECURITY}


def test_most_severe_outcome_wins_and_all_matches_reported():
    p = policy_from_dict(_doc())
    d = evaluate(p, {"amount": 90000, "security_severity": "CRITICAL"})
    assert d.outcome is PolicyOutcome.BLOCK and set(d.matched_rules) == {"r1", "r2"}
    assert len(d.explanations) == 2 and d.context_hash
    d2 = evaluate(p, {"amount": 100, "security_severity": "NONE"})
    assert d2.outcome is PolicyOutcome.ALLOW and d2.matched_rules == ()


def test_evaluation_is_deterministic_and_order_independent():
    p1 = policy_from_dict(_doc())
    doc = _doc()
    doc["rules"].reverse()
    p2 = policy_from_dict(doc)
    ctx = {"amount": 90000, "security_severity": "CRITICAL"}
    assert evaluate(p1, ctx).outcome is evaluate(p2, ctx).outcome
    assert evaluate(p1, ctx).context_hash == evaluate(p2, ctx).context_hash


def test_missing_required_field_is_an_error_not_allow():
    p = policy_from_dict(_doc(required_fields=["evidence_verdict"]))
    with pytest.raises(PolicyEvaluationError):
        evaluate(p, {"amount": 1})


def test_absent_referenced_field_is_an_error_never_a_silent_non_match():
    """Fail-closed: a missing input can never disable a rule. (v2.0.0 treated an absent
    field as 'condition does not hold', which silently switched BLOCK rules off.)"""
    p = policy_from_dict(_doc())
    with pytest.raises(PolicyEvaluationError):
        evaluate(p, {})
    with pytest.raises(PolicyEvaluationError):
        evaluate(p, {"amount": 90000})  # security_severity is referenced by r2


def test_rules_may_only_reference_declared_or_always_present_fields():
    bad = _doc(
        rules=[
            {
                "id": "frozen",
                "when": [{"field": "account_status", "op": "==", "value": "frozen"}],
                "outcome": "BLOCK",
            }
        ]
    )
    with pytest.raises(PolicyValidationError, match="required_fields"):
        policy_from_dict(bad)
    ok = policy_from_dict({**bad, "required_fields": ["account_status"]})
    assert evaluate(ok, {"account_status": "frozen"}).outcome is PolicyOutcome.BLOCK
    with pytest.raises(PolicyEvaluationError):
        evaluate(ok, {})


def test_policy_content_hash_changes_when_content_changes_not_when_version_label_reused():
    a = policy_from_dict(_doc())
    b = policy_from_dict(_doc())
    doc = _doc()
    doc["rules"][0]["when"][0]["value"] = 10_000  # same policy_id, same version, new threshold
    c = policy_from_dict(doc)
    assert a.content_hash == b.content_hash and a.content_hash != c.content_hash
    assert evaluate(a, {"amount": 1, "security_severity": "NONE"}).policy_hash == a.content_hash


@pytest.mark.parametrize(
    "bad",
    [
        {
            "rules": [
                {"id": "r", "when": [{"field": "nope", "op": "==", "value": 1}], "outcome": "BLOCK"}
            ]
        },
        {
            "rules": [
                {
                    "id": "r",
                    "when": [{"field": "amount", "op": "~", "value": 1}],
                    "outcome": "BLOCK",
                }
            ]
        },
        {
            "rules": [
                {
                    "id": "r",
                    "when": [{"field": "risk_level", "op": ">", "value": 1}],
                    "outcome": "BLOCK",
                }
            ]
        },
        {
            "rules": [
                {"id": "r", "when": [{"field": "amount", "op": "is_true"}], "outcome": "BLOCK"}
            ]
        },
        {
            "rules": [
                {
                    "id": "r",
                    "when": [{"field": "amount", "op": "in", "value": 5}],
                    "outcome": "BLOCK",
                }
            ]
        },
        {"rules": [{"id": "r", "when": [], "outcome": "BLOCK"}]},
        {
            "rules": [
                {
                    "id": "r",
                    "when": [{"field": "amount", "op": "==", "value": 1}],
                    "outcome": "MAYBE",
                }
            ]
        },
        {"version": 0},
        {
            "rules": [
                {
                    "id": "r",
                    "when": [{"field": "amount", "op": "==", "value": 1}],
                    "outcome": "BLOCK",
                },
                {
                    "id": "r",
                    "when": [{"field": "amount", "op": "==", "value": 2}],
                    "outcome": "BLOCK",
                },
            ]
        },
    ],
)
def test_schema_validation_rejects_malformed_policies(bad):
    with pytest.raises(PolicyValidationError):
        policy_from_dict(_doc(**bad))


def test_operators():
    p = Policy(
        "p",
        1,
        Workflow.DISPUTE,
        "",
        (
            Rule("in", (Condition("evidence_verdict", "in", ["A", "B"]),), PolicyOutcome.BLOCK, ""),
            Rule("notin", (Condition("claim_type", "not_in", ["x"]),), PolicyOutcome.STEP_UP, ""),
            Rule(
                "contains",
                (Condition("threat_classes", "contains", "direct_injection"),),
                PolicyOutcome.TEMPORARY_HOLD,
                "",
            ),
            Rule(
                "false",
                (Condition("new_device", "is_false"),),
                PolicyOutcome.REQUIRE_HUMAN_REVIEW,
                "",
            ),
        ),
    )
    d = evaluate(
        p,
        {
            "evidence_verdict": "A",
            "claim_type": "y",
            "threat_classes": ["direct_injection"],
            "new_device": False,
        },
    )
    assert set(d.matched_rules) == {"in", "notin", "contains", "false"}
    # type confusion never matches numerically
    p2 = Policy(
        "p",
        1,
        Workflow.DISPUTE,
        "",
        (Rule("gt", (Condition("amount", ">", 5),), PolicyOutcome.BLOCK, ""),),
    )
    assert evaluate(p2, {"amount": "999"}).outcome is PolicyOutcome.ALLOW
    assert evaluate(p2, {"amount": True}).outcome is PolicyOutcome.ALLOW


def test_load_from_file_and_roundtrip(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps(_doc()))
    p = load_policy(path)
    assert p.key == "t@v1"
    again = policy_from_dict(p.to_dict())
    assert again == p


def test_registry_versions_and_errors():
    reg = PolicyRegistry()
    reg.register(policy_from_dict(_doc(version=1)))
    reg.register(policy_from_dict(_doc(version=3)))
    assert (
        reg.versions("t") == [1, 3] and reg.get("t").version == 3 and reg.get("t", 1).version == 1
    )
    with pytest.raises(KeyError):
        reg.get("t", 2)
    with pytest.raises(KeyError):
        reg.get("missing")
