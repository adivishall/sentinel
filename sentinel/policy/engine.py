"""Deterministic policy evaluation.

All rules are evaluated (not first-match), the most severe outcome wins, and
every matched rule is reported -- so the explanation is complete and stable
regardless of rule order. Missing required fields are an error, which the
composer turns into a fail-safe human review rather than a silent ALLOW."""

from __future__ import annotations

from collections.abc import Mapping

from sentinel.domain.decisions import PolicyDecision
from sentinel.domain.ids import content_hash
from sentinel.policy.models import CONTEXT_FIELDS, FIELD_CATALOG, OPS, Condition, Policy, Rule


class PolicyValidationError(ValueError):
    """The policy document is malformed or references unknown fields."""


class PolicyEvaluationError(ValueError):
    """The context is missing fields the policy requires."""


def _cmp(op: str, actual: object, expected: object) -> bool:
    try:
        if op == "==":
            return actual == expected
        if op == "!=":
            return actual != expected
        if op == "is_true":
            return actual is True
        if op == "is_false":
            return actual is False
        if op == "in":
            return isinstance(expected, (list, tuple, set, frozenset)) and actual in expected
        if op == "not_in":
            return isinstance(expected, (list, tuple, set, frozenset)) and actual not in expected
        if op == "contains":
            return isinstance(actual, (list, tuple, set, frozenset, str)) and expected in actual
        if not isinstance(actual, (int, float)) or isinstance(actual, bool):
            return False
        if not isinstance(expected, (int, float)) or isinstance(expected, bool):
            return False
        return {
            ">": actual > expected,
            ">=": actual >= expected,
            "<": actual < expected,
            "<=": actual <= expected,
        }[op]
    except TypeError:
        return False


def condition_holds(c: Condition, context: Mapping[str, object]) -> bool:
    if c.field not in context:
        # ``evaluate`` rejects a context missing any referenced field before rules run;
        # this branch only guards direct calls.
        raise PolicyEvaluationError(f"condition on {c.field!r}: field absent from context")
    return _cmp(c.op, context[c.field], c.value)


def rule_matches(r: Rule, context: Mapping[str, object]) -> bool:
    return all(condition_holds(c, context) for c in r.when)


def validate(policy: Policy) -> None:
    if not policy.policy_id or policy.version < 1:
        raise PolicyValidationError("policy_id and version >= 1 are required")
    seen: set[str] = set()
    for r in policy.rules:
        if r.rule_id in seen:
            raise PolicyValidationError(f"duplicate rule id {r.rule_id!r}")
        seen.add(r.rule_id)
        if not r.when:
            raise PolicyValidationError(f"rule {r.rule_id!r} has no conditions")
        for c in r.when:
            if c.field not in FIELD_CATALOG:
                raise PolicyValidationError(f"rule {r.rule_id!r}: unknown field {c.field!r}")
            if c.op not in OPS:
                raise PolicyValidationError(f"rule {r.rule_id!r}: unknown op {c.op!r}")
            ftype = FIELD_CATALOG[c.field][0]
            if c.op in (">", ">=", "<", "<=") and ftype not in ("int", "float"):
                raise PolicyValidationError(
                    f"rule {r.rule_id!r}: {c.op} on non-numeric field {c.field!r}"
                )
            if c.op in ("is_true", "is_false") and ftype != "bool":
                raise PolicyValidationError(
                    f"rule {r.rule_id!r}: {c.op} on non-bool field {c.field!r}"
                )
            if c.op in ("in", "not_in") and not isinstance(c.value, (list, tuple)):
                raise PolicyValidationError(f"rule {r.rule_id!r}: {c.op} needs a list value")
    for f in policy.required_fields:
        if f not in FIELD_CATALOG:
            raise PolicyValidationError(f"required field {f!r} is not in the catalog")
    undeclared = sorted(policy.referenced_fields - CONTEXT_FIELDS - set(policy.required_fields))
    if undeclared:
        raise PolicyValidationError(
            f"rules reference {undeclared} which the composer does not always provide; "
            "declare them in required_fields so their absence fails safe"
        )


def evaluate(policy: Policy, context: Mapping[str, object]) -> PolicyDecision:
    """Fail-closed: every field a rule reads must be present. A missing input can
    never silently disable a rule."""
    needed = set(policy.required_fields) | policy.referenced_fields
    missing = sorted(f for f in needed if f not in context)
    if missing:
        raise PolicyEvaluationError(f"{policy.key}: context missing fields {missing}")
    matched = [r for r in policy.rules if rule_matches(r, context)]
    outcome = policy.default_outcome
    for r in matched:
        if r.outcome.rank > outcome.rank:
            outcome = r.outcome
    return PolicyDecision(
        policy_id=policy.policy_id,
        version=policy.version,
        outcome=outcome,
        matched_rules=tuple(r.rule_id for r in matched),
        explanations=tuple(f"[{r.rule_id}] {r.describe()}: {r.reason}" for r in matched),
        context_hash=content_hash({k: context[k] for k in sorted(context)}),
        policy_hash=policy.content_hash,
    )
