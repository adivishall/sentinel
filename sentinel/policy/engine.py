"""Deterministic policy evaluation.

All rules are evaluated (not first-match), the most severe outcome wins, and
every matched rule is reported -- so the explanation is complete and stable
regardless of rule order. Missing required fields are an error, which the
composer turns into a fail-safe human review rather than a silent ALLOW."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from sentinel.domain.decisions import PolicyDecision
from sentinel.domain.enums import Capability, PolicyOutcome
from sentinel.domain.ids import content_hash
from sentinel.domain.vocab import CONTEXT_VALUES
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


def _type_ok(ftype: str, v: object) -> bool:
    if ftype == "int":
        return isinstance(v, int) and not isinstance(v, bool)
    if ftype == "float":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if ftype == "bool":
        return isinstance(v, bool)
    if ftype == "str":
        return isinstance(v, str)
    if ftype == "list":
        return isinstance(v, (list, tuple))
    return False


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
            # A value the field can never take makes a rule that can never fire -- a gate
            # that silently does nothing. Refused at load, not left to the linter.
            vals = c.value if isinstance(c.value, (list, tuple)) else [c.value]
            if c.field in _CAPABILITY_FIELDS and c.op in ("==", "!=", "in", "not_in"):
                caps = {x.value for x in Capability} | {"NONE"}
                bad = [v for v in vals if str(v) not in caps]
                if bad:
                    raise PolicyValidationError(f"rule {r.rule_id!r}: unknown capability {bad}")
            if c.field in _ENUM_VALUES and c.op in ("==", "!=", "in", "not_in"):
                bad = [v for v in vals if str(v) not in _ENUM_VALUES[c.field]]
                if bad:
                    raise PolicyValidationError(
                        f"rule {r.rule_id!r}: {c.field} can never be {bad} "
                        f"(allowed: {sorted(_ENUM_VALUES[c.field])})"
                    )
    for f in policy.required_fields:
        if f not in FIELD_CATALOG:
            raise PolicyValidationError(f"required field {f!r} is not in the catalog")
    undeclared = sorted(policy.referenced_fields - CONTEXT_FIELDS - set(policy.required_fields))
    if undeclared:
        raise PolicyValidationError(
            f"rules reference {undeclared} which the composer does not always provide; "
            "declare them in required_fields so their absence fails safe"
        )


_CAPABILITY_FIELDS = frozenset({"requested_capability"})
# One source with the record validation (sentinel.domain.vocab), so a value a record may
# hold is exactly a value a rule may name.
_ENUM_VALUES: dict[str, frozenset[str]] = CONTEXT_VALUES


def lint(policy: Policy) -> list[str]:
    """Configuration problems ``validate`` accepts but an operator should fix before
    activating a policy: unknown capability or enum values (a rule that can never
    fire), contradictory conditions on one field, duplicate conditions, rules
    shadowed by an identical stricter rule, an ALLOW rule (which can never change
    the outcome), and a missing effective date. Returns human-readable findings."""
    findings: list[str] = []
    if not policy.effective_from:
        findings.append("policy has no effective_from date")
    if not policy.rules:
        findings.append("policy has no rules; every decision falls to the default outcome")
    seen_when: dict[tuple[tuple[str, str, str], ...], str] = {}
    caps = {c.value for c in Capability}
    for r in policy.rules:
        if r.outcome is PolicyOutcome.ALLOW:
            findings.append(
                f"rule {r.rule_id!r}: outcome ALLOW never changes a decision (most severe wins)"
            )
        by_field: dict[str, list[Condition]] = {}
        for c in r.when:
            by_field.setdefault(c.field, []).append(c)
            vals = [c.value] if not isinstance(c.value, (list, tuple)) else list(c.value)
            if c.field in _CAPABILITY_FIELDS and c.op in ("==", "in", "!=", "not_in"):
                for v in vals:
                    if v != "NONE" and str(v) not in caps:
                        findings.append(f"rule {r.rule_id!r}: unknown capability {v!r}")
            if c.field in _ENUM_VALUES and c.op in ("==", "in", "!=", "not_in"):
                for v in vals:
                    if str(v) not in _ENUM_VALUES[c.field]:
                        findings.append(
                            f"rule {r.rule_id!r}: {c.field} can never equal {v!r} (allowed: {sorted(_ENUM_VALUES[c.field])})"
                        )
        for fld, conds in by_field.items():
            keys = {(c.op, repr(c.value)) for c in conds}
            if len(keys) < len(conds):
                findings.append(f"rule {r.rule_id!r}: duplicate condition on {fld!r}")
            eqs = {repr(c.value) for c in conds if c.op == "=="}
            if len(eqs) > 1:
                findings.append(
                    f"rule {r.rule_id!r}: contradictory equalities on {fld!r}; can never fire"
                )
            lo = [
                c.value for c in conds if c.op in (">", ">=") and isinstance(c.value, (int, float))
            ]
            hi = [
                c.value for c in conds if c.op in ("<", "<=") and isinstance(c.value, (int, float))
            ]
            if lo and hi and max(lo) >= min(hi):  # type: ignore[type-var]
                findings.append(
                    f"rule {r.rule_id!r}: empty numeric range on {fld!r}; can never fire"
                )
        key = tuple(sorted((c.field, c.op, repr(c.value)) for c in r.when))
        if key in seen_when:
            findings.append(f"rule {r.rule_id!r}: same conditions as rule {seen_when[key]!r}")
        else:
            seen_when[key] = r.rule_id
    return findings


def _named(*problems: list[str]) -> set[str]:
    return {p.split("=", 1)[0] for group in problems for p in group}


def _decisive_block(policy: Policy, context: Mapping[str, object], *, bad: set[str]):
    """The first BLOCK rule that can be evaluated on this context (none of its fields is
    missing, mistyped or outside its vocabulary) and matches; None otherwise."""
    for r in policy.rules:
        if r.outcome is not PolicyOutcome.BLOCK:
            continue
        fields = {c.field for c in r.when}
        if fields & bad or not fields <= set(context):
            continue
        if rule_matches(r, context):
            return PolicyDecision(
                policy_id=policy.policy_id,
                version=policy.version,
                outcome=PolicyOutcome.BLOCK,
                matched_rules=(r.rule_id,),
                explanations=(f"[{r.rule_id}] {r.describe()}: {r.reason}",),
                context_hash=content_hash({k: context[k] for k in sorted(context)}),
                policy_hash=policy.content_hash,
            )
    return None


def evaluate(policy: Policy, context: Mapping[str, object]) -> PolicyDecision:
    """Fail-closed: every field a rule reads must be present AND of its catalog type. A
    missing or mistyped input can never silently disable a rule (a string risk score
    would otherwise make ``risk_score >= 75`` quietly false)."""
    needed = set(policy.required_fields) | policy.referenced_fields
    missing = sorted(f for f in needed if f not in context)
    mistyped = sorted(
        f"{f}={context[f]!r} (expected {FIELD_CATALOG[f][0]})"
        for f in needed
        if f in context and f in FIELD_CATALOG and not _type_ok(FIELD_CATALOG[f][0], context[f])
    )
    # A value outside a field's vocabulary makes every rule on it silently false (a BLOCK on
    # refund_state == "refunded" never fires for "REFUNDED"): fail closed instead.
    unknown = sorted(
        f"{f}={context[f]!r}"
        for f in needed
        if f in context and f in _ENUM_VALUES and context[f] not in _ENUM_VALUES[f]
    )
    if missing or mistyped or unknown:
        # A context problem never lowers the outcome: a BLOCK rule whose own fields are all
        # present and valid, and which matches, is decisive -- the policy said BLOCK, and no
        # field the context lacks could have said anything stronger. (A failed-signature
        # BLOCK is not masked by the facts that failed with it.)
        problem = (
            (f"context missing fields {missing}" if missing else "")
            + (f" context fields of the wrong type {mistyped}" if mistyped else "")
            + (f" context values outside the vocabulary {unknown}" if unknown else "")
        ).strip()
        decisive = _decisive_block(policy, context, bad=set(missing) | _named(mistyped, unknown))
        if decisive is not None:
            note = f"[fail-closed] the context could not be fully evaluated ({problem})"
            return replace(decisive, explanations=decisive.explanations + (note,))
        raise PolicyEvaluationError(f"{policy.key}: {problem}")
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
