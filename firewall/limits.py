"""Layer 4 -- Capability policy engine (last line of defence).

Independent of anything the model decided: high-impact, irreversible effects are
gated by explicit policy. Even if every other layer were bypassed, an auto-refund
above the policy limit cannot execute without a human.

Policies are represented as data (a list of ``Rule``s), each producing an
explainable ``PolicyOutcome``:

    ALLOW                 the effect may execute as-is
    REQUIRE_HUMAN_REVIEW  downgrade to an escalation for a human
    BLOCK                 refuse the effect outright

The engine considers action type, amount/risk, reversibility and authorization.
``enforce`` keeps its original ``(Effect, reason|None)`` contract so the pipeline
is unchanged; ``evaluate`` exposes the full decision for the API/console.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from agents.tools import Effect


class PolicyOutcome(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class Rule:
    name: str
    outcome: PolicyOutcome
    applies: Callable[[Effect, dict], bool]
    explain: Callable[[Effect, dict], str]


@dataclass
class PolicyDecision:
    outcome: PolicyOutcome
    rule: str | None
    reason: str | None
    effect: Effect


def _auto_limit(facts: dict) -> int:
    try:
        return int(facts.get("policy_auto_limit", 50_000) or 50_000)
    except (TypeError, ValueError):
        return 50_000


# ---- Policy set (data). First matching non-ALLOW rule wins. -------------------
RULES: list[Rule] = [
    Rule(
        name="refund_over_auto_limit",
        outcome=PolicyOutcome.REQUIRE_HUMAN_REVIEW,
        applies=lambda e, f: e.action == "approve_refund"
        and e.irreversible
        and e.amount > _auto_limit(f),
        explain=lambda e, f: (f"Auto-refund ₹{e.amount:,} exceeds ₹{_auto_limit(f):,} auto-limit."),
    ),
    Rule(
        name="irreversible_merchant_high_risk",
        outcome=PolicyOutcome.REQUIRE_HUMAN_REVIEW,
        applies=lambda e, f: e.action == "approve_merchant"
        and e.irreversible
        and str(f.get("mcc_risk", "")).lower() == "high",
        explain=lambda e, f: "Irreversible merchant onboarding at high MCC risk.",
    ),
]


def evaluate(effect: Effect, facts: dict) -> PolicyDecision:
    """Apply the policy set to a proposed effect and return an explainable decision."""
    for rule in RULES:
        if rule.applies(effect, facts):
            reason = rule.explain(effect, facts)
            if rule.outcome is PolicyOutcome.ALLOW:
                continue
            if rule.outcome is PolicyOutcome.BLOCK:
                new = Effect("deny", 0, reason)
            else:  # REQUIRE_HUMAN_REVIEW
                new = Effect("escalate", 0, reason)
            return PolicyDecision(rule.outcome, rule.name, f"capability_limit: {reason}", new)
    return PolicyDecision(PolicyOutcome.ALLOW, None, None, effect)


def enforce(effect: Effect, ledger: dict) -> tuple[Effect, str | None]:
    """Backwards-compatible wrapper: returns (possibly transformed effect, reason)."""
    decision = evaluate(effect, ledger)
    return decision.effect, decision.reason
