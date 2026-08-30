"""Tools the back-office agents can call. Each returns a structured effect.

The `effect` is what a real system would ACT on -- money movement, account
state. The firewall's job is to ensure the effect matches policy and the
verified facts, not the attacker's text."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Effect:
    action: str  # approve_refund | deny | escalate | approve_merchant | ...
    amount: int = 0
    reason: str = ""
    irreversible: bool = False  # money leaves / merchant goes live


# Dispute-triage tool surface
DISPUTE_TOOLS = {
    "approve_refund": lambda amount=0, reason="", **_: Effect(
        "approve_refund", amount, reason, irreversible=True
    ),
    "deny": lambda reason="", **_: Effect("deny", 0, reason),
    "escalate": lambda reason="", **_: Effect("escalate", 0, reason),
}
# KYB / merchant-onboarding tool surface
KYB_TOOLS = {
    "approve_merchant": lambda reason="", **_: Effect(
        "approve_merchant", 0, reason, irreversible=True
    ),
    "reject_merchant": lambda reason="", **_: Effect("reject_merchant", 0, reason),
    "manual_review": lambda reason="", **_: Effect("manual_review", 0, reason),
}


def apply(toolset: dict, call: dict) -> Effect:
    name = call.get("tool", "")
    fn = toolset.get(name)
    if fn is None:
        return Effect("noop", reason=f"unknown tool {name!r}")
    kwargs = {k: v for k, v in call.items() if k != "tool"}
    try:
        return fn(**kwargs)
    except TypeError:
        return fn(reason=call.get("reason", ""))
