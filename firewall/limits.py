"""Layer 4 -- Capability limits (last line of defence).

Independent of anything the model decided: irreversible, high-value effects are
hard-gated. Even if every other layer is bypassed, an auto-refund above the
policy limit cannot execute without a human."""

from __future__ import annotations

from agents.tools import Effect


def enforce(effect: Effect, ledger: dict) -> tuple[Effect, str | None]:
    limit = ledger.get("policy_auto_limit", 50_000)
    if effect.action == "approve_refund" and effect.irreversible:
        if effect.amount > limit:
            return (
                Effect("escalate", 0, f"Auto-refund ₹{effect.amount:,} exceeds ₹{limit:,} limit."),
                f"capability_limit: amount {effect.amount} > {limit}",
            )
    return effect, None
