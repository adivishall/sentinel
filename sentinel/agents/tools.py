"""Tool calls an agent can emit, and how they map to recommendations.

An agent's tool call is *interpreted*, never executed. ``interpret`` turns the
raw call into an ``AIRecommendation`` whose ``requested_capability`` names the
consequential capability the model was asking for (if any). The composer
records it and decides independently.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from sentinel.domain.decisions import AIRecommendation
from sentinel.domain.enums import Capability
from sentinel.domain.ids import content_hash

# tool name -> capability the model is asking the system to exercise
TOOL_CAPABILITY: dict[str, Capability | None] = {
    "approve_refund": Capability.APPROVE_REFUND,
    "approve_merchant": Capability.APPROVE_MERCHANT,
    "approve_transaction": Capability.APPROVE_TRANSACTION,
    "allow": Capability.APPROVE_TRANSACTION,
    "release_funds": Capability.RELEASE_FUNDS,
    "change_payout": Capability.CHANGE_PAYOUT,
    "unfreeze_account": Capability.UNFREEZE_ACCOUNT,
    "freeze_account": Capability.FREEZE_ACCOUNT,
    "close_case": Capability.CLOSE_CASE,
    "alter_risk": Capability.ALTER_RISK,
    "skip_review": Capability.SKIP_REVIEW,
    # non-consequential
    "deny": None,
    "reject_merchant": None,
    "manual_review": None,
    "escalate": None,
    "review": None,
    "step_up": None,
    "block": None,
    "summarize": None,
    "noop": None,
}


@dataclass(frozen=True)
class ToolCall:
    tool: str
    amount: int
    reason: str
    raw: str


def parse_tool_call(raw: str, fallback_tool: str) -> ToolCall:
    """Fail-safe parse of a model's JSON tool call. Unparseable output falls
    back to the agent's safe tool (escalate / manual_review / review)."""
    text = raw.strip()
    a, b = text.find("{"), text.rfind("}")
    if a >= 0 and b > a:
        try:
            obj = json.loads(text[a : b + 1])
            if isinstance(obj, dict):
                tool = str(obj.get("tool", fallback_tool)).strip().lower()
                amount = obj.get("amount", 0)
                try:
                    amount_i = int(amount)
                except (TypeError, ValueError):
                    amount_i = 0
                return ToolCall(tool, amount_i, str(obj.get("reason", ""))[:300], raw)
        except json.JSONDecodeError:
            pass
    return ToolCall(fallback_tool, 0, "unparseable agent output", raw)


def interpret(
    call: ToolCall,
    *,
    agent: str,
    provider: str,
    model: str,
    latency_ms: float,
) -> AIRecommendation:
    cap = TOOL_CAPABILITY.get(call.tool, Capability.RECOMMEND_ACTION)
    return AIRecommendation(
        agent=agent,
        recommended_action=call.tool,
        requested_capability=cap,
        amount=call.amount,
        rationale=call.reason,
        provider=provider,
        model=model,
        latency_ms=round(latency_ms, 3),
        raw_hash=content_hash(call.raw),
    )
