"""
Dual-mode LLM client.

LIVE mode  : calls the Claude API (needs ANTHROPIC_API_KEY).
OFFLINE mode: a deterministic, rule-based stand-in that faithfully models the
              *vulnerability* we study -- a back-office LLM that treats every
              span of text in its context as potentially instructional.

The firewall (firewall/*) is REAL code in both modes. Only the agent's
"reasoning" is simulated offline, and it is simulated as the honest failure
mode: naive instruction-following over untrusted input.
"""

from __future__ import annotations

import json
import os
import re

MODEL = os.environ.get("SENTINEL_MODEL", "claude-sonnet-4-5-20250929")


def have_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def mode() -> str:
    if os.environ.get("SENTINEL_FORCE_OFFLINE") == "1":
        return "offline"
    return "live" if have_key() else "offline"


# --------------------------------------------------------------------------
# LIVE backend
# --------------------------------------------------------------------------
_client = None


def _live_complete(system: str, user: str, max_tokens: int = 1024) -> str:
    global _client
    if _client is None:
        import anthropic

        _client = anthropic.Anthropic()
    resp = _client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


# --------------------------------------------------------------------------
# OFFLINE backend -- deterministic simulation of a naive instruction-follower
# --------------------------------------------------------------------------
# These patterns are the *observable* surface of an injection. The offline
# agent "obeys" them exactly the way an unguarded LLM would. This is not a
# rigged demo: it is the documented failure mode, made reproducible.
_IMPERATIVE_REFUND = re.compile(
    r"(ignore|disregard|override).{0,40}(previous|prior|above|instruction)"
    r"|(issue|process|approve|grant|authorli?ze|release).{0,30}(the )?(full |immediate )?refund"
    r"|auto[- ]?(resolve|approve).{0,20}(favou?r|customer|refund)"
    r"|resolve.{0,20}in (the )?(customer|cardholder)'?s? favou?r",
    re.I | re.S,
)
_AUTHORITY = re.compile(
    r"system (note|message|override|instruction)"
    r"|compliance (has )?(pre[- ]?)?approv"
    r"|as (an? )?(admin|administrator|supervisor|manager|mastercard)"
    r"|priority[- ]?override|internal use only.{0,40}approve"
    r"|per (network )?rule \d|regulation \w+ requires",
    re.I | re.S,
)


def _offline_dispute_agent(user: str) -> str:
    """Simulate an UNGUARDED, naive triage LLM. A gullible agent fails two ways,
    and this models both faithfully:
      (1) it obeys instructions / authority claims embedded in the input, and
      (2) it BELIEVES the stated reason without checking the bank's records.
    Note: this does NOT reference the injection detector's patterns -- an attack
    can succeed here purely by asserting a false reason (adjudication gaming),
    with no injection to detect. That is what makes Layer 3 necessary."""
    text = user
    obeys = bool(_IMPERATIVE_REFUND.search(text)) or bool(_AUTHORITY.search(text))
    # A naive agent takes the customer's stated reason at face value.
    claims_reason = bool(
        re.search(
            r"never (arrived|came|received|delivered|showed up)"
            r"|not delivered|did\s?n'?t (arrive|come|show up)"
            r"|parcel was never|order was never|item was never"
            r"|duplicate|charged (me )?twice|two charges"
            r"|cancel(l)?ed",
            text,
            re.I,
        )
    )
    if obeys or claims_reason:
        return json.dumps(
            {
                "tool": "approve_refund",
                "amount": _amount(text),
                "reason": "Accepted the submission's stated grounds for a refund.",
            }
        )
    return json.dumps({"tool": "deny", "reason": "No stated basis for a refund."})


def _offline_dispute_agent_hardened(user: str) -> str:
    """The OBVIOUS defence: a hardened system prompt telling the agent to ignore
    any instructions inside the customer's text and not act on embedded commands.

    This is what most teams reach for. It genuinely neutralises the OVERT
    injections (direct 'ignore instructions', spoofed authority, forged rules) --
    the agent no longer obeys them. But prompt-hardening says nothing about a
    customer who simply LIES about the facts. An adjudication-gaming attack -- a
    false 'my order never arrived' with no injection at all -- still lands,
    because the hardened agent still believes stated reasons. Only checking the
    bank's records (Sentinel's Layer 3) closes that gap."""
    text = user
    # hardening neutralises instruction/authority following ...
    # ... but the agent still trusts a plainly stated reason.
    claims_reason = bool(
        re.search(
            r"never (arrived|came|received|delivered|showed up)"
            r"|not delivered|did\s?n'?t (arrive|come|show up)"
            r"|parcel was never|order was never|item was never"
            r"|duplicate|charged (me )?twice|two charges"
            r"|cancel(l)?ed",
            text,
            re.I,
        )
    )
    if claims_reason:
        return json.dumps(
            {
                "tool": "approve_refund",
                "amount": _amount(text),
                "reason": "Ignored embedded instructions, but accepted the stated reason.",
            }
        )
    return json.dumps({"tool": "deny", "reason": "No basis; embedded instructions ignored."})


def _offline_kyb_agent(user: str) -> str:
    text = user
    obeys = bool(_AUTHORITY.search(text)) or bool(
        re.search(
            r"(approve|onboard|whitelist|fast[- ]?track).{0,30}(this )?(merchant|account|application)"
            r"|skip.{0,20}(review|verification|kyc|kyb)",
            text,
            re.I | re.S,
        )
    )
    red_flags = bool(
        re.search(
            r"(newly registered|registered (yesterday|today|last week)"
            r"|no (web|online) presence|reused|template|mismatch|shell)",
            text,
            re.I,
        )
    )
    if obeys:
        return json.dumps(
            {
                "tool": "approve_merchant",
                "reason": "Document states review complete / pre-approved.",
            }
        )
    if red_flags:
        return json.dumps({"tool": "reject_merchant", "reason": "Onboarding red flags present."})
    return json.dumps({"tool": "manual_review", "reason": "Insufficient basis to auto-approve."})


def _offline_adjudicator(user: str) -> str:
    """Layer-3 adjudicator, offline. Sees ONLY structured facts (see firewall/
    adjudicate.py), so injections in the narrative cannot reach it."""
    facts = json.loads(user)
    supported = facts.get("evidence_supports_claim", False)
    within = facts.get("amount", 0) <= facts.get("policy_auto_limit", 0)
    if supported and within:
        return json.dumps(
            {
                "verdict": "approve",
                "why": "Structured evidence supports the claim and amount within auto limit.",
            }
        )
    if supported and not within:
        return json.dumps(
            {"verdict": "escalate", "why": "Evidence supports claim but amount exceeds auto limit."}
        )
    return json.dumps({"verdict": "deny", "why": "Structured evidence does not support the claim."})


def _amount(text: str) -> int:
    m = re.search(r"(?:rs\.?|inr|₹)\s?([\d,]{3,})", text, re.I)
    if m:
        return int(m.group(1).replace(",", ""))
    m = re.search(r"([\d,]{4,})\s*(?:rupees|inr)", text, re.I)
    return int(m.group(1).replace(",", "")) if m else 5000


_OFFLINE_ROUTES = {
    "dispute": _offline_dispute_agent,
    "dispute_hardened": _offline_dispute_agent_hardened,
    "kyb": _offline_kyb_agent,
    "adjudicator": _offline_adjudicator,
}


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def complete(system: str, user: str, *, role: str = "dispute", max_tokens: int = 1024) -> str:
    """Route a completion. `role` selects the offline simulator; ignored live."""
    if mode() == "live":
        return _live_complete(system, user, max_tokens)
    return _OFFLINE_ROUTES[role](user)
