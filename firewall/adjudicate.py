"""Layer 3 -- Structured-facts adjudication  (the core idea).

Even a perfect injection detector will miss 'adjudication gaming': a narrative
with NO injection that is simply written to exploit the model's decision
heuristics. So the final decision is NOT made over the raw narrative.

Instead we extract STRUCTURED FACTS from verified sources (the bank's own DB,
plus claims from the narrative clearly labelled as unverified), and a second
adjudicator decides using only those facts. The attacker's prose never reaches
the decision maker. This layer is structurally immune to text-level attacks."""

from __future__ import annotations

import json
import re

from llm import complete


def extract_facts(narrative: str, ledger: dict) -> dict:
    """Build the structured fact sheet. `ledger` = verified account/txn facts
    the bank already holds (trusted). Narrative claims are recorded but flagged
    unverified and are NOT sufficient on their own."""
    claim_type = _claim_type(narrative)
    facts = {
        # trusted, from the bank's own records
        "amount": ledger.get("amount", 0),
        "merchant": ledger.get("merchant", "unknown"),
        "delivery_status": ledger.get("delivery_status", "unknown"),
        "prior_disputes_90d": ledger.get("prior_disputes_90d", 0),
        "policy_auto_limit": ledger.get("policy_auto_limit", 50_000),
        # derived
        "claimed_reason": claim_type,
        # the verdict-relevant boolean is computed ONLY from trusted evidence
        "evidence_supports_claim": _supported(claim_type, ledger),
    }
    return facts


ADJUDICATOR_SYSTEM = (
    "You are a payments dispute adjudicator. You receive ONLY a JSON object of "
    "structured, verified facts -- never customer prose. Decide strictly from "
    "these facts. Reply with a single JSON object and nothing else: "
    '{"verdict": "approve" | "deny" | "escalate", "why": "<one sentence>"}. '
    "Approve only when evidence_supports_claim is true and the amount is within "
    "policy_auto_limit; escalate when supported but over limit; otherwise deny."
)

_VALID_VERDICTS = ("approve", "deny", "escalate")


def _parse_verdict(raw: str) -> dict:
    """Fail-safe parse of adjudicator output. Any malformed or unexpected
    response escalates to a human -- the decisive layer never crashes or
    silently approves on bad output (mirrors the input fail-safe in pipeline)."""
    a, b = raw.find("{"), raw.rfind("}")
    if a >= 0 and b > a:
        try:
            v = json.loads(raw[a : b + 1])
            if isinstance(v, dict) and v.get("verdict") in _VALID_VERDICTS:
                return {"verdict": v["verdict"], "why": str(v.get("why", ""))[:300]}
        except json.JSONDecodeError:
            pass
    return {"verdict": "escalate", "why": "Adjudicator output unparseable; escalated for safety."}


def adjudicate(narrative: str, ledger: dict) -> dict:
    facts = extract_facts(narrative, ledger)
    verdict = _parse_verdict(complete(ADJUDICATOR_SYSTEM, json.dumps(facts), role="adjudicator"))
    verdict["facts"] = facts
    return verdict


def _claim_type(text: str) -> str:
    t = text.lower()
    if re.search(r"never (arrived|received|delivered)|not delivered|non[- ]receipt", t):
        return "non_receipt"
    if re.search(r"in transit|still (on the way|coming)|not (yet )?arrived", t):
        return "in_transit"
    if re.search(r"duplicate|charged twice|two charges|charged.{0,10}twice", t):
        return "duplicate"
    if re.search(r"cancel(l)?ed?.{0,20}order|order.{0,20}cancel|cancelled.{0,20}(it|within)", t):
        return "cancellation"
    if re.search(
        r"fraud|didn'?t (make|authorize)|unauthori[sz]ed|don'?t recognis|"
        r"not mine|card with me|never (made|authori)",
        t,
    ):
        return "unauthorized"
    return "unspecified"


def _supported(claim: str, ledger: dict) -> bool:
    """Is the claim backed by the bank's OWN trusted records?"""
    ds = ledger.get("delivery_status", "unknown")
    if claim == "non_receipt":
        return ds in ("not_delivered", "returned", "lost")
    if claim == "duplicate":
        return ledger.get("duplicate_confirmed", False)
    if claim == "cancellation":
        return ledger.get("cancellation_confirmed", False)
    if claim == "unauthorized":
        return ledger.get("cardholder_present", True) is False
    return False
