"""Layer 3 -- Structured-facts adjudication  (the core idea).

Even a perfect injection detector will miss 'adjudication gaming': a narrative
with NO injection that is simply written to exploit the model's decision
heuristics. So the final decision is NOT made over the raw narrative.

Instead we extract STRUCTURED FACTS from verified sources (the bank's own DB),
and a second adjudicator decides using only those facts. The attacker's prose
never reaches the decision maker.

The trust boundary is enforced by types (see ``firewall/trust.py``): the only
value derived from the untrusted narrative is a coarse ``ClaimType``, which
merely selects *which* verified fact to check. The authoritative
``evidence_supports_claim`` is a pure function of ``DisputeFacts`` -- data the
bank already holds. This layer is structurally immune to text-level attacks.
"""

from __future__ import annotations

import json

from firewall.trust import ClaimType, DisputeFacts, UntrustedText
from llm import complete


def extract_facts(narrative: str, ledger: dict) -> dict:
    """Build the structured fact sheet handed to the adjudicator.

    ``ledger`` = verified account/txn facts the bank already holds (trusted).
    The narrative contributes ONLY a coarse claim label; the verdict-relevant
    boolean (``evidence_supports_claim``) is computed solely from trusted facts.
    """
    claim = UntrustedText(narrative).classify()
    facts = DisputeFacts.from_ledger(ledger)
    return facts.as_adjudicator_input(claim)


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
    """Decide a dispute. The narrative is used *only* to classify the claim type;
    the authoritative facts come from the ledger. The adjudicator model is handed
    the structured facts JSON and never the prose."""
    facts = extract_facts(narrative, ledger)
    verdict = _parse_verdict(complete(ADJUDICATOR_SYSTEM, json.dumps(facts), role="adjudicator"))
    verdict["facts"] = facts
    return verdict


# --- Backwards-compatible helpers (kept so existing imports/tests keep working) --


def _claim_type(text: str) -> str:
    """Legacy string API; delegates to the typed classifier."""
    return UntrustedText(text).classify().value


def _supported(claim: str, ledger: dict) -> bool:
    """Legacy string API; delegates to ``DisputeFacts.supports``."""
    return DisputeFacts.from_ledger(ledger).supports(ClaimType(claim))
