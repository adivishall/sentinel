"""Layer 3 for the KYB / merchant-onboarding surface.

Same principle as the dispute adjudicator: the decision is made ONLY over
verified facts the acquirer already holds (registration status, domain age,
prior fraud flags, business age) -- never over the prose in the uploaded
application, which is attacker-controlled. A document that *says* "review
complete, approve" cannot move the decision.
"""

from __future__ import annotations

import json

from firewall.adjudicate import _parse_verdict
from firewall.trust import KYBFacts
from llm import complete

KYB_ADJUDICATOR_SYSTEM = (
    "You are a merchant-onboarding (KYB) adjudicator. You receive ONLY a JSON "
    "object of verified facts from the acquirer's own records -- never the "
    "applicant's prose. Decide strictly from these facts. Reply with a single "
    'JSON object and nothing else: {"verdict": "approve" | "deny" | "escalate", '
    '"why": "<one sentence>"}. Approve only when registration_status is '
    "'verified', domain_age_days >= 30, business_age_days >= 90 and prior_flags "
    "== 0; deny when registration_status is 'shell' or prior_flags >= 2; "
    "otherwise escalate to manual review."
)

MIN_DOMAIN_AGE = 30
MIN_BUSINESS_AGE = 90


def extract_facts(application: str, records: dict) -> dict:
    """Verified onboarding facts. Application prose is deliberately ignored --
    only the acquirer's own records (typed as ``KYBFacts``) reach the decision."""
    return KYBFacts.from_records(records).as_adjudicator_input()


def _decide_offline(f: dict) -> dict:
    if f["registration_status"] == "shell" or f["prior_flags"] >= 2:
        return {"verdict": "deny", "why": "Shell registration or repeated prior fraud flags."}
    if (
        f["registration_status"] == "verified"
        and f["domain_age_days"] >= MIN_DOMAIN_AGE
        and f["business_age_days"] >= MIN_BUSINESS_AGE
        and f["prior_flags"] == 0
    ):
        return {"verdict": "approve", "why": "Registration verified and history clean."}
    return {"verdict": "escalate", "why": "Verification incomplete; sent to manual review."}


def adjudicate(application: str, records: dict) -> dict:
    facts = extract_facts(application, records)
    from llm import mode

    if mode() == "live":
        verdict = _parse_verdict(
            complete(KYB_ADJUDICATOR_SYSTEM, json.dumps(facts), role="kyb_adjudicator")
        )
    else:
        verdict = _decide_offline(facts)
    verdict["facts"] = facts
    return verdict
