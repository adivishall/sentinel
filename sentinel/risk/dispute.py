"""Dispute-level risk over trusted dispute facts and the account profile."""

from __future__ import annotations

from sentinel.domain.risk import RiskAssessment
from sentinel.risk import scoring
from sentinel.risk.scoring import RiskModel, Rule, num
from sentinel.security.trust_boundary import DisputeFacts


def extract_features(
    facts: DisputeFacts, *, contradicted: bool, account_risk_score: int, security_flagged: bool
) -> dict[str, object]:
    return {
        "amount": facts.amount,
        "prior_disputes_90d": facts.prior_disputes_90d,
        "over_auto_limit": facts.amount > facts.policy_auto_limit,
        "claim_contradicted": contradicted,
        "account_risk_score": account_risk_score,
        "security_flagged": security_flagged,
        "evidence_ids": {},
    }


RULES: tuple[Rule, ...] = (
    (
        "prior_disputes_many",
        "Multiple prior disputes",
        lambda f, m: (
            f"{f.get('prior_disputes_90d')} in 90 days"
            if num(f, "prior_disputes_90d") >= 2
            else None
        ),
    ),
    (
        "prior_disputes_some",
        "A prior dispute",
        lambda f, m: "1 in 90 days" if num(f, "prior_disputes_90d") == 1 else None,
    ),
    (
        "amount_over_auto_limit",
        "Amount over auto-approval limit",
        lambda f, m: f"₹{int(num(f, 'amount')):,}" if f.get("over_auto_limit") else None,
    ),
    (
        "claim_contradicted",
        "Claim contradicted by ledger",
        lambda f, m: (
            "trusted record disagrees with the claim" if f.get("claim_contradicted") else None
        ),
    ),
    (
        "account_risk_high",
        "High account risk",
        lambda f, m: (
            f"account score {int(num(f, 'account_risk_score'))}"
            if num(f, "account_risk_score") >= 50
            else None
        ),
    ),
    (
        "account_risk_medium",
        "Medium account risk",
        lambda f, m: (
            f"account score {int(num(f, 'account_risk_score'))}"
            if 25 <= num(f, "account_risk_score") < 50
            else None
        ),
    ),
    (
        "security_flagged",
        "AI-security finding on submission",
        lambda f, m: "gateway flagged the submission" if f.get("security_flagged") else None,
    ),
)


def assess_dispute(
    dispute_id: str,
    facts: DisputeFacts,
    *,
    contradicted: bool,
    account_risk_score: int = 0,
    security_flagged: bool = False,
    model: RiskModel = scoring.DISPUTE_V1,
) -> RiskAssessment:
    features = extract_features(
        facts,
        contradicted=contradicted,
        account_risk_score=account_risk_score,
        security_flagged=security_flagged,
    )
    return scoring.build_assessment(
        entity_type="dispute", entity_id=dispute_id, features=features, model=model, rules=RULES
    )
