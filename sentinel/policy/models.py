"""Policy schema.

    policy_id: dispute-refund
    version: 2
    workflow: dispute
    rules:
      - id: block-critical-security
        when: [{field: security_severity, op: "==", value: CRITICAL}]
        outcome: BLOCK
        reason: ...

Every field a rule may reference is declared in ``FIELD_CATALOG`` with its
type and meaning; the loader rejects anything else. That is what makes a
policy a validated schema rather than displayed YAML."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.enums import PolicyOutcome, Workflow
from sentinel.domain.ids import content_hash

OPS: frozenset[str] = frozenset(
    {"==", "!=", ">", ">=", "<", "<=", "in", "not_in", "is_true", "is_false", "contains"}
)

# name -> (type, description). Types: int | float | str | bool | list
FIELD_CATALOG: dict[str, tuple[str, str]] = {
    "workflow": ("str", "Workflow being decided"),
    "subject_type": ("str", "transaction | dispute | merchant | login | account"),
    "amount": ("int", "Amount in INR (whole rupees)"),
    "requested_capability": ("str", "Consequential capability the decision path is considering"),
    "capability_irreversible": ("bool", "Whether that capability is irreversible"),
    "capability_financial_effect": (
        "bool",
        "Whether that capability moves money / changes financial state",
    ),
    "risk_score": ("int", "Risk score 0-100"),
    "risk_level": ("str", "LOW | MEDIUM | HIGH | CRITICAL"),
    "risk_factors": ("list", "Factor codes that fired"),
    "evidence_verdict": ("str", "SUPPORTED | UNSUPPORTED | CONTRADICTED | INSUFFICIENT"),
    "evidence_supports_claim": ("bool", "Verdict is SUPPORTED"),
    "contradiction_count": ("int", "Claims contradicted by verified facts"),
    "claim_type": ("str", "Claim label derived from untrusted text (selector only)"),
    "security_severity": ("str", "NONE | LOW | MEDIUM | HIGH | CRITICAL"),
    "security_score": ("float", "Peak detection weight"),
    "security_flagged": ("bool", "Severity >= MEDIUM"),
    "capability_escalation": ("bool", "Model requested an off-surface capability"),
    "threat_classes": ("list", "Threat classes found"),
    "policy_auto_limit": ("int", "Auto-approval limit from trusted facts"),
    "prior_disputes_90d": ("int", "Prior disputes in 90 days"),
    "delivery_status": ("str", "Ledger delivery status"),
    "refund_state": ("str", "none | pending | refunded -- has the money already gone back?"),
    "transaction_status": ("str", "settled | pending | reversed"),
    "merchant_response": ("str", "none | accepted | contested"),
    "auth_strength": ("str", "none | password | otp | biometric (from the switch record)"),
    "customer_tenure_days": ("int", "Days since the customer joined"),
    "account_status": ("str", "active | frozen | closed"),
    "account_risk_score": ("int", "Entity risk of the account"),
    "merchant_risk_score": ("int", "Entity risk of the merchant"),
    "merchant_risk_level": ("str", "Merchant risk level"),
    "registration_status": ("str", "verified | unverified | shell"),
    "prior_flags": ("int", "Merchant prior fraud flags"),
    "mcc_risk": ("str", "low | medium | high"),
    "domain_age_days": ("int", "Merchant domain age"),
    "business_age_days": ("int", "Merchant business age"),
    "new_device": ("bool", "Login from an unknown device"),
    "new_country": ("bool", "Login from an unknown country"),
    "impossible_travel": ("bool", "Country changed implausibly fast"),
    "payout_change": ("bool", "Payout destination changed this session"),
    "mfa_change": ("bool", "MFA changed this session"),
    "mfa_passed": ("bool", "Second factor completed"),
    "monitoring_patterns": ("list", "Monitoring indicator codes"),
}

# Fields the decision composer sets on EVERY policy context. A rule may reference
# any other catalog field only if the policy declares it in ``required_fields``,
# so that its absence is an evaluation error (fail-safe) rather than a rule that
# silently cannot fire (fail-open).
CONTEXT_FIELDS: frozenset[str] = frozenset(
    {
        "workflow",
        "amount",
        "requested_capability",
        "capability_irreversible",
        "capability_financial_effect",
        "risk_score",
        "risk_level",
        "risk_factors",
        "evidence_verdict",
        "evidence_supports_claim",
        "contradiction_count",
        "claim_type",
        "security_severity",
        "security_score",
        "security_flagged",
        "capability_escalation",
        "threat_classes",
    }
)


@dataclass(frozen=True)
class Condition:
    field: str
    op: str
    value: object = None

    def describe(self) -> str:
        if self.op in ("is_true", "is_false"):
            return f"{self.field} {self.op}"
        return f"{self.field} {self.op} {self.value!r}"


@dataclass(frozen=True)
class Rule:
    rule_id: str
    when: tuple[Condition, ...]
    outcome: PolicyOutcome
    reason: str

    def describe(self) -> str:
        return " AND ".join(c.describe() for c in self.when) + f" -> {self.outcome.value}"


@dataclass(frozen=True)
class Policy:
    policy_id: str
    version: int
    workflow: Workflow
    description: str
    rules: tuple[Rule, ...]
    default_outcome: PolicyOutcome = PolicyOutcome.ALLOW
    required_fields: tuple[str, ...] = field(default_factory=tuple)
    effective_from: str = ""
    # Hash of the full document, computed once at construction (``dataclasses.replace``
    # re-runs ``__post_init__``, so a modified copy gets its own hash). A version number
    # is a label that a file edit can silently reuse; this is what a decision and a
    # replay pin.
    content_hash: str = field(default="", compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "content_hash", content_hash(self.to_dict()))

    @property
    def key(self) -> str:
        return f"{self.policy_id}@v{self.version}"

    @property
    def referenced_fields(self) -> frozenset[str]:
        return frozenset(c.field for r in self.rules for c in r.when)

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "workflow": self.workflow.value,
            "description": self.description,
            "default_outcome": self.default_outcome.value,
            "required_fields": list(self.required_fields),
            "effective_from": self.effective_from,
            "rules": [
                {
                    "id": r.rule_id,
                    "when": [
                        {
                            "field": c.field,
                            "op": c.op,
                            **({"value": c.value} if c.op not in ("is_true", "is_false") else {}),
                        }
                        for c in r.when
                    ],
                    "outcome": r.outcome.value,
                    "reason": r.reason,
                }
                for r in self.rules
            ],
        }
