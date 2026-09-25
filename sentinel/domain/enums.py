"""Closed vocabularies shared by every layer.

These are Sentinel's *internal* vocabularies (risk bands, capability names,
outcomes). They are documented as such -- they are not claimed to be industry
standards.
"""

from __future__ import annotations

from enum import StrEnum


class TrustClass(StrEnum):
    """Where a piece of information came from, and therefore how much authority
    it can carry. Only ``TRUSTED_INTERNAL`` and ``VERIFIED_EXTERNAL`` may ever
    contribute to an authoritative decision."""

    TRUSTED_INTERNAL = "TRUSTED_INTERNAL"  # our own ledger / records / policy
    VERIFIED_EXTERNAL = "VERIFIED_EXTERNAL"  # network / acquirer records we verified
    USER_CONTROLLED = "USER_CONTROLLED"  # a cardholder narrative, chat turn, form field
    MERCHANT_CONTROLLED = "MERCHANT_CONTROLLED"  # merchant application copy, website text
    DOCUMENT_CONTROLLED = "DOCUMENT_CONTROLLED"  # an uploaded invoice / PDF / receipt
    MODEL_GENERATED = "MODEL_GENERATED"  # anything an LLM produced
    UNKNOWN = "UNKNOWN"

    @property
    def is_trusted(self) -> bool:
        return self in (TrustClass.TRUSTED_INTERNAL, TrustClass.VERIFIED_EXTERNAL)


class Workflow(StrEnum):
    DISPUTE = "dispute"
    TRANSACTION = "transaction"
    MERCHANT_ONBOARDING = "merchant_onboarding"
    ACCOUNT_SECURITY = "account_security"
    INVESTIGATION = "investigation"
    AI_SECURITY = "ai_security"


class RiskLevel(StrEnum):
    """Sentinel's internal 0-100 risk bands."""

    LOW = "LOW"  # 0-24
    MEDIUM = "MEDIUM"  # 25-49
    HIGH = "HIGH"  # 50-74
    CRITICAL = "CRITICAL"  # 75-100

    @classmethod
    def from_score(cls, score: int) -> RiskLevel:
        if score >= 75:
            return cls.CRITICAL
        if score >= 50:
            return cls.HIGH
        if score >= 25:
            return cls.MEDIUM
        return cls.LOW

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class Severity(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]


_SEV_RANK = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ThreatClass(StrEnum):
    """The AI threat taxonomy. Fifteen classes; several are not lexical and are
    caught structurally (contradiction engine, capability registry, session
    model, model-output inspection) rather than by pattern matching."""

    DIRECT_INJECTION = "direct_injection"
    AUTHORITY_SPOOF = "authority_spoof"
    DOCUMENT_BORNE = "document_borne"
    FAKE_POLICY = "fake_policy"
    CONTEXT_POISONING = "context_poisoning"
    TOOL_MANIPULATION = "tool_manipulation"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    UNICODE_OBFUSCATION = "unicode_obfuscation"
    INDIRECT_INJECTION = "indirect_injection"
    ADJUDICATION_GAMING = "adjudication_gaming"
    FINANCIAL_SOCIAL_ENGINEERING = "financial_social_engineering"
    CAPABILITY_ESCALATION = "capability_escalation"
    MODEL_OUTPUT_INJECTION = "model_output_injection"  # text that mimics the agent's own output
    FALSE_EVIDENCE = "false_evidence"  # a verifiable-sounding fact that the records refute
    SYNTHETIC_EVIDENCE = "synthetic_evidence"  # a fabricated record / report presented as trusted


class ClaimType(StrEnum):
    """What an untrusted party *says* happened. Derived from prose, so it is only
    ever a selector for which trusted fact to check -- never evidence."""

    NON_RECEIPT = "non_receipt"
    IN_TRANSIT = "in_transit"
    DUPLICATE = "duplicate"
    CANCELLATION = "cancellation"
    UNAUTHORIZED = "unauthorized"
    UNSPECIFIED = "unspecified"


class EvidenceKind(StrEnum):
    LEDGER_FACT = "ledger_fact"
    ACQUIRER_RECORD = "acquirer_record"
    SESSION_RECORD = "session_record"
    RISK_SIGNAL = "risk_signal"
    USER_CLAIM = "user_claim"
    MERCHANT_CLAIM = "merchant_claim"
    DOCUMENT_CLAIM = "document_claim"


class EvidenceStatus(StrEnum):
    VERIFIED = "VERIFIED"  # from a trusted source
    CLAIMED = "CLAIMED"  # asserted by an untrusted party; unverified
    CONTRADICTED = "CONTRADICTED"  # a claim the trusted record disagrees with


class EvidenceVerdict(StrEnum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT = "INSUFFICIENT"  # the claim cannot be mapped to any trusted fact

    @property
    def supports(self) -> bool:
        return self is EvidenceVerdict.SUPPORTED


class Capability(StrEnum):
    READ_TRANSACTION = "READ_TRANSACTION"
    READ_ACCOUNT = "READ_ACCOUNT"
    READ_MERCHANT = "READ_MERCHANT"
    CREATE_CASE = "CREATE_CASE"
    CREATE_ALERT = "CREATE_ALERT"
    RECOMMEND_REFUND = "RECOMMEND_REFUND"
    RECOMMEND_ACTION = "RECOMMEND_ACTION"
    APPROVE_REFUND = "APPROVE_REFUND"
    APPROVE_MERCHANT = "APPROVE_MERCHANT"
    APPROVE_TRANSACTION = "APPROVE_TRANSACTION"
    FREEZE_ACCOUNT = "FREEZE_ACCOUNT"
    UNFREEZE_ACCOUNT = "UNFREEZE_ACCOUNT"
    CHANGE_PAYOUT = "CHANGE_PAYOUT"
    RELEASE_FUNDS = "RELEASE_FUNDS"
    CLOSE_CASE = "CLOSE_CASE"
    ALTER_RISK = "ALTER_RISK"
    SKIP_REVIEW = "SKIP_REVIEW"


class ActorKind(StrEnum):
    SYSTEM = "SYSTEM"  # Sentinel's deterministic decision path
    AI_AGENT = "AI_AGENT"  # an LLM agent
    HUMAN_REVIEWER = "HUMAN_REVIEWER"
    SENIOR_REVIEWER = "SENIOR_REVIEWER"
    EXTERNAL = "EXTERNAL"  # a customer / merchant


class AuthorizationStatus(StrEnum):
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    PENDING_HUMAN = "PENDING_HUMAN"


class PolicyOutcome(StrEnum):
    """Ordered by severity; the engine reports the most severe matching outcome."""

    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    TEMPORARY_HOLD = "TEMPORARY_HOLD"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        return _POLICY_RANK[self]


_POLICY_RANK = {
    PolicyOutcome.ALLOW: 0,
    PolicyOutcome.STEP_UP: 1,
    PolicyOutcome.REQUIRE_HUMAN_REVIEW: 2,
    PolicyOutcome.TEMPORARY_HOLD: 3,
    PolicyOutcome.BLOCK: 4,
}


class FinalAction(StrEnum):
    """What actually happens to the request. ``ALLOW`` means the request
    proceeds -- and if a consequential capability was requested, it executes
    (refund paid, merchant live, payment authorised)."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"
    TEMPORARY_HOLD = "TEMPORARY_HOLD"
    BLOCK = "BLOCK"

    @property
    def permissiveness(self) -> int:
        """Higher = more permissive. Used by the decision-integrity evaluation
        to check that untrusted input can only ever *tighten* an outcome."""
        return _PERMISSIVENESS[self]


_PERMISSIVENESS = {
    FinalAction.ALLOW: 5,
    FinalAction.STEP_UP: 4,
    FinalAction.REQUIRE_HUMAN_REVIEW: 3,
    FinalAction.TEMPORARY_HOLD: 2,
    FinalAction.DENY: 1,
    FinalAction.BLOCK: 0,
}


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    TRIAGE = "TRIAGE"
    INVESTIGATING = "INVESTIGATING"
    WAITING_HUMAN = "WAITING_HUMAN"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


class CasePriority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
