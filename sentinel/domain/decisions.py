"""The canonical Decision and its typed inputs.

    AUTHORITATIVE_DECISION = f(TRUSTED_FACTS, VERIFIED_EVIDENCE, RISK_STATE,
                               POLICY, AUTHORIZATION)

An ``AIRecommendation`` is *recorded* on the decision (for explainability and
for measuring how often the model was wrong) but the composer never reads it
when computing ``final_action``. That separation is enforced in
``sentinel.decision.composer`` and tested by the decision-integrity invariants.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.enums import (
    ActorKind,
    AuthorizationStatus,
    Capability,
    EvidenceVerdict,
    FinalAction,
    PolicyOutcome,
    RiskLevel,
    Severity,
    TrustClass,
    Workflow,
)


@dataclass(frozen=True)
class AIRecommendation:
    """What the model wanted. Trust is always MODEL_GENERATED."""

    agent: str
    recommended_action: str  # e.g. "approve_refund", "deny", "escalate", "allow", "block"
    requested_capability: Capability | None
    amount: int
    rationale: str
    provider: str
    model: str
    latency_ms: float = 0.0
    raw_hash: str = ""
    trust: TrustClass = TrustClass.MODEL_GENERATED

    def __post_init__(self) -> None:
        if self.trust is not TrustClass.MODEL_GENERATED:
            raise ValueError("an AIRecommendation is always MODEL_GENERATED")


@dataclass(frozen=True)
class Authorization:
    status: AuthorizationStatus
    capability: Capability | None
    actor: ActorKind
    reason: str
    requires_human: bool = False


@dataclass(frozen=True)
class PolicyDecision:
    policy_id: str
    version: int
    outcome: PolicyOutcome
    matched_rules: tuple[str, ...]
    explanations: tuple[str, ...]
    context_hash: str = ""
    policy_hash: str = ""  # content hash of the policy document (versions are labels; this is not)


@dataclass(frozen=True)
class HumanReview:
    required: bool
    reason: str = ""
    case_id: str | None = None


@dataclass(frozen=True)
class TrailEntry:
    stage: str
    summary: str
    detail: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    """One canonical, serialisable record per evaluated request."""

    decision_id: str
    workflow: Workflow
    subject_type: str
    subject_id: str
    amount: int
    requested_capability: Capability | None
    risk_score: int
    risk_level: RiskLevel
    risk_assessment_id: str | None
    ai_recommendation: AIRecommendation | None
    evidence_verdict: EvidenceVerdict
    evidence_ids: tuple[str, ...]
    contradiction_count: int
    security_severity: Severity
    security_event_id: str | None
    policy: PolicyDecision
    authorization: Authorization
    human_review: HumanReview
    final_action: FinalAction
    blocked_by: tuple[str, ...]
    reason: str
    trail: tuple[TrailEntry, ...]
    input_hash: str
    provider: str
    model: str
    created_at: str
    case_id: str | None = None
    audit_event_id: str | None = None
    session_id: str | None = None
    controls: tuple[str, ...] = field(default_factory=tuple)
    ai_agreed: bool | None = None  # did the model's wish coincide with the outcome?
    executed_capability: Capability | None = None  # the consequential capability that ran, if any
    # True only for a decision recorded by a persisting runtime after the authority check
    # (sentinel.decision.authority); a what-if or unpersisted evaluation is False.
    authoritative: bool = False

    @property
    def executed(self) -> bool:
        """Did a consequential capability actually run?"""
        return self.final_action is FinalAction.ALLOW and self.executed_capability is not None
