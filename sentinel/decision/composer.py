"""The Decision Composer -- the single place where a financial outcome is
computed.

    AUTHORITATIVE_DECISION = f(TRUSTED_FACTS, VERIFIED_EVIDENCE, RISK_STATE,
                               POLICY, AUTHORIZATION)

Inputs arrive as ``DecisionInputs``. The model's recommendation is one of
them -- but only so it can be *recorded* and compared. ``_decide`` receives a
``_TrustedView`` that is constructed without it, so the final action cannot be
a function of what the model wanted. The only model-derived signal that
reaches policy is the gateway's structural check on the model's *output*
(capability escalation), and that can only make an outcome stricter.

``controls`` exists for the ablation study: switching a control off reproduces
the behaviour of a system that lacks it (e.g. with ``adjudication`` off the
model's stated verdict is believed). The protected path is always ``FULL``.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.decisions import (
    AIRecommendation,
    Authorization,
    Decision,
    HumanReview,
    PolicyDecision,
    TrailEntry,
)
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
from sentinel.domain.evidence import Reconciliation
from sentinel.domain.ids import content_hash, new_id, now_iso
from sentinel.domain.risk import RiskAssessment
from sentinel.domain.security import SecurityAssessment
from sentinel.policy.engine import PolicyEvaluationError, evaluate
from sentinel.policy.models import Policy
from sentinel.security import capabilities

# ---- controls (for ablation) -----------------------------------------------------
DETECTION = "detection"  # AI Security Gateway findings reach policy
RISK = "risk"  # risk assessment reaches policy
ADJUDICATION = "adjudication"  # trusted-evidence verdict (vs believing the model)
POLICY = "policy"  # versioned policy evaluated
AUTHORIZATION = "authorization"  # capability registry consulted
FULL: frozenset[str] = frozenset({DETECTION, RISK, ADJUDICATION, POLICY, AUTHORIZATION})
NONE: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DecisionInputs:
    workflow: Workflow
    subject_type: str
    subject_id: str
    amount: int
    candidate_capability: Capability | None  # what executing THIS request would exercise
    facts: dict[str, object]  # trusted fact fields exposed to policy
    reconciliation: Reconciliation
    security: SecurityAssessment
    policy: Policy
    risk: RiskAssessment | None = None
    ai: AIRecommendation | None = None
    actor: ActorKind = ActorKind.SYSTEM
    controls: frozenset[str] = FULL
    input_hash: str = ""
    session_id: str | None = None
    provider: str = "offline"
    model: str = "offline-simulator"
    claim_type: str | None = None


@dataclass(frozen=True)
class _TrustedView:
    """Everything ``_decide`` may look at. Note: no AIRecommendation field, and no
    free-form context: every policy input is either computed here from trusted
    inputs or is a named trusted fact from the workflow."""

    workflow: Workflow
    amount: int
    candidate_capability: Capability | None
    facts: dict[str, object]
    verdict: EvidenceVerdict
    contradiction_count: int
    risk: RiskAssessment | None
    security: SecurityAssessment
    policy: Policy
    actor: ActorKind
    controls: frozenset[str]
    claim_type: str | None


_NO_SECURITY = SecurityAssessment(
    Severity.NONE, 0.0, (), (), TrustClass.UNKNOWN, "", False, None, False
)


def build_policy_context(v: _TrustedView) -> dict[str, object]:
    """Flat, typed context for the policy engine -- trusted inputs only."""
    sec = v.security if DETECTION in v.controls else _NO_SECURITY
    risk_score = v.risk.score if (v.risk and RISK in v.controls) else 0
    risk_level = v.risk.level if (v.risk and RISK in v.controls) else RiskLevel.LOW
    spec = capabilities.spec(v.candidate_capability) if v.candidate_capability else None
    ctx: dict[str, object] = {
        "workflow": v.workflow.value,
        "amount": v.amount,
        "requested_capability": v.candidate_capability.value if v.candidate_capability else "NONE",
        "capability_irreversible": bool(spec and spec.irreversible),
        "capability_financial_effect": bool(spec and spec.financial_effect),
        "risk_score": risk_score,
        "risk_level": risk_level.value,
        "risk_factors": [f.code for f in v.risk.factors] if (v.risk and RISK in v.controls) else [],
        "evidence_verdict": v.verdict.value,
        "evidence_supports_claim": v.verdict.supports,
        "contradiction_count": v.contradiction_count,
        "claim_type": v.claim_type or "none",
        "security_severity": sec.severity.value,
        "security_score": sec.score,
        "security_flagged": sec.flagged,
        "capability_escalation": sec.capability_escalation,
        "threat_classes": [t.value for t in sec.threat_classes],
    }
    for k, val in v.facts.items():
        ctx.setdefault(k, val)  # a fact can never overwrite a computed field
    return ctx


def _final_action(
    verdict: EvidenceVerdict,
    policy: PolicyDecision,
    auth: Authorization,
    security: SecurityAssessment,
    controls: frozenset[str],
) -> tuple[FinalAction, str]:
    security_caused = DETECTION in controls and (
        security.severity.rank >= Severity.HIGH.rank or security.capability_escalation
    )
    if policy.outcome is PolicyOutcome.BLOCK:
        if security_caused:
            return FinalAction.BLOCK, "blocked: AI-security finding and policy"
        return FinalAction.DENY, "denied: policy outcome BLOCK on trusted inputs"
    if verdict is EvidenceVerdict.INSUFFICIENT:
        return FinalAction.REQUIRE_HUMAN_REVIEW, "held: evidence insufficient to decide (fail-safe)"
    if not verdict.supports:
        return FinalAction.DENY, "denied: verified evidence does not support the request"
    if policy.outcome is PolicyOutcome.TEMPORARY_HOLD:
        return FinalAction.TEMPORARY_HOLD, "temporary hold under policy"
    if (
        policy.outcome is PolicyOutcome.REQUIRE_HUMAN_REVIEW
        or auth.status is AuthorizationStatus.PENDING_HUMAN
    ):
        return FinalAction.REQUIRE_HUMAN_REVIEW, "human review required: " + (
            auth.reason if auth.status is AuthorizationStatus.PENDING_HUMAN else "policy"
        )
    if policy.outcome is PolicyOutcome.STEP_UP and auth.status is AuthorizationStatus.GRANTED:
        return FinalAction.STEP_UP, "step-up authentication under policy; proceeds once satisfied"
    if auth.status is AuthorizationStatus.GRANTED:
        return FinalAction.ALLOW, "allowed: evidence supported, policy ALLOW, authorization granted"
    return FinalAction.DENY, f"denied: authorization {auth.status.value} ({auth.reason})"


def _decide(
    v: _TrustedView,
) -> tuple[PolicyDecision, Authorization, FinalAction, str, dict[str, object]]:
    context = build_policy_context(v)
    if POLICY in v.controls:
        try:
            pol = evaluate(v.policy, context)
        except PolicyEvaluationError as e:  # malformed context -> fail safe, never silent allow
            pol = PolicyDecision(
                v.policy.policy_id,
                v.policy.version,
                PolicyOutcome.REQUIRE_HUMAN_REVIEW,
                ("fail-safe",),
                (f"policy could not be evaluated: {e}",),
            )
    elif DETECTION in v.controls and (v.security.flagged or v.security.capability_escalation):
        # A detector-only system holds exactly what it flags (severity >= MEDIUM, the same
        # threshold ``detection_recall`` counts) and has no policy of its own.
        pol = PolicyDecision(
            v.policy.policy_id,
            v.policy.version,
            PolicyOutcome.REQUIRE_HUMAN_REVIEW,
            ("detection-only-hold",),
            ("policy control disabled; detection held the request for a human",),
        )
    else:
        pol = PolicyDecision(
            v.policy.policy_id,
            v.policy.version,
            PolicyOutcome.ALLOW,
            (),
            ("policy control disabled",),
        )
    supported = v.verdict.supports
    if AUTHORIZATION in v.controls:
        auth = capabilities.authorize(
            v.candidate_capability,
            actor=v.actor,
            amount=v.amount,
            policy_outcome=pol.outcome,
            evidence_supported=supported,
        )
    else:
        auth = Authorization(
            AuthorizationStatus.GRANTED if supported else AuthorizationStatus.DENIED,
            v.candidate_capability,
            v.actor,
            "authorization control disabled",
        )
    action, reason = _final_action(v.verdict, pol, auth, v.security, v.controls)
    return pol, auth, action, reason, context


def compose(inputs: DecisionInputs) -> Decision:
    # ---- 1. build the trusted view: the model's wish is deliberately absent ----
    if ADJUDICATION in inputs.controls:
        verdict = inputs.reconciliation.verdict
        candidate = inputs.candidate_capability
    else:
        # Ablation: believe the model. Its requested capability becomes the candidate.
        wants = inputs.ai.requested_capability if inputs.ai else None
        candidate = wants if capabilities.is_consequential(wants) else None
        verdict = (
            EvidenceVerdict.SUPPORTED if candidate is not None else EvidenceVerdict.UNSUPPORTED
        )
    view = _TrustedView(
        workflow=inputs.workflow,
        amount=inputs.amount,
        candidate_capability=candidate,
        facts=inputs.facts,
        verdict=verdict,
        contradiction_count=len(inputs.reconciliation.contradictions),
        risk=inputs.risk,
        security=inputs.security,
        policy=inputs.policy,
        actor=inputs.actor,
        controls=inputs.controls,
        claim_type=inputs.claim_type,
    )
    pol, auth, action, reason, context = _decide(view)

    # ---- 2. explain -------------------------------------------------------------
    ai = inputs.ai
    wanted_execute = bool(
        ai and ai.requested_capability and capabilities.is_consequential(ai.requested_capability)
    )
    blocked_by: list[str] = []
    if wanted_execute and action is not FinalAction.ALLOW:
        if ADJUDICATION in inputs.controls and not inputs.reconciliation.supports_claim:
            blocked_by.append("trusted_evidence")
        if DETECTION in inputs.controls and (
            inputs.security.severity.rank >= Severity.HIGH.rank
            or inputs.security.capability_escalation
        ):
            blocked_by.append("ai_security_gateway")
        if POLICY in inputs.controls and pol.outcome is not PolicyOutcome.ALLOW:
            blocked_by.append(f"policy:{pol.policy_id}@v{pol.version}")
        if AUTHORIZATION in inputs.controls and auth.status is not AuthorizationStatus.GRANTED:
            blocked_by.append("capability_authorization")
        if ai and ai.requested_capability and ai.requested_capability != candidate:
            blocked_by.append("capability_registry")
    if (
        wanted_execute
        and ai
        and ai.requested_capability not in (None, candidate)
        and action is FinalAction.ALLOW
    ):
        # The request was allowed, but not the capability the model asked for.
        blocked_by.append("capability_registry")

    human = action in (FinalAction.REQUIRE_HUMAN_REVIEW, FinalAction.TEMPORARY_HOLD) or (
        action is FinalAction.BLOCK and capabilities.is_consequential(candidate)
    )
    executed = (
        candidate
        if (action is FinalAction.ALLOW and capabilities.is_consequential(candidate))
        else None
    )
    ai_agreed = None
    if ai is not None:
        ai_agreed = (
            wanted_execute and action is FinalAction.ALLOW and ai.requested_capability == candidate
        ) or (not wanted_execute and action is not FinalAction.ALLOW)

    trail = [
        TrailEntry(
            "provenance",
            f"untrusted input hashed ({inputs.input_hash or 'n/a'}); trusted facts from records",
            {"facts": sorted(inputs.facts)},
        ),
        TrailEntry(
            "ai_security_gateway",
            f"severity {inputs.security.severity.value}; classes {[t.value for t in inputs.security.threat_classes]}",
            {
                "score": inputs.security.score,
                "capability_escalation": inputs.security.capability_escalation,
            },
        ),
    ]
    if inputs.risk is not None:
        trail.append(
            TrailEntry(
                "risk",
                f"{inputs.risk.score}/100 {inputs.risk.level.value} ({inputs.risk.model_version})",
                {"factors": [f"{f.points:+d} {f.label}" for f in inputs.risk.factors]},
            )
        )
    if ai is not None:
        trail.append(
            TrailEntry(
                "ai_recommendation",
                f"{ai.agent} -> {ai.recommended_action} (MODEL_GENERATED, recorded, not authoritative)",
                {
                    "requested_capability": (
                        ai.requested_capability.value if ai.requested_capability else None
                    ),
                    "amount": ai.amount,
                },
            )
        )
    trail.append(
        TrailEntry(
            "trusted_evidence",
            f"verdict {inputs.reconciliation.verdict.value}: {inputs.reconciliation.explanation}",
            {
                "contradictions": [
                    f"{c.field}: claimed {c.claimed!r}, recorded {c.recorded!r}"
                    for c in inputs.reconciliation.contradictions
                ],
                "verified_evidence": [
                    e.evidence_id for e in inputs.reconciliation.evidence.verified()
                ],
            },
        )
    )
    trail.append(
        TrailEntry(
            "policy",
            f"{pol.policy_id}@v{pol.version} -> {pol.outcome.value}",
            {"matched": list(pol.matched_rules), "explanations": list(pol.explanations)},
        )
    )
    trail.append(
        TrailEntry(
            "authorization",
            f"{auth.status.value}: {auth.reason}",
            {
                "capability": auth.capability.value if auth.capability else None,
                "actor": auth.actor.value,
            },
        )
    )
    trail.append(
        TrailEntry(
            "final",
            f"{action.value}: {reason}",
            {"executed_capability": executed.value if executed else None, "human_review": human},
        )
    )

    return Decision(
        decision_id=new_id("DEC"),
        workflow=inputs.workflow,
        subject_type=inputs.subject_type,
        subject_id=inputs.subject_id,
        amount=inputs.amount,
        requested_capability=candidate,
        risk_score=inputs.risk.score if inputs.risk else 0,
        risk_level=inputs.risk.level if inputs.risk else RiskLevel.LOW,
        risk_assessment_id=inputs.risk.assessment_id if inputs.risk else None,
        ai_recommendation=ai,
        evidence_verdict=(
            inputs.reconciliation.verdict if ADJUDICATION in inputs.controls else verdict
        ),
        evidence_ids=inputs.reconciliation.evidence.ids(),
        contradiction_count=len(inputs.reconciliation.contradictions),
        security_severity=inputs.security.severity,
        security_event_id=None,
        policy=PolicyDecision(
            pol.policy_id,
            pol.version,
            pol.outcome,
            pol.matched_rules,
            pol.explanations,
            content_hash(context),
            inputs.policy.content_hash,
        ),
        authorization=auth,
        human_review=HumanReview(human, reason if human else ""),
        final_action=action,
        blocked_by=tuple(dict.fromkeys(blocked_by)),
        reason=reason,
        trail=tuple(trail),
        input_hash=inputs.input_hash,
        provider=inputs.provider,
        model=inputs.model,
        created_at=now_iso(),
        session_id=inputs.session_id,
        controls=tuple(sorted(inputs.controls)),
        ai_agreed=ai_agreed,
        executed_capability=executed,
    )
