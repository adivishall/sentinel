"""Deterministic case-creation rules. A case opens when a decision needs a
human, when it was blocked for security reasons, or when critical risk met a
consequential capability -- never because a model asked for one."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.decisions import Decision
from sentinel.domain.enums import CasePriority, FinalAction, RiskLevel, Severity, Workflow
from sentinel.security import capabilities


@dataclass(frozen=True)
class CaseTrigger:
    rule: str
    priority: CasePriority
    title: str


def should_open_case(d: Decision) -> CaseTrigger | None:
    consequential = capabilities.is_consequential(d.requested_capability)
    ai_off_surface = (
        d.security_severity is Severity.CRITICAL and "capability_registry" in d.blocked_by
    )
    if ai_off_surface or (
        d.ai_recommendation
        and d.ai_recommendation.requested_capability
        and d.ai_recommendation.requested_capability != d.requested_capability
        and d.final_action is FinalAction.BLOCK
    ):
        return CaseTrigger(
            "capability_escalation",
            CasePriority.P1,
            f"AI capability escalation attempt in {d.workflow.value}",
        )
    if d.risk_level is RiskLevel.CRITICAL and consequential:
        return CaseTrigger(
            "critical_risk_financial",
            CasePriority.P1,
            f"Critical risk on {d.subject_type} {d.subject_id}",
        )
    if d.final_action is FinalAction.BLOCK and d.security_severity.rank >= Severity.HIGH.rank:
        return CaseTrigger(
            "ai_security_block", CasePriority.P2, f"AI-security block in {d.workflow.value}"
        )
    if d.final_action in (FinalAction.REQUIRE_HUMAN_REVIEW, FinalAction.TEMPORARY_HOLD):
        prio = (
            CasePriority.P1
            if d.amount > 150_000 or d.final_action is FinalAction.TEMPORARY_HOLD
            else CasePriority.P2
        )
        return CaseTrigger(
            "human_review_required", prio, f"Human review: {d.workflow.value} {d.subject_id}"
        )
    if d.workflow is Workflow.INVESTIGATION and d.risk_level.rank >= RiskLevel.HIGH.rank:
        return CaseTrigger(
            "monitoring_patterns", CasePriority.P2, f"Monitoring indicators on {d.subject_id}"
        )
    return None
