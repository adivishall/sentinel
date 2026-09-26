"""Investigations as first-class objects."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.enums import CasePriority, CaseStatus, Workflow


@dataclass(frozen=True)
class CaseEvent:
    event_id: str
    case_id: str
    kind: str  # created | status_changed | evidence_attached | human_decision | note
    actor: str
    detail: dict[str, object]
    created_at: str


@dataclass(frozen=True)
class HumanDecision:
    decision_id: str
    case_id: str
    reviewer: str
    outcome: str  # approve | deny | escalate
    note: str
    created_at: str
    role: str = "HUMAN_REVIEWER"  # declared by the reviewer; see LIMITATIONS (no identity)


@dataclass(frozen=True)
class Case:
    case_id: str
    case_type: Workflow
    status: CaseStatus
    priority: CasePriority
    title: str
    entities: tuple[str, ...]
    decision_ids: tuple[str, ...]
    risk_assessment_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    security_event_ids: tuple[str, ...]
    ai_recommendations: tuple[str, ...]
    policy_decisions: tuple[str, ...]
    human_decisions: tuple[HumanDecision, ...]
    events: tuple[CaseEvent, ...]
    created_at: str
    updated_at: str
    opened_by_rule: str = ""
    resolution: str | None = None
    audit_event_ids: tuple[str, ...] = field(default_factory=tuple)
    # Who may approve: derived from the capability registry when the case is opened
    # (HUMAN_REVIEWER | SENIOR_REVIEWER | NOBODY). Denying or escalating needs any human.
    required_authorization: str = "HUMAN_REVIEWER"
    # What the decision that opened the case would execute and on what footing; a human
    # approval is checked against the registry with these (``CaseService.approval``).
    capability: str | None = None
    policy_outcome: str | None = None
    evidence_verdict: str | None = None
