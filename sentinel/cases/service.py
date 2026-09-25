"""Case management: open, transition, resolve. Storage is behind a
small repository protocol so the SQLite store can back it without the
service knowing."""

from __future__ import annotations

from dataclasses import replace
from typing import Protocol

from sentinel.cases.rules import CaseTrigger, should_open_case
from sentinel.domain.cases import Case, CaseEvent, HumanDecision
from sentinel.domain.decisions import Decision
from sentinel.domain.enums import CasePriority, CaseStatus, Workflow
from sentinel.domain.ids import new_id, now_iso

TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset(
        {
            CaseStatus.TRIAGE,
            CaseStatus.INVESTIGATING,
            CaseStatus.WAITING_HUMAN,
            CaseStatus.ESCALATED,
        }
    ),
    CaseStatus.TRIAGE: frozenset(
        {
            CaseStatus.INVESTIGATING,
            CaseStatus.WAITING_HUMAN,
            CaseStatus.RESOLVED,
            CaseStatus.ESCALATED,
        }
    ),
    CaseStatus.INVESTIGATING: frozenset(
        {CaseStatus.WAITING_HUMAN, CaseStatus.RESOLVED, CaseStatus.ESCALATED}
    ),
    CaseStatus.WAITING_HUMAN: frozenset(
        {CaseStatus.INVESTIGATING, CaseStatus.RESOLVED, CaseStatus.ESCALATED}
    ),
    CaseStatus.ESCALATED: frozenset({CaseStatus.INVESTIGATING, CaseStatus.RESOLVED}),
    CaseStatus.RESOLVED: frozenset(),
}


class InvalidTransition(ValueError):
    pass


class CaseRepository(Protocol):
    def save(self, case: Case) -> None: ...
    def get(self, case_id: str) -> Case | None: ...
    def list(self, *, status: CaseStatus | None = None, limit: int = 100) -> list[Case]: ...


class MemoryCaseRepository:
    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}

    def save(self, case: Case) -> None:
        self._cases[case.case_id] = case

    def get(self, case_id: str) -> Case | None:
        return self._cases.get(case_id)

    def list(self, *, status: CaseStatus | None = None, limit: int = 100) -> list[Case]:
        rows = [c for c in self._cases.values() if status is None or c.status is status]
        rows.sort(key=lambda c: c.created_at, reverse=True)
        return rows[:limit]


class CaseService:
    def __init__(self, repo: CaseRepository | None = None) -> None:
        self.repo: CaseRepository = repo or MemoryCaseRepository()

    # ---- opening ----------------------------------------------------------------------
    def open_for_decision(self, d: Decision, *, entities: tuple[str, ...] = ()) -> Case | None:
        trig = should_open_case(d)
        if trig is None:
            return None
        return self.open(trig, d, entities)

    def open(self, trig: CaseTrigger, d: Decision, entities: tuple[str, ...] = ()) -> Case:
        now = now_iso()
        case_id = new_id("CASE")
        status = CaseStatus.WAITING_HUMAN if d.human_review.required else CaseStatus.OPEN
        ev = CaseEvent(
            new_id("CEV"),
            case_id,
            "created",
            "sentinel",
            {"rule": trig.rule, "decision_id": d.decision_id, "final_action": d.final_action.value},
            now,
        )
        case = Case(
            case_id=case_id,
            case_type=d.workflow,
            status=status,
            priority=trig.priority,
            title=trig.title,
            entities=tuple(dict.fromkeys((f"{d.subject_type}:{d.subject_id}",) + entities)),
            decision_ids=(d.decision_id,),
            risk_assessment_ids=(d.risk_assessment_id,) if d.risk_assessment_id else (),
            evidence_ids=d.evidence_ids,
            security_event_ids=(d.security_event_id,) if d.security_event_id else (),
            ai_recommendations=(
                (f"{d.ai_recommendation.agent}:{d.ai_recommendation.recommended_action}",)
                if d.ai_recommendation
                else ()
            ),
            policy_decisions=(
                f"{d.policy.policy_id}@v{d.policy.version}:{d.policy.outcome.value}",
            ),
            human_decisions=(),
            events=(ev,),
            created_at=now,
            updated_at=now,
            opened_by_rule=trig.rule,
        )
        self.repo.save(case)
        return case

    def open_manual(
        self,
        case_type: Workflow,
        title: str,
        entities: tuple[str, ...],
        priority: CasePriority = CasePriority.P3,
        actor: str = "human",
    ) -> Case:
        now = now_iso()
        case_id = new_id("CASE")
        ev = CaseEvent(new_id("CEV"), case_id, "created", actor, {"rule": "manual"}, now)
        case = Case(
            case_id,
            case_type,
            CaseStatus.OPEN,
            priority,
            title,
            entities,
            (),
            (),
            (),
            (),
            (),
            (),
            (),
            (ev,),
            now,
            now,
            "manual",
        )
        self.repo.save(case)
        return case

    # ---- lifecycle ---------------------------------------------------------------------
    def transition(self, case_id: str, to: CaseStatus, *, actor: str, note: str = "") -> Case:
        case = self._require(case_id)
        if to is CaseStatus.RESOLVED:
            raise InvalidTransition(
                "a case is resolved only by a recorded human decision (record_human_decision); "
                "a status transition cannot close it"
            )
        if to not in TRANSITIONS[case.status]:
            raise InvalidTransition(f"{case.status.value} -> {to.value} is not allowed")
        now = now_iso()
        ev = CaseEvent(
            new_id("CEV"),
            case_id,
            "status_changed",
            actor,
            {"from": case.status.value, "to": to.value, "note": note},
            now,
        )
        case = replace(case, status=to, events=case.events + (ev,), updated_at=now)
        self.repo.save(case)
        return case

    def record_human_decision(
        self, case_id: str, *, reviewer: str, outcome: str, note: str = ""
    ) -> Case:
        """A human's verdict. Only a human actor may resolve; the model has no path here."""
        if outcome not in ("approve", "deny", "escalate"):
            raise ValueError("outcome must be approve | deny | escalate")
        case = self._require(case_id)
        now = now_iso()
        hd = HumanDecision(new_id("HDEC"), case_id, reviewer, outcome, note, now)
        ev = CaseEvent(
            new_id("CEV"),
            case_id,
            "human_decision",
            reviewer,
            {"outcome": outcome, "note": note},
            now,
        )
        to = CaseStatus.ESCALATED if outcome == "escalate" else CaseStatus.RESOLVED
        if to not in TRANSITIONS[case.status]:
            raise InvalidTransition(f"{case.status.value} -> {to.value} is not allowed")
        case = replace(
            case,
            status=to,
            human_decisions=case.human_decisions + (hd,),
            events=case.events + (ev,),
            updated_at=now,
            resolution=None if to is CaseStatus.ESCALATED else outcome,
        )
        self.repo.save(case)
        return case

    def link_audit(self, case_id: str, audit_event_id: str) -> Case:
        case = self._require(case_id)
        case = replace(case, audit_event_ids=case.audit_event_ids + (audit_event_id,))
        self.repo.save(case)
        return case

    def get(self, case_id: str) -> Case | None:
        return self.repo.get(case_id)

    def list(self, *, status: CaseStatus | None = None, limit: int = 100) -> list[Case]:
        return self.repo.list(status=status, limit=limit)

    def _require(self, case_id: str) -> Case:
        c = self.repo.get(case_id)
        if c is None:
            raise KeyError(f"unknown case {case_id}")
        return c
