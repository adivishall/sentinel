"""Case management: open, transition, resolve. Storage is behind a
small repository protocol so the SQLite store can back it without the
service knowing.

With an audit chain attached (every recording ``Runtime`` attaches its own), each
human action -- opening a case by hand, a status change, a human decision -- is
appended to the tamper-evident chain before the case is saved, so a resolution
cannot be written into the case table without leaving a chained record."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Protocol

from sentinel.cases.rules import CaseTrigger, should_open_case
from sentinel.domain.cases import Case, CaseEvent, HumanDecision
from sentinel.domain.decisions import Decision
from sentinel.domain.enums import (
    ActorKind,
    AuthorizationStatus,
    Capability,
    CasePriority,
    CaseStatus,
    EvidenceVerdict,
    PolicyOutcome,
    Workflow,
)
from sentinel.domain.ids import content_hash, new_id, now_iso
from sentinel.security.capabilities import authorize
from sentinel.security.capabilities import spec as cap_spec

if TYPE_CHECKING:
    from sentinel.audit.chain import AuditChain

# Status moves an analyst or the system may make. RESOLVED is deliberately not a target
# anywhere in this table: a case reaches RESOLVED only through ``record_human_decision``.
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
        {CaseStatus.INVESTIGATING, CaseStatus.WAITING_HUMAN, CaseStatus.ESCALATED}
    ),
    CaseStatus.INVESTIGATING: frozenset({CaseStatus.WAITING_HUMAN, CaseStatus.ESCALATED}),
    CaseStatus.WAITING_HUMAN: frozenset({CaseStatus.INVESTIGATING, CaseStatus.ESCALATED}),
    CaseStatus.ESCALATED: frozenset({CaseStatus.INVESTIGATING}),
    CaseStatus.RESOLVED: frozenset(),  # final: a resolved case is never reopened
}

# Where a human decision may be recorded. An OPEN case is triaged first; a RESOLVED case
# is final. approve/deny -> RESOLVED; escalate -> ESCALATED (not from ESCALATED).
DECIDABLE_FROM: frozenset[CaseStatus] = frozenset(
    {
        CaseStatus.TRIAGE,
        CaseStatus.INVESTIGATING,
        CaseStatus.WAITING_HUMAN,
        CaseStatus.ESCALATED,
    }
)

# Actor names that denote the system or a model. A human decision recorded under one of
# them (or under the name of an agent that recommended on the case) is refused: neither
# the pipeline nor a model has a path to RESOLVED.
RESERVED_ACTORS = frozenset(
    {"sentinel", "system", "automation", "auto", "agent", "ai", "model", "llm", "bot"}
)
_RESERVED_PREFIXES = ("agent:", "ai:", "model:", "llm:", "sentinel:", "system:")
_ROLE_RANK = {"HUMAN_REVIEWER": 1, "SENIOR_REVIEWER": 2}


def required_authorization(capability: Capability | None) -> str:
    """Who may approve a case about ``capability``, from the capability registry."""
    if capability is None:
        return "HUMAN_REVIEWER"
    allowed = cap_spec(capability).allowed_actors
    if ActorKind.HUMAN_REVIEWER in allowed:
        return "HUMAN_REVIEWER"
    if ActorKind.SENIOR_REVIEWER in allowed:
        return "SENIOR_REVIEWER"
    return "NOBODY"  # e.g. SKIP_REVIEW: no actor may invoke it


class InvalidTransition(ValueError):
    pass


class ReviewerNotAuthorized(ValueError):
    """The recorded reviewer is not a human actor, or lacks the level the case needs."""


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
    def __init__(self, repo: CaseRepository | None = None, audit: AuditChain | None = None) -> None:
        self.repo: CaseRepository = repo or MemoryCaseRepository()
        self.audit: AuditChain | None = audit

    def _record(self, case: Case, *, actor: str, action: str, detail: dict[str, object]) -> Case:
        """Chain a human case action, then link it to the case. Free text (titles, notes)
        is hashed, never stored in the chain."""
        if self.audit is None:
            return case
        ev = self.audit.append(
            actor=actor,
            workflow=case.case_type.value,
            action=action,
            subject_id=case.case_id,
            capability=case.capability,
            case_id=case.case_id,
            kind="case",
            detail={**detail, "decision_ids": list(case.decision_ids)},
        )
        return replace(case, audit_event_ids=case.audit_event_ids + (ev.event_id,))

    def approval(self, case: Case, role: str) -> tuple[bool, str]:
        """May a reviewer at ``role`` approve this case? The same registry answer the
        automated path gets, for a human actor: the role must be allowed the capability, a
        policy BLOCK is final for every actor, and records that contradict (or do not
        confirm) the claim cannot be approved. A claim the classifier could not read
        (INSUFFICIENT) is exactly what the human was asked to read, so it may be."""
        need = case.required_authorization
        if need == "NOBODY":
            return False, "no actor may approve this capability"
        if _ROLE_RANK.get(role, 0) < _ROLE_RANK.get(need, 99):
            return False, f"approving this case needs {need}; the reviewer declared {role}"
        if case.capability is None:
            return True, "no consequential capability on this case"
        auth = authorize(
            Capability(case.capability),
            actor=ActorKind(role),
            amount=0,
            policy_outcome=PolicyOutcome(case.policy_outcome or "REQUIRE_HUMAN_REVIEW"),
            evidence_supported=case.evidence_verdict
            in (EvidenceVerdict.SUPPORTED.value, EvidenceVerdict.INSUFFICIENT.value),
        )
        if auth.status is AuthorizationStatus.DENIED:
            return False, f"the capability registry denies it: {auth.reason}"
        return True, (
            f"the registry allows {role} to approve {case.capability} "
            f"(policy {case.policy_outcome}, evidence {case.evidence_verdict})"
        )

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
            required_authorization=required_authorization(d.requested_capability),
            capability=d.requested_capability.value if d.requested_capability else None,
            policy_outcome=d.policy.outcome.value,
            evidence_verdict=d.evidence_verdict.value,
        )
        # an automated case is chained by its decision's audit event (``link_audit``)
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
        case = self._record(
            case,
            actor=actor,
            action="CASE_OPENED",
            detail={
                "rule": "manual",
                "priority": priority.value,
                "title_hash": content_hash(title),
            },
        )
        self.repo.save(case)
        return case

    # ---- lifecycle ---------------------------------------------------------------------
    def transition(self, case_id: str, to: CaseStatus, *, actor: str, note: str = "") -> Case:
        case = self._require(case_id)
        if to is CaseStatus.RESOLVED:  # also absent from TRANSITIONS; the message says why
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
        prev = case.status
        case = replace(case, status=to, events=case.events + (ev,), updated_at=now)
        case = self._record(
            case,
            actor=actor,
            action=f"CASE_{to.value}",
            detail={"from": prev.value, "to": to.value, "note_hash": content_hash(note)},
        )
        self.repo.save(case)
        return case

    def record_human_decision(
        self,
        case_id: str,
        *,
        reviewer: str,
        outcome: str,
        note: str = "",
        role: str = "HUMAN_REVIEWER",
    ) -> Case:
        """A human's verdict: the only path to RESOLVED. The system and the models have no
        path here -- a reserved actor name, or the name of an agent that recommended on this
        case, is refused -- and approving needs the level the case's capability requires."""
        if outcome not in ("approve", "deny", "escalate"):
            raise ValueError("outcome must be approve | deny | escalate")
        if role not in _ROLE_RANK:
            raise ValueError(f"role must be one of {sorted(_ROLE_RANK)}")
        case = self._require(case_id)
        who = reviewer.strip()
        agents = {a.split(":", 1)[0].lower() for a in case.ai_recommendations}
        if (
            not who
            or who.lower() in RESERVED_ACTORS
            or who.lower() in agents
            or who.lower().startswith(_RESERVED_PREFIXES)
        ):
            raise ReviewerNotAuthorized(
                f"{reviewer!r} is not a human reviewer; only a human decision resolves a case"
            )
        if case.status is CaseStatus.RESOLVED:
            raise InvalidTransition("the case is already resolved; a resolved case is final")
        if case.status not in DECIDABLE_FROM:
            raise InvalidTransition(
                f"a human decision cannot be recorded on a {case.status.value} case; "
                "move it to triage or investigation first"
            )
        if outcome == "escalate" and case.status is CaseStatus.ESCALATED:
            raise InvalidTransition("the case is already escalated")
        if case.status is CaseStatus.ESCALATED and _ROLE_RANK[role] < _ROLE_RANK["SENIOR_REVIEWER"]:
            # escalating hands the case up; it is not advisory
            raise ReviewerNotAuthorized("an escalated case is decided by a SENIOR_REVIEWER")
        if outcome == "approve":
            ok, why = self.approval(case, role)
            if not ok:
                raise ReviewerNotAuthorized(why)
        now = now_iso()
        hd = HumanDecision(new_id("HDEC"), case_id, who, outcome, note, now, role)
        ev = CaseEvent(
            new_id("CEV"),
            case_id,
            "human_decision",
            who,
            {"outcome": outcome, "note": note, "role": role},
            now,
        )
        to = CaseStatus.ESCALATED if outcome == "escalate" else CaseStatus.RESOLVED
        prev = case.status
        case = replace(
            case,
            status=to,
            human_decisions=case.human_decisions + (hd,),
            events=case.events + (ev,),
            updated_at=now,
            resolution=None if to is CaseStatus.ESCALATED else outcome,
        )
        case = self._record(
            case,
            actor=who,
            action=f"HUMAN_{outcome.upper()}",
            detail={
                "outcome": outcome,
                "role": role,  # declared, not authenticated (see LIMITATIONS)
                "required_authorization": case.required_authorization,
                "from": prev.value,
                "to": to.value,
                "note_hash": content_hash(note),
            },
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
