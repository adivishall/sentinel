"""Case management: open, transition, resolve. Storage is behind a
small repository protocol so the SQLite store can back it without the
service knowing.

With an audit chain attached (every recording ``Runtime`` attaches its own), each
human action -- opening a case by hand, a status change, a human decision -- is
appended to the tamper-evident chain before the case is saved, so a resolution
cannot be written into the case table without leaving a chained record."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol

from sentinel.cases.identity import RESERVED_IDS, ROLE_RANK, Reviewer
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
    ProvenanceStatus,
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

# Identifiers that denote the system or a model: the reviewer registry refuses them, so no
# authenticated reviewer can carry one and neither the pipeline nor a model has a path to
# RESOLVED (sentinel.cases.identity).
RESERVED_ACTORS = RESERVED_IDS
_ROLE_RANK = ROLE_RANK


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
    """The authenticated reviewer may not take this action (level, authority limit,
    four-eyes, an inactive credential)."""


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
    def __init__(
        self,
        repo: CaseRepository | None = None,
        audit: AuditChain | None = None,
        *,
        standing: Callable[[str], bool] | None = None,
    ) -> None:
        self.repo: CaseRepository = repo or MemoryCaseRepository()
        self.audit: AuditChain | None = audit
        # Whether a reviewer id still holds an active credential -- the registry's answer at
        # decision time. With it, a deactivated reviewer's pending approval stops counting
        # toward four eyes. None (a bare service) counts every recorded approval.
        self.standing = standing

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
            return False, f"approving this case needs {need}; the reviewer is a {role}"
        if case.capability is None:
            return True, "no consequential capability on this case"
        auth = authorize(
            Capability(case.capability),
            actor=ActorKind(role),
            amount=0,
            policy_outcome=PolicyOutcome(case.policy_outcome or "REQUIRE_HUMAN_REVIEW"),
            evidence_supported=case.evidence_verdict
            in (EvidenceVerdict.SUPPORTED.value, EvidenceVerdict.INSUFFICIENT.value),
            facts_provenance=(
                ProvenanceStatus(case.facts_provenance) if case.facts_provenance else None
            ),
        )
        if auth.status is AuthorizationStatus.DENIED:
            return False, f"the capability registry denies it: {auth.reason}"
        return True, (
            f"the registry allows {role} to approve {case.capability} "
            f"(policy {case.policy_outcome}, evidence {case.evidence_verdict}, "
            f"facts {case.facts_provenance or 'of unrecorded provenance'})"
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
            facts_provenance=d.provenance.status.value if d.provenance is not None else None,
            amount=d.amount,
            approvals_required=(
                cap_spec(d.requested_capability).approvals_required(d.amount)
                if d.requested_capability is not None
                else 1
            ),
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
        *,
        by: Reviewer,
    ) -> Case:
        _require_active(by)
        actor = by.reviewer_id
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
                **_who(by),
            },
        )
        self.repo.save(case)
        return case

    # ---- lifecycle ---------------------------------------------------------------------
    def transition(self, case_id: str, to: CaseStatus, *, by: Reviewer, note: str = "") -> Case:
        _require_active(by)
        actor = by.reviewer_id
        case = self._require(case_id)
        if to is CaseStatus.RESOLVED:  # also absent from TRANSITIONS; the message says why
            raise InvalidTransition(
                "a case is resolved only by a recorded human decision (record_human_decision); "
                "a status transition cannot close it"
            )
        if to not in TRANSITIONS[case.status]:
            raise InvalidTransition(f"{case.status.value} -> {to.value} is not allowed")
        if case.status is CaseStatus.ESCALATED and by.rank < _ROLE_RANK["SENIOR_REVIEWER"]:
            # an escalation hands the case up: only the level it went to may move it on
            raise ReviewerNotAuthorized("an escalated case is moved on by a SENIOR_REVIEWER")
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
            detail={
                "from": prev.value,
                "to": to.value,
                "note_hash": content_hash(note),
                **_who(by),
            },
        )
        self.repo.save(case)
        return case

    def record_human_decision(
        self,
        case_id: str,
        *,
        by: Reviewer,
        outcome: str,
        note: str = "",
    ) -> Case:
        """A human's verdict: the only path to RESOLVED. ``by`` is the reviewer the
        registry authenticated -- the id, role and authority limit on the record are the
        registry's, never the request's. Approving needs the level the case's capability
        requires (a SENIOR_REVIEWER once escalated), an authority limit that covers the
        amount, the registry's answer for a human actor, and -- where the registry asks for
        four eyes -- a second approval by a different reviewer before the case resolves."""
        if outcome not in ("approve", "deny", "escalate"):
            raise ValueError("outcome must be approve | deny | escalate")
        _require_active(by)
        case = self._require(case_id)
        if case.status is CaseStatus.RESOLVED:
            raise InvalidTransition("the case is already resolved; a resolved case is final")
        if case.status not in DECIDABLE_FROM:
            raise InvalidTransition(
                f"a human decision cannot be recorded on a {case.status.value} case; "
                "move it to triage or investigation first"
            )
        if outcome == "escalate" and case.status is CaseStatus.ESCALATED:
            raise InvalidTransition("the case is already escalated")
        if _escalated(case) and by.rank < _ROLE_RANK["SENIOR_REVIEWER"]:
            # escalating hands the case up; it is not advisory, and it stays handed up when
            # the case moves back to investigation
            raise ReviewerNotAuthorized("an escalated case is decided by a SENIOR_REVIEWER")
        pending = _pending_approvals(case, self.standing)
        required = _approvals_required(case)
        final = True
        if outcome == "approve":
            ok, why = self.approval(case, by.role)
            if not ok:
                raise ReviewerNotAuthorized(why)
            if case.amount > by.authority_limit:
                raise ReviewerNotAuthorized(
                    f"{by.reviewer_id} may approve up to {by.authority_limit:,}; this case is "
                    f"{case.amount:,}"
                )
            if by.reviewer_id in pending:
                raise ReviewerNotAuthorized(
                    f"four eyes: {by.reviewer_id} has already approved this case; a second, "
                    "different reviewer must"
                )
            final = len(pending) + 1 >= required
        now = now_iso()
        hd = HumanDecision(
            new_id("HDEC"), case_id, by.reviewer_id, outcome, note, now, by.role, by.credential_id
        )
        detail: dict[str, object] = {"outcome": outcome, "role": by.role}
        if outcome == "approve":
            detail.update(approvals=len(pending) + 1, required=required)
        ev = CaseEvent(new_id("CEV"), case_id, "human_decision", by.reviewer_id, detail, now)
        to = (
            CaseStatus.ESCALATED
            if outcome == "escalate"
            else CaseStatus.RESOLVED if final else case.status  # a first of two approvals
        )
        prev = case.status
        case = replace(
            case,
            status=to,
            human_decisions=case.human_decisions + (hd,),
            events=case.events + (ev,),
            updated_at=now,
            resolution=outcome if to is CaseStatus.RESOLVED else None,
        )
        case = self._record(
            case,
            actor=by.reviewer_id,
            action=f"HUMAN_{outcome.upper()}" + ("" if final else "_PENDING"),
            detail={
                **detail,
                **_who(by),
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


def _require_active(by: Reviewer) -> None:
    if not isinstance(by, Reviewer) or not by.active:
        raise ReviewerNotAuthorized("a case action needs an active, authenticated reviewer")


def _who(by: Reviewer) -> dict[str, object]:
    """Who acted, as the registry resolved them (never the credential itself)."""
    return {
        "reviewer_id": by.reviewer_id,
        "role": by.role,
        "credential_id": by.credential_id,
        "authority_limit": by.authority_limit,
    }


def _escalations(case: Case) -> list[int]:
    """Positions in the case's event history where it was escalated -- by a decision or
    by a status change."""
    return [
        i
        for i, e in enumerate(case.events)
        if (e.kind == "human_decision" and e.detail.get("outcome") == "escalate")
        or (e.kind == "status_changed" and e.detail.get("to") == CaseStatus.ESCALATED.value)
    ]


def _escalated(case: Case) -> bool:
    return bool(_escalations(case))


def _pending_approvals(case: Case, standing: Callable[[str], bool] | None = None) -> list[str]:
    """Reviewers whose approvals count toward the case's current decision: approvals since
    the last escalation, however it was escalated (an escalated case is decided afresh at
    the higher level), by reviewers who still hold an active credential."""
    since = max(_escalations(case), default=-1)
    return [
        e.actor
        for e in case.events[since + 1 :]
        if e.kind == "human_decision"
        and e.detail.get("outcome") == "approve"
        and (standing is None or standing(e.actor))
    ]


def _approvals_required(case: Case) -> int:
    """Distinct approvals the case needs: what was recorded when it opened, and never fewer
    than the capability registry asks for the case's amount now."""
    if case.capability is None:
        return case.approvals_required
    registry = cap_spec(Capability(case.capability)).approvals_required(case.amount)
    return max(case.approvals_required, registry)
