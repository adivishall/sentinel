"""Event model: an in-process bus with typed events.

This is deliberately *not* a distributed system. The value is the clean
separation between event, processing, decision and side-effect, which is what
makes the pipeline replayable and the audit trail complete."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from sentinel.domain.ids import new_id, now_iso


@dataclass(frozen=True)
class DomainEvent:
    name: str
    subject_id: str
    payload: dict[str, object] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: new_id("EVT"))
    occurred_at: str = field(default_factory=now_iso)


# Event names used across the platform (kept as constants so typos fail loudly).
TRANSACTION_CREATED = "TransactionCreated"
TRANSACTION_RISK_ASSESSED = "TransactionRiskAssessed"
SECURITY_THREAT_DETECTED = "SecurityThreatDetected"
DISPUTE_SUBMITTED = "DisputeSubmitted"
DISPUTE_EVALUATED = "DisputeEvaluated"
CASE_CREATED = "CaseCreated"
POLICY_EVALUATED = "PolicyEvaluated"
HUMAN_REVIEW_REQUESTED = "HumanReviewRequested"
DECISION_FINALIZED = "DecisionFinalized"
AUDIT_RECORDED = "AuditRecorded"

Handler = Callable[[DomainEvent], None]


class EventBus:
    """Synchronous, in-process publish/subscribe with a bounded history."""

    def __init__(self, keep: int = 5000) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._history: list[DomainEvent] = []
        self._keep = keep

    def subscribe(self, name: str, handler: Handler) -> None:
        self._handlers[name].append(handler)

    def publish(self, event: DomainEvent) -> None:
        self._history.append(event)
        if len(self._history) > self._keep:
            del self._history[: len(self._history) - self._keep]
        handlers = list(self._handlers.get(event.name, [])) + list(self._handlers.get("*", []))
        for h in handlers:
            h(event)

    def emit(self, name: str, subject_id: str, **payload: object) -> DomainEvent:
        ev = DomainEvent(name=name, subject_id=subject_id, payload=dict(payload))
        self.publish(ev)
        return ev

    @property
    def history(self) -> tuple[DomainEvent, ...]:
        return tuple(self._history)
