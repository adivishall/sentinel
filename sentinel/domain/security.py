"""AI-security findings and events emitted by the gateway."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.enums import Capability, Severity, ThreatClass, TrustClass


@dataclass(frozen=True)
class SecurityFinding:
    threat_class: ThreatClass
    signal: str
    weight: float
    span_hash: str  # hash of the matched span; the span itself is never persisted
    span_len: int = 0
    detail: str = ""


@dataclass(frozen=True)
class SecurityAssessment:
    """Gateway verdict over one piece (or transcript) of untrusted content."""

    severity: Severity
    score: float
    findings: tuple[SecurityFinding, ...]
    threat_classes: tuple[ThreatClass, ...]
    source_trust: TrustClass
    content_hash: str
    normalized_changed: bool = False  # unicode/homoglyph folding altered the text
    requested_capability: Capability | None = None
    capability_escalation: bool = False

    @property
    def flagged(self) -> bool:
        return self.severity.rank >= Severity.MEDIUM.rank


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    agent: str
    workflow: str
    severity: Severity
    threat_classes: tuple[ThreatClass, ...]
    findings: tuple[SecurityFinding, ...]
    source_trust: TrustClass
    content_hash: str
    requested_capability: Capability | None
    ai_recommendation: str | None
    evidence_verdict: str | None
    policy_id: str | None
    final_action: str | None
    blocked_by: tuple[str, ...] = field(default_factory=tuple)
    decision_id: str | None = None
    created_at: str = ""
