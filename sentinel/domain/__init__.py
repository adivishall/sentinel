"""Typed domain primitives. Everything else in Sentinel composes these:

Entity  Event  Evidence  RiskAssessment  SecurityEvent  Capability
Policy  Decision  Case  AuditEvent
"""

from sentinel.domain.enums import (
    ActorKind,
    AuthorizationStatus,
    Capability,
    CaseStatus,
    ClaimType,
    EvidenceKind,
    EvidenceStatus,
    EvidenceVerdict,
    FinalAction,
    PolicyOutcome,
    RiskLevel,
    Severity,
    ThreatClass,
    TrustClass,
    Workflow,
)

__all__ = [
    "ActorKind",
    "AuthorizationStatus",
    "Capability",
    "CaseStatus",
    "ClaimType",
    "EvidenceKind",
    "EvidenceStatus",
    "EvidenceVerdict",
    "FinalAction",
    "PolicyOutcome",
    "RiskLevel",
    "Severity",
    "ThreatClass",
    "TrustClass",
    "Workflow",
]
