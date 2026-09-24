"""Serialise / restore DecisionInputs so a decision can be replayed later
under a different policy version, risk model or (to prove irrelevance)
model recommendation -- without touching any source system."""

from __future__ import annotations

from typing import Any

from sentinel.decision.composer import DecisionInputs
from sentinel.domain.decisions import AIRecommendation
from sentinel.domain.enums import (
    ActorKind,
    Capability,
    ClaimType,
    EvidenceKind,
    EvidenceStatus,
    EvidenceVerdict,
    RiskLevel,
    Severity,
    ThreatClass,
    TrustClass,
    Workflow,
)
from sentinel.domain.evidence import Claim, Contradiction, Evidence, EvidenceSet, Reconciliation
from sentinel.domain.risk import RiskAssessment, RiskFactor
from sentinel.domain.security import SecurityAssessment, SecurityFinding
from sentinel.domain.serialization import to_dict
from sentinel.policy.loader import PolicyRegistry


def snapshot(inputs: DecisionInputs) -> dict[str, Any]:
    d = to_dict(inputs)
    d["policy"] = {
        "policy_id": inputs.policy.policy_id,
        "version": inputs.policy.version,
        "content_hash": inputs.policy.content_hash,
    }
    return d


def _evidence(e: dict[str, Any]) -> Evidence:
    return Evidence(
        e["evidence_id"],
        EvidenceKind(e["kind"]),
        e["source"],
        TrustClass(e["trust"]),
        e["field"],
        e["value"],
        EvidenceStatus(e["status"]),
        e.get("content_hash", ""),
        e.get("note", ""),
    )


def _reconciliation(r: dict[str, Any]) -> Reconciliation:
    claim = None
    if r.get("claim"):
        c = r["claim"]
        claim = Claim(
            ClaimType(c["claim_type"]), c["source"], TrustClass(c["trust"]), c["text_hash"]
        )
    return Reconciliation(
        claim,
        EvidenceVerdict(r["verdict"]),
        EvidenceSet.of([_evidence(e) for e in r["evidence"]["items"]]),
        tuple(
            Contradiction(
                c["claim_evidence_id"],
                c["fact_evidence_id"],
                c["field"],
                c["claimed"],
                c["recorded"],
                c.get("impact", ""),
            )
            for c in r.get("contradictions", [])
        ),
        r.get("explanation", ""),
    )


def _security(s: dict[str, Any]) -> SecurityAssessment:
    return SecurityAssessment(
        Severity(s["severity"]),
        float(s["score"]),
        tuple(
            SecurityFinding(
                ThreatClass(f["threat_class"]),
                f["signal"],
                float(f["weight"]),
                f["span_hash"],
                int(f.get("span_len", 0)),
                f.get("detail", ""),
            )
            for f in s.get("findings", [])
        ),
        tuple(ThreatClass(t) for t in s.get("threat_classes", [])),
        TrustClass(s["source_trust"]),
        s.get("content_hash", ""),
        bool(s.get("normalized_changed", False)),
        Capability(s["requested_capability"]) if s.get("requested_capability") else None,
        bool(s.get("capability_escalation", False)),
    )


def _risk(r: dict[str, Any] | None) -> RiskAssessment | None:
    if not r:
        return None
    return RiskAssessment(
        r["assessment_id"],
        r["entity_type"],
        r["entity_id"],
        int(r["score"]),
        RiskLevel(r["level"]),
        tuple(
            RiskFactor(
                f["code"],
                f["label"],
                int(f["points"]),
                f.get("detail", ""),
                tuple(f.get("evidence_ids", [])),
            )
            for f in r.get("factors", [])
        ),
        r.get("recommended_action", "ALLOW"),
        r.get("model_version", ""),
        dict(r.get("features", {})),
        r.get("computed_at", ""),
    )


def _ai(a: dict[str, Any] | None) -> AIRecommendation | None:
    if not a:
        return None
    return AIRecommendation(
        a["agent"],
        a["recommended_action"],
        Capability(a["requested_capability"]) if a.get("requested_capability") else None,
        int(a.get("amount", 0)),
        a.get("rationale", ""),
        a.get("provider", ""),
        a.get("model", ""),
        float(a.get("latency_ms", 0.0)),
        a.get("raw_hash", ""),
    )


def restore(
    d: dict[str, Any], policies: PolicyRegistry, *, policy_version: int | None = None
) -> DecisionInputs:
    pol = d["policy"]
    return DecisionInputs(
        workflow=Workflow(d["workflow"]),
        subject_type=d["subject_type"],
        subject_id=d["subject_id"],
        amount=int(d["amount"]),
        candidate_capability=(
            Capability(d["candidate_capability"]) if d.get("candidate_capability") else None
        ),
        facts=dict(d.get("facts", {})),
        reconciliation=_reconciliation(d["reconciliation"]),
        security=_security(d["security"]),
        policy=policies.get(
            pol["policy_id"], policy_version if policy_version is not None else pol["version"]
        ),
        risk=_risk(d.get("risk")),
        ai=_ai(d.get("ai")),
        actor=ActorKind(d.get("actor", "SYSTEM")),
        controls=frozenset(d.get("controls", [])),
        input_hash=d.get("input_hash", ""),
        session_id=d.get("session_id"),
        provider=d.get("provider", "offline"),
        model=d.get("model", "offline-simulator"),
        claim_type=d.get("claim_type"),
        extra_context=dict(d.get("extra_context", {})),
    )
