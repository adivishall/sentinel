"""Closed vocabularies for record fields that policy compares as strings.

One source for two checks that must agree: a record whose field holds anything else is
malformed (the workflow fails safe to a human), and a policy context value outside the
vocabulary is an evaluation error (the engine fails safe). A value the rules were not
written for -- ``"REFUNDED"``, ``"Refunded "`` -- would otherwise make every rule on the
field silently false, and a BLOCK rule that never fires is an ALLOW.
"""

from __future__ import annotations

from sentinel.domain.enums import ProvenanceStatus, RiskLevel, Severity, Workflow

RECORD_VALUES: dict[str, frozenset[str]] = {
    "delivery_status": frozenset(
        {"delivered", "not_delivered", "in_transit", "returned", "lost", "unknown"}
    ),
    "refund_state": frozenset({"none", "pending", "refunded"}),
    "transaction_status": frozenset({"settled", "pending", "reversed"}),
    "merchant_response": frozenset({"none", "accepted", "contested"}),
    "auth_strength": frozenset({"none", "password", "otp", "biometric", "unknown"}),
    "registration_status": frozenset({"verified", "unverified", "shell"}),
    "mcc_risk": frozenset({"low", "medium", "high", "unknown"}),
    "account_status": frozenset({"active", "frozen", "closed"}),
}

# Every policy-context string field with a closed vocabulary.
CONTEXT_VALUES: dict[str, frozenset[str]] = {
    **RECORD_VALUES,
    "risk_level": frozenset(r.value for r in RiskLevel),
    "merchant_risk_level": frozenset(r.value for r in RiskLevel),
    "security_severity": frozenset(s.value for s in Severity),
    "evidence_verdict": frozenset({"SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "INSUFFICIENT"}),
    "workflow": frozenset(w.value for w in Workflow),
    "facts_provenance": frozenset(p.value for p in ProvenanceStatus) | {"NONE"},
}
