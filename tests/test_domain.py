"""Domain primitives: the structural guarantees the rest of the system builds on."""

import json

import pytest

from sentinel.domain.decisions import AIRecommendation
from sentinel.domain.enums import (
    ClaimType,
    EvidenceKind,
    EvidenceStatus,
    FinalAction,
    PolicyOutcome,
    RiskLevel,
    Severity,
    TrustClass,
)
from sentinel.domain.events import EventBus
from sentinel.domain.evidence import Claim, Evidence, EvidenceSet
from sentinel.domain.serialization import to_dict


def test_only_trusted_sources_are_trusted():
    assert TrustClass.TRUSTED_INTERNAL.is_trusted
    assert TrustClass.VERIFIED_EXTERNAL.is_trusted
    for t in (
        TrustClass.USER_CONTROLLED,
        TrustClass.MERCHANT_CONTROLLED,
        TrustClass.DOCUMENT_CONTROLLED,
        TrustClass.MODEL_GENERATED,
        TrustClass.UNKNOWN,
    ):
        assert not t.is_trusted, t


def test_risk_bands():
    assert RiskLevel.from_score(0) is RiskLevel.LOW
    assert RiskLevel.from_score(24) is RiskLevel.LOW
    assert RiskLevel.from_score(25) is RiskLevel.MEDIUM
    assert RiskLevel.from_score(49) is RiskLevel.MEDIUM
    assert RiskLevel.from_score(50) is RiskLevel.HIGH
    assert RiskLevel.from_score(75) is RiskLevel.CRITICAL
    assert RiskLevel.from_score(100) is RiskLevel.CRITICAL


def test_outcome_and_severity_ordering():
    assert (
        PolicyOutcome.BLOCK.rank
        > PolicyOutcome.REQUIRE_HUMAN_REVIEW.rank
        > PolicyOutcome.ALLOW.rank
    )
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.NONE.rank
    assert (
        FinalAction.ALLOW.permissiveness
        > FinalAction.REQUIRE_HUMAN_REVIEW.permissiveness
        > FinalAction.BLOCK.permissiveness
    )


def test_untrusted_evidence_can_never_be_verified():
    with pytest.raises(ValueError):
        Evidence(
            "EV-x",
            EvidenceKind.USER_CLAIM,
            "cardholder",
            TrustClass.USER_CONTROLLED,
            "delivery_status",
            "never_received",
            EvidenceStatus.VERIFIED,
        )
    with pytest.raises(ValueError):
        Evidence(
            "EV-m",
            EvidenceKind.MODEL_ASSERTION,
            "llm",
            TrustClass.MODEL_GENERATED,
            "verdict",
            "approve",
            EvidenceStatus.VERIFIED,
        )


def test_claim_helper_rejects_trusted_source():
    with pytest.raises(ValueError):
        Evidence.claim("EV-1", "ledger", "f", 1, trust=TrustClass.TRUSTED_INTERNAL)
    with pytest.raises(ValueError):
        Claim(ClaimType.NON_RECEIPT, "ledger", TrustClass.TRUSTED_INTERNAL, "abc")


def test_evidence_set_reads_only_verified_values():
    fact = Evidence.fact("EV-1", "payment_ledger", "delivery_status", "delivered")
    claim = Evidence.claim("EV-2", "cardholder", "delivery_status", "never_received")
    es = EvidenceSet.of([claim, fact])
    assert es.verified_value("delivery_status") == "delivered"
    assert len(es.verified()) == 1 and len(es.claims()) == 1
    # a set with only the claim answers nothing
    assert EvidenceSet.of([claim]).verified_value("delivery_status") is None


def test_ai_recommendation_is_always_model_generated():
    with pytest.raises(ValueError):
        AIRecommendation("a", "approve", None, 0, "", "p", "m", trust=TrustClass.TRUSTED_INTERNAL)
    r = AIRecommendation("a", "approve", None, 0, "", "p", "m")
    assert r.trust is TrustClass.MODEL_GENERATED


def test_to_dict_is_json_serialisable():
    fact = Evidence.fact("EV-1", "payment_ledger", "delivery_status", "delivered")
    d = to_dict(EvidenceSet.of([fact]))
    json.dumps(d)
    assert d["items"][0]["trust"] == "TRUSTED_INTERNAL"


def test_event_bus_publishes_and_keeps_history():
    bus = EventBus(keep=3)
    seen = []
    bus.subscribe("X", lambda e: seen.append(e.subject_id))
    bus.subscribe("*", lambda e: seen.append("*" + e.name))
    for i in range(5):
        bus.emit("X", f"s{i}")
    assert seen[:2] == ["s0", "*X"]
    assert len(bus.history) == 3  # bounded
