"""Evidence reconciliation and the contradiction engine."""

from sentinel.domain.decisions import AIRecommendation
from sentinel.domain.enums import Capability, ClaimType, EvidenceVerdict, TrustClass
from sentinel.domain.evidence import Claim, Evidence, EvidenceSet
from sentinel.evidence.contradiction import find_contradictions, is_consistent
from sentinel.evidence.reconcile import (
    model_evidence,
    reconcile_dispute,
    reconcile_kyb,
    reconcile_records_only,
)
from sentinel.security.trust_boundary import DisputeFacts, KYBFacts, UntrustedText


def _facts(**kw):
    base = {"amount": 18000, "delivery_status": "delivered", "policy_auto_limit": 50000}
    base.update(kw)
    return DisputeFacts.from_ledger(base)


def test_contradiction_when_claim_and_record_disagree():
    fact = Evidence.fact("EV-1", "payment_ledger", "delivery_status", "delivered")
    claim = Evidence.claim("EV-2", "cardholder", "delivery_status", "never_received")
    cs = find_contradictions(EvidenceSet.of([fact, claim]))
    assert len(cs) == 1 and cs[0].claimed == "never_received" and cs[0].recorded == "delivered"
    assert cs[0].impact == "claim unsupported"


def test_consistent_claims_are_not_contradictions():
    assert is_consistent("delivery_status", "never_received", "not_delivered")
    assert is_consistent("delivery_status", "in_transit", "in_transit")
    assert not is_consistent("cardholder_present", False, True)
    assert is_consistent("unknown_field", 1, 1) and not is_consistent("unknown_field", 1, 2)


def test_non_receipt_supported_contradicted_and_insufficient():
    claim = UntrustedText("my order never arrived").claim()
    assert (
        reconcile_dispute(claim, _facts(delivery_status="not_delivered")).verdict
        is EvidenceVerdict.SUPPORTED
    )
    r = reconcile_dispute(claim, _facts(delivery_status="delivered"))
    assert r.verdict is EvidenceVerdict.CONTRADICTED and r.contradictions
    assert "delivered" in r.explanation
    t = reconcile_dispute(
        UntrustedText("still in transit I think").claim(), _facts(delivery_status="in_transit")
    )
    assert t.verdict is EvidenceVerdict.INSUFFICIENT


def test_boolean_claims_unsupported_vs_supported():
    dup = UntrustedText("I was charged twice").claim()
    assert (
        reconcile_dispute(dup, _facts(duplicate_confirmed=True)).verdict
        is EvidenceVerdict.SUPPORTED
    )
    assert reconcile_dispute(dup, _facts()).verdict is EvidenceVerdict.UNSUPPORTED
    un = UntrustedText("this charge is fraud, not mine").claim()
    assert (
        reconcile_dispute(un, _facts(cardholder_present=False)).verdict is EvidenceVerdict.SUPPORTED
    )
    assert reconcile_dispute(un, _facts()).verdict is EvidenceVerdict.CONTRADICTED


def test_unspecified_claim_is_unsupported():
    r = reconcile_dispute(UntrustedText("arrived but I don't love the colour").claim(), _facts())
    assert r.verdict is EvidenceVerdict.UNSUPPORTED and r.claim.claim_type is ClaimType.UNSPECIFIED


def test_document_claim_kept_as_untrusted_evidence():
    user = UntrustedText("see attached").claim()
    doc = Claim(ClaimType.NON_RECEIPT, "invoice", TrustClass.DOCUMENT_CONTROLLED, "h")
    r = reconcile_dispute(user, _facts(), extra_claims=(doc,))
    kinds = {e.kind.value for e in r.evidence.claims()}
    assert "document_claim" in kinds
    assert (
        r.evidence.verified_value("delivery_status") == "delivered"
    )  # the document changed nothing
    assert r.verdict is not EvidenceVerdict.SUPPORTED


def test_model_output_is_untrusted_evidence():
    ai = AIRecommendation(
        "agent", "approve_refund", Capability.APPROVE_REFUND, 1, "", "offline", "sim"
    )
    e = model_evidence(ai)
    assert e.trust is TrustClass.MODEL_GENERATED and not e.is_verified
    es = EvidenceSet.of([e])
    assert es.verified_value("recommended_action") is None


def test_kyb_reconciliation():
    good = KYBFacts.from_records(
        {
            "registration_status": "verified",
            "domain_age_days": 900,
            "business_age_days": 1600,
            "prior_flags": 0,
        }
    )
    assert reconcile_kyb(good).verdict is EvidenceVerdict.SUPPORTED
    shell = KYBFacts.from_records({"registration_status": "shell", "prior_flags": 3})
    assert reconcile_kyb(shell).verdict is EvidenceVerdict.CONTRADICTED
    border = KYBFacts.from_records(
        {"registration_status": "unverified", "domain_age_days": 200, "business_age_days": 300}
    )
    assert reconcile_kyb(border).verdict is EvidenceVerdict.INSUFFICIENT
    claim = Claim(ClaimType.UNSPECIFIED, "application", TrustClass.MERCHANT_CONTROLLED, "h")
    r = reconcile_kyb(shell, application_claim=claim)
    assert r.contradictions and r.contradictions[0].field == "registration_status"


def test_records_only_reconciliation():
    r = reconcile_records_only(_facts().to_evidence())
    assert r.verdict is EvidenceVerdict.SUPPORTED and r.claim is None and len(r.evidence) == 13
