"""Reconciliation: does verified evidence support what the untrusted party
claims? This is the generalisation of the original firewall's Layer 3.

The verdict is a pure function of ``TrustedFacts`` and a ``ClaimType``. The
prose that produced the claim type never enters. Unknown / unmappable claims
are INSUFFICIENT, which the composer treats as fail-safe (human review), never
as support."""

from __future__ import annotations

from sentinel.domain.enums import ClaimType, EvidenceKind, EvidenceVerdict, TrustClass
from sentinel.domain.evidence import Claim, Evidence, EvidenceSet, Reconciliation
from sentinel.domain.provenance import FactProvenance
from sentinel.evidence.contradiction import find_contradictions
from sentinel.security.trust_boundary import DisputeFacts, KYBFacts

# What each claim type asserts, as a (field, claimed value) the contradiction
# engine can compare against the trusted record.
CLAIM_ASSERTIONS: dict[ClaimType, tuple[str, str | bool]] = {
    ClaimType.NON_RECEIPT: ("delivery_status", "never_received"),
    ClaimType.IN_TRANSIT: ("delivery_status", "in_transit"),
    ClaimType.DUPLICATE: ("duplicate_confirmed", True),
    ClaimType.CANCELLATION: ("cancellation_confirmed", True),
    ClaimType.UNAUTHORIZED: ("cardholder_present", False),
}


def claim_evidence(claim: Claim, evidence_id: str = "EV-CLAIM") -> Evidence | None:
    a = CLAIM_ASSERTIONS.get(claim.claim_type)
    if a is None:
        return None
    kind = {
        TrustClass.DOCUMENT_CONTROLLED: EvidenceKind.DOCUMENT_CLAIM,
        TrustClass.MERCHANT_CONTROLLED: EvidenceKind.MERCHANT_CLAIM,
    }.get(claim.trust, EvidenceKind.USER_CLAIM)
    return Evidence.claim(
        evidence_id,
        claim.source,
        a[0],
        a[1],
        kind=kind,
        trust=claim.trust,
        note=f"claim_type={claim.claim_type.value}",
    )


def _gate(
    verdict: EvidenceVerdict, why: str, provenance: FactProvenance | None
) -> tuple[EvidenceVerdict, str]:
    """Unverified records may make an outcome stricter, never looser: a claim they would
    support is held for a human instead (INSUFFICIENT)."""
    if provenance is not None and not provenance.status.trusted and verdict.supports:
        return (
            EvidenceVerdict.INSUFFICIENT,
            f"{why} -- but only per a record Sentinel could not establish "
            f"({provenance.status.value}: {provenance.reason}); held for a human",
        )
    return verdict, why


def reconcile_dispute(
    claim: Claim,
    facts: DisputeFacts,
    *,
    extra_claims: tuple[Claim, ...] = (),
    provenance: FactProvenance | None = None,
) -> Reconciliation:
    """Ledger facts vs the cardholder's (and any document's) claim."""
    fact_ev = facts.to_evidence(
        "EV-LEDGER", provenance.evidence_trust if provenance is not None else None
    )
    claims: list[Evidence] = []
    ce = claim_evidence(claim, "EV-CLAIM-1")
    if ce is not None:
        claims.append(ce)
    for i, c in enumerate(extra_claims, start=2):
        e = claim_evidence(c, f"EV-CLAIM-{i}")
        if e is not None:
            claims.append(e)
    evidence = EvidenceSet.of(list(fact_ev) + claims)
    contradictions = find_contradictions(evidence)

    ct = claim.claim_type
    if ct is ClaimType.UNSPECIFIED and claim.abstained:
        verdict, why = (
            EvidenceVerdict.INSUFFICIENT,
            "the claim could not be read from the submission; held for a human",
        )
    elif ct is ClaimType.UNSPECIFIED:
        verdict, why = (
            EvidenceVerdict.UNSUPPORTED,
            "no refundable claim is asserted (recognised non-claim)",
        )
    elif ct is ClaimType.IN_TRANSIT:
        if facts.delivery_status == "delivered":
            verdict, why = (
                EvidenceVerdict.CONTRADICTED,
                "claims in transit; ledger records delivered",
            )
        else:
            verdict, why = (
                EvidenceVerdict.INSUFFICIENT,
                "item still in transit; premature dispute, held for a human",
            )
    elif facts.unknown(ct):
        verdict, why = (
            EvidenceVerdict.INSUFFICIENT,
            f"claims {ct.value}; the records do not state {DisputeFacts.CLAIM_FIELDS[ct][0]}",
        )
    elif facts.supports(ct):
        verdict, why = EvidenceVerdict.SUPPORTED, f"ledger supports {ct.value}"
    else:
        # Is it a contradiction (record says the opposite) or merely unsupported?
        if any(c.field == DisputeFacts.CLAIM_FIELDS[ct][0] for c in contradictions):
            verdict, why = (
                EvidenceVerdict.CONTRADICTED,
                f"claims {ct.value}; ledger records {getattr(facts, DisputeFacts.CLAIM_FIELDS[ct][0])!r}",
            )
        else:
            verdict, why = EvidenceVerdict.UNSUPPORTED, f"ledger does not confirm {ct.value}"
    verdict, why = _gate(verdict, why, provenance)
    return Reconciliation(claim, verdict, evidence, contradictions, why)


def reconcile_kyb(
    facts: KYBFacts,
    *,
    application_claim: Claim | None = None,
    provenance: FactProvenance | None = None,
) -> Reconciliation:
    """The applicant implicitly claims to be a verified, clean business. The
    acquirer's records either support that, contradict it (shell / flagged) or
    are incomplete (unverified) -> human review."""
    fact_ev = facts.to_evidence(
        "EV-ACQ", provenance.evidence_trust if provenance is not None else None
    )
    claims: list[Evidence] = []
    if application_claim is not None:
        claims.append(
            Evidence.claim(
                "EV-CLAIM-1",
                application_claim.source,
                "registration_status",
                "verified",
                kind=EvidenceKind.MERCHANT_CLAIM,
                trust=application_claim.trust,
                note="applicant asserts verified status",
            )
        )
    evidence = EvidenceSet.of(list(fact_ev) + claims)
    contradictions = find_contradictions(evidence)
    if facts.registration_status == "shell" or facts.prior_flags >= 2:
        verdict, why = (
            EvidenceVerdict.CONTRADICTED,
            "shell registration or repeated prior fraud flags",
        )
    elif (
        facts.registration_status == "verified"
        and facts.domain_age_days >= 30
        and facts.business_age_days >= 90
        and facts.prior_flags == 0
    ):
        verdict, why = EvidenceVerdict.SUPPORTED, "registration verified and history clean"
    else:
        verdict, why = EvidenceVerdict.INSUFFICIENT, "verification incomplete"
    verdict, why = _gate(verdict, why, provenance)
    return Reconciliation(application_claim, verdict, evidence, contradictions, why)


def reconcile_records_only(
    fact_evidence: tuple[Evidence, ...],
    *,
    why: str = "trusted records consistent",
    provenance: FactProvenance | None = None,
) -> Reconciliation:
    """Workflows with no external claim (transaction authorisation, account
    security, investigations): the evidence is the records themselves, so they support
    the request exactly as far as the records can be trusted."""
    verdict, reason = _gate(EvidenceVerdict.SUPPORTED, why, provenance)
    return Reconciliation(None, verdict, EvidenceSet.of(fact_evidence), (), reason)
