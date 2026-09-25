"""The trust boundary, made structural (not just documented).

Sentinel's whole thesis is that the **authoritative decision must never be
computed from attacker-controlled prose**. This module turns it into a type
invariant that mypy checks and regression tests prove:

- ``UntrustedText`` wraps any span that came from outside the institution. It
  is deliberately opaque -- the only things you can get out of it are a coarse
  ``ClaimType`` and a hash. It exposes **no** way to read verified evidence.
- ``TrustedFacts`` (``DisputeFacts`` / ``KYBFacts``) is an immutable record built
  **only** from the institution's own records. It is the sole authoritative
  input to an adjudicator, and it can render itself as verified ``Evidence``.
- The single thing derived from untrusted text is a ``ClaimType`` -- a label of
  *what* the customer is claiming. It selects *which* trusted fact to check; it
  is never itself treated as evidence.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from sentinel.domain.enums import ClaimType, EvidenceKind, TrustClass
from sentinel.domain.evidence import Claim, Evidence
from sentinel.domain.ids import content_hash
from sentinel.security.claims import ClaimClassification, classify


def as_int(value: object, default: int = 0) -> int:
    """Coerce a ledger value to int, falling back safely on bad/missing data.

    Handles plain ints, floats, and numeric strings with commas or currency
    symbols ("₹50,000", "50,000.0"). Anything genuinely unparseable falls back
    to ``default`` rather than crashing -- and a zero amount is fail-safe (it
    can never exceed a policy limit)."""
    if isinstance(value, bool):  # bool is an int subclass; treat as not-a-number
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        cleaned = re.sub(r"(?i)^\s*(rs\.?|inr|₹|\$)\s*", "", value.strip()).replace(",", "")
        if not cleaned:
            return default
        try:
            return int(cleaned)
        except ValueError:
            try:
                return int(float(cleaned))  # "50000.0" -> 50000
            except ValueError:
                return default
    return default


@dataclass(frozen=True)
class UntrustedText:
    """A span of attacker-controllable text.

    Opaque by construction: the class offers a ``ClaimType`` classifier, a
    ``Claim`` builder and a content hash and nothing else. There is intentionally
    no accessor that turns this into evidence."""

    text: str
    source: str = "external"
    trust: TrustClass = TrustClass.USER_CONTROLLED

    def __post_init__(self) -> None:
        if self.trust.is_trusted:
            raise ValueError("UntrustedText cannot carry a trusted TrustClass")

    def sha256(self) -> str:
        return content_hash(self.text, length=64)

    def classify_detailed(self) -> ClaimClassification:
        """The classifier's full reading: type, kind (claim / non_claim / abstain),
        confidence and the signals that fired. This is the *only* value derived
        from prose (``security/claims.py``)."""
        return classify(self.text)

    def classify(self) -> ClaimType:
        """Coarse claim label; UNSPECIFIED when the classifier abstains or reads a
        recognised non-claim."""
        return self.classify_detailed().claim_type

    def claim(self) -> Claim:
        c = self.classify_detailed()
        return Claim(
            c.claim_type,
            self.source,
            self.trust,
            content_hash(self.text),
            c.confidence,
            c.kind,
            c.signals,
        )


@dataclass(frozen=True)
class TrustedFacts:
    """Marker base for verified, authoritative facts. An adjudicator's decision
    is a pure function of a ``TrustedFacts`` instance and a ``ClaimType``."""

    SOURCE: ClassVar[str] = "institution_records"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.LEDGER_FACT
    TRUST: ClassVar[TrustClass] = TrustClass.TRUSTED_INTERNAL

    def as_adjudicator_input(self, claim: ClaimType) -> dict[str, object]:
        raise NotImplementedError  # pragma: no cover

    def to_evidence(self, prefix: str = "EV") -> tuple[Evidence, ...]:
        """Render every verified field as ``Evidence`` (TRUSTED, VERIFIED)."""
        out = []
        for i, f in enumerate(dataclasses.fields(self), start=1):
            out.append(
                Evidence.fact(
                    f"{prefix}-{i:03d}",
                    self.SOURCE,
                    f.name,
                    getattr(self, f.name),
                    kind=self.KIND,
                    trust=self.TRUST,
                )
            )
        return tuple(out)


@dataclass(frozen=True)
class DisputeFacts(TrustedFacts):
    """Verified dispute facts, from the institution's own ledger only."""

    amount: int = 0
    merchant: str = "unknown"
    delivery_status: str = "unknown"  # delivered | not_delivered | in_transit | returned | lost
    prior_disputes_90d: int = 0
    policy_auto_limit: int = 50_000
    duplicate_confirmed: bool = False
    cancellation_confirmed: bool = False
    cardholder_present: bool = True
    refund_state: str = "none"  # none | pending | refunded  (has money already gone back?)
    transaction_status: str = "settled"  # settled | pending | reversed
    merchant_response: str = "none"  # none | accepted | contested
    auth_strength: str = "unknown"  # none | password | otp | biometric (from the switch record)
    customer_tenure_days: int = 0

    SOURCE: ClassVar[str] = "payment_ledger"

    @classmethod
    def from_ledger(cls, ledger: Mapping[str, object]) -> DisputeFacts:
        g = ledger.get
        return cls(
            amount=as_int(g("amount", 0)),
            merchant=str(g("merchant", "unknown")),
            delivery_status=str(g("delivery_status", "unknown")),
            prior_disputes_90d=as_int(g("prior_disputes_90d", 0)),
            policy_auto_limit=as_int(g("policy_auto_limit", 50_000), 50_000),
            duplicate_confirmed=bool(g("duplicate_confirmed", False)),
            cancellation_confirmed=bool(g("cancellation_confirmed", False)),
            cardholder_present=bool(g("cardholder_present", True)),
            refund_state=str(g("refund_state", "none")),
            transaction_status=str(g("transaction_status", "settled")),
            merchant_response=str(g("merchant_response", "none")),
            auth_strength=str(g("auth_strength", "unknown")),
            customer_tenure_days=as_int(g("customer_tenure_days", 0)),
        )

    # Which trusted field each claim type is checked against, and which values
    # of that field support the claim. Data, so the reconciliation engine and
    # the UI can show "claimed X, recorded Y".
    CLAIM_FIELDS: ClassVar[dict[ClaimType, tuple[str, tuple[object, ...]]]] = {
        ClaimType.NON_RECEIPT: ("delivery_status", ("not_delivered", "returned", "lost")),
        ClaimType.DUPLICATE: ("duplicate_confirmed", (True,)),
        ClaimType.CANCELLATION: ("cancellation_confirmed", (True,)),
        ClaimType.UNAUTHORIZED: ("cardholder_present", (False,)),
    }

    def supports(self, claim: ClaimType) -> bool:
        """Is the claim backed by the institution's OWN trusted records? Computed
        purely from ``self`` -- ``claim`` only chooses which field to read."""
        mapping = self.CLAIM_FIELDS.get(claim)
        if mapping is None:
            return False
        fld, supporting = mapping
        return getattr(self, fld) in supporting

    def as_policy_facts(self) -> dict[str, object]:
        """The trusted fields the dispute policy may read. The composer adds the
        context fields it always provides; the workflow adds the account's risk."""
        return {
            "policy_auto_limit": self.policy_auto_limit,
            "prior_disputes_90d": self.prior_disputes_90d,
            "delivery_status": self.delivery_status,
            "refund_state": self.refund_state,
            "transaction_status": self.transaction_status,
            "merchant_response": self.merchant_response,
            "auth_strength": self.auth_strength,
            "customer_tenure_days": self.customer_tenure_days,
        }

    def as_adjudicator_input(self, claim: ClaimType) -> dict[str, object]:
        """The exact JSON object handed to the adjudicator. No prose -- only
        verified fields plus the coarse claim label and the trusted-only verdict."""
        return {
            "amount": self.amount,
            "merchant": self.merchant,
            "delivery_status": self.delivery_status,
            "prior_disputes_90d": self.prior_disputes_90d,
            "policy_auto_limit": self.policy_auto_limit,
            "refund_state": self.refund_state,
            "transaction_status": self.transaction_status,
            "merchant_response": self.merchant_response,
            "auth_strength": self.auth_strength,
            "claimed_reason": claim.value,
            "evidence_supports_claim": self.supports(claim),
        }


@dataclass(frozen=True)
class KYBFacts(TrustedFacts):
    """Verified merchant-onboarding facts, from the acquirer's records only."""

    registration_status: str = "unverified"
    domain_age_days: int = 0
    business_age_days: int = 0
    prior_flags: int = 0
    mcc_risk: str = "unknown"

    SOURCE: ClassVar[str] = "acquirer_records"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.ACQUIRER_RECORD
    TRUST: ClassVar[TrustClass] = TrustClass.VERIFIED_EXTERNAL

    @classmethod
    def from_records(cls, records: Mapping[str, object]) -> KYBFacts:
        g = records.get
        return cls(
            registration_status=str(g("registration_status", "unverified")),
            domain_age_days=as_int(g("domain_age_days", 0)),
            business_age_days=as_int(g("business_age_days", 0)),
            prior_flags=as_int(g("prior_flags", 0)),
            mcc_risk=str(g("mcc_risk", "unknown")),
        )

    def as_adjudicator_input(self, claim: ClaimType = ClaimType.UNSPECIFIED) -> dict[str, object]:
        return {
            "registration_status": self.registration_status,
            "domain_age_days": self.domain_age_days,
            "business_age_days": self.business_age_days,
            "prior_flags": self.prior_flags,
            "mcc_risk": self.mcc_risk,
        }


# Fields on a ledger/records mapping that are NOT verified facts and must never
# be copied into a TrustedFacts.
UNTRUSTED_LEDGER_KEYS = frozenset({"source", "narrative", "document", "note"})
