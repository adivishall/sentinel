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


_CLAIM_PATTERNS: tuple[tuple[ClaimType, re.Pattern[str]], ...] = (
    (
        ClaimType.NON_RECEIPT,
        re.compile(
            r"never (arrived|received|delivered|reached|came|turned up|showed up)"
            r"|not delivered|non[- ]?receipt"
            r"|(has ?n'?t|have ?n'?t|had ?n'?t|did ?n'?t|has not|have not|still (has|had) not)"
            r".{0,15}(arriv|reach|deliver|came|come|turn(ed)? up|show(ed)? up)"
        ),
    ),
    (ClaimType.IN_TRANSIT, re.compile(r"in transit|still (on the way|coming)|not (yet )?arrived")),
    (
        ClaimType.DUPLICATE,
        re.compile(
            r"duplicate|charged (me )?twice|billed .{0,15}(twice|two times)"
            r"|(two|2|double|multiple) .{0,12}(charges|times|entries|debits)"
            r"|charged .{0,12}(twice|two times|multiple times)"
        ),
    ),
    (
        ClaimType.CANCELLATION,
        re.compile(r"cancel(l)?ed?.{0,20}order|order.{0,20}cancel|cancelled.{0,20}(it|within)"),
    ),
    (
        ClaimType.UNAUTHORIZED,
        re.compile(
            r"fraud|didn'?t (make|authori[sz]e)|unauthori[sz]ed|don'?t recognis"
            r"|not mine|card with me|never (made|authori)|never left my wallet"
        ),
    ),
)


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

    def classify(self) -> ClaimType:
        """Coarse claim label. This is the *only* value derived from prose.
        Order matters: a clear 'never arrived' is non-receipt even if the same
        message also mentions 'in transit' tracking."""
        t = self.text.lower()
        for claim_type, rx in _CLAIM_PATTERNS:
            if rx.search(t):
                return claim_type
        return ClaimType.UNSPECIFIED

    def claim(self) -> Claim:
        return Claim(self.classify(), self.source, self.trust, content_hash(self.text))


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
    delivery_status: str = "unknown"
    prior_disputes_90d: int = 0
    policy_auto_limit: int = 50_000
    duplicate_confirmed: bool = False
    cancellation_confirmed: bool = False
    cardholder_present: bool = True

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

    def as_adjudicator_input(self, claim: ClaimType) -> dict[str, object]:
        """The exact JSON object handed to the adjudicator. No prose -- only
        verified fields plus the coarse claim label and the trusted-only verdict."""
        return {
            "amount": self.amount,
            "merchant": self.merchant,
            "delivery_status": self.delivery_status,
            "prior_disputes_90d": self.prior_disputes_90d,
            "policy_auto_limit": self.policy_auto_limit,
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
