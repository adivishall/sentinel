"""The trust boundary, made structural (not just documented).

Sentinel's whole thesis is that the **authoritative decision must never be
computed from attacker-controlled prose**. Everywhere else in the codebase that
is enforced by discipline and comments. This module turns it into a type
invariant that mypy checks and a regression test proves:

- ``UntrustedText`` wraps any span that came from outside the bank (a cardholder
  narrative, an uploaded document). It is deliberately opaque -- the only things
  you can get out of it are a coarse ``ClaimType`` and a hash. It exposes **no**
  way to read verified evidence.
- ``TrustedFacts`` (``DisputeFacts`` / ``KYBFacts``) is an immutable record built
  **only** from the bank's own verified records. It is the *sole* authoritative
  input to an adjudicator.
- The single thing derived from untrusted text is a ``ClaimType`` -- a label of
  *what* the customer is claiming (non-receipt, duplicate, ...). It selects
  *which* trusted fact to check; it is never itself treated as evidence.

Because an adjudicator's evidence check has the signature
``TrustedFacts.supports(ClaimType) -> bool``, you cannot pass a narrative string
where evidence is expected: mypy rejects it, and ``tests/test_trust_boundary.py``
proves the narrative never reaches the decision input.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum


def _as_int(value: object, default: int = 0) -> int:
    """Coerce a ledger value to int, falling back safely on bad/missing data."""
    if isinstance(value, bool):  # bool is an int subclass; treat as not-a-number
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip() or default)
        except ValueError:
            return default
    return default


class ClaimType(StrEnum):
    """What the customer *says* happened. Derived from untrusted text, so it is
    only ever a hint that selects which trusted fact to verify -- never evidence."""

    NON_RECEIPT = "non_receipt"
    IN_TRANSIT = "in_transit"
    DUPLICATE = "duplicate"
    CANCELLATION = "cancellation"
    UNAUTHORIZED = "unauthorized"
    UNSPECIFIED = "unspecified"


@dataclass(frozen=True)
class UntrustedText:
    """A span of attacker-controllable text.

    Opaque by construction: the class offers a ``ClaimType`` classifier and a
    content hash and nothing else. There is intentionally no accessor that turns
    this into evidence, so no code path can smuggle prose into a decision.
    """

    text: str
    source: str = "external"

    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8", "replace")).hexdigest()

    def classify(self) -> ClaimType:
        """Coarse claim label. This is the *only* value derived from prose.

        Order matters: a clear 'never arrived' is non-receipt even if the same
        message also mentions 'in transit' tracking (matches the original
        adjudicator's precedence)."""
        t = self.text.lower()
        if re.search(
            r"never (arrived|received|delivered|reached|came|turned up|showed up)"
            r"|not delivered|non[- ]?receipt"
            r"|(has ?n'?t|have ?n'?t|had ?n'?t|did ?n'?t|has not|have not|still (has|had) not)"
            r".{0,15}(arriv|reach|deliver|came|come|turn(ed)? up|show(ed)? up)",
            t,
        ):
            return ClaimType.NON_RECEIPT
        if re.search(r"in transit|still (on the way|coming)|not (yet )?arrived", t):
            return ClaimType.IN_TRANSIT
        if re.search(
            r"duplicate|charged (me )?twice|billed .{0,15}(twice|two times)"
            r"|(two|2|double|multiple) .{0,12}(charges|times|entries|debits)"
            r"|charged .{0,12}(twice|two times|multiple times)",
            t,
        ):
            return ClaimType.DUPLICATE
        if re.search(
            r"cancel(l)?ed?.{0,20}order|order.{0,20}cancel|cancelled.{0,20}(it|within)", t
        ):
            return ClaimType.CANCELLATION
        if re.search(
            r"fraud|didn'?t (make|authorize)|unauthori[sz]ed|don'?t recognis|"
            r"not mine|card with me|never (made|authori)",
            t,
        ):
            return ClaimType.UNAUTHORIZED
        return ClaimType.UNSPECIFIED


@dataclass(frozen=True)
class TrustedFacts:
    """Marker base for verified, authoritative facts. An adjudicator's decision
    is a pure function of a ``TrustedFacts`` instance and a ``ClaimType``."""

    def as_adjudicator_input(self, claim: ClaimType) -> dict:  # pragma: no cover - overridden
        raise NotImplementedError


@dataclass(frozen=True)
class DisputeFacts(TrustedFacts):
    """Verified dispute facts, from the bank's own ledger only."""

    amount: int
    merchant: str
    delivery_status: str
    prior_disputes_90d: int
    policy_auto_limit: int
    duplicate_confirmed: bool
    cancellation_confirmed: bool
    cardholder_present: bool

    @classmethod
    def from_ledger(cls, ledger: Mapping[str, object]) -> DisputeFacts:
        g = ledger.get
        return cls(
            amount=_as_int(g("amount", 0)),
            merchant=str(g("merchant", "unknown")),
            delivery_status=str(g("delivery_status", "unknown")),
            prior_disputes_90d=_as_int(g("prior_disputes_90d", 0)),
            policy_auto_limit=_as_int(g("policy_auto_limit", 50_000), 50_000),
            duplicate_confirmed=bool(g("duplicate_confirmed", False)),
            cancellation_confirmed=bool(g("cancellation_confirmed", False)),
            cardholder_present=bool(g("cardholder_present", True)),
        )

    def supports(self, claim: ClaimType) -> bool:
        """Is the claim backed by the bank's OWN trusted records? Computed purely
        from ``self`` -- ``claim`` only chooses which field to read."""
        if claim is ClaimType.NON_RECEIPT:
            return self.delivery_status in ("not_delivered", "returned", "lost")
        if claim is ClaimType.DUPLICATE:
            return self.duplicate_confirmed
        if claim is ClaimType.CANCELLATION:
            return self.cancellation_confirmed
        if claim is ClaimType.UNAUTHORIZED:
            return self.cardholder_present is False
        return False

    def as_adjudicator_input(self, claim: ClaimType) -> dict:
        """The exact JSON object handed to the adjudicator. Note: no prose -- only
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

    registration_status: str
    domain_age_days: int
    business_age_days: int
    prior_flags: int
    mcc_risk: str

    @classmethod
    def from_records(cls, records: Mapping[str, object]) -> KYBFacts:
        g = records.get
        return cls(
            registration_status=str(g("registration_status", "unverified")),
            domain_age_days=_as_int(g("domain_age_days", 0)),
            business_age_days=_as_int(g("business_age_days", 0)),
            prior_flags=_as_int(g("prior_flags", 0)),
            mcc_risk=str(g("mcc_risk", "unknown")),
        )

    def as_adjudicator_input(self, claim: ClaimType = ClaimType.UNSPECIFIED) -> dict:
        return {
            "registration_status": self.registration_status,
            "domain_age_days": self.domain_age_days,
            "business_age_days": self.business_age_days,
            "prior_flags": self.prior_flags,
            "mcc_risk": self.mcc_risk,
        }


# Fields on a ledger/records mapping that are NOT verified facts and must never
# be copied into a TrustedFacts. Kept as documentation + a guard for tests.
UNTRUSTED_LEDGER_KEYS = frozenset({"source"})


@dataclass
class _BoundaryReport:
    """Diagnostic used by tests: what crossed into the decision, and what didn't."""

    claim: ClaimType
    input_hash: str
    adjudicator_input_keys: list = field(default_factory=list)
