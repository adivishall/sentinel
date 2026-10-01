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
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from sentinel.domain.enums import ClaimType, EvidenceKind, TrustClass
from sentinel.domain.evidence import Claim, Evidence
from sentinel.domain.ids import content_hash
from sentinel.domain.vocab import RECORD_VALUES
from sentinel.security.claims import ClaimClassification, classify

# The largest amount or count a record may state: the range every JSON reader holds
# exactly, and SQLite's INTEGER (a larger value is malformed, not a very large refund).
MAX_AMOUNT = 2**53 - 1


def parse_int(value: object) -> int | None:
    """A ledger number as int, or ``None`` when it is not a finite number.

    Handles plain ints, finite floats, and numeric strings with commas or currency
    symbols ("₹50,000", "50,000.0")."""
    if isinstance(value, bool):  # bool is an int subclass; treat as not-a-number
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else None
    if isinstance(value, str):
        cleaned = re.sub(r"(?i)^\s*(rs\.?|inr|₹|\$)\s*", "", value.strip()).replace(",", "")
        try:
            return int(cleaned)
        except ValueError:
            try:
                f = float(cleaned)
            except ValueError:
                return None
            return int(f) if math.isfinite(f) else None
    return None


def parse_bool(value: object) -> bool | None:
    """A ledger flag as bool, or ``None`` when it is not a JSON boolean. ``bool("false")``
    is True in Python; a flag like ``duplicate_confirmed`` must never be read that way."""
    return value if isinstance(value, bool) else None


def record_problems(
    record: Mapping[str, object],
    numeric: tuple[str, ...],
    required: tuple[str, ...] = (),
    boolean: tuple[str, ...] = (),
    vocab: tuple[str, ...] = (),
) -> list[str]:
    """Why a trusted record cannot be used as-is: a required field missing, a numeric
    field that is present but not a finite, non-negative number, or a flag that is not a
    boolean. The workflows fail SAFE on any problem (human review): coercing ``"ten
    lakh"`` or ``-50000`` to a number, or ``"false"`` to True, would otherwise slip a
    request past a limit or a check."""
    out = [f"{k} missing" for k in required if k not in record]
    out += [  # null is allowed: the record does not say (reconciliation then holds)
        f"{k}={record[k]!r} is not a boolean"
        for k in boolean
        if k in record and record[k] is not None and parse_bool(record[k]) is None
    ]
    out += [  # a value the rules were not written for would make them silently false
        f"{k}={record[k]!r} is not one of {sorted(RECORD_VALUES[k])}"
        for k in vocab
        if k in record and (not isinstance(record[k], str) or record[k] not in RECORD_VALUES[k])
    ]
    for k in numeric:
        if k in record:
            v = parse_int(record[k])
            if v is None:
                out.append(f"{k}={record[k]!r} is not a number")
            elif v < 0:
                out.append(f"{k}={v} is negative")
            elif v > MAX_AMOUNT:
                out.append(f"{k}={v} is out of range")
    return out


def _flag(record: Mapping[str, object], key: str, default: bool) -> bool | None:
    """A ledger flag: the documented default when absent, None when the record states it
    as unknown (null). A non-boolean is rejected by ``record_problems``."""
    if key not in record:
        return default
    v = record[key]
    return None if v is None else parse_bool(v)


def as_int(value: object, default: int = 0) -> int:
    """Coerce a ledger value to int, or ``default``. Only safe after ``record_problems``
    has rejected the record: on its own a coerced 0 would pass a limit check."""
    v = parse_int(value)
    return default if v is None else v


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
    """Base for the record an adjudicator decides on. An adjudicator's decision is a pure
    function of a ``TrustedFacts`` instance and a ``ClaimType``; how far the record itself
    can be trusted is its ``FactProvenance`` (``sentinel.trust``), which the workflow
    computes and ``to_evidence`` receives as ``trust``."""

    SOURCE: ClassVar[str] = "institution_records"
    KIND: ClassVar[EvidenceKind] = EvidenceKind.LEDGER_FACT
    TRUST: ClassVar[TrustClass] = TrustClass.TRUSTED_INTERNAL

    def to_evidence(
        self, prefix: str = "EV", trust: TrustClass | None = None
    ) -> tuple[Evidence, ...]:
        """Render every field as ``Evidence``: VERIFIED facts when the record's provenance
        is trusted, CLAIMED (``UNVERIFIED_RECORD``) otherwise -- a record Sentinel could
        not establish is a claim about the records, not a record."""
        t = trust or self.TRUST
        out = []
        for i, f in enumerate(dataclasses.fields(self), start=1):
            eid, value = f"{prefix}-{i:03d}", getattr(self, f.name)
            if t.is_trusted:
                out.append(Evidence.fact(eid, self.SOURCE, f.name, value, kind=self.KIND, trust=t))
            else:
                out.append(
                    Evidence.claim(
                        eid,
                        self.SOURCE,
                        f.name,
                        value,
                        kind=self.KIND,
                        trust=t,
                        note="unverified record field",
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
    # A policy parameter, not a ledger fact: never read from a ledger (a caller could
    # otherwise move the limit that the over-limit risk factor is measured against).
    policy_auto_limit: int = 50_000
    # None = the record does not say. A claim that depends on an unknown flag is held
    # for a human (INSUFFICIENT), never decided on an assumed value.
    duplicate_confirmed: bool | None = False
    cancellation_confirmed: bool | None = False
    cardholder_present: bool | None = True
    refund_state: str = "none"  # none | pending | refunded  (has money already gone back?)
    transaction_status: str = "settled"  # settled | pending | reversed
    merchant_response: str = "none"  # none | accepted | contested
    auth_strength: str = "unknown"  # none | password | otp | biometric (from the switch record)
    customer_tenure_days: int = 0

    SOURCE: ClassVar[str] = "payment_ledger"
    BOOLEAN: ClassVar[tuple[str, ...]] = (
        "duplicate_confirmed",
        "cancellation_confirmed",
        "cardholder_present",
    )
    NUMERIC: ClassVar[tuple[str, ...]] = (
        "amount",
        "prior_disputes_90d",
        "customer_tenure_days",
    )

    @classmethod
    def problems(cls, ledger: Mapping[str, object]) -> list[str]:
        return record_problems(
            ledger,
            cls.NUMERIC,
            required=("amount",),
            boolean=cls.BOOLEAN,
            vocab=(
                "delivery_status",
                "refund_state",
                "transaction_status",
                "merchant_response",
                "auth_strength",
            ),
        )

    @classmethod
    def from_ledger(cls, ledger: Mapping[str, object]) -> DisputeFacts:
        g = ledger.get
        return cls(
            amount=as_int(g("amount", 0)),
            merchant=str(g("merchant", "unknown")),
            delivery_status=str(g("delivery_status", "unknown")),
            prior_disputes_90d=as_int(g("prior_disputes_90d", 0)),
            duplicate_confirmed=_flag(ledger, "duplicate_confirmed", False),
            cancellation_confirmed=_flag(ledger, "cancellation_confirmed", False),
            cardholder_present=_flag(ledger, "cardholder_present", True),
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

    def unknown(self, claim: ClaimType) -> bool:
        """Does the record leave the claim's field unstated?"""
        mapping = self.CLAIM_FIELDS.get(claim)
        return mapping is not None and getattr(self, mapping[0]) is None

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

    @classmethod
    def problems(cls, records: Mapping[str, object]) -> list[str]:
        return record_problems(
            records,
            ("domain_age_days", "business_age_days", "prior_flags"),
            vocab=("registration_status", "mcc_risk"),
        )

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
