"""Evidence: the unit of explanation for every authoritative decision.

The core distinction Sentinel enforces is *claim* versus *verified fact*:

    EV-1001  ledger_fact   payment_ledger   delivery_status = DELIVERED       TRUSTED
    EV-1002  user_claim    cardholder       delivery_status = NEVER_RECEIVED  UNTRUSTED

An ``EvidenceSet`` can only ever answer questions from its *verified* members.
Claims are kept for explainability and contradiction reporting; they carry no
authority. Model output is evidence of kind ``MODEL_ASSERTION`` with
``MODEL_GENERATED`` trust -- it is never VERIFIED.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from sentinel.domain.enums import (
    ClaimType,
    EvidenceKind,
    EvidenceStatus,
    EvidenceVerdict,
    TrustClass,
)
from sentinel.domain.ids import content_hash

Scalar = str | int | float | bool | None


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    kind: EvidenceKind
    source: str
    trust: TrustClass
    field: str
    value: Scalar
    status: EvidenceStatus
    content_hash: str = ""
    note: str = ""

    def __post_init__(self) -> None:
        # Structural guarantee: only trusted sources can be VERIFIED.
        if self.status is EvidenceStatus.VERIFIED and not self.trust.is_trusted:
            raise ValueError(
                f"evidence {self.evidence_id}: {self.trust} sources cannot be VERIFIED"
            )
        if not self.content_hash:
            object.__setattr__(
                self, "content_hash", content_hash({"f": self.field, "v": self.value})
            )

    @property
    def is_verified(self) -> bool:
        return self.status is EvidenceStatus.VERIFIED and self.trust.is_trusted

    @staticmethod
    def fact(
        evidence_id: str,
        source: str,
        field: str,
        value: Scalar,
        *,
        kind: EvidenceKind = EvidenceKind.LEDGER_FACT,
        trust: TrustClass = TrustClass.TRUSTED_INTERNAL,
        note: str = "",
    ) -> Evidence:
        return Evidence(
            evidence_id, kind, source, trust, field, value, EvidenceStatus.VERIFIED, note=note
        )

    @staticmethod
    def claim(
        evidence_id: str,
        source: str,
        field: str,
        value: Scalar,
        *,
        kind: EvidenceKind = EvidenceKind.USER_CLAIM,
        trust: TrustClass = TrustClass.USER_CONTROLLED,
        note: str = "",
    ) -> Evidence:
        if trust.is_trusted:
            raise ValueError("a claim cannot come from a trusted source; use Evidence.fact")
        return Evidence(
            evidence_id, kind, source, trust, field, value, EvidenceStatus.CLAIMED, note=note
        )


@dataclass(frozen=True)
class Claim:
    """A structured reading of what an untrusted party asserts. Produced only by
    the claim classifier over ``UntrustedText``; carries the trust of its source."""

    claim_type: ClaimType
    source: str
    trust: TrustClass
    text_hash: str
    confidence: float = 1.0
    kind: str = "claim"  # claim | non_claim | abstain  (see security/claims.py)
    signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.trust.is_trusted:
            raise ValueError("a Claim is by definition untrusted")

    @property
    def abstained(self) -> bool:
        """The classifier could not read a claim: reconciliation fails safe to a human."""
        return self.kind == "abstain"


@dataclass(frozen=True)
class Contradiction:
    claim_evidence_id: str
    fact_evidence_id: str
    field: str
    claimed: Scalar
    recorded: Scalar
    impact: str = "claim unsupported"


@dataclass(frozen=True)
class EvidenceSet:
    items: tuple[Evidence, ...] = field(default_factory=tuple)

    def __iter__(self) -> Iterator[Evidence]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    @classmethod
    def of(cls, items: Iterable[Evidence]) -> EvidenceSet:
        return cls(tuple(items))

    def add(self, *more: Evidence) -> EvidenceSet:
        return EvidenceSet(self.items + tuple(more))

    def verified(self) -> tuple[Evidence, ...]:
        return tuple(e for e in self.items if e.is_verified)

    def claims(self) -> tuple[Evidence, ...]:
        return tuple(e for e in self.items if not e.is_verified)

    def verified_value(self, field: str) -> Scalar:
        """The trusted value of a field, or ``None`` when no verified evidence
        carries it. Claims are *never* consulted here -- this is the only
        accessor the decision path uses."""
        for e in self.items:
            if e.field == field and e.is_verified:
                return e.value
        return None

    def ids(self) -> tuple[str, ...]:
        return tuple(e.evidence_id for e in self.items)


@dataclass(frozen=True)
class Reconciliation:
    """Result of checking a claim against trusted evidence."""

    claim: Claim | None
    verdict: EvidenceVerdict
    evidence: EvidenceSet
    contradictions: tuple[Contradiction, ...] = field(default_factory=tuple)
    explanation: str = ""

    @property
    def supports_claim(self) -> bool:
        return self.verdict.supports
