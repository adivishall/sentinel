"""An issuer: the system of record's side of a fact envelope.

A real deployment's issuers are other systems (the core ledger, the acquirer's KYB
registry, the authentication service); Sentinel only verifies. This class exists so that
the demo, the evaluation harness and an operator's tooling (``sentinel trust sign``) can
produce envelopes the same way. ``Issuer.ephemeral`` generates a key in memory that is
never written anywhere: the demo dataset and the evaluation fixtures are signed by one,
so their facts are VERIFIED_EXTERNAL *within that process* and nothing an API caller
sends can be.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.domain.enums import FactKind
from sentinel.trust import crypto
from sentinel.trust.facts import sign_fact
from sentinel.trust.keys import FACTS, TrustedKey


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@dataclass
class Issuer:
    issuer: str
    key: TrustedKey
    private: Ed25519PrivateKey = field(repr=False)
    validity: timedelta = timedelta(days=30)
    clock: Callable[[], datetime] = utc_now

    @classmethod
    def ephemeral(
        cls,
        issuer: str,
        *,
        scopes: Iterable[str] = ("*",),
        label: str = "",
        validity: timedelta = timedelta(days=30),
        clock: Callable[[], datetime] = utc_now,
    ) -> Issuer:
        private = crypto.generate()
        pub = crypto.public_raw(private)
        key = TrustedKey(
            key_id=crypto.key_id(pub),
            issuer=issuer,
            public_key=pub,
            purpose=FACTS,
            scopes=frozenset(scopes),
            not_before=clock() - timedelta(days=1),
            max_validity_days=max(1, validity.days),
            label=label or f"{issuer} (ephemeral key, generated in this process)",
        )
        return cls(issuer, key, private, validity, clock)

    @classmethod
    def from_private(
        cls,
        private: Ed25519PrivateKey,
        issuer: str,
        *,
        scopes: Iterable[str] = ("*",),
        not_before: datetime | None = None,
        validity: timedelta = timedelta(days=30),
        label: str = "",
    ) -> Issuer:
        pub = crypto.public_raw(private)
        key = TrustedKey(
            key_id=crypto.key_id(pub),
            issuer=issuer,
            public_key=pub,
            purpose=FACTS,
            scopes=frozenset(scopes),
            not_before=not_before or utc_now() - timedelta(days=1),
            max_validity_days=max(1, validity.days),
            label=label,
        )
        return cls(issuer, key, private, validity)

    def sign(
        self,
        kind: FactKind,
        record_id: str,
        payload: dict[str, Any],
        *,
        sequence: int = 1,
        effective_at: datetime | None = None,
        issued_at: datetime | None = None,
        validity: timedelta | None = None,
    ) -> dict[str, Any]:
        issued = issued_at or self.clock()
        return sign_fact(
            self.private,
            issuer=self.issuer,
            kind=kind,
            subject=kind.subject(record_id),
            payload=payload,
            sequence=sequence,
            issued_at=issued,
            effective_at=effective_at or issued,
            expires_at=issued + (validity or self.validity),
        )
