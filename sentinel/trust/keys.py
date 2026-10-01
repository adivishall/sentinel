"""The trust store: which public keys the operator trusts, for what, and until when.

A trust store is deployment configuration supplied by the operator (``SENTINEL_TRUST_STORE``
or ``--trust-store``). It must not live where the data it verifies lives: an attacker who
can write the record store or the policy directory must not also be able to add a key.

Each entry binds a key to an **issuer**, exactly one **purpose** (``facts`` or
``policy-release``: key separation, so a leaked fact-issuer key can never sign a policy
release) and **scopes** within the purpose (fact kinds, or policy ids / ``*``).
Rotation and revocation are different on purpose:

- **retired** (``not_after`` set): the key stopped signing. Statements it signed before
  ``not_after`` stay valid until they expire. This assumes the private key was destroyed
  on retirement; if it may have leaked, revoke instead.
- **revoked** (``revoked_at`` set): the key is treated as compromised. Everything it ever
  signed is REVOKED, whatever the statement's own ``issued_at`` says -- a compromised key
  can backdate.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel.domain.enums import FactKind
from sentinel.trust import crypto
from sentinel.trust.canonical import CanonicalError, strict_loads

FACTS = "facts"
POLICY_RELEASE = "policy-release"
AUDIT_CHECKPOINT = "audit-checkpoint"
# one purpose per key: a fact issuer cannot sign a policy release or an audit checkpoint
PURPOSES = frozenset({FACTS, POLICY_RELEASE, AUDIT_CHECKPOINT})
FORMAT = "sentinel.trust-store/1"
DEFAULT_MAX_VALIDITY_DAYS = 30

_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ISSUER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class TrustStoreError(ValueError):
    """The trust store is malformed; loading fails closed (nothing is trusted)."""


def parse_ts(value: object, what: str) -> datetime:
    """Exactly ``YYYY-MM-DDTHH:MM:SSZ`` (UTC). One format, so no two spellings of an
    instant compare differently as strings or parse to different times."""
    if not isinstance(value, str) or not _TS.match(value):
        raise ValueError(f"{what} must be YYYY-MM-DDTHH:MM:SSZ, got {value!r}")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def format_ts(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    issuer: str
    public_key: bytes
    purpose: str
    scopes: frozenset[str]
    not_before: datetime
    not_after: datetime | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    max_validity_days: int = DEFAULT_MAX_VALIDITY_DAYS
    label: str = ""

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None

    def allows(self, purpose: str, scope: str) -> bool:
        return purpose == self.purpose and (scope in self.scopes or "*" in self.scopes)

    def to_json(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "issuer": self.issuer,
            "public_key": crypto.b64e(self.public_key),
            "purpose": self.purpose,
            "scopes": sorted(self.scopes),
            "not_before": format_ts(self.not_before),
            "not_after": format_ts(self.not_after) if self.not_after else None,
            "revoked_at": format_ts(self.revoked_at) if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
            "max_validity_days": self.max_validity_days,
            "label": self.label,
        }


_KEY_FIELDS = frozenset(
    {
        "key_id",
        "issuer",
        "public_key",
        "purpose",
        "scopes",
        "not_before",
        "not_after",
        "revoked_at",
        "revocation_reason",
        "max_validity_days",
        "label",
    }
)


def _key_from_json(d: object, where: str) -> TrustedKey:
    if not isinstance(d, dict):
        raise TrustStoreError(f"{where}: a key entry must be an object")
    extra = sorted(set(d) - _KEY_FIELDS)
    if extra:
        raise TrustStoreError(f"{where}: unknown fields {extra}")
    try:
        pub = crypto.b64d(d["public_key"])
        if len(pub) != crypto.PUBLIC_KEY_BYTES:
            raise ValueError("an Ed25519 public key is 32 bytes")
        kid = str(d["key_id"])
        if kid != crypto.key_id(pub):
            raise ValueError(f"key_id {kid} is not the fingerprint of its public key")
        issuer = str(d["issuer"])
        if not _ISSUER.match(issuer):
            raise ValueError(f"issuer {issuer!r} is not a lowercase identifier")
        purpose = str(d["purpose"])
        if purpose not in PURPOSES:
            raise ValueError(f"purpose must be one of {sorted(PURPOSES)}")
        scopes = frozenset(str(s) for s in d["scopes"])
        if not scopes:
            raise ValueError("scopes must not be empty")
        if purpose == FACTS:
            bad = scopes - {k.value for k in FactKind} - {"*"}
            if bad:
                raise ValueError(f"unknown fact kinds {sorted(bad)}")
        validity = int(d.get("max_validity_days", DEFAULT_MAX_VALIDITY_DAYS))
        if not 1 <= validity <= 366:
            raise ValueError("max_validity_days must be 1..366")
        key = TrustedKey(
            key_id=kid,
            issuer=issuer,
            public_key=pub,
            purpose=purpose,
            scopes=scopes,
            not_before=parse_ts(d["not_before"], "not_before"),
            not_after=parse_ts(d["not_after"], "not_after") if d.get("not_after") else None,
            revoked_at=parse_ts(d["revoked_at"], "revoked_at") if d.get("revoked_at") else None,
            revocation_reason=(
                str(d["revocation_reason"]) if d.get("revocation_reason") is not None else None
            ),
            max_validity_days=validity,
            label=str(d.get("label", ""))[:200],
        )
    except (KeyError, TypeError, ValueError) as e:
        raise TrustStoreError(f"{where}: {e}") from None
    if key.not_after is not None and key.not_after < key.not_before:
        raise TrustStoreError(f"{where}: not_after precedes not_before")
    return key


@dataclass(frozen=True)
class TrustStore:
    keys: dict[str, TrustedKey] = field(default_factory=dict)
    origin: str = "empty"  # where it was loaded from, for the system report

    @classmethod
    def empty(cls) -> TrustStore:
        return cls()

    @classmethod
    def from_json(cls, doc: object, *, origin: str = "inline") -> TrustStore:
        if not isinstance(doc, dict) or doc.get("format") != FORMAT:
            raise TrustStoreError(f"a trust store is an object with format {FORMAT!r}")
        extra = sorted(set(doc) - {"format", "keys"})
        if extra:
            raise TrustStoreError(f"trust store: unknown fields {extra}")
        entries = doc.get("keys")
        if not isinstance(entries, list):
            raise TrustStoreError("trust store: keys must be a list")
        keys: dict[str, TrustedKey] = {}
        for i, e in enumerate(entries):
            k = _key_from_json(e, f"keys[{i}]")
            if k.key_id in keys:
                raise TrustStoreError(f"keys[{i}]: duplicate key_id {k.key_id}")
            keys[k.key_id] = k
        return cls(keys, origin)

    @classmethod
    def load(cls, path: str | Path) -> TrustStore:
        p = Path(path)
        try:
            doc = strict_loads(p.read_bytes())
        except (OSError, CanonicalError) as e:
            raise TrustStoreError(f"unreadable trust store {p}: {e}") from None
        return cls.from_json(doc, origin=str(p))

    def to_json(self) -> dict[str, Any]:
        return {"format": FORMAT, "keys": [k.to_json() for k in self.keys.values()]}

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=2) + "\n"

    def with_key(self, key: TrustedKey) -> TrustStore:
        if key.key_id in self.keys and self.keys[key.key_id] != key:
            raise TrustStoreError(f"{key.key_id} is already trusted with other settings")
        return replace(self, keys={**self.keys, key.key_id: key})

    def get(self, kid: str) -> TrustedKey | None:
        return self.keys.get(kid)

    def summary(self) -> list[dict[str, Any]]:
        """What is trusted, for ``/v1/system`` and ``sentinel trust list`` (no key bytes)."""
        return [
            {
                "key_id": k.key_id,
                "issuer": k.issuer,
                "purpose": k.purpose,
                "scopes": sorted(k.scopes),
                "status": "revoked" if k.revoked else "retired" if k.not_after else "active",
                "label": k.label,
            }
            for k in self.keys.values()
        ]
