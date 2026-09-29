"""Signed fact envelopes: how an issuer's record reaches a decision with proof of origin.

    source record -> canonical payload -> SHA-256 -> header -> Ed25519 signature
                  -> envelope -> (any transport) -> verify -> VERIFIED_EXTERNAL facts

An envelope is a JSON object::

    {"format": "sentinel.fact/1", "issuer": "core-ledger", "key_id": "ed25519:...",
     "kind": "dispute_ledger", "subject": "dispute:DSP-000123", "sequence": 7,
     "issued_at": "2026-09-29T05:00:00Z", "effective_at": "2026-09-29T04:59:00Z",
     "expires_at": "2026-10-06T05:00:00Z", "payload_sha256": "<hex>",
     "payload": {...record fields...}, "signature": "<base64url>"}

The signature covers ``b"sentinel.fact/1\\n" + canonical_json(header)``, where the header
is every field except ``payload`` and ``signature``; the payload is bound through
``payload_sha256``. The domain prefix means no other Sentinel signature (a policy
release) can be replayed as a fact.

**What a VERIFIED_EXTERNAL result proves:** the holder of a private key that the
operator's trust store assigns to this issuer, for this kind of fact, signed exactly
this payload about exactly this subject, within the key's validity window; the statement
has not expired; and it is not older than a statement for the same subject that this
deployment already acted on. **What it does not prove:** that the issuer's record is
*true*, that the issuer has not since issued a newer statement Sentinel has not seen
(expiry bounds that window), or anything about a key the operator should not have
trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel.domain.enums import FactKind, ProvenanceStatus
from sentinel.domain.ids import content_hash
from sentinel.domain.provenance import FactProvenance
from sentinel.trust import crypto
from sentinel.trust.canonical import CanonicalError, canonical_json, digest, sha256_hex
from sentinel.trust.keys import FACTS, TrustStore, format_ts, parse_ts

FORMAT = "sentinel.fact/1"
DOMAIN = b"sentinel.fact/1\n"
MAX_CLOCK_SKEW = timedelta(minutes=5)
HEADER_FIELDS = (
    "format",
    "issuer",
    "key_id",
    "kind",
    "subject",
    "sequence",
    "issued_at",
    "effective_at",
    "expires_at",
    "payload_sha256",
)
ENVELOPE_FIELDS = frozenset(HEADER_FIELDS) | {"payload", "signature"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# <kind prefix>:<record id>; the id becomes a decision's subject, so it is bounded
_SUBJECT = re.compile(r"^[a-z]+:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class SequenceLedger(Protocol):
    """The highest sequence this deployment has acted on, per issuer and subject."""

    def last(self, issuer: str, subject: str) -> tuple[int, str] | None: ...

    def advance(self, issuer: str, subject: str, sequence: int, envelope_digest: str) -> None: ...


class MemorySequences:
    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], tuple[int, str]] = {}

    def last(self, issuer: str, subject: str) -> tuple[int, str] | None:
        return self._seen.get((issuer, subject))

    def advance(self, issuer: str, subject: str, sequence: int, envelope_digest: str) -> None:
        cur = self._seen.get((issuer, subject))
        if cur is None or sequence > cur[0]:
            self._seen[(issuer, subject)] = (sequence, envelope_digest)


@dataclass(frozen=True)
class FactVerification:
    provenance: FactProvenance
    # The envelope's payload when it could be read (for display and for a stricter
    # outcome); it supports a decision only when provenance.status is VERIFIED_EXTERNAL.
    payload: dict[str, Any] | None

    @property
    def verified(self) -> bool:
        return self.provenance.status is ProvenanceStatus.VERIFIED_EXTERNAL


def sign_fact(
    private: Ed25519PrivateKey,
    *,
    issuer: str,
    kind: FactKind,
    subject: str,
    payload: dict[str, Any],
    sequence: int,
    issued_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    header = {
        "format": FORMAT,
        "issuer": issuer,
        "key_id": crypto.key_id(crypto.public_raw(private)),
        "kind": kind.value,
        "subject": subject,
        "sequence": sequence,
        "issued_at": format_ts(issued_at),
        "effective_at": format_ts(effective_at),
        "expires_at": format_ts(expires_at),
        "payload_sha256": digest(payload),
    }
    sig = crypto.sign(private, DOMAIN + canonical_json(header))
    return {**header, "payload": payload, "signature": crypto.b64e(sig)}


def envelope_digest(doc: dict[str, Any]) -> str:
    """Identifies one signed statement: SHA-256 of its canonical header."""
    return sha256_hex(canonical_json({k: doc[k] for k in HEADER_FIELDS}))


def verify_fact(
    doc: object,
    *,
    trust: TrustStore,
    now: datetime,
    kind: FactKind,
    subject: str | None = None,
    sequences: SequenceLedger | None = None,
) -> FactVerification:
    """Verify an envelope for a decision about ``subject`` (or, when ``subject`` is None,
    about whatever subject of ``kind`` the envelope names). Fails closed: every check is
    a reason to refuse, and only a statement that passes all of them is
    VERIFIED_EXTERNAL."""
    d = doc if isinstance(doc, dict) else {}
    named_subject = d.get("subject") if isinstance(d.get("subject"), str) else None
    raw_issuer, raw_kid = d.get("issuer"), d.get("key_id")
    issuer: str = raw_issuer if isinstance(raw_issuer, str) else "unknown"
    kid: str | None = raw_kid if isinstance(raw_kid, str) else None
    payload = d.get("payload") if isinstance(d.get("payload"), dict) else None
    env_digest: str | None = None

    def result(status: ProvenanceStatus, reason: str) -> FactVerification:
        try:
            pdig = digest(payload) if payload is not None else content_hash(None, 64)
        except CanonicalError:
            pdig = content_hash(payload, 64)
        seq = d.get("sequence")
        return FactVerification(
            FactProvenance(
                status=status,
                kind=kind,
                subject=subject or named_subject or f"{kind.subject_prefix}:?",
                source=issuer,
                payload_digest=pdig,
                reason=reason,
                key_id=kid,
                envelope_digest=env_digest,
                sequence=seq if isinstance(seq, int) and not isinstance(seq, bool) else None,
                issued_at=d.get("issued_at") if isinstance(d.get("issued_at"), str) else None,
                effective_at=(
                    d.get("effective_at") if isinstance(d.get("effective_at"), str) else None
                ),
                expires_at=d.get("expires_at") if isinstance(d.get("expires_at"), str) else None,
            ),
            payload,
        )

    invalid = ProvenanceStatus.INVALID
    # ---- 1. shape ----------------------------------------------------------------------
    if not isinstance(doc, dict):
        return result(invalid, "the envelope is not a JSON object")
    missing = sorted(ENVELOPE_FIELDS - set(d))
    extra = sorted(set(d) - ENVELOPE_FIELDS)
    if missing or extra:
        return result(invalid, f"malformed envelope (missing {missing}, unknown {extra})")
    if d["format"] != FORMAT:
        return result(invalid, f"unsupported envelope format {d['format']!r}")
    if payload is None:
        return result(invalid, "the payload is not an object")
    seq = d["sequence"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return result(invalid, "sequence is not a non-negative integer")
    for f in ("issuer", "key_id", "kind", "subject", "signature", "payload_sha256"):
        if not isinstance(d[f], str):
            return result(invalid, f"{f} is not a string")
    try:
        header_bytes = canonical_json({k: d[k] for k in HEADER_FIELDS})
        payload_digest = digest(payload)
        issued = parse_ts(d["issued_at"], "issued_at")
        effective = parse_ts(d["effective_at"], "effective_at")
        expires = parse_ts(d["expires_at"], "expires_at")
    except (CanonicalError, ValueError) as e:
        return result(invalid, f"malformed envelope: {e}")
    env_digest = sha256_hex(header_bytes)
    # ---- 2. payload bound to the header -------------------------------------------------
    if not _HEX64.match(d["payload_sha256"]) or payload_digest != d["payload_sha256"]:
        return result(invalid, "the payload does not match its signed digest (altered)")
    # ---- 3. what the statement is about -----------------------------------------------
    if d["kind"] != kind.value:
        return result(invalid, f"a {d['kind']!r} statement cannot be used as {kind.value}")
    if not _SUBJECT.match(d["subject"]):
        return result(invalid, "malformed subject (expected <kind>:<record id>, id <= 64 chars)")
    if not d["subject"].startswith(kind.subject_prefix + ":"):
        return result(invalid, f"subject {d['subject']!r} is not a {kind.subject_prefix}")
    if subject is not None and d["subject"] != subject:
        return result(invalid, f"signed for {d['subject']}, not {subject}")
    # ---- 4. who may have signed it ------------------------------------------------------
    key = trust.get(d["key_id"])
    if key is None:
        return result(invalid, f"unknown signer {d['key_id']} (not in the trust store)")
    if key.issuer != d["issuer"]:
        return result(invalid, f"key {key.key_id} belongs to {key.issuer}, not {d['issuer']}")
    if not key.allows(FACTS, kind.value):
        return result(invalid, f"key {key.key_id} is not trusted to sign {kind.value} facts")
    # ---- 5. the signature --------------------------------------------------------------
    try:
        sig = crypto.b64d(d["signature"])
    except ValueError as e:
        return result(invalid, f"malformed signature: {e}")
    if not crypto.verify(key.public_key, sig, DOMAIN + header_bytes):
        return result(invalid, "the signature does not verify")
    # ---- 6. revocation: a compromised key can backdate, so issued_at does not help -------
    if key.revoked:
        return result(
            ProvenanceStatus.REVOKED,
            f"signed by {key.key_id}, revoked {format_ts(key.revoked_at)}"  # type: ignore[arg-type]
            + (f" ({key.revocation_reason})" if key.revocation_reason else ""),
        )
    # ---- 7. the key's validity window (rotation) -----------------------------------------
    if issued < key.not_before:
        return result(invalid, "signed before the key's validity began")
    if key.not_after is not None and issued > key.not_after:
        return result(invalid, "signed after the key was retired")
    # ---- 8. time ------------------------------------------------------------------------
    if issued > now + MAX_CLOCK_SKEW:
        return result(invalid, "issued in the future")
    if effective > issued:
        return result(invalid, "effective after it was issued")
    if expires <= issued:
        return result(invalid, "expires before it was issued")
    if expires - issued > timedelta(days=key.max_validity_days):
        return result(invalid, f"valid for longer than the key allows ({key.max_validity_days}d)")
    if now >= expires:
        return result(ProvenanceStatus.EXPIRED, f"expired {d['expires_at']}")
    # ---- 9. rollback: never act on an older statement than one already acted on ----------
    if sequences is not None:
        last = sequences.last(d["issuer"], d["subject"])
        if last is not None:
            last_seq, last_digest = last
            if seq < last_seq:
                return result(
                    ProvenanceStatus.SUPERSEDED,
                    f"sequence {seq} is older than {last_seq}, already acted on",
                )
            if seq == last_seq and env_digest != last_digest:
                return result(
                    invalid, f"a different statement with the same sequence {seq} (equivocation)"
                )
    return result(
        ProvenanceStatus.VERIFIED_EXTERNAL,
        f"signed by {d['issuer']} ({key.key_id}), sequence {seq}",
    )
