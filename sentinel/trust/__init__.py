"""Trusted fact provenance: why Sentinel may trust the facts behind a decision.

- ``canonical`` -- one byte string per signable value; strict parsing.
- ``crypto`` -- Ed25519 via pyca/cryptography (the only import of it).
- ``keys`` -- the operator's trust store: issuers, purposes, scopes, rotation, revocation.
- ``facts`` -- signed fact envelopes and their verification (with anti-rollback).
- ``issuer`` -- the signing side, for the demo, the evaluation and operator tooling.

The provenance of unsigned facts is decided here too, so that the only code that can
produce each ``ProvenanceStatus`` is in this package.
"""

from __future__ import annotations

from collections.abc import Mapping

from sentinel.domain.enums import FactKind, ProvenanceStatus
from sentinel.domain.ids import content_hash
from sentinel.domain.provenance import RECORD_STORE, REQUEST_BODY, FactProvenance
from sentinel.trust.canonical import CanonicalError, digest


def record_digest(record: Mapping[str, object]) -> str:
    """SHA-256 of a record as used: its canonical form when it has one (so a verified
    statement's digest is its signed ``payload_sha256``), otherwise a stable JSON hash of
    what was there (a request body may hold values canonical JSON refuses)."""
    try:
        return digest(dict(record))
    except CanonicalError:
        return content_hash(dict(record), length=64)


def local(kind: FactKind, record_id: str, record: Mapping[str, object]) -> FactProvenance:
    """Read by id from Sentinel's own record store: trusted because of where it is kept,
    not because anything proves it (a DB-write attacker could change it)."""
    return FactProvenance(
        ProvenanceStatus.TRUSTED_LOCAL,
        kind,
        kind.subject(record_id),
        RECORD_STORE,
        record_digest(record),
        "read by id from the record store (unsigned)",
    )


def untrusted(kind: FactKind, record_id: str, record: Mapping[str, object]) -> FactProvenance:
    """Supplied in a request body, unsigned: a claim about the records, not a record."""
    return FactProvenance(
        ProvenanceStatus.UNTRUSTED,
        kind,
        kind.subject(record_id),
        REQUEST_BODY,
        record_digest(record),
        "supplied in the request, unsigned: nothing establishes its source",
    )
