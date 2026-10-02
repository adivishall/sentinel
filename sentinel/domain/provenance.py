"""Fact provenance: what establishes the facts an authoritative decision was made on.

Every decision carries one ``FactProvenance`` for its primary record (the dispute ledger,
the acquirer record, the transaction, the login session). It is computed by the workflow
from how the facts arrived -- read by id from the record store, supplied in a request
body, or carried by a signed envelope that ``sentinel.trust`` verified -- and it binds the
decision to the exact payload used (``payload_digest``). Nothing in a request can set it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.domain.enums import FactKind, ProvenanceStatus, TrustClass

# Where unsigned facts came from, as recorded in ``FactProvenance.source``.
RECORD_STORE = "record_store"
REQUEST_BODY = "request_body"


@dataclass(frozen=True)
class FactProvenance:
    status: ProvenanceStatus
    kind: FactKind
    subject: str  # e.g. dispute:DSP-000001
    source: str  # the issuer for a signed envelope; record_store / request_body otherwise
    payload_digest: str  # SHA-256 of the facts actually used
    reason: str
    key_id: str | None = None
    envelope_digest: str | None = None  # identifies the exact signed statement
    sequence: int | None = None
    issued_at: str | None = None
    effective_at: str | None = None
    expires_at: str | None = None

    @property
    def evidence_trust(self) -> TrustClass:
        """The trust class a record field carries as evidence. A record Sentinel could not
        establish is never rendered as a trusted fact."""
        if self.status is ProvenanceStatus.VERIFIED_EXTERNAL:
            return TrustClass.VERIFIED_EXTERNAL
        if self.status is ProvenanceStatus.TRUSTED_LOCAL:
            return TrustClass.TRUSTED_INTERNAL
        return TrustClass.UNVERIFIED_RECORD

    def audit_detail(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "kind": self.kind.value,
            "subject": self.subject,
            "source": self.source,
            "key_id": self.key_id,
            "envelope_digest": self.envelope_digest,
            "payload_digest": self.payload_digest,
            "sequence": self.sequence,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FactProvenance:
        return cls(
            ProvenanceStatus(d["status"]),
            FactKind(d["kind"]),
            d["subject"],
            d["source"],
            d["payload_digest"],
            d.get("reason", ""),
            d.get("key_id"),
            d.get("envelope_digest"),
            d.get("sequence"),
            d.get("issued_at"),
            d.get("effective_at"),
            d.get("expires_at"),
        )
