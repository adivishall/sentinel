"""Tamper-evident audit trail: hash_n = SHA256(event_n || hash_(n-1))."""

from sentinel.audit.chain import (
    AuditChain,
    AuditEvent,
    ChainVerification,
    JsonlBackend,
    MemoryBackend,
)

__all__ = ["AuditChain", "AuditEvent", "ChainVerification", "JsonlBackend", "MemoryBackend"]
