"""Hash-chained audit events.

Each event carries the hash of the previous event; its own hash covers its
content *and* that previous hash. Modifying, deleting or reordering any
record breaks every hash after it, and ``verify`` names the first bad record.

Privacy: the chain stores hashes of untrusted content, never the content. A
defensive ``redact`` pass hashes any stray raw-text field before it is written.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Protocol

from sentinel.domain.ids import content_hash, new_id, now_iso

GENESIS = "0" * 64
_RAW_TEXT_KEYS = frozenset(
    {"span", "text", "narrative", "submission", "document", "prompt", "rationale"}
)


def redact(obj: object) -> object:
    """Hash any raw-text field so no untrusted prose is ever persisted."""
    if isinstance(obj, dict):
        out: dict[str, object] = {}
        for k, v in obj.items():
            if k in _RAW_TEXT_KEYS and isinstance(v, str):
                out[f"{k}_sha256"] = content_hash(v)
                out[f"{k}_len"] = len(v)
            else:
                out[str(k)] = redact(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def chain_hash(body: dict[str, object], previous_hash: str) -> str:
    return hashlib.sha256((canonical(body) + previous_hash).encode("utf-8")).hexdigest()


def _list(v: object) -> list[object]:
    return list(v) if isinstance(v, (list, tuple)) else []


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    sequence: int
    timestamp: str
    decision_id: str | None
    previous_hash: str
    event_hash: str
    actor: str
    workflow: str
    subject_id: str | None
    risk_score: int
    risk_level: str
    policy_id: str | None
    policy_version: int | None
    capability: str | None
    action: str
    evidence_ids: tuple[str, ...]
    security_severity: str
    input_hash: str
    case_id: str | None = None
    kind: str = "decision"  # decision | case | human_decision | system
    detail: dict[str, object] = field(default_factory=dict)

    def body(self) -> dict[str, object]:
        """Everything the hash covers (all fields except the two hashes)."""
        d = {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "decision_id": self.decision_id,
            "actor": self.actor,
            "workflow": self.workflow,
            "subject_id": self.subject_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "capability": self.capability,
            "action": self.action,
            "evidence_ids": list(self.evidence_ids),
            "security_severity": self.security_severity,
            "input_hash": self.input_hash,
            "case_id": self.case_id,
            "kind": self.kind,
            "detail": self.detail,
        }
        return d

    def to_dict(self) -> dict[str, object]:
        d = self.body()
        d["previous_hash"] = self.previous_hash
        d["event_hash"] = self.event_hash
        return d

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> AuditEvent:
        return cls(
            event_id=str(d["event_id"]),
            sequence=int(d["sequence"]),  # type: ignore[call-overload]
            timestamp=str(d["timestamp"]),
            decision_id=(str(d["decision_id"]) if d.get("decision_id") is not None else None),
            previous_hash=str(d["previous_hash"]),
            event_hash=str(d["event_hash"]),
            actor=str(d["actor"]),
            workflow=str(d["workflow"]),
            subject_id=(str(d["subject_id"]) if d.get("subject_id") is not None else None),
            risk_score=int(d.get("risk_score", 0)),  # type: ignore[call-overload]
            risk_level=str(d.get("risk_level", "LOW")),
            policy_id=(str(d["policy_id"]) if d.get("policy_id") is not None else None),
            policy_version=(int(d["policy_version"]) if d.get("policy_version") is not None else None),  # type: ignore[call-overload]
            capability=(str(d["capability"]) if d.get("capability") is not None else None),
            action=str(d["action"]),
            evidence_ids=tuple(str(x) for x in _list(d.get("evidence_ids"))),
            security_severity=str(d.get("security_severity", "NONE")),
            input_hash=str(d.get("input_hash", "")),
            case_id=(str(d["case_id"]) if d.get("case_id") is not None else None),
            kind=str(d.get("kind", "decision")),
            detail=dict(d.get("detail", {})),  # type: ignore[call-overload]
        )


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    length: int
    problems: tuple[str, ...]
    first_bad_sequence: int | None = None
    head_hash: str = GENESIS


class AuditBackend(Protocol):
    def append(self, record: dict[str, object]) -> None: ...
    def read_all(self) -> list[dict[str, object]]: ...


class MemoryBackend:
    def __init__(self) -> None:
        self._rows: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self._rows.append(record)

    def read_all(self) -> list[dict[str, object]]:
        return list(self._rows)


class JsonlBackend:
    def __init__(self, path: str) -> None:
        self.path = path

    def append(self, record: dict[str, object]) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical(record) + "\n")

    def read_all(self) -> list[dict[str, object]]:
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    out.append(json.loads(ln))
        return out


def verify_records(records: list[dict[str, object]]) -> ChainVerification:
    """Recompute the chain from genesis. Detects modification (hash mismatch),
    deletion / insertion (sequence gap), and reordering (previous-hash mismatch)."""
    problems: list[str] = []
    prev = GENESIS
    first_bad: int | None = None
    for i, rec in enumerate(records):
        try:
            ev = AuditEvent.from_dict(rec)
        except (KeyError, ValueError, TypeError) as e:
            problems.append(f"record {i}: unreadable ({e})")
            first_bad = first_bad if first_bad is not None else i
            break
        seq_ok = ev.sequence == i
        link_ok = ev.previous_hash == prev
        hash_ok = chain_hash(ev.body(), ev.previous_hash) == ev.event_hash
        if not seq_ok:
            problems.append(
                f"record {i}: sequence {ev.sequence} != {i} (record deleted, inserted or reordered)"
            )
        if not link_ok:
            problems.append(
                f"record {i}: previous_hash does not match the prior event (chain broken)"
            )
        if not hash_ok:
            problems.append(f"record {i}: event_hash mismatch (content modified)")
        if not (seq_ok and link_ok and hash_ok) and first_bad is None:
            first_bad = i
        prev = ev.event_hash
    return ChainVerification(not problems, len(records), tuple(problems), first_bad, prev)


class AuditChain:
    """Append-only, hash-chained log over a backend. Thread-safe appends."""

    def __init__(self, backend: AuditBackend | None = None) -> None:
        self.backend: AuditBackend = backend or MemoryBackend()
        self._lock = threading.Lock()
        rows = self.backend.read_all()
        self._length = len(rows)
        self._head = str(rows[-1]["event_hash"]) if rows else GENESIS

    @property
    def head(self) -> str:
        return self._head

    def __len__(self) -> int:
        return self._length

    def append(
        self,
        *,
        actor: str,
        workflow: str,
        action: str,
        decision_id: str | None = None,
        subject_id: str | None = None,
        risk_score: int = 0,
        risk_level: str = "LOW",
        policy_id: str | None = None,
        policy_version: int | None = None,
        capability: str | None = None,
        evidence_ids: tuple[str, ...] = (),
        security_severity: str = "NONE",
        input_hash: str = "",
        case_id: str | None = None,
        kind: str = "decision",
        detail: dict[str, object] | None = None,
    ) -> AuditEvent:
        with self._lock:
            seq = self._length
            prev = self._head
            body = {
                "event_id": new_id("AUD"),
                "sequence": seq,
                "timestamp": now_iso(),
                "decision_id": decision_id,
                "actor": actor,
                "workflow": workflow,
                "subject_id": subject_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "capability": capability,
                "action": action,
                "evidence_ids": list(evidence_ids),
                "security_severity": security_severity,
                "input_hash": input_hash,
                "case_id": case_id,
                "kind": kind,
                "detail": redact(dict(detail or {})),
            }
            h = chain_hash(body, prev)
            rec = dict(body)
            rec["previous_hash"] = prev
            rec["event_hash"] = h
            self.backend.append(rec)
            self._length += 1
            self._head = h
            return AuditEvent.from_dict(rec)

    def events(self) -> list[AuditEvent]:
        return [AuditEvent.from_dict(r) for r in self.backend.read_all()]

    def get(self, event_id: str) -> AuditEvent | None:
        for r in self.backend.read_all():
            if r.get("event_id") == event_id or r.get("decision_id") == event_id:
                return AuditEvent.from_dict(r)
        return None

    def verify(self) -> ChainVerification:
        return verify_records(self.backend.read_all())
