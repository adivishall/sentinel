"""Tamper-evident application audit chain.

Each event carries the hash of the previous event; its own hash covers its
content *and* that previous hash. Modifying, deleting, inserting or reordering
any record breaks every hash after it, and ``verify`` names the first bad
record. This is an application-level audit chain -- not a blockchain and not
an immutable ledger: a party who can rewrite the *whole* store from genesis
can produce a consistent chain. An exported **checkpoint** (length + head hash,
optionally HMAC-signed with ``SENTINEL_AUDIT_KEY``) held outside the store is
what makes that rewrite detectable. ``docs/AUDIT_MODEL.md`` states exactly
what is and is not protected.

Lookups do not re-read the log: every backend answers ``find`` / ``at`` /
``tail`` / ``count`` from an index (a dict, a byte-offset map, or SQL).
Verification necessarily reads everything.

Privacy: the chain stores hashes of untrusted content, never the content. A
defensive ``redact`` pass hashes any stray raw-text field before it is written.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass, field
from typing import Protocol

from sentinel.domain.ids import content_hash, new_id, now_iso

GENESIS = "0" * 64


class AuditIntegrityError(RuntimeError):
    """The backend refused an append because the stored chain is inconsistent with the
    chain's own view of it (a record was deleted or inserted underneath). Appending
    would hide the tampering, so the chain fails closed; run ``sentinel audit verify``."""


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


UNREADABLE = "_unreadable"


def _decode(raw: str | bytes) -> dict[str, object]:
    """A stored record, or an ``{_unreadable: reason}`` marker so that verification
    reports a malformed record at its index instead of crashing before it runs."""
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as e:
        return {UNREADABLE: f"malformed JSON ({type(e).__name__})"}
    return dict(obj) if isinstance(obj, dict) else {UNREADABLE: "record is not an object"}


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
    """Append-only storage plus indexed reads. ``read_all`` is for verification and
    export; the other reads must not scan the whole log."""

    def append(self, record: dict[str, object]) -> None: ...
    def read_all(self) -> list[dict[str, object]]: ...
    def count(self) -> int: ...
    def at(self, sequence: int) -> dict[str, object] | None: ...
    def tail(self, n: int) -> list[dict[str, object]]: ...
    def find(
        self, event_id: str | None = None, decision_id: str | None = None
    ) -> dict[str, object] | None: ...


class MemoryBackend:
    def __init__(self) -> None:
        self._rows: list[dict[str, object]] = []
        self._by_event: dict[str, int] = {}
        self._by_decision: dict[str, int] = {}

    def append(self, record: dict[str, object]) -> None:
        i = len(self._rows)
        self._rows.append(record)
        self._by_event[str(record["event_id"])] = i
        d = record.get("decision_id")
        if d is not None:
            self._by_decision.setdefault(str(d), i)

    def read_all(self) -> list[dict[str, object]]:
        return list(self._rows)

    def count(self) -> int:
        return len(self._rows)

    def at(self, sequence: int) -> dict[str, object] | None:
        return self._rows[sequence] if 0 <= sequence < len(self._rows) else None

    def tail(self, n: int) -> list[dict[str, object]]:
        return list(self._rows[-n:]) if n > 0 else []

    def find(
        self, event_id: str | None = None, decision_id: str | None = None
    ) -> dict[str, object] | None:
        i = None
        if event_id is not None:
            i = self._by_event.get(event_id)
        if i is None and decision_id is not None:
            i = self._by_decision.get(decision_id)
        return self._rows[i] if i is not None else None


class JsonlBackend:
    """One canonical JSON record per line. A byte-offset index (built lazily on the
    first read, kept current by ``append``) makes lookups a seek, not a scan."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._offsets: list[int] | None = None  # sequence -> byte offset of its line
        self._by_event: dict[str, int] = {}
        self._by_decision: dict[str, int] = {}

    def _ensure_index(self) -> list[int]:
        if self._offsets is not None:
            return self._offsets
        offsets: list[int] = []
        self._by_event, self._by_decision = {}, {}
        if os.path.exists(self.path):
            with open(self.path, "rb") as fh:
                pos = 0
                for raw in fh:
                    ln = raw.strip()
                    if ln:
                        rec = _decode(ln)
                        if UNREADABLE not in rec:
                            self._register(rec, len(offsets))
                        offsets.append(pos)
                    pos += len(raw)
        self._offsets = offsets
        return offsets

    def _register(self, rec: dict[str, object], seq: int) -> None:
        self._by_event[str(rec["event_id"])] = seq
        d = rec.get("decision_id")
        if d is not None:
            self._by_decision.setdefault(str(d), seq)

    def _read_at_offset(self, offset: int) -> dict[str, object]:
        with open(self.path, "rb") as fh:
            fh.seek(offset)
            return _decode(fh.readline())

    def append(self, record: dict[str, object]) -> None:
        offsets = self._ensure_index()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "ab") as fh:
            pos = fh.tell()
            fh.write((canonical(record) + "\n").encode("utf-8"))
        self._register(record, len(offsets))
        offsets.append(pos)

    def read_all(self) -> list[dict[str, object]]:
        self._offsets = None  # verification always re-reads from disk
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    out.append(_decode(ln))
        return out

    def count(self) -> int:
        return len(self._ensure_index())

    def at(self, sequence: int) -> dict[str, object] | None:
        offsets = self._ensure_index()
        if 0 <= sequence < len(offsets):
            return self._read_at_offset(offsets[sequence])
        return None

    def tail(self, n: int) -> list[dict[str, object]]:
        offsets = self._ensure_index()
        return [self._read_at_offset(o) for o in offsets[-n:]] if n > 0 else []

    def find(
        self, event_id: str | None = None, decision_id: str | None = None
    ) -> dict[str, object] | None:
        self._ensure_index()
        seq = None
        if event_id is not None:
            seq = self._by_event.get(event_id)
        if seq is None and decision_id is not None:
            seq = self._by_decision.get(decision_id)
        return self.at(seq) if seq is not None else None


def verify_records(records: list[dict[str, object]]) -> ChainVerification:
    """Recompute the chain from genesis. Detects modification (hash mismatch),
    deletion / insertion (sequence gap), reordering (previous-hash mismatch) and
    unreadable records (malformed JSON, truncated line, missing field). Verification
    continues past an unreadable record, so every later problem is reported too; the
    link from an unreadable record to the next cannot be checked and is not assumed."""
    problems: list[str] = []
    prev: str | None = GENESIS
    first_bad: int | None = None

    def bad(i: int, msg: str) -> None:
        nonlocal first_bad
        problems.append(f"record {i}: {msg}")
        if first_bad is None:
            first_bad = i

    for i, rec in enumerate(records):
        if UNREADABLE in rec:
            bad(i, f"unreadable ({rec[UNREADABLE]})")
            prev = None
            continue
        try:
            ev = AuditEvent.from_dict(rec)
        except KeyError as e:
            bad(i, f"unreadable (missing field {e})")
            prev = None
            continue
        except (ValueError, TypeError) as e:
            bad(i, f"unreadable ({e})")
            prev = None
            continue
        if ev.sequence != i:
            bad(i, f"sequence {ev.sequence} != {i} (record deleted, inserted or reordered)")
        if prev is not None and ev.previous_hash != prev:
            bad(i, "previous_hash does not match the prior event (chain broken)")
        if chain_hash(ev.body(), ev.previous_hash) != ev.event_hash:
            bad(i, "event_hash mismatch (content modified)")
        prev = ev.event_hash
    return ChainVerification(not problems, len(records), tuple(problems), first_bad, prev or "")


@dataclass(frozen=True)
class Checkpoint:
    """A statement, meant to be stored *outside* the audit store, that at ``length``
    events the chain's head hash was ``head_hash``. With a key it is HMAC-signed."""

    length: int
    head_hash: str
    created_at: str
    algorithm: str = "sha256-chain"
    signature: str | None = None  # HMAC-SHA256 over the canonical body, if a key was given

    def body(self) -> dict[str, object]:
        return {
            "length": self.length,
            "head_hash": self.head_hash,
            "created_at": self.created_at,
            "algorithm": self.algorithm,
        }

    @property
    def signed(self) -> bool:
        return self.signature is not None

    def to_dict(self) -> dict[str, object]:
        return {**self.body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, d: dict[str, object]) -> Checkpoint:
        return cls(
            int(d["length"]),  # type: ignore[call-overload]
            str(d["head_hash"]),
            str(d.get("created_at", "")),
            str(d.get("algorithm", "sha256-chain")),
            str(d["signature"]) if d.get("signature") else None,
        )


def sign_checkpoint(body: dict[str, object], key: bytes) -> str:
    return hmac.new(key, canonical(body).encode("utf-8"), hashlib.sha256).hexdigest()


def checkpoint_key() -> bytes | None:
    k = os.environ.get("SENTINEL_AUDIT_KEY")
    return k.encode("utf-8") if k else None


class AuditChain:
    """Append-only, hash-chained log over a backend. Thread-safe appends."""

    def __init__(self, backend: AuditBackend | None = None) -> None:
        self.backend: AuditBackend = backend or MemoryBackend()
        self._lock = threading.Lock()
        self._length = self.backend.count()
        last = self.backend.tail(1)
        self._head = str(last[-1]["event_hash"]) if last else GENESIS

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
            stored = self.backend.count()
            if stored != self._length:
                raise AuditIntegrityError(
                    f"audit chain is inconsistent: the store holds {stored} events but the chain "
                    f"expects {self._length} (a record was deleted or inserted underneath the "
                    "chain); refusing to append -- run `sentinel audit verify`"
                )
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
        """Every event (a full read; use ``tail`` for listings)."""
        return [AuditEvent.from_dict(r) for r in self.backend.read_all()]

    def tail(self, n: int) -> list[AuditEvent]:
        return [AuditEvent.from_dict(r) for r in self.backend.tail(n)]

    def at(self, sequence: int) -> AuditEvent | None:
        r = self.backend.at(sequence)
        return AuditEvent.from_dict(r) if r else None

    def get(self, event_id: str) -> AuditEvent | None:
        """By event id, or the first event recorded for a decision id -- indexed."""
        r = self.backend.find(event_id=event_id, decision_id=event_id)
        return AuditEvent.from_dict(r) if r else None

    def verify(self) -> ChainVerification:
        return verify_records(self.backend.read_all())

    # ---- checkpoints --------------------------------------------------------------
    def checkpoint(self, key: bytes | None = None) -> Checkpoint:
        """Export the current (length, head) for storage outside the audit store."""
        body = {
            "length": self._length,
            "head_hash": self._head,
            "created_at": now_iso(),
            "algorithm": "sha256-chain",
        }
        sig = sign_checkpoint(body, key) if key else None
        return Checkpoint(self._length, self._head, str(body["created_at"]), "sha256-chain", sig)

    def verify_checkpoint(self, cp: Checkpoint, key: bytes | None = None) -> ChainVerification:
        """Verify the chain AND that it still contains the checkpointed prefix: the
        event at ``cp.length - 1`` must hash to ``cp.head_hash``. A consistent rewrite
        from genesis passes ``verify`` but fails here."""
        v = self.verify()
        problems = list(v.problems)
        if cp.signed:
            if key is None:
                problems.append("checkpoint is signed but no key was given (SENTINEL_AUDIT_KEY)")
            elif not hmac.compare_digest(sign_checkpoint(cp.body(), key), cp.signature or ""):
                problems.append("checkpoint signature does not verify (wrong key or edited file)")
        elif key is not None:
            problems.append("checkpoint is unsigned; it cannot be authenticated with the key")
        first_bad = v.first_bad_sequence
        if v.length < cp.length:
            problems.append(
                f"chain has {v.length} events but the checkpoint attests {cp.length} (truncated)"
            )
            first_bad = v.length if first_bad is None else first_bad
        elif cp.length > 0:
            ev = self.at(cp.length - 1)
            if ev is None or ev.event_hash != cp.head_hash:
                problems.append(
                    f"event #{cp.length - 1} hash does not match the checkpoint head (rewritten history)"
                )
                first_bad = cp.length - 1 if first_bad is None else first_bad
        return ChainVerification(not problems, v.length, tuple(problems), first_bad, v.head_hash)
