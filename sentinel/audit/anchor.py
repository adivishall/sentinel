"""Asymmetric audit checkpoints and external anchoring.

The audit chain proves self-consistency: the stored events are what some writer wrote, in
order. Someone who can write the store and recompute SHA-256 can rewrite a suffix of it
consistently, and ``verify`` passes. A checkpoint fixes a prefix; an anchor keeps the
checkpoint somewhere that writer cannot reach.

A checkpoint here is a ``sentinel.audit-checkpoint/1`` statement -- {chain id, length,
head hash, checkpoint sequence, the previous checkpoint's digest, issued_at} -- signed
with Ed25519 by a key whose trust-store purpose is ``audit-checkpoint`` (a facts or
policy-release key is refused). The verifier holds only the public key, so verifying
cannot forge (the HMAC checkpoint could). Checkpoints link to each other, so a dropped or
substituted one is a visible gap, and each publication is itself recorded in the chain
(``CHECKPOINT_PUBLISHED``), so deleting the newest anchored checkpoint is visible -- unless
the same party can also rewrite the chain's unanchored tail, where that record lies; only
an anchor nobody can delete from (WORM, a transparency log) closes that.

What ``anchored`` proves for an event: a checkpoint signed by a trusted audit-checkpoint
key, held by the anchor, covers it, and the chain from genesis to that checkpoint
recomputes to the signed head -- the event is what it was when the checkpoint was signed,
unless the signing key or the anchor itself was compromised. ``not_anchored``: nothing
covers it yet; a consistent rewrite of it cannot be excluded. ``anchor_mismatch``: the
chain and the anchor disagree (rewritten history, a broken or missing checkpoint, an
untrusted or revoked key).

Anchors are append-only stores of checkpoint statements: a directory with one file per
checkpoint, never overwritten (export it, or commit it to a repository the operator
controls), or an append-only JSONL file. ``Anchor`` is the interface a WORM store or a
transparency log would implement; none is integrated here.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from sentinel.audit.chain import GENESIS, chain_hash
from sentinel.trust import crypto
from sentinel.trust.canonical import CanonicalError, canonical_json, sha256_hex, strict_loads
from sentinel.trust.keys import AUDIT_CHECKPOINT, TrustStore, format_ts, parse_ts

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FORMAT = "sentinel.audit-checkpoint/1"
DOMAIN = b"sentinel.audit-checkpoint/1\n"
HEADER_FIELDS = (
    "format",
    "signer",
    "key_id",
    "chain_id",
    "checkpoint_sequence",
    "previous_checkpoint",
    "length",
    "head_hash",
    "issued_at",
)
_HEX64 = re.compile(r"[0-9a-f]{64}")  # fullmatch: "$" alone also matches before a final "\n"
ANCHORED, NOT_ANCHORED, MISMATCH = "anchored", "not_anchored", "anchor_mismatch"


class AnchorError(ValueError):
    """An anchor refused a checkpoint (out of order, not linked, already present)."""


def checkpoint_digest(stmt: dict[str, Any]) -> str:
    return sha256_hex(canonical_json({k: stmt[k] for k in HEADER_FIELDS}))


def chain_id(records: list[dict[str, Any]]) -> str | None:
    """A chain is named by its first event's hash: a checkpoint for another deployment's
    chain does not cover this one."""
    return str(records[0]["event_hash"]) if records else None


def sign_checkpoint_statement(
    private: Ed25519PrivateKey,
    *,
    signer: str,
    records: list[dict[str, Any]],
    previous: dict[str, Any] | None,
    issued_at: datetime,
) -> dict[str, Any]:
    """Sign the chain's current head. ``records`` is the chain as stored (``read_all``);
    the head is recomputed, not read from the last record's stored field."""
    if not records:
        raise AnchorError("an empty chain has nothing to checkpoint")
    heads = _recomputed_heads(records)
    if heads[-1] is None:
        broken = heads.index(None)
        raise AnchorError(
            f"the chain does not verify from event #{broken}: refusing to sign a checkpoint "
            "over it (run `sentinel audit verify`)"
        )
    head = heads[-1]
    header = {
        "format": FORMAT,
        "signer": signer,
        "key_id": crypto.key_id(crypto.public_raw(private)),
        "chain_id": chain_id(records),
        "checkpoint_sequence": (previous["checkpoint_sequence"] + 1) if previous else 1,
        "previous_checkpoint": checkpoint_digest(previous) if previous else None,
        "length": len(records),
        "head_hash": head,
        "issued_at": format_ts(issued_at),
    }
    sig = crypto.sign(private, DOMAIN + canonical_json(header))
    return {**header, "signature": crypto.b64e(sig)}


def _shape(stmt: object) -> tuple[bool, str]:
    """Shape only: fields, types, digests, timestamp format."""
    if not isinstance(stmt, dict):
        return False, "not a JSON object"
    want = set(HEADER_FIELDS) | {"signature"}
    if set(stmt) != want:
        return (
            False,
            f"malformed (missing {sorted(want - set(stmt))}, unknown {sorted(set(stmt) - want)})",
        )
    if stmt["format"] != FORMAT:
        return False, f"unsupported format {stmt['format']!r}"
    for f in ("signer", "key_id", "chain_id", "head_hash", "signature", "issued_at"):
        if not isinstance(stmt[f], str):
            return False, f"{f} is not a string"
    for f in ("checkpoint_sequence", "length"):
        v = stmt[f]
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            return False, f"{f} is not a positive integer"
    prev = stmt["previous_checkpoint"]
    if prev is not None and (not isinstance(prev, str) or not _HEX64.fullmatch(prev)):
        return False, "previous_checkpoint is not a digest"
    if not _HEX64.fullmatch(stmt["head_hash"]) or not _HEX64.fullmatch(stmt["chain_id"]):
        return False, "head_hash / chain_id is not a SHA-256"
    try:
        canonical_json({k: stmt[k] for k in HEADER_FIELDS})
        parse_ts(stmt["issued_at"], "issued_at")
    except (CanonicalError, ValueError) as e:
        return False, f"malformed: {e}"
    return True, ""


RETIRED = "retired"  # signed by a key revoked since: proves nothing, but not tampering


def verify_statement(
    stmt: object, trust: TrustStore, now: datetime | None = None
) -> tuple[bool | str, str]:
    """The statement's own validity: shape, a trusted audit-checkpoint key, signature,
    the key's window, not issued in the future. Returns (True, why), (False, why), or
    (RETIRED, why) for a genuine statement whose key has been revoked since -- it no
    longer covers anything, and it is not evidence of tampering either."""
    ok, why = _shape(stmt)
    if not ok:
        return False, why
    assert isinstance(stmt, dict)
    header = canonical_json({k: stmt[k] for k in HEADER_FIELDS})
    issued = parse_ts(stmt["issued_at"], "issued_at")
    key = trust.get(stmt["key_id"])
    if key is None:
        return False, f"unknown signer {stmt['key_id']} (not in the trust store)"
    if key.issuer != stmt["signer"]:
        return False, f"key {key.key_id} belongs to {key.issuer}, not {stmt['signer']}"
    if not key.allows(AUDIT_CHECKPOINT, stmt["chain_id"]):
        return False, f"key {key.key_id} is not trusted to sign audit checkpoints"
    try:
        sig = crypto.b64d(stmt["signature"])
    except ValueError as e:
        return False, f"malformed signature: {e}"
    if not crypto.verify(key.public_key, sig, DOMAIN + header):
        return False, "the signature does not verify"
    if issued < key.not_before or (key.not_after is not None and issued > key.not_after):
        return False, "signed outside the key's validity window"
    if now is not None and issued.timestamp() > now.timestamp() + 300:
        return False, "issued in the future"
    if key.revoked:
        return RETIRED, (
            f"signed by {key.key_id}, revoked since ({key.revocation_reason or 'no reason'}): "
            "no longer counts; re-anchor with a current key"
        )
    return True, f"signed by {stmt['signer']} ({key.key_id})"


# ---- anchors -----------------------------------------------------------------------------------
class Anchor(Protocol):
    """An append-only home for checkpoint statements, out of the audit store writer's
    reach. A WORM bucket or a transparency log implements the same two methods; the
    statements are self-verifying, so the anchor needs to guarantee only that what was
    published stays published, in order."""

    name: str

    def publish(self, stmt: dict[str, Any]) -> str: ...

    def all(self) -> list[dict[str, Any]]: ...


def _check_append(existing: list[dict[str, Any]], stmt: dict[str, Any]) -> None:
    ok, why = _shape(stmt)
    if not ok:
        raise AnchorError(f"not a checkpoint statement: {why}")
    if existing and "_unreadable" in existing[-1]:
        raise AnchorError("the anchor's latest entry is unreadable; repair the anchor first")
    last = existing[-1] if existing else None
    want = (last["checkpoint_sequence"] + 1) if last else 1
    if stmt.get("checkpoint_sequence") != want:
        raise AnchorError(f"checkpoint {stmt.get('checkpoint_sequence')} is not next ({want})")
    if stmt.get("previous_checkpoint") != (checkpoint_digest(last) if last else None):
        raise AnchorError("the checkpoint does not link to the anchor's latest")
    if last is not None and stmt.get("length", 0) < last["length"]:
        raise AnchorError("a checkpoint may not attest a shorter chain than the previous one")


@dataclass
class DirectoryAnchor:
    """One file per checkpoint (``cp-00000001-<digest16>.json``), created exclusively and
    never overwritten. Export the directory, or commit it to a repository the operator
    controls (its history is then the anchor's strength)."""

    path: Path
    name: str = field(init=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.name = f"dir:{self.path.name}"

    def publish(self, stmt: dict[str, Any]) -> str:
        self.path.mkdir(parents=True, exist_ok=True)
        _check_append(self.all(), stmt)
        f = self.path / f"cp-{stmt['checkpoint_sequence']:08d}-{checkpoint_digest(stmt)[:16]}.json"
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(stmt, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return f.name

    def all(self) -> list[dict[str, Any]]:
        if not self.path.is_dir():
            return []
        out = []
        for f in sorted(self.path.glob("cp-*.json")):
            try:
                out.append(strict_loads(f.read_bytes()))
            except OSError as e:  # the reason, never the path on disk
                out.append({"_unreadable": f"{f.name}: {e.strerror or type(e).__name__}"})
            except CanonicalError as e:
                out.append({"_unreadable": f"{f.name}: {e}"})
        return out


@dataclass
class JsonlAnchor:
    """An append-only JSONL file: one checkpoint per line, opened for append only."""

    path: Path
    name: str = field(init=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.name = f"jsonl:{self.path.name}"

    def publish(self, stmt: dict[str, Any]) -> str:
        _check_append(self.all(), stmt)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(stmt, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return f"{self.path.name}#{stmt['checkpoint_sequence']}"

    def all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for i, raw in enumerate(self.path.read_bytes().splitlines()):
            if not raw.strip():
                continue
            try:
                out.append(strict_loads(raw))
            except (CanonicalError, UnicodeDecodeError) as e:
                out.append({"_unreadable": f"line {i + 1}: {type(e).__name__}"})
        return out


def open_anchor(spec: str) -> Anchor:
    """``SENTINEL_AUDIT_ANCHOR``: a directory, or a ``.jsonl`` file."""
    return JsonlAnchor(Path(spec)) if spec.endswith(".jsonl") else DirectoryAnchor(Path(spec))


# ---- verification ------------------------------------------------------------------------------
def _recomputed_heads(records: list[dict[str, Any]]) -> list[str | None]:
    """The hash each event *should* have, recomputed from genesis; None from the first
    event whose stored form is unreadable or breaks the chain onward."""
    from sentinel.audit.chain import AuditEvent

    out: list[str | None] = []
    prev = GENESIS
    broken = False
    for i, r in enumerate(records):
        if broken:
            out.append(None)
            continue
        try:
            ev = AuditEvent.from_dict(r)
            h = chain_hash(ev.body(), prev)
        except (KeyError, ValueError, TypeError):
            broken = True
            out.append(None)
            continue
        if ev.sequence != i or ev.previous_hash != prev or ev.event_hash != h:
            broken = True  # the stored chain diverges here: nothing after it is the chain
            out.append(None)
            continue
        out.append(h)
        prev = h
    return out


@dataclass(frozen=True)
class Anchoring:
    status: str  # anchored | not_anchored | anchor_mismatch
    anchor: str | None
    covered_length: int  # events 0..covered_length-1 are covered by a verified checkpoint
    length: int
    latest: dict[str, Any] | None = None
    reasons: tuple[str, ...] = ()
    # events after the covered prefix, not counting the record of publishing a checkpoint
    unanchored_events: int = 0
    notes: tuple[str, ...] = ()  # e.g. checkpoints signed by a key revoked since

    def for_event(self, sequence: int | None) -> str:
        """The status of one event (a decision's)."""
        if self.status == MISMATCH:
            return MISMATCH
        if sequence is not None and sequence < self.covered_length:
            return ANCHORED
        return NOT_ANCHORED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "anchor": self.anchor,
            "covered_through": self.covered_length - 1 if self.covered_length else None,
            "unanchored_events": self.unanchored_events,
            "length": self.length,
            "latest_checkpoint": self.latest,
            "reasons": list(self.reasons),
            "notes": list(self.notes),
        }


def _is_publication(r: dict[str, Any]) -> bool:
    return r.get("kind") == "system" and r.get("action") == "CHECKPOINT_PUBLISHED"


def anchoring(
    records: list[dict[str, Any]],
    anchor: Anchor | None,
    trust: TrustStore,
    *,
    now: datetime | None = None,
    require_publication: bool = False,
) -> Anchoring:
    """Check the chain against every checkpoint the anchor holds.

    ``require_publication``: the latest checkpoint's publication must be recorded in the
    chain (the application always records it), so removing that record is a mismatch."""
    n = len(records)
    if anchor is None:
        return Anchoring(NOT_ANCHORED, None, 0, n, None, ("no anchor configured",), n)
    stmts = anchor.all()
    published = [r for r in records if _is_publication(r)]
    if not stmts and not published:
        return Anchoring(
            NOT_ANCHORED, anchor.name, 0, n, None, ("the anchor holds no checkpoint",), n
        )
    heads = _recomputed_heads(records)
    cid = chain_id(records)
    reasons: list[str] = []
    notes: list[str] = []
    covered = 0
    latest: dict[str, Any] | None = None
    prev: dict[str, Any] | None = None
    for i, s in enumerate(stmts):
        if "_unreadable" in s:
            reasons.append(f"checkpoint unreadable ({s['_unreadable']})")
            break
        ok, why = verify_statement(s, trust, now)
        if ok is False:
            reasons.append(f"checkpoint {s.get('checkpoint_sequence', i + 1)}: {why}")
            break
        # continuity holds for every statement, retired or not: the anchor is one log
        if s["checkpoint_sequence"] != i + 1:
            reasons.append(f"checkpoint {i + 1} missing (found {s['checkpoint_sequence']})")
            break
        if s["previous_checkpoint"] != (checkpoint_digest(prev) if prev else None):
            reasons.append(f"checkpoint {i + 1} does not link to checkpoint {i}")
            break
        if s["chain_id"] != cid:
            reasons.append(f"checkpoint {i + 1} is for another chain")
            break
        if s["length"] > n:
            reasons.append(
                f"checkpoint {i + 1} attests {s['length']} events; the chain has {n} (truncated)"
            )
            break
        prev = s
        if ok == RETIRED:
            notes.append(f"checkpoint {i + 1}: {why}")
            continue
        if heads[s["length"] - 1] != s["head_hash"]:
            reasons.append(
                f"checkpoint {i + 1}: event #{s['length'] - 1} does not recompute to the signed "
                "head (history before it was rewritten)"
            )
            break
        # every checkpoint attests the whole prefix from genesis: the latest valid one is
        # the coverage
        covered, latest = s["length"], s
    held = {
        checkpoint_digest(s): s.get("checkpoint_sequence")
        for s in stmts
        if "_unreadable" not in s and _shape(s)[0]
    }
    recorded = {(r.get("detail") or {}).get("digest") for r in published}
    for r in published:
        d = r.get("detail") or {}
        if d.get("digest") not in held:
            reasons.append(
                f"the chain records publishing checkpoint {d.get('checkpoint_sequence')}, "
                "which the anchor does not hold"
            )
    if require_publication and latest is not None and checkpoint_digest(latest) not in recorded:
        reasons.append(
            f"the chain does not record publishing checkpoint {latest['checkpoint_sequence']} "
            "(its publication record is missing)"
        )
    unanchored = sum(
        1
        for r in records[covered:]
        if not (_is_publication(r) and (r.get("detail") or {}).get("digest") in held)
    )
    summary = (
        {
            k: latest[k]
            for k in ("checkpoint_sequence", "length", "head_hash", "issued_at", "signer", "key_id")
        }
        if latest
        else None
    )
    if reasons:
        return Anchoring(
            MISMATCH, anchor.name, covered, n, summary, tuple(reasons), unanchored, tuple(notes)
        )
    return Anchoring(
        ANCHORED if covered else NOT_ANCHORED,
        anchor.name,
        covered,
        n,
        summary,
        (),
        unanchored,
        tuple(notes),
    )
