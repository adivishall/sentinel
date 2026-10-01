"""Signed policy releases: why Sentinel may trust the policy that decides.

A policy version is **released** when a key the operator trusts for policy releases signs
its exact content -- the full SHA-256 of the canonical document -- as that version
(``sentinel.policy-release/1``). It is **active** when such a key signs an activation for
it (``sentinel.policy-activation/1``) that is in effect now: explicit, sequenced, never
before the document's own ``effective_from``. A higher version number activates nothing.

The policy directory is not the trust root. Its files, ``MANIFEST.json`` and
``RELEASES.json`` are statements anyone who can write the directory can write; only a
signature from a ``policy-release`` key in the policy trust store -- operator
configuration kept outside the directory (``SENTINEL_POLICY_TRUST``, or the shipped root
``sentinel/trust/policy_root.json``) -- makes one count. So editing a policy and
recomputing the manifest, adding an unsigned version, or forging an activation fails.

What a VERIFIED release proves: the holder of a trusted policy-release key, scoped to this
policy, approved exactly this document as this version. It does not prove that the policy
is right: a signer can release a bad policy, and replay is how one finds out.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sentinel.trust import crypto
from sentinel.trust.canonical import CanonicalError, canonical_json, sha256_hex, strict_loads
from sentinel.trust.keys import POLICY_RELEASE, TrustStore, format_ts, parse_ts

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from sentinel.policy.models import Policy

RELEASE_FORMAT = "sentinel.policy-release/1"
ACTIVATION_FORMAT = "sentinel.policy-activation/1"
BOOK_FORMAT = "sentinel.policy-releases/1"
RELEASES_FILE = "RELEASES.json"
_RELEASE_DOMAIN = b"sentinel.policy-release/1\n"
_ACTIVATION_DOMAIN = b"sentinel.policy-activation/1\n"
_SKEW_SECONDS = 300
RELEASE_FIELDS = (
    "format",
    "signer",
    "key_id",
    "policy_id",
    "version",
    "digest",
    "released_at",
)
ACTIVATION_FIELDS = (
    "format",
    "signer",
    "key_id",
    "policy_id",
    "version",
    "digest",
    "sequence",
    "effective_from",
    "issued_at",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReleaseStatus(StrEnum):
    VERIFIED = "VERIFIED"  # a trusted policy-release key signed exactly this document
    UNSIGNED = "UNSIGNED"  # no release statement names this version
    INVALID = "INVALID"  # a statement exists but does not verify for this document
    REVOKED = "REVOKED"  # signed by a key revoked since


@dataclass(frozen=True)
class PolicyRelease:
    """What establishes one loaded policy version -- recorded with every decision."""

    status: ReleaseStatus
    policy_id: str
    version: int
    digest: str  # the loaded document's full SHA-256
    signer: str | None = None
    key_id: str | None = None
    released_at: str | None = None
    reason: str = ""
    # set on the active version: the activation that made it active
    activation_sequence: int | None = None
    effective_from: str | None = None

    @property
    def verified(self) -> bool:
        return self.status is ReleaseStatus.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "policy_id": self.policy_id,
            "version": self.version,
            "digest": self.digest,
            "signer": self.signer,
            "key_id": self.key_id,
            "released_at": self.released_at,
            "reason": self.reason,
            "activation_sequence": self.activation_sequence,
            "effective_from": self.effective_from,
        }


@dataclass(frozen=True)
class Activation:
    policy_id: str
    version: int
    digest: str
    sequence: int
    effective_from: datetime
    signer: str
    key_id: str
    statement_digest: str


# ---- signing (operator tooling: the release pipeline holds the private key) ---------------------
def _signed(private: Ed25519PrivateKey, domain: bytes, header: dict[str, Any]) -> dict[str, Any]:
    sig = crypto.sign(private, domain + canonical_json(header))
    return {**header, "signature": crypto.b64e(sig)}


def sign_release(
    private: Ed25519PrivateKey, *, signer: str, policy: Policy, released_at: datetime
) -> dict[str, Any]:
    from sentinel.policy.loader import policy_digest

    return _signed(
        private,
        _RELEASE_DOMAIN,
        {
            "format": RELEASE_FORMAT,
            "signer": signer,
            "key_id": crypto.key_id(crypto.public_raw(private)),
            "policy_id": policy.policy_id,
            "version": policy.version,
            "digest": policy_digest(policy),
            "released_at": format_ts(released_at),
        },
    )


def sign_activation(
    private: Ed25519PrivateKey,
    *,
    signer: str,
    policy: Policy,
    sequence: int,
    effective_from: datetime,
    issued_at: datetime,
) -> dict[str, Any]:
    from sentinel.policy.loader import policy_digest

    return _signed(
        private,
        _ACTIVATION_DOMAIN,
        {
            "format": ACTIVATION_FORMAT,
            "signer": signer,
            "key_id": crypto.key_id(crypto.public_raw(private)),
            "policy_id": policy.policy_id,
            "version": policy.version,
            "digest": policy_digest(policy),
            "sequence": sequence,
            "effective_from": format_ts(effective_from),
            "issued_at": format_ts(issued_at),
        },
    )


# ---- verification -----------------------------------------------------------------------------
def _signer_check(
    d: dict[str, Any],
    fields: tuple[str, ...],
    fmt: str,
    domain: bytes,
    trust: TrustStore,
    ts_field: str,
) -> tuple[str | None, str]:
    """Shared checks for both statements: shape, format, signer, signature, revocation,
    key window and time. Returns (None, reason-if-ok) or (status, reason) on failure,
    where status is "INVALID" or "REVOKED"."""
    want = set(fields) | {"signature"}
    if set(d) != want:
        return "INVALID", (
            f"malformed statement (missing {sorted(want - set(d))}, unknown {sorted(set(d) - want)})"
        )
    if d["format"] != fmt:
        return "INVALID", f"unsupported format {d['format']!r}"
    for f in ("signer", "key_id", "policy_id", "digest", "signature", ts_field):
        if not isinstance(d[f], str):
            return "INVALID", f"{f} is not a string"
    v = d["version"]
    if not isinstance(v, int) or isinstance(v, bool) or v < 1:
        return "INVALID", "version is not a positive integer"
    if not _HEX64.match(d["digest"]):
        return "INVALID", "digest is not a full SHA-256"
    try:
        header = canonical_json({k: d[k] for k in fields})
        at = parse_ts(d[ts_field], ts_field)
    except (CanonicalError, ValueError) as e:
        return "INVALID", f"malformed statement: {e}"
    key = trust.get(d["key_id"])
    if key is None:
        return "INVALID", f"unknown signer {d['key_id']} (not in the policy trust store)"
    if key.issuer != d["signer"]:
        return "INVALID", f"key {key.key_id} belongs to {key.issuer}, not {d['signer']}"
    if not key.allows(POLICY_RELEASE, d["policy_id"]):
        return "INVALID", f"key {key.key_id} is not trusted to release {d['policy_id']}"
    try:
        sig = crypto.b64d(d["signature"])
    except ValueError as e:
        return "INVALID", f"malformed signature: {e}"
    if not crypto.verify(key.public_key, sig, domain + header):
        return "INVALID", "the signature does not verify"
    if key.revoked:
        return "REVOKED", (
            f"signed by {key.key_id}, revoked {format_ts(key.revoked_at)}"  # type: ignore[arg-type]
            + (f" ({key.revocation_reason})" if key.revocation_reason else "")
        )
    if at < key.not_before:
        return "INVALID", "signed before the key's validity began"
    if key.not_after is not None and at > key.not_after:
        return "INVALID", "signed after the key was retired"
    return None, f"signed by {d['signer']} ({key.key_id})"


def verify_release(
    doc: object, *, policy: Policy, trust: TrustStore, now: datetime
) -> PolicyRelease:
    """Does ``doc`` release exactly ``policy`` (this id, this version, this content)?"""
    from sentinel.policy.loader import policy_digest

    actual = policy_digest(policy)

    def out(status: ReleaseStatus, reason: str, d: dict[str, Any] | None = None) -> PolicyRelease:
        d = d or {}
        return PolicyRelease(
            status,
            policy.policy_id,
            policy.version,
            actual,
            d.get("signer") if isinstance(d.get("signer"), str) else None,
            d.get("key_id") if isinstance(d.get("key_id"), str) else None,
            d.get("released_at") if isinstance(d.get("released_at"), str) else None,
            reason,
        )

    if not isinstance(doc, dict):
        return out(ReleaseStatus.INVALID, "the release statement is not a JSON object")
    bad, why = _signer_check(
        doc, RELEASE_FIELDS, RELEASE_FORMAT, _RELEASE_DOMAIN, trust, "released_at"
    )
    if bad is not None:
        return out(ReleaseStatus(bad), why, doc)
    if doc["policy_id"] != policy.policy_id or doc["version"] != policy.version:
        return out(
            ReleaseStatus.INVALID,
            f"released {doc['policy_id']}@v{doc['version']}, not {policy.key}",
            doc,
        )
    if doc["digest"] != actual:
        return out(
            ReleaseStatus.INVALID,
            "the document is not the one released (its content changed after signing)",
            doc,
        )
    if parse_ts(doc["released_at"], "released_at").timestamp() > now.timestamp() + _SKEW_SECONDS:
        return out(ReleaseStatus.INVALID, "released in the future", doc)
    return out(ReleaseStatus.VERIFIED, why, doc)


def verify_activation(
    doc: object,
    *,
    trust: TrustStore,
    now: datetime,
    released: dict[tuple[str, int], PolicyRelease],
    effective_floor: dict[str, datetime],
) -> tuple[Activation | None, str]:
    """An activation counts only if it is signed by a trusted policy-release key, names a
    version whose release verified with the same digest, and takes effect no earlier than
    the document's own ``effective_from``."""
    if not isinstance(doc, dict):
        return None, "the activation is not a JSON object"
    bad, why = _signer_check(
        doc, ACTIVATION_FIELDS, ACTIVATION_FORMAT, _ACTIVATION_DOMAIN, trust, "issued_at"
    )
    if bad is not None:
        return None, f"{bad}: {why}"
    seq = doc["sequence"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        return None, "INVALID: sequence is not a positive integer"
    pid, v = doc["policy_id"], doc["version"]
    rel = released.get((pid, v))
    if rel is None or not rel.verified:
        return None, f"INVALID: activates {pid}@v{v}, which has no verified release"
    if rel.digest != doc["digest"]:
        return None, f"INVALID: activates other content than {pid}@v{v}'s released document"
    try:
        effective = parse_ts(doc["effective_from"], "effective_from")
        issued = parse_ts(doc["issued_at"], "issued_at")
    except ValueError as e:
        return None, f"INVALID: {e}"
    if issued.timestamp() > now.timestamp() + _SKEW_SECONDS:
        return None, "INVALID: issued in the future"
    floor = effective_floor.get(f"{pid}@v{v}")
    if floor is not None and effective < floor:
        return None, (
            f"INVALID: takes effect {format_ts(effective)}, before {pid}@v{v}'s own "
            f"effective_from {format_ts(floor)}"
        )
    return (
        Activation(
            pid,
            v,
            doc["digest"],
            seq,
            effective,
            doc["signer"],
            doc["key_id"],
            sha256_hex(canonical_json({k: doc[k] for k in ACTIVATION_FIELDS})),
        ),
        why,
    )


def document_effective_from(policy: Policy) -> datetime | None:
    """The policy document's own ``effective_from`` (a date or an instant), as UTC."""
    raw = policy.effective_from.strip()
    if not raw:
        return None
    try:
        if len(raw) == 10:
            return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=UTC)
        return parse_ts(raw, "effective_from")
    except ValueError:
        return None


# ---- the release book (RELEASES.json): statements, not trust -----------------------------------
@dataclass
class ReleaseBook:
    releases: list[dict[str, Any]] = field(default_factory=list)
    activations: list[dict[str, Any]] = field(default_factory=list)
    origin: str = "empty"

    @classmethod
    def load(cls, path: str | Path) -> ReleaseBook:
        p = Path(path)
        if not p.exists():
            return cls(origin=f"{p} (missing)")
        try:
            doc = strict_loads(p.read_bytes(), max_bytes=4 * 1024 * 1024)
        except (OSError, CanonicalError) as e:
            raise ValueError(f"unreadable release book {p}: {e}") from None
        if not isinstance(doc, dict) or doc.get("format") != BOOK_FORMAT:
            raise ValueError(f"{p}: a release book is an object with format {BOOK_FORMAT!r}")
        if set(doc) - {"format", "releases", "activations"}:
            raise ValueError(f"{p}: unknown fields {sorted(set(doc) - {'format'})}")
        rel, act = doc.get("releases", []), doc.get("activations", [])
        if not isinstance(rel, list) or not isinstance(act, list):
            raise ValueError(f"{p}: releases and activations must be lists")
        return cls(list(rel), list(act), str(p))

    def to_json(self) -> dict[str, Any]:
        return {"format": BOOK_FORMAT, "releases": self.releases, "activations": self.activations}

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=2, ensure_ascii=False) + "\n"

    def release_for(self, policy_id: str, version: int) -> list[dict[str, Any]]:
        return [
            r
            for r in self.releases
            if isinstance(r, dict)
            and r.get("policy_id") == policy_id
            and r.get("version") == version
        ]


@dataclass(frozen=True)
class Resolution:
    """The release status of every loaded version and the verified activations."""

    releases: dict[tuple[str, int], PolicyRelease]
    activations: dict[str, list[Activation]]  # by policy id, highest sequence first
    problems: tuple[str, ...]


def resolve(
    policies: list[Policy], book: ReleaseBook, trust: TrustStore, now: datetime
) -> Resolution:
    from sentinel.policy.loader import policy_digest

    releases: dict[tuple[str, int], PolicyRelease] = {}
    problems: list[str] = []
    for p in policies:
        stmts = book.release_for(p.policy_id, p.version)
        if not stmts:
            releases[(p.policy_id, p.version)] = PolicyRelease(
                ReleaseStatus.UNSIGNED,
                p.policy_id,
                p.version,
                policy_digest(p),
                reason="no release statement names this version",
            )
            continue
        results = [verify_release(s, policy=p, trust=trust, now=now) for s in stmts]
        best = next((r for r in results if r.verified), None)
        if best is None:  # report the most serious refusal (REVOKED before INVALID)
            best = sorted(results, key=lambda r: r.status is not ReleaseStatus.REVOKED)[0]
        releases[(p.policy_id, p.version)] = best
    floors = {p.key: f for p in policies if (f := document_effective_from(p)) is not None}
    activations: dict[str, list[Activation]] = {}
    for i, stmt in enumerate(book.activations):
        act, why = verify_activation(
            stmt, trust=trust, now=now, released=releases, effective_floor=floors
        )
        if act is None:
            problems.append(f"activations[{i}]: {why}")
            continue
        activations.setdefault(act.policy_id, []).append(act)
    for pid, acts in activations.items():
        acts.sort(key=lambda x: x.sequence, reverse=True)
        seen: dict[int, str] = {}
        for x in acts:
            if x.sequence in seen and seen[x.sequence] != x.statement_digest:
                problems.append(
                    f"{pid}: two different activations with sequence {x.sequence} (equivocation)"
                )
            seen[x.sequence] = x.statement_digest
    return Resolution(releases, activations, tuple(problems))
