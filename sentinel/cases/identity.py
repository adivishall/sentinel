"""Reviewer identity: who a human case action is from is resolved, never declared.

A reviewer registry is operator configuration (``SENTINEL_REVIEWERS``), kept apart from
the case data. Each reviewer has an id, a role (``HUMAN_REVIEWER`` | ``SENIOR_REVIEWER``),
an authority limit -- the largest amount they may approve -- an active flag, and one
bearer credential stored only as its SHA-256. A case action presents the credential; the
registry answers with the ``Reviewer``, and the role, the limit and the id on the record
come from that answer. Nothing in a request body can name a reviewer or a role.

The credential is a random 256-bit token (``srv_...``). SHA-256 is the right store for a
token that long: there is nothing to brute-force, so a slow password hash would buy
nothing. Matching compares against every entry in constant time and returns only after
all comparisons.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from sentinel.trust.canonical import CanonicalError, strict_loads

FORMAT = "sentinel.reviewers/1"
ROLES = ("HUMAN_REVIEWER", "SENIOR_REVIEWER")
ROLE_RANK = {"HUMAN_REVIEWER": 1, "SENIOR_REVIEWER": 2}
# Words that denote the system or a model: an id with one as a component (split on . _ -)
# is refused -- ``sentinel``, ``sentinel-bot``, ``ai-reviewer``, ``claude``, ``gpt-4o``. A
# name check is hygiene for the audit trail, not the control: authority comes from the
# credential the operator issued, and the operator owns the ids.
RESERVED_IDS = frozenset(
    {"sentinel", "system", "automation", "auto", "agent", "ai", "model", "llm", "bot", "human"}
)
MODEL_NAMES = frozenset({"claude", "anthropic", "gpt", "openai", "gemini", "llama", "copilot"})
# Applied with ``fullmatch``: ``$`` alone also matches before a final newline.
_ID = re.compile(r"[a-z][a-z0-9._-]{1,39}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CREDENTIAL_ID = re.compile(r"cred-[0-9a-f]{12}")


class ReviewerRegistryError(ValueError):
    """The registry is malformed; loading fails closed (nobody can act)."""


@dataclass(frozen=True)
class Reviewer:
    reviewer_id: str
    name: str
    role: str
    authority_limit: int  # INR: the largest case amount this reviewer may approve
    credential_id: str  # names the credential in the audit chain (never the token)
    active: bool = True

    @property
    def rank(self) -> int:
        return ROLE_RANK[self.role]


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def credential_id(digest: str) -> str:
    """The credential's name in the audit chain: derived from its digest, never the token."""
    return "cred-" + digest[:12]


def reserved(reviewer_id: str) -> bool:
    """Whether an id names the system or a model (in whole or as a component)."""
    return bool(set(re.split(r"[._-]", reviewer_id)) & (RESERVED_IDS | MODEL_NAMES))


def issue_token() -> str:
    return "srv_" + secrets.token_urlsafe(32)


@dataclass(frozen=True)
class _Entry:
    reviewer: Reviewer
    token_sha256: str


class ReviewerRegistry:
    def __init__(self, entries: tuple[_Entry, ...] = (), origin: str = "empty") -> None:
        self._entries = entries
        self.origin = origin

    # ---- authentication -------------------------------------------------------------
    def authenticate(self, token: str | None) -> Reviewer | None:
        """The active reviewer holding ``token``, or None. Every entry is compared (in
        constant time) whatever matches, so timing does not reveal which one did."""
        if not token or not isinstance(token, str) or len(token) > 200:
            return None
        presented = token_digest(token)
        found: Reviewer | None = None
        for e in self._entries:
            if hmac.compare_digest(presented, e.token_sha256):
                found = e.reviewer
        return found if found is not None and found.active else None

    def get(self, reviewer_id: str) -> Reviewer | None:
        return next(
            (e.reviewer for e in self._entries if e.reviewer.reviewer_id == reviewer_id), None
        )

    def reviewers(self) -> list[Reviewer]:
        return [e.reviewer for e in self._entries]

    # ---- administration (operator tooling) ------------------------------------------
    def add(
        self, reviewer_id: str, name: str, role: str, authority_limit: int
    ) -> tuple[ReviewerRegistry, str]:
        """A new reviewer and their one-time token (shown once, stored only hashed)."""
        if self.get(reviewer_id) is not None:
            raise ReviewerRegistryError(f"reviewer {reviewer_id!r} exists")
        token = issue_token()
        r = _validate(
            Reviewer(reviewer_id, name, role, authority_limit, credential_id(token_digest(token)))
        )
        return (
            ReviewerRegistry(self._entries + (_Entry(r, token_digest(token)),), self.origin),
            token,
        )

    def deactivate(self, reviewer_id: str) -> ReviewerRegistry:
        if self.get(reviewer_id) is None:
            raise ReviewerRegistryError(f"no reviewer {reviewer_id!r}")
        return ReviewerRegistry(
            tuple(
                (
                    _Entry(replace(e.reviewer, active=False), e.token_sha256)
                    if e.reviewer.reviewer_id == reviewer_id
                    else e
                )
                for e in self._entries
            ),
            self.origin,
        )

    # ---- (de)serialisation -----------------------------------------------------------
    def to_json(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "reviewers": [
                {
                    "reviewer_id": e.reviewer.reviewer_id,
                    "name": e.reviewer.name,
                    "role": e.reviewer.role,
                    "authority_limit": e.reviewer.authority_limit,
                    "credential_id": e.reviewer.credential_id,
                    "active": e.reviewer.active,
                    "token_sha256": e.token_sha256,
                }
                for e in self._entries
            ],
        }

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=2) + "\n"

    @classmethod
    def from_json(cls, doc: object, *, origin: str = "inline") -> ReviewerRegistry:
        if not isinstance(doc, dict) or doc.get("format") != FORMAT:
            raise ReviewerRegistryError(f"a reviewer registry is an object with format {FORMAT!r}")
        if set(doc) - {"format", "reviewers"} or not isinstance(doc.get("reviewers"), list):
            raise ReviewerRegistryError("a reviewer registry has only format and a reviewers list")
        entries: list[_Entry] = []
        allowed = {
            "reviewer_id",
            "name",
            "role",
            "authority_limit",
            "credential_id",
            "active",
            "token_sha256",
        }
        for i, e in enumerate(doc["reviewers"]):
            if not isinstance(e, dict) or set(e) - allowed:
                raise ReviewerRegistryError(f"reviewers[{i}]: unknown or malformed fields")
            try:
                for k in ("reviewer_id", "name", "role", "credential_id", "token_sha256"):
                    if not isinstance(e[k], str):
                        raise ReviewerRegistryError(f"{k} must be a string")
                r = _validate(
                    Reviewer(
                        e["reviewer_id"],
                        e["name"],
                        e["role"],
                        e["authority_limit"],
                        e["credential_id"],
                        e.get("active", True),
                    )
                )
                digest = e["token_sha256"]
                if not _HEX64.fullmatch(digest):
                    raise ReviewerRegistryError("token_sha256 must be 64 hex characters")
                if r.credential_id != credential_id(digest):
                    # derived from the digest: it cannot be blank, shared or the token itself
                    raise ReviewerRegistryError("credential_id does not name this credential")
            except (KeyError, TypeError) as err:
                raise ReviewerRegistryError(f"reviewers[{i}]: {err}") from None
            except ReviewerRegistryError as err:
                raise ReviewerRegistryError(f"reviewers[{i}]: {err}") from None
            if any(x.reviewer.reviewer_id == r.reviewer_id for x in entries):
                raise ReviewerRegistryError(f"reviewers[{i}]: duplicate id {r.reviewer_id}")
            if any(x.token_sha256 == digest for x in entries):
                raise ReviewerRegistryError(f"reviewers[{i}]: a credential is shared")
            entries.append(_Entry(r, digest))
        return cls(tuple(entries), origin)

    @classmethod
    def load(cls, path: str | Path) -> ReviewerRegistry:
        p = Path(path)
        try:
            doc = strict_loads(p.read_bytes())
        except (OSError, CanonicalError) as e:
            raise ReviewerRegistryError(f"unreadable reviewer registry {p}: {e}") from None
        return cls.from_json(doc, origin=str(p))


def _validate(r: Reviewer) -> Reviewer:
    if not _ID.fullmatch(r.reviewer_id) or reserved(r.reviewer_id):
        raise ReviewerRegistryError(
            f"reviewer id {r.reviewer_id!r} must be a lowercase identifier that names neither "
            "the system nor a model"
        )
    if not _CREDENTIAL_ID.fullmatch(r.credential_id):
        raise ReviewerRegistryError("credential_id must be cred- and 12 hex characters")
    if not r.name or len(r.name) > 80 or any(ord(c) < 32 for c in r.name):
        raise ReviewerRegistryError("name must be 1-80 printable characters")
    if r.role not in ROLES:
        raise ReviewerRegistryError(f"role must be one of {ROLES}")
    if isinstance(r.authority_limit, bool) or not isinstance(r.authority_limit, int):
        raise ReviewerRegistryError("authority_limit must be an integer amount")
    if r.authority_limit < 0:
        raise ReviewerRegistryError("authority_limit must not be negative")
    if not isinstance(r.active, bool):
        raise ReviewerRegistryError("active must be a boolean")
    return r
