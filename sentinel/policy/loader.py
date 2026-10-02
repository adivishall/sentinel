"""Load and register policies. JSON is canonical (zero dependencies); a
``.yaml`` file is accepted when PyYAML happens to be installed."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.domain.enums import PolicyOutcome, Workflow
from sentinel.domain.ids import content_hash
from sentinel.policy.engine import PolicyValidationError, validate
from sentinel.policy.models import Condition, Policy, Rule
from sentinel.policy.release import (
    RELEASES_FILE,
    Activation,
    PolicyRelease,
    ReleaseBook,
    ReleaseStatus,
    resolve,
)
from sentinel.trust.issuer import utc_now
from sentinel.trust.keys import TrustStore, format_ts

POLICY_DIR = Path(__file__).parent / "policies"
MANIFEST = "MANIFEST.json"
# the policy trust root shipped with Sentinel: outside the policy directory, public keys only
SHIPPED_POLICY_ROOT = Path(__file__).parent.parent / "trust" / "policy_root.json"


class PolicyIntegrityError(PolicyValidationError):
    """A policy file does not match the digest pinned for its version (edited in place,
    added without pinning, or deleted). Loading fails closed: nothing is registered."""


def policy_digest(policy: Policy) -> str:
    """Full SHA-256 of the canonical policy document (``content_hash`` is its prefix)."""
    return content_hash(policy.to_dict(), length=64)


def _read_manifest(path: Path) -> dict[str, str]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        pinned = doc["policies"]
        assert isinstance(pinned, dict)
    except (OSError, ValueError, KeyError, AssertionError) as e:
        raise PolicyIntegrityError(f"unreadable policy manifest {path}: {e}") from e
    return {str(k): str(v) for k, v in pinned.items()}


def verify_manifest(policies: list[Policy], path: Path) -> None:
    """Every loaded version is pinned with a matching digest and every pinned version is
    present (replay needs historical versions). All problems are reported together."""
    if not path.exists():
        raise PolicyIntegrityError(f"missing policy manifest {path}")
    pinned = _read_manifest(path)
    problems: list[str] = []
    seen = set()
    for p in policies:
        seen.add(p.key)
        want = pinned.get(p.key)
        if want is None:
            problems.append(f"{p.key} is not pinned in {MANIFEST}")
        elif want != policy_digest(p):
            problems.append(
                f"{p.key} does not match its pinned digest (edited in place? a changed "
                "policy needs a new version)"
            )
    problems += [f"{k} is pinned but its file is missing" for k in sorted(set(pinned) - seen)]
    if problems:
        raise PolicyIntegrityError("; ".join(problems))


def pin_manifest(directory: str | Path = POLICY_DIR) -> list[str]:
    """Pin versions that are not yet in the manifest. An already-pinned version is never
    re-pinned: changing a shipped version is refused, so a policy change is a new version.
    Returns the keys added."""
    d = Path(directory)
    path = d / MANIFEST
    pinned = _read_manifest(path) if path.exists() else {}
    added = []
    for p in (load_policy(f) for f in _policy_files(d)):
        digest = policy_digest(p)
        if p.key in pinned and pinned[p.key] != digest:
            raise PolicyIntegrityError(
                f"{p.key} is already pinned with different content; add a new version instead"
            )
        if p.key not in pinned:
            pinned[p.key] = digest
            added.append(p.key)
    path.write_text(
        json.dumps({"algorithm": "sha256", "policies": dict(sorted(pinned.items()))}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return added


def _policy_files(d: Path) -> list[Path]:
    return sorted(f for f in d.glob("*.json") if f.name not in (MANIFEST, RELEASES_FILE)) + sorted(
        d.glob("*.y*ml")
    )


def _as_list(v: object) -> list[object]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise PolicyValidationError("expected a list")
    return list(v)


_DOC_KEYS = frozenset(
    {
        "policy_id",
        "version",
        "workflow",
        "description",
        "rules",
        "default_outcome",
        "required_fields",
        "effective_from",
    }
)
_RULE_KEYS = frozenset({"id", "when", "outcome", "reason"})
_COND_KEYS = frozenset({"field", "op", "value"})


def _json_native(v: object, where: str) -> None:
    """A rule value must be a JSON value (str, int, float, bool, null, or a list of them).
    A YAML date or a byte string stringifies to text another document could hold, so two
    different documents would share a digest; refuse it instead."""
    if v is None or isinstance(v, (str, bool, int, float)):
        return
    if isinstance(v, list):
        for x in v:
            _json_native(x, where)
        return
    raise PolicyValidationError(f"{where}: value {v!r} is not a JSON value ({type(v).__name__})")


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise PolicyValidationError(
                f"duplicate key {k!r}: a reviewer and the engine could read different values"
            )
        out[k] = v
    return out


def _strict(obj: object, allowed: frozenset[str], where: str) -> None:
    """Fail closed on keys the engine does not read: a misspelt ``"unless"`` or an
    ``"enabled": false`` would otherwise be silently ignored."""
    if not isinstance(obj, dict):
        raise PolicyValidationError(f"{where} must be a mapping")
    extra = sorted(set(obj) - allowed)
    if extra:
        raise PolicyValidationError(f"{where}: unknown keys {extra}; allowed {sorted(allowed)}")


def _parse(doc: dict[str, object]) -> Policy:
    _strict(doc, _DOC_KEYS, "policy")
    if "default_outcome" not in doc:
        # No implicit ALLOW: the document states what happens when no rule matches.
        raise PolicyValidationError("policy must declare default_outcome")
    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PolicyValidationError(f"version must be a positive integer, got {version!r}")
    try:
        rules = []
        for r in _as_list(doc.get("rules", [])):
            _strict(r, _RULE_KEYS, f"rule {r.get('id') if isinstance(r, dict) else r!r}")
            assert isinstance(r, dict)
            for c in _as_list(r["when"]):
                _strict(c, _COND_KEYS, f"rule {r.get('id')!r} condition")
                assert isinstance(c, dict)
                _json_native(c.get("value"), f"rule {r.get('id')!r} condition")
            conds = tuple(
                Condition(str(c["field"]), str(c["op"]), c.get("value")) for c in r["when"]
            )
            rules.append(
                Rule(
                    str(r["id"]), conds, PolicyOutcome(str(r["outcome"])), str(r.get("reason", ""))
                )
            )
        policy = Policy(
            policy_id=str(doc["policy_id"]),
            version=int(doc["version"]),  # type: ignore[call-overload]
            workflow=Workflow(str(doc["workflow"])),
            description=str(doc.get("description", "")),
            rules=tuple(rules),
            default_outcome=PolicyOutcome(str(doc["default_outcome"])),
            required_fields=tuple(str(x) for x in _as_list(doc.get("required_fields", []))),
            effective_from=str(doc.get("effective_from", "")),
        )
    except (KeyError, ValueError, TypeError, AssertionError) as e:
        raise PolicyValidationError(f"malformed policy document: {e}") from e
    validate(policy)
    return policy


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as e:  # pragma: no cover
            raise PolicyValidationError("YAML policies need PyYAML; use JSON") from e
        doc = yaml.safe_load(text)
    else:
        doc = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    if not isinstance(doc, dict):
        raise PolicyValidationError("policy document must be a mapping")
    return _parse(doc)


def policy_from_dict(doc: dict[str, object]) -> Policy:
    return _parse(doc)


class PolicyRegistry:
    def __init__(
        self,
        *,
        autoload: str | Path | None = None,
        signed: bool = False,
        trust: TrustStore | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        """``autoload``: a directory loaded (and verified) on first use rather than at
        construction, so importing the package never fails but using an unverified
        policy set always does -- and ``sentinel policy pin`` can still run.

        ``signed``: every loaded version must carry a verified release
        (``sentinel.policy.release``), and the active version of each policy is the one a
        signed activation in effect names -- never simply the highest number. ``trust``
        is the policy trust root (default: ``policy_trust()``, outside the directory)."""
        self._policies: dict[tuple[str, int], Policy] = {}
        self._autoload = Path(autoload) if autoload is not None else None
        self.signed = signed
        self._trust = trust
        self._clock = clock
        self._activations: dict[str, list[Activation]] = {}
        self._floor: dict[str, int] = {}
        self.release_problems: tuple[str, ...] = ()
        self.release_origin = "unsigned"
        self.trust_root = "none"

    def _ensure(self) -> None:
        if self._autoload is not None:
            d, self._autoload = self._autoload, None
            try:
                self.load_dir(d)
            except Exception:
                self._autoload = d  # stay unusable: every later use raises again
                raise

    def register(self, policy: Policy) -> Policy:
        if policy.release is None:
            policy = replace(
                policy,
                release=PolicyRelease(
                    ReleaseStatus.UNSIGNED,
                    policy.policy_id,
                    policy.version,
                    policy_digest(policy),
                    reason="registered without a release (unsigned registry)",
                ),
            )
        self._policies[(policy.policy_id, policy.version)] = policy
        return policy

    def load_dir(self, directory: str | Path = POLICY_DIR, *, pinned: bool | None = None) -> int:
        """Load every policy in ``directory``. The shipped directory is always verified
        against its manifest; another directory is verified when it has one (or when
        ``pinned=True``). A signed registry also verifies every version's release against
        the policy trust root and refuses any version without one. Verification happens
        before anything is registered."""
        d = Path(directory)
        if self.signed and any(Path(f).suffix in (".yaml", ".yml") for f in _policy_files(d)):
            raise PolicyIntegrityError(
                "signed policies are JSON only (YAML typing is not canonical)"
            )
        policies = [load_policy(f) for f in _policy_files(d)]
        if pinned is None:
            pinned = d.resolve() == POLICY_DIR.resolve() or (d / MANIFEST).exists()
        if pinned:
            verify_manifest(policies, d / MANIFEST)
        if self.signed:
            policies = self._verify_releases(policies, d)
        for p in policies:
            self.register(p)
        return len(policies)

    def _verify_releases(self, policies: list[Policy], d: Path) -> list[Policy]:
        if any(Path(f).suffix in (".yaml", ".yml") for f in _policy_files(d)):
            raise PolicyIntegrityError(
                "signed policies are JSON only (YAML typing is not canonical)"
            )
        if not policies:
            raise PolicyIntegrityError(f"no policies in {d}: nothing to decide with")
        try:
            trust = self._trust if self._trust is not None else policy_trust()
        except (ValueError, OSError) as e:
            raise PolicyIntegrityError(f"the policy trust root does not load: {e}") from None
        try:
            book = ReleaseBook.load(d / RELEASES_FILE)
        except ValueError as e:
            raise PolicyIntegrityError(str(e)) from None
        res = resolve(policies, book, trust, self._clock())
        refused = [r for r in res.releases.values() if not r.verified]
        if refused:
            raise PolicyIntegrityError(
                "policy versions without a verified release: "
                + "; ".join(
                    f"{r.policy_id}@v{r.version} {r.status.value} ({r.reason})" for r in refused
                )
            )
        fatal = [
            x
            for x in res.problems
            if "equivocation" in x or "effective_from" in x and "unreadable" in x
        ]
        if fatal:
            raise PolicyIntegrityError("; ".join(fatal))
        self._activations = res.activations
        self.release_problems = res.problems
        # file names only: /v1/system shows this, and paths on disk are not its business
        self.release_origin = f"{Path(book.origin).name} verified against {Path(trust.origin).name}"
        self.trust_root = (
            "operator"
            if self._trust is not None or os.environ.get("SENTINEL_POLICY_TRUST")
            else "shipped"
        )
        return [replace(p, release=res.releases[(p.policy_id, p.version)]) for p in policies]

    def set_activation_floor(self, policy_id: str, sequence: int) -> None:
        """The highest activation sequence already acted on (read from the audit chain):
        an older activation is a rollback and is refused."""
        self._floor[policy_id] = max(sequence, self._floor.get(policy_id, 0))

    def versions(self, policy_id: str) -> list[int]:
        self._ensure()
        return sorted(v for (pid, v) in self._policies if pid == policy_id)

    def get(self, policy_id: str, version: int | None = None) -> Policy:
        """``version=None`` is the active version. Naming a version is a historical lookup,
        which only replay and what-if runs make (``sentinel.decision.authority``)."""
        if version is None:
            return self.active(policy_id)
        versions = self.versions(policy_id)
        if not versions:
            raise KeyError(f"unknown policy {policy_id!r}")
        try:
            return self._policies[(policy_id, version)]
        except KeyError:
            raise KeyError(
                f"policy {policy_id!r} has no version {version}; have {versions}"
            ) from None

    def active(self, policy_id: str) -> Policy:
        """The active version. Unsigned registry: the highest version shipped. Signed
        registry: the version named by the highest-sequence verified activation in effect
        now -- explicit, never before the document's effective_from, and never older than
        an activation already acted on. Authoritative evaluation always uses it; no
        request parameter selects another."""
        versions = self.versions(policy_id)
        if not versions:
            raise KeyError(f"unknown policy {policy_id!r}")
        if not self.signed:
            return self._policies[(policy_id, versions[-1])]
        now = self._clock()
        acts = [a for a in self._activations.get(policy_id, []) if a.effective_from <= now]
        if not acts:
            raise PolicyIntegrityError(f"{policy_id} has no signed activation in effect")
        a = acts[0]  # highest sequence first
        floor = self._floor.get(policy_id, 0)
        if a.sequence < floor:
            raise PolicyIntegrityError(
                f"{policy_id}: activation {a.sequence} is older than activation {floor}, "
                "already acted on (rollback)"
            )
        p = self._policies[(policy_id, a.version)]
        assert p.release is not None
        return replace(
            p,
            release=replace(
                p.release,
                activation_sequence=a.sequence,
                effective_from=format_ts(a.effective_from),
            ),
        )

    def historical(self, policy_id: str) -> list[int]:
        """Versions kept only so recorded decisions can be replayed and compared."""
        active = self.active(policy_id).version
        return [v for v in self.versions(policy_id) if v != active]

    def all(self) -> list[Policy]:
        self._ensure()
        return sorted(self._policies.values(), key=lambda p: (p.policy_id, p.version))

    def release_report(self) -> dict[str, Any]:
        """Per policy: the active version and what establishes it; and every refused
        statement -- for ``/v1/system`` and ``sentinel policy verify``."""
        out: dict[str, Any] = {
            "signed": self.signed,
            "origin": self.release_origin,
            # "shipped": the root packaged with Sentinel -- it stops a writer confined to the
            # policy directory; a deployment sets SENTINEL_POLICY_TRUST to a root it controls
            "trust_root": self.trust_root,
            "problems": list(self.release_problems),
            "policies": {},
        }
        for pid in sorted({p.policy_id for p in self.all()}):
            try:
                a = self.active(pid)
                active: dict[str, Any] = a.release.to_dict() if a.release else {}
            except PolicyIntegrityError as e:
                active = {"status": "NO_ACTIVE_VERSION", "reason": str(e)}
            out["policies"][pid] = {
                "active": active,
                "versions": {
                    str(p.version): p.release.status.value if p.release else "UNSIGNED"
                    for p in self.all()
                    if p.policy_id == pid
                },
            }
        return out


def require_signed_policy() -> bool:
    """Signed policy releases are required unless ``SENTINEL_REQUIRE_SIGNED_POLICY=0``."""
    return os.environ.get("SENTINEL_REQUIRE_SIGNED_POLICY", "1").strip().lower() not in (
        "0",
        "false",
        "no",
    )


def policy_trust() -> TrustStore:
    """The policy trust root: ``SENTINEL_POLICY_TRUST`` (an operator's trust store holding
    ``policy-release`` keys), else the root shipped with Sentinel. Never the policy
    directory."""
    path = os.environ.get("SENTINEL_POLICY_TRUST")
    return TrustStore.load(path) if path else TrustStore.load(SHIPPED_POLICY_ROOT)


DEFAULT_REGISTRY = PolicyRegistry(autoload=POLICY_DIR, signed=require_signed_policy())
