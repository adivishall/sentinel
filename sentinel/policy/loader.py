"""Load and register policies. JSON is canonical (zero dependencies); a
``.yaml`` file is accepted when PyYAML happens to be installed."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.domain.enums import PolicyOutcome, Workflow
from sentinel.domain.ids import content_hash
from sentinel.policy.engine import PolicyValidationError, validate
from sentinel.policy.models import Condition, Policy, Rule

POLICY_DIR = Path(__file__).parent / "policies"
MANIFEST = "MANIFEST.json"


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
    return sorted(f for f in d.glob("*.json") if f.name != MANIFEST) + sorted(d.glob("*.y*ml"))


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
    try:
        rules = []
        for r in _as_list(doc.get("rules", [])):
            _strict(r, _RULE_KEYS, f"rule {r.get('id') if isinstance(r, dict) else r!r}")
            assert isinstance(r, dict)
            for c in _as_list(r["when"]):
                _strict(c, _COND_KEYS, f"rule {r.get('id')!r} condition")
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
        doc = json.loads(text)
    if not isinstance(doc, dict):
        raise PolicyValidationError("policy document must be a mapping")
    return _parse(doc)


def policy_from_dict(doc: dict[str, object]) -> Policy:
    return _parse(doc)


class PolicyRegistry:
    def __init__(self, *, autoload: str | Path | None = None) -> None:
        """``autoload``: a directory loaded (and verified) on first use rather than at
        construction, so importing the package never fails but using an unverified
        policy set always does -- and ``sentinel policy pin`` can still run."""
        self._policies: dict[tuple[str, int], Policy] = {}
        self._autoload = Path(autoload) if autoload is not None else None

    def _ensure(self) -> None:
        if self._autoload is not None:
            d, self._autoload = self._autoload, None
            try:
                self.load_dir(d)
            except PolicyValidationError:
                self._autoload = d  # stay unusable: every later use raises again
                raise

    def register(self, policy: Policy) -> Policy:
        self._policies[(policy.policy_id, policy.version)] = policy
        return policy

    def load_dir(self, directory: str | Path = POLICY_DIR, *, pinned: bool | None = None) -> int:
        """Load every policy in ``directory``. The shipped directory is always verified
        against its manifest; another directory is verified when it has one (or when
        ``pinned=True``). Verification happens before anything is registered."""
        d = Path(directory)
        policies = [load_policy(f) for f in _policy_files(d)]
        if pinned is None:
            pinned = d.resolve() == POLICY_DIR.resolve() or (d / MANIFEST).exists()
        if pinned:
            verify_manifest(policies, d / MANIFEST)
        for p in policies:
            self.register(p)
        return len(policies)

    def versions(self, policy_id: str) -> list[int]:
        self._ensure()
        return sorted(v for (pid, v) in self._policies if pid == policy_id)

    def get(self, policy_id: str, version: int | None = None) -> Policy:
        """``version=None`` is the active version. Naming a version is a historical lookup,
        which only replay and what-if runs make (``sentinel.decision.authority``)."""
        versions = self.versions(policy_id)
        if not versions:
            raise KeyError(f"unknown policy {policy_id!r}")
        v = version if version is not None else versions[-1]
        try:
            return self._policies[(policy_id, v)]
        except KeyError:
            raise KeyError(f"policy {policy_id!r} has no version {v}; have {versions}") from None

    def active(self, policy_id: str) -> Policy:
        """The configured active version: the highest version shipped. Authoritative
        evaluation always uses it; no request parameter selects another."""
        return self.get(policy_id)

    def historical(self, policy_id: str) -> list[int]:
        """Versions kept only so recorded decisions can be replayed and compared."""
        return self.versions(policy_id)[:-1]

    def all(self) -> list[Policy]:
        self._ensure()
        return sorted(self._policies.values(), key=lambda p: (p.policy_id, p.version))


DEFAULT_REGISTRY = PolicyRegistry(autoload=POLICY_DIR)
