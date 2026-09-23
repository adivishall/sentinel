"""Load and register policies. JSON is canonical (zero dependencies); a
``.yaml`` file is accepted when PyYAML happens to be installed."""

from __future__ import annotations

import json
from pathlib import Path

from sentinel.domain.enums import PolicyOutcome, Workflow
from sentinel.policy.engine import PolicyValidationError, validate
from sentinel.policy.models import Condition, Policy, Rule

POLICY_DIR = Path(__file__).parent / "policies"


def _as_list(v: object) -> list[object]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise PolicyValidationError("expected a list")
    return list(v)


def _parse(doc: dict[str, object]) -> Policy:
    try:
        rules = []
        for r in _as_list(doc.get("rules", [])):
            assert isinstance(r, dict)
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
            default_outcome=PolicyOutcome(str(doc.get("default_outcome", "ALLOW"))),
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
    def __init__(self) -> None:
        self._policies: dict[tuple[str, int], Policy] = {}

    def register(self, policy: Policy) -> Policy:
        self._policies[(policy.policy_id, policy.version)] = policy
        return policy

    def load_dir(self, directory: str | Path = POLICY_DIR) -> int:
        n = 0
        for p in sorted(Path(directory).glob("*.json")) + sorted(Path(directory).glob("*.y*ml")):
            self.register(load_policy(p))
            n += 1
        return n

    def versions(self, policy_id: str) -> list[int]:
        return sorted(v for (pid, v) in self._policies if pid == policy_id)

    def get(self, policy_id: str, version: int | None = None) -> Policy:
        versions = self.versions(policy_id)
        if not versions:
            raise KeyError(f"unknown policy {policy_id!r}")
        v = version if version is not None else versions[-1]
        try:
            return self._policies[(policy_id, v)]
        except KeyError:
            raise KeyError(f"policy {policy_id!r} has no version {v}; have {versions}") from None

    def latest_for(self, workflow: Workflow) -> Policy:
        candidates = [p for p in self._policies.values() if p.workflow is workflow]
        if not candidates:
            raise KeyError(f"no policy registered for workflow {workflow.value}")
        by_id: dict[str, Policy] = {}
        for p in candidates:
            if p.policy_id not in by_id or p.version > by_id[p.policy_id].version:
                by_id[p.policy_id] = p
        return sorted(by_id.values(), key=lambda p: p.policy_id)[0]

    def all(self) -> list[Policy]:
        return sorted(self._policies.values(), key=lambda p: (p.policy_id, p.version))


DEFAULT_REGISTRY = PolicyRegistry()
DEFAULT_REGISTRY.load_dir()
