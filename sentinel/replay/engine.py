"""Replay engine.

    Replay #REPLAY-1002
      Old policy: REQUIRE_HUMAN_REVIEW        New policy: BLOCK
      Changed because: risk threshold 75 -> 70

Determinism is what makes this possible: the composer is a pure function of
its snapshot, so re-running it under different *versions* isolates the
effect of the change. Overriding the model recommendation exists to show it
changes nothing on the protected path."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from sentinel.decision.composer import compose
from sentinel.decision.snapshot import restore
from sentinel.domain.decisions import AIRecommendation, Decision
from sentinel.domain.enums import Capability
from sentinel.domain.ids import new_id, now_iso
from sentinel.policy.loader import PolicyRegistry
from sentinel.policy.models import Condition, Policy, Rule
from sentinel.risk import scoring
from sentinel.risk.transaction import rescore


@dataclass(frozen=True)
class ReplayOverrides:
    policy_version: int | None = None
    risk_model: str | None = None  # e.g. "txn-1.1"
    rule_values: dict[str, object] = field(default_factory=dict)  # rule_id -> new threshold value
    ai_recommendation: str | None = None  # e.g. "approve_refund" (demonstrates irrelevance)
    ai_capability: Capability | None = None
    controls: frozenset[str] | None = None

    def describe(self) -> list[str]:
        out = []
        if self.policy_version is not None:
            out.append(f"policy version -> {self.policy_version}")
        if self.risk_model:
            out.append(f"risk model -> {self.risk_model}")
        for k, v in self.rule_values.items():
            out.append(f"rule {k} threshold -> {v!r}")
        if self.ai_recommendation:
            out.append(f"AI recommendation -> {self.ai_recommendation}")
        if self.controls is not None:
            out.append(f"controls -> {sorted(self.controls)}")
        return out


@dataclass(frozen=True)
class Diff:
    field: str
    before: object
    after: object


@dataclass(frozen=True)
class ReplayResult:
    replay_id: str
    decision_id: str
    overrides: list[str]
    original: dict[str, Any]
    replayed: dict[str, Any]
    changed: bool
    diffs: tuple[Diff, ...]
    explanation: str
    replayed_decision: Decision
    created_at: str
    # The policy version named in the snapshot no longer has the content it had at decision
    # time (the JSON was edited without a version bump). The replay ran the CURRENT content.
    policy_drift: bool = False
    # Re-deriving the original from its snapshot gave a different outcome from the one that
    # was actually recorded -- the engine changed since the decision was made.
    original_drift: bool = False

    @property
    def engine_drift(self) -> bool:
        """Alias: the recorded outcome no longer reproduces from its own snapshot."""
        return self.original_drift

    @property
    def decision_diff(self) -> list[dict[str, Any]]:
        return [{"field": d.field, "before": d.before, "after": d.after} for d in self.diffs]

    def to_dict(self) -> dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "decision_id": self.decision_id,
            "overrides": self.overrides,
            "original": self.original,
            "replayed": self.replayed,
            "changed": self.changed,
            "decision_diff": self.decision_diff,
            "diffs": self.decision_diff,
            "explanation": self.explanation,
            "created_at": self.created_at,
            "policy_drift": self.policy_drift,
            "engine_drift": self.engine_drift,
            "original_drift": self.original_drift,
        }


def _summary(d: Decision) -> dict[str, Any]:
    return {
        "final_action": d.final_action.value,
        "policy": f"{d.policy.policy_id}@v{d.policy.version}",
        "policy_outcome": d.policy.outcome.value,
        "matched_rules": list(d.policy.matched_rules),
        "risk_score": d.risk_score,
        "risk_level": d.risk_level.value,
        "authorization": d.authorization.status.value,
        "executed_capability": d.executed_capability.value if d.executed_capability else None,
        "evidence_verdict": d.evidence_verdict.value,
        "contradiction_count": d.contradiction_count,
        "ai_recommendation": (
            d.ai_recommendation.recommended_action if d.ai_recommendation else None
        ),
    }


def summary_from_stored(d: dict[str, Any]) -> dict[str, Any]:
    """The same summary read from a stored decision payload (``Decision.to_dict``), so a
    replay is compared with what was actually recorded, not with a fresh re-derivation."""
    pol = d.get("policy") or {}
    auth = d.get("authorization") or {}
    ai = d.get("ai_recommendation") or {}
    return {
        "final_action": d.get("final_action"),
        "policy": f"{pol.get('policy_id')}@v{pol.get('version')}",
        "policy_outcome": pol.get("outcome"),
        "matched_rules": list(pol.get("matched_rules") or []),
        "risk_score": d.get("risk_score"),
        "risk_level": d.get("risk_level"),
        "authorization": auth.get("status"),
        "executed_capability": d.get("executed_capability"),
        "evidence_verdict": d.get("evidence_verdict"),
        "contradiction_count": d.get("contradiction_count"),
        "ai_recommendation": ai.get("recommended_action") if ai else None,
    }


# Fields whose disagreement between the stored decision and its re-derivation means the
# engine (or its data) changed since the decision was made.
DRIFT_FIELDS = (
    "final_action",
    "policy_outcome",
    "matched_rules",
    "risk_score",
    "authorization",
    "executed_capability",
    "evidence_verdict",
)


def _with_rule_values(policy: Policy, values: dict[str, object]) -> Policy:
    rules = []
    for r in policy.rules:
        if r.rule_id in values:
            new_when = tuple(
                (
                    Condition(c.field, c.op, values[r.rule_id])
                    if c.op in (">", ">=", "<", "<=", "==")
                    else c
                )
                for c in r.when
            )
            rules.append(
                Rule(
                    r.rule_id,
                    new_when,
                    r.outcome,
                    r.reason + f" [replay override: {values[r.rule_id]!r}]",
                )
            )
        else:
            rules.append(r)
    return replace(policy, rules=tuple(rules))


class ReplayEngine:
    def __init__(self, policies: PolicyRegistry) -> None:
        self.policies = policies

    def replay(
        self,
        original: Decision,
        snapshot: dict[str, Any],
        overrides: ReplayOverrides,
        *,
        recorded: dict[str, Any] | None = None,
    ) -> ReplayResult:
        """``original`` is the canonical re-derivation of the stored decision; ``recorded``
        is the stored decision payload itself when the caller has it, so the two can be
        compared for drift."""
        inputs = restore(snapshot, self.policies, policy_version=overrides.policy_version)
        pinned = str(snapshot.get("policy", {}).get("content_hash") or "")
        policy_drift = bool(
            overrides.policy_version is None and pinned and pinned != inputs.policy.content_hash
        )
        if overrides.rule_values:
            inputs = replace(inputs, policy=_with_rule_values(inputs.policy, overrides.rule_values))
        risk = inputs.risk
        if overrides.risk_model and risk is not None:
            model = scoring.get_model(overrides.risk_model)
            if risk.entity_type == "transaction":
                inputs = replace(inputs, risk=rescore(risk.features, risk.entity_id, model))
            else:
                from sentinel.risk import account_security, monitoring
                from sentinel.risk import dispute as dispute_risk

                rules = {
                    "login": account_security.RULES,
                    "account": monitoring.RULES,
                    "dispute": dispute_risk.RULES,
                }.get(risk.entity_type)
                if rules is not None:
                    inputs = replace(
                        inputs,
                        risk=scoring.build_assessment(
                            entity_type=risk.entity_type,
                            entity_id=risk.entity_id,
                            features=risk.features,
                            model=model,
                            rules=rules,
                        ),
                    )
        if overrides.ai_recommendation is not None:
            base = inputs.ai or AIRecommendation(
                "replay", "none", None, inputs.amount, "", "replay", "replay"
            )
            inputs = replace(
                inputs,
                ai=replace(
                    base,
                    recommended_action=overrides.ai_recommendation,
                    requested_capability=overrides.ai_capability,
                ),
            )
        if overrides.controls is not None:
            inputs = replace(inputs, controls=overrides.controls)
        new = compose(inputs)
        rederived, after = _summary(original), _summary(new)
        # ``before`` is the STORED decision when the caller has it; the diff is always
        # "what was recorded" vs "what the replay produced".
        before = summary_from_stored(recorded) if recorded is not None else rederived
        diffs = tuple(Diff(k, before[k], after[k]) for k in before if before[k] != after[k])
        changed = any(
            d.field in ("final_action", "policy_outcome", "authorization", "executed_capability")
            for d in diffs
        )
        why = "; ".join(overrides.describe()) or "no overrides"
        if changed:
            expl = f"Outcome changed ({before['final_action']} -> {after['final_action']}) because: {why}."
        else:
            expl = f"Outcome unchanged ({before['final_action']}) under: {why}."
        original_drift = bool(
            recorded is not None
            and before.get("final_action") is not None
            and any(before[k] != rederived[k] for k in DRIFT_FIELDS)
        )
        if policy_drift:
            expl += (
                f" WARNING: {inputs.policy.key} no longer has the content recorded at decision "
                f"time (hash {pinned} -> {inputs.policy.content_hash}); the replay used the "
                "current content."
            )
        if original_drift:
            expl += (
                " WARNING: re-deriving the original decision from its snapshot no longer "
                f"reproduces the recorded decision (recorded {before['final_action']} / "
                f"{before['policy_outcome']} / risk {before['risk_score']}, re-derived "
                f"{rederived['final_action']} / {rederived['policy_outcome']} / risk "
                f"{rederived['risk_score']}); the engine has changed."
            )
        return ReplayResult(
            new_id("REPLAY"),
            original.decision_id,
            overrides.describe(),
            before,
            after,
            changed,
            diffs,
            expl,
            new,
            now_iso(),
            policy_drift,
            original_drift,
        )
