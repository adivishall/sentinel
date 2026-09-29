"""Replay engine.

    Replay #REPLAY-1002
      Old policy: REQUIRE_HUMAN_REVIEW        New policy: BLOCK
      Changed because: risk threshold 75 -> 70

Determinism is what makes this possible: the composer is a pure function of
its snapshot, so re-running it under different *versions* isolates the
effect of the change. Overriding the model recommendation exists to show it
changes nothing on the protected path.

What a replay compares, and why it can be trusted:

- ``original`` is what was RECORDED, anchored to the tamper-evident audit chain:
  the fields the decision's audit event carries (action, risk score, policy
  version, authorization, executed capability, evidence verdict, risk model)
  come from the audit event, and any disagreement with the stored decision is a
  ``record_issue``. The stored input snapshot is checked against the SHA-256 the
  audit event recorded, so an edited snapshot cannot replay as "no change".
- ``replayed`` is the composer's output on that snapshot under the overrides.
- ``engine_drift``: the snapshot re-derived with no overrides no longer gives
  the recorded outcome (the engine changed). ``policy_drift``: the named policy
  version no longer has the content recorded at decision time.
- ``versions`` names the policy, risk model and engine on each side.

A replay is a what-if: it is stored as a replay record (and an audit event of
kind ``replay``) and never overwrites or re-records the original decision."""

from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from typing import Any

from sentinel import __version__
from sentinel.decision.composer import compose
from sentinel.decision.snapshot import restore, snapshot_hash
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
    # policy / risk_model / engine: {"recorded": ..., "replay": ...}
    versions: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Did the stored decision and snapshot agree with the decision's audit event?
    record_verified: bool = True
    record_issues: tuple[str, ...] = ()
    # The recorded facts' provenance, and the signed statement verified again against the
    # current trust store (a key revoked since the decision shows here).
    facts: dict[str, Any] = field(default_factory=dict)

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
            "versions": self.versions,
            "record_verified": self.record_verified,
            "record_issues": list(self.record_issues),
            "facts": self.facts,
        }


def _summary(d: Decision, risk_model: str | None = None) -> dict[str, Any]:
    return {
        "final_action": d.final_action.value,
        "policy": f"{d.policy.policy_id}@v{d.policy.version}",
        "risk_model": risk_model,
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


def _snap_model(snap: dict[str, Any]) -> str | None:
    r = snap.get("risk") or {}
    return str(r["model_version"]) if r.get("model_version") else None


def summary_from_stored(d: dict[str, Any], snap: dict[str, Any] | None = None) -> dict[str, Any]:
    """The same summary read from a stored decision payload (``Decision.to_dict``), so a
    replay is compared with what was actually recorded, not with a fresh re-derivation."""
    pol = d.get("policy") or {}
    auth = d.get("authorization") or {}
    ai = d.get("ai_recommendation") or {}
    return {
        "final_action": d.get("final_action"),
        "policy": f"{pol.get('policy_id')}@v{pol.get('version')}",
        "risk_model": _snap_model(snap or {}),
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


def anchor_to_audit(
    before: dict[str, Any], snap: dict[str, Any], audit: dict[str, Any] | None
) -> tuple[dict[str, Any], list[str]]:
    """Overlay the fields the decision's audit event records onto ``before`` and list
    every disagreement. The audit chain is tamper-evident; the decisions table is not."""
    if audit is None:
        return before, ["no audit event records this decision; the stored record is unverified"]
    issues: list[str] = []
    if audit.get("kind", "decision") != "decision":
        issues.append(f"the first audit event for this decision is a {audit.get('kind')!r} event")
    detail = audit.get("detail") or {}
    want = detail.get("snapshot_hash")
    if not want:
        issues.append("the audit event has no snapshot hash; the input snapshot is unverified")
    elif snapshot_hash(snap) != want:
        issues.append("the stored input snapshot does not match the hash in its audit event")
    anchored = {
        "final_action": audit.get("action"),
        "risk_score": audit.get("risk_score"),
        "policy": f"{audit.get('policy_id')}@v{audit.get('policy_version')}",
        "executed_capability": detail.get("executed_capability"),
        "authorization": detail.get("authorization"),
        "evidence_verdict": detail.get("evidence_verdict"),
    }
    if "risk_model" in detail:
        anchored["risk_model"] = detail.get("risk_model")
    out = dict(before)
    for k, v in anchored.items():
        if out.get(k) != v:
            issues.append(f"stored {k} {out.get(k)!r} differs from its audit event ({v!r})")
            out[k] = v
    return out, issues


def _with_rule_values(policy: Policy, values: dict[str, object]) -> Policy:
    unknown = sorted(set(values) - {r.rule_id for r in policy.rules})
    if unknown:
        raise ValueError(f"{policy.key} has no rule(s) {unknown}")
    for k, v in values.items():
        number = isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)
        if not (number or isinstance(v, bool) or (isinstance(v, str) and 0 < len(v) <= 40)):
            raise ValueError(f"rule {k}: a threshold must be a finite number or a short value")
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
        audit: dict[str, Any] | None = None,
        verify: bool = False,
    ) -> ReplayResult:
        """``original`` is the canonical re-derivation of the stored decision; ``recorded``
        is the stored decision payload and ``audit`` its audit event. With ``verify`` the
        recorded side is anchored to the audit event (``anchor_to_audit``)."""
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
        rederived = _summary(original, _snap_model(snapshot))
        after = _summary(new, inputs.risk.model_version if inputs.risk is not None else None)
        # ``before`` is the STORED decision when the caller has it, anchored to its audit
        # event; the diff is always "what was recorded" vs "what the replay produced".
        before = summary_from_stored(recorded, snapshot) if recorded is not None else rederived
        issues: list[str] = []
        if verify:
            before, issues = anchor_to_audit(before, snapshot, audit)
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
        if issues:
            expl = (
                "WARNING: the stored record does not match its audit event ("
                + "; ".join(issues)
                + "). The recorded side below uses the audit event's values. "
                + expl
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
            # the recorded decision's id: ``original`` is a re-derivation with a fresh id
            (
                str(recorded.get("decision_id") or original.decision_id)
                if recorded is not None
                else original.decision_id
            ),
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
            {
                "policy": {"recorded": before["policy"], "replay": after["policy"]},
                "risk_model": {"recorded": before["risk_model"], "replay": after["risk_model"]},
                "engine": {
                    "recorded": snapshot.get("engine_version", "unrecorded (pre-2.2.0 snapshot)"),
                    "replay": __version__,
                },
            },
            not issues,
            tuple(issues),
        )
