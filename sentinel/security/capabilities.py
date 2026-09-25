"""Capability security: what may happen, who may make it happen, and what it
takes.

Every consequential capability declares its risk, reversibility, monetary
impact, the actors allowed to invoke it, the authorization it requires and the
amount above which a human must sign off. The values are **Sentinel demo
policy values**, not claimed industry standards.

The structural invariant: ``ActorKind.AI_AGENT`` is never in the allowed-actor
set of any consequential capability. A model can *recommend* a refund; only the
deterministic system path (under policy) or a human can *execute* one.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sentinel.domain.decisions import Authorization
from sentinel.domain.enums import (
    ActorKind,
    AuthorizationStatus,
    Capability,
    PolicyOutcome,
    RiskLevel,
)


class AuthorizationLevel(StrEnum):
    NONE = "NONE"  # anyone with access may invoke
    SYSTEM_POLICY = "SYSTEM_POLICY"  # the deterministic path may invoke under policy
    HUMAN_REVIEWER = "HUMAN_REVIEWER"  # a human must approve
    SENIOR_REVIEWER = "SENIOR_REVIEWER"  # a senior human must approve


@dataclass(frozen=True)
class CapabilitySpec:
    capability: Capability
    risk: RiskLevel
    irreversible: bool
    financial_effect: bool
    required_authorization: AuthorizationLevel
    allowed_actors: frozenset[ActorKind]
    human_review_threshold: int | None  # amount (INR) above which a human must sign
    description: str

    @property
    def consequential(self) -> bool:
        """A capability whose execution matters: it is irreversible, moves money, or
        is reserved to a human (closing a fraud case or overriding a risk score has no
        direct monetary effect, but an agent doing it is exactly the failure the
        registry exists to prevent, so it counts as a breach when it executes)."""
        return (
            self.irreversible
            or self.financial_effect
            or self.required_authorization
            in (AuthorizationLevel.HUMAN_REVIEWER, AuthorizationLevel.SENIOR_REVIEWER)
        )


_HUMANS = frozenset({ActorKind.HUMAN_REVIEWER, ActorKind.SENIOR_REVIEWER})
_SYSTEM_AND_HUMANS = _HUMANS | {ActorKind.SYSTEM}
_EVERYONE = _SYSTEM_AND_HUMANS | {ActorKind.AI_AGENT}


def _spec(
    cap: Capability,
    risk: RiskLevel,
    *,
    irreversible: bool,
    financial: bool,
    auth: AuthorizationLevel,
    actors: frozenset[ActorKind],
    threshold: int | None,
    desc: str,
) -> CapabilitySpec:
    return CapabilitySpec(cap, risk, irreversible, financial, auth, actors, threshold, desc)


REGISTRY: dict[Capability, CapabilitySpec] = {
    Capability.READ_TRANSACTION: _spec(
        Capability.READ_TRANSACTION,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Read a transaction record.",
    ),
    Capability.READ_ACCOUNT: _spec(
        Capability.READ_ACCOUNT,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Read an account record.",
    ),
    Capability.READ_MERCHANT: _spec(
        Capability.READ_MERCHANT,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Read a merchant record.",
    ),
    Capability.CREATE_CASE: _spec(
        Capability.CREATE_CASE,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Open an investigation case.",
    ),
    Capability.CREATE_ALERT: _spec(
        Capability.CREATE_ALERT,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Raise an alert for a human.",
    ),
    Capability.RECOMMEND_REFUND: _spec(
        Capability.RECOMMEND_REFUND,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Recommend (not execute) a refund.",
    ),
    Capability.RECOMMEND_ACTION: _spec(
        Capability.RECOMMEND_ACTION,
        RiskLevel.LOW,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.NONE,
        actors=_EVERYONE,
        threshold=None,
        desc="Recommend (not execute) an action.",
    ),
    Capability.APPROVE_REFUND: _spec(
        Capability.APPROVE_REFUND,
        RiskLevel.HIGH,
        irreversible=True,
        financial=True,
        auth=AuthorizationLevel.SYSTEM_POLICY,
        actors=_SYSTEM_AND_HUMANS,
        threshold=50_000,
        desc="Pay a refund to the cardholder. Money leaves.",
    ),
    Capability.APPROVE_TRANSACTION: _spec(
        Capability.APPROVE_TRANSACTION,
        RiskLevel.HIGH,
        irreversible=True,
        financial=True,
        auth=AuthorizationLevel.SYSTEM_POLICY,
        actors=_SYSTEM_AND_HUMANS,
        threshold=150_000,
        desc="Authorise a payment to proceed.",
    ),
    Capability.APPROVE_MERCHANT: _spec(
        Capability.APPROVE_MERCHANT,
        RiskLevel.HIGH,
        irreversible=True,
        financial=True,
        auth=AuthorizationLevel.SYSTEM_POLICY,
        actors=_SYSTEM_AND_HUMANS,
        threshold=None,
        desc="Onboard a merchant so it can transact.",
    ),
    Capability.FREEZE_ACCOUNT: _spec(
        Capability.FREEZE_ACCOUNT,
        RiskLevel.MEDIUM,
        irreversible=False,
        financial=True,
        auth=AuthorizationLevel.SYSTEM_POLICY,
        actors=_SYSTEM_AND_HUMANS,
        threshold=None,
        desc="Temporarily freeze an account (reversible, protective).",
    ),
    Capability.UNFREEZE_ACCOUNT: _spec(
        Capability.UNFREEZE_ACCOUNT,
        RiskLevel.HIGH,
        irreversible=False,
        financial=True,
        auth=AuthorizationLevel.HUMAN_REVIEWER,
        actors=_HUMANS,
        threshold=None,
        desc="Lift a freeze. Only a human may do this.",
    ),
    Capability.CHANGE_PAYOUT: _spec(
        Capability.CHANGE_PAYOUT,
        RiskLevel.CRITICAL,
        irreversible=True,
        financial=True,
        auth=AuthorizationLevel.HUMAN_REVIEWER,
        actors=_HUMANS,
        threshold=0,
        desc="Change where money is paid out to. Classic account-takeover target.",
    ),
    Capability.RELEASE_FUNDS: _spec(
        Capability.RELEASE_FUNDS,
        RiskLevel.CRITICAL,
        irreversible=True,
        financial=True,
        auth=AuthorizationLevel.SENIOR_REVIEWER,
        actors=frozenset({ActorKind.SENIOR_REVIEWER}),
        threshold=0,
        desc="Release held funds. Senior human only.",
    ),
    Capability.CLOSE_CASE: _spec(
        Capability.CLOSE_CASE,
        RiskLevel.MEDIUM,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.HUMAN_REVIEWER,
        actors=_HUMANS,
        threshold=None,
        desc="Close an investigation. A model may never close its own case.",
    ),
    Capability.ALTER_RISK: _spec(
        Capability.ALTER_RISK,
        RiskLevel.HIGH,
        irreversible=False,
        financial=False,
        auth=AuthorizationLevel.SENIOR_REVIEWER,
        actors=frozenset({ActorKind.SENIOR_REVIEWER}),
        threshold=None,
        desc="Override a computed risk score.",
    ),
    Capability.SKIP_REVIEW: _spec(
        Capability.SKIP_REVIEW,
        RiskLevel.CRITICAL,
        irreversible=True,
        financial=True,
        auth=AuthorizationLevel.SENIOR_REVIEWER,
        actors=frozenset(),
        threshold=None,
        desc="Bypass human review. No actor may invoke this.",
    ),
}

CONSEQUENTIAL: frozenset[Capability] = frozenset(c for c, s in REGISTRY.items() if s.consequential)


def spec(capability: Capability) -> CapabilitySpec:
    return REGISTRY[capability]


def matrix() -> list[dict[str, Any]]:
    """The security boundary as data: one row per capability with its risk,
    irreversibility, monetary impact, allowed actors, required authorization,
    human-review threshold and the policy conditions that gate it. Rendered into
    docs/SECURITY_MODEL.md, GET /v1/capabilities and `sentinel capability list`."""
    from sentinel.policy.loader import DEFAULT_REGISTRY

    gates: dict[str, set[str]] = {}
    for p in DEFAULT_REGISTRY.all():
        for r in p.rules:
            for c in r.when:
                if c.field == "requested_capability":
                    vals = c.value if isinstance(c.value, (list, tuple)) else [c.value]
                    for v in vals:
                        gates.setdefault(str(v), set()).add(f"{p.key}:{r.rule_id}")
    rows: list[dict[str, Any]] = []
    for cap, s in REGISTRY.items():
        rows.append(
            {
                "capability": cap.value,
                "risk": s.risk.value,
                "irreversible": s.irreversible,
                "financial_effect": s.financial_effect,
                "consequential": s.consequential,
                "allowed_actors": sorted(a.value for a in s.allowed_actors),
                "ai_agent_allowed": ActorKind.AI_AGENT in s.allowed_actors,
                "required_authorization": s.required_authorization.value,
                "human_review_threshold": s.human_review_threshold,
                "requires_verified_evidence": s.consequential,
                "policy_gates": sorted(gates.get(cap.value, ())),
                "description": s.description,
            }
        )
    return rows


def is_consequential(capability: Capability | None) -> bool:
    return capability is not None and capability in CONSEQUENTIAL


def authorize(
    capability: Capability | None,
    *,
    actor: ActorKind,
    amount: int,
    policy_outcome: PolicyOutcome,
    evidence_supported: bool,
) -> Authorization:
    """Deterministic authorization for one requested capability.

    The model's wish never enters here -- ``capability`` is what the *decision
    path* is considering executing, ``actor`` is who is asking (SYSTEM for the
    automated path), and policy/evidence are trusted inputs."""
    if capability is None:
        return Authorization(
            AuthorizationStatus.GRANTED, None, actor, "no consequential capability requested"
        )
    s = REGISTRY[capability]
    if actor not in s.allowed_actors:
        return Authorization(
            AuthorizationStatus.DENIED,
            capability,
            actor,
            f"{actor.value} may not invoke {capability.value} (allowed: "
            f"{', '.join(sorted(a.value for a in s.allowed_actors)) or 'nobody'})",
        )
    if policy_outcome is PolicyOutcome.BLOCK:
        return Authorization(AuthorizationStatus.DENIED, capability, actor, "policy outcome BLOCK")
    if s.consequential and not evidence_supported:
        return Authorization(
            AuthorizationStatus.DENIED,
            capability,
            actor,
            "consequential capability requires verified evidence supporting it",
        )
    if policy_outcome in (PolicyOutcome.REQUIRE_HUMAN_REVIEW, PolicyOutcome.TEMPORARY_HOLD):
        return Authorization(
            AuthorizationStatus.PENDING_HUMAN,
            capability,
            actor,
            f"policy outcome {policy_outcome.value}",
            requires_human=True,
        )
    if actor is ActorKind.SYSTEM and s.required_authorization in (
        AuthorizationLevel.HUMAN_REVIEWER,
        AuthorizationLevel.SENIOR_REVIEWER,
    ):
        return Authorization(
            AuthorizationStatus.PENDING_HUMAN,
            capability,
            actor,
            f"{capability.value} requires {s.required_authorization.value}",
            requires_human=True,
        )
    if (
        s.human_review_threshold is not None
        and amount > s.human_review_threshold
        and actor is ActorKind.SYSTEM
    ):
        return Authorization(
            AuthorizationStatus.PENDING_HUMAN,
            capability,
            actor,
            f"amount {amount:,} exceeds human-review threshold {s.human_review_threshold:,}",
            requires_human=True,
        )
    if policy_outcome is PolicyOutcome.STEP_UP:
        return Authorization(
            AuthorizationStatus.GRANTED,
            capability,
            actor,
            "authorized subject to step-up authentication",
        )
    return Authorization(AuthorizationStatus.GRANTED, capability, actor, "authorized under policy")
