"""Capability security: who may make what happen."""

import pytest

from sentinel.domain.enums import ActorKind, AuthorizationStatus, Capability, PolicyOutcome
from sentinel.security import capabilities as caps


def test_ai_agent_never_allowed_on_consequential_capabilities():
    for c in caps.CONSEQUENTIAL:
        assert ActorKind.AI_AGENT not in caps.spec(c).allowed_actors, c


def test_every_capability_has_a_spec():
    for c in Capability:
        assert c in caps.REGISTRY


def test_refund_within_limit_and_supported_is_granted_to_system():
    a = caps.authorize(
        Capability.APPROVE_REFUND,
        actor=ActorKind.SYSTEM,
        amount=18_000,
        policy_outcome=PolicyOutcome.ALLOW,
        evidence_supported=True,
    )
    assert a.status is AuthorizationStatus.GRANTED


def test_refund_over_threshold_is_pending_human():
    a = caps.authorize(
        Capability.APPROVE_REFUND,
        actor=ActorKind.SYSTEM,
        amount=185_000,
        policy_outcome=PolicyOutcome.ALLOW,
        evidence_supported=True,
    )
    assert a.status is AuthorizationStatus.PENDING_HUMAN and a.requires_human


def test_unsupported_evidence_denies_consequential():
    a = caps.authorize(
        Capability.APPROVE_REFUND,
        actor=ActorKind.SYSTEM,
        amount=1,
        policy_outcome=PolicyOutcome.ALLOW,
        evidence_supported=False,
    )
    assert a.status is AuthorizationStatus.DENIED


def test_policy_block_denies_even_supported():
    a = caps.authorize(
        Capability.APPROVE_REFUND,
        actor=ActorKind.SYSTEM,
        amount=1,
        policy_outcome=PolicyOutcome.BLOCK,
        evidence_supported=True,
    )
    assert a.status is AuthorizationStatus.DENIED


@pytest.mark.parametrize(
    "cap",
    [
        Capability.UNFREEZE_ACCOUNT,
        Capability.CHANGE_PAYOUT,
        Capability.RELEASE_FUNDS,
        Capability.CLOSE_CASE,
        Capability.ALTER_RISK,
    ],
)
def test_human_only_capabilities_never_granted_to_system(cap):
    a = caps.authorize(
        cap,
        actor=ActorKind.SYSTEM,
        amount=0,
        policy_outcome=PolicyOutcome.ALLOW,
        evidence_supported=True,
    )
    assert a.status is not AuthorizationStatus.GRANTED


def test_skip_review_has_no_allowed_actor():
    for actor in ActorKind:
        a = caps.authorize(
            Capability.SKIP_REVIEW,
            actor=actor,
            amount=0,
            policy_outcome=PolicyOutcome.ALLOW,
            evidence_supported=True,
        )
        assert a.status is AuthorizationStatus.DENIED


def test_no_capability_is_trivially_granted():
    a = caps.authorize(
        None,
        actor=ActorKind.AI_AGENT,
        amount=0,
        policy_outcome=PolicyOutcome.ALLOW,
        evidence_supported=False,
    )
    assert a.status is AuthorizationStatus.GRANTED and a.capability is None
