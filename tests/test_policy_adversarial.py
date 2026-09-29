"""Adversarial audit of the policy engine and the capability registry: every way to make
a policy or an authorization fail OPEN, tried in one place. Each must fail closed.

policy downgrade / risk-model downgrade  -> tests/test_evaluation_authority.py (structural)
missing fields, mistyped fields          -> PolicyEvaluationError -> composer human review
unknown fields / keys / values           -> PolicyValidationError at load
threshold edges                          -> exact boundary behaviour, both layers agree
conflicting rules                        -> most severe wins, all matches reported
unknown capability / actor, no authz     -> DENIED; never executed
tampered policy file / hash mismatch     -> PolicyIntegrityError; nothing registered
malformed trusted records                -> human review, never a coerced number"""

from __future__ import annotations

import json
import shutil

import pytest

from sentinel.app import SentinelApp
from sentinel.data.store import SentinelStore
from sentinel.decision.composer import AUTHORIZATION, FULL, POLICY
from sentinel.decision.workflows import (
    DisputeRequest,
    KYBRequest,
    RunOptions,
    Runtime,
    run_dispute,
    run_kyb,
)
from sentinel.domain.enums import (
    ActorKind,
    AuthorizationStatus,
    Capability,
    FactKind,
    FactsSource,
    FinalAction,
    PolicyOutcome,
    ProvenanceStatus,
)
from sentinel.policy import DEFAULT_REGISTRY, evaluate
from sentinel.policy.engine import PolicyEvaluationError, PolicyValidationError
from sentinel.policy.loader import (
    MANIFEST,
    POLICY_DIR,
    PolicyIntegrityError,
    PolicyRegistry,
    pin_manifest,
    policy_from_dict,
)
from sentinel.security import capabilities
from sentinel.security.capabilities import CONSEQUENTIAL, REGISTRY, authorize
from sentinel.security.provenance import UntrustedContent
from sentinel.trust.issuer import Issuer
from sentinel.trust.keys import TrustStore

CLAIM = "My order never arrived, please refund."
LEDGER = {"amount": 12000, "delivery_status": "not_delivered", "policy_auto_limit": 50000}

# the facts these calls authorize on are the institution's own records
LOCAL = ProvenanceStatus.TRUSTED_LOCAL


_ISSUER = Issuer.ephemeral("test-ledger")
_TRUST = TrustStore.empty().with_key(_ISSUER.key)


def _dispute(ledger, opts=None):
    """A decision on the ledger as its issuer signs it (VERIFIED_EXTERNAL): these tests
    are about the policy, so the facts are the strongest kind."""
    try:
        env = _ISSUER.sign(FactKind.DISPUTE_LEDGER, "D-1", dict(ledger))
    except ValueError:  # values canonical JSON refuses (floats): the record as stored
        return run_dispute(
            Runtime(persist=False),
            DisputeRequest(
                UntrustedContent(CLAIM), ledger, facts_source=FactsSource.SYSTEM_OF_RECORD
            ),
            opts or RunOptions(),
        )
    return run_dispute(
        Runtime(persist=False, trust=_TRUST),
        DisputeRequest(UntrustedContent(CLAIM), {}, "D-1", envelope=env),
        opts or RunOptions(),
    )


def _doc(rules, **over):
    d = {
        "policy_id": "t",
        "version": 1,
        "workflow": "dispute",
        "default_outcome": "ALLOW",
        "effective_from": "2026-01-01",
        "required_fields": ["amount"],
        "rules": rules,
    }
    d.update(over)
    return d


BLOCK_BIG = [
    {"id": "big", "when": [{"field": "amount", "op": ">", "value": 50000}], "outcome": "BLOCK"}
]


# ---- missing and mistyped fields -------------------------------------------------------------
def test_missing_field_fails_closed_to_a_human_not_an_allow():
    p = policy_from_dict(_doc(BLOCK_BIG))
    with pytest.raises(PolicyEvaluationError, match="missing"):
        evaluate(p, {})
    # end to end: the composer turns an evaluation error into REQUIRE_HUMAN_REVIEW
    rt = Runtime(persist=False, policies=PolicyRegistry())
    doc = DEFAULT_REGISTRY.active("dispute-refund").to_dict()
    doc["required_fields"] = list(doc["required_fields"]) + ["registration_status"]  # never set
    rt.policies.register(policy_from_dict(doc))
    b = run_dispute(rt, DisputeRequest(UntrustedContent(CLAIM), LEDGER))
    assert b.decision.final_action is FinalAction.REQUIRE_HUMAN_REVIEW
    assert "fail-safe" in b.decision.policy.matched_rules and not b.decision.executed


@pytest.mark.parametrize("bad", ["999999", None, True, 9.5, [], {}])
def test_mistyped_field_cannot_silently_disable_a_block_rule(bad):
    p = policy_from_dict(_doc(BLOCK_BIG))
    with pytest.raises(PolicyEvaluationError, match="wrong type"):
        evaluate(p, {"amount": bad})


def test_a_fact_can_never_overwrite_a_computed_policy_field():
    """Trusted facts are merged under the computed fields: a ledger key called
    ``evidence_verdict`` or ``risk_score`` cannot rewrite them."""
    b = _dispute({**LEDGER, "delivery_status": "delivered"})
    assert b.decision.evidence_verdict.value != "SUPPORTED"
    forged = {**LEDGER, "delivery_status": "delivered", "evidence_verdict": "SUPPORTED"}
    b2 = _dispute(forged)
    assert b2.decision.final_action is b.decision.final_action and not b2.decision.executed


# ---- unknown keys, fields and values -----------------------------------------------------------
@pytest.mark.parametrize(
    "doc, needle",
    [
        (_doc(BLOCK_BIG, enabled=False), "unknown keys"),
        (_doc([{**BLOCK_BIG[0], "disabled": True}]), "unknown keys"),
        (
            _doc([{**BLOCK_BIG[0], "when": [{**BLOCK_BIG[0]["when"][0], "unless": 1}]}]),
            "unknown keys",
        ),
        ({k: v for k, v in _doc(BLOCK_BIG).items() if k != "default_outcome"}, "default_outcome"),
        (
            _doc(
                [
                    {
                        "id": "r",
                        "when": [{"field": "nope", "op": "==", "value": 1}],
                        "outcome": "BLOCK",
                    }
                ]
            ),
            "unknown field",
        ),
        (
            _doc(
                [
                    {
                        "id": "r",
                        "when": [{"field": "amount", "op": "~=", "value": 1}],
                        "outcome": "BLOCK",
                    }
                ]
            ),
            "unknown op",
        ),
        (
            _doc(
                [
                    {
                        "id": "r",
                        "when": [
                            {"field": "requested_capability", "op": "==", "value": "GRANT_ALL"}
                        ],
                        "outcome": "BLOCK",
                    }
                ]
            ),
            "unknown capability",
        ),
        (
            _doc(
                [
                    {
                        "id": "r",
                        "when": [{"field": "risk_level", "op": "in", "value": ["HIGH", "SEVERE"]}],
                        "outcome": "BLOCK",
                    }
                ]
            ),
            "can never be",
        ),
        (
            _doc(
                [
                    {
                        "id": "r",
                        "when": [{"field": "amount", "op": ">", "value": 1}],
                        "outcome": "NUKE",
                    }
                ]
            ),
            "malformed",
        ),
        (_doc([{"id": "r", "when": [], "outcome": "BLOCK"}]), "no conditions"),
        (_doc(BLOCK_BIG + BLOCK_BIG), "duplicate rule id"),
        (
            _doc(
                [
                    {
                        "id": "r",
                        "when": [{"field": "registration_status", "op": "==", "value": "shell"}],
                        "outcome": "BLOCK",
                    }
                ],
                required_fields=[],
            ),
            "required_fields",
        ),
    ],
)
def test_a_malformed_policy_is_refused_at_load(doc, needle):
    with pytest.raises(PolicyValidationError, match=needle):
        policy_from_dict(doc)


# ---- threshold edges -------------------------------------------------------------------------
@pytest.mark.parametrize(
    "amount, action",
    [(50_000, FinalAction.ALLOW), (50_001, FinalAction.REQUIRE_HUMAN_REVIEW)],
)
def test_the_auto_limit_boundary_is_exact_and_both_layers_agree(amount, action):
    b = _dispute({**LEDGER, "amount": amount})
    assert b.decision.final_action is action
    auth = authorize(
        Capability.APPROVE_REFUND,
        actor=ActorKind.SYSTEM,
        amount=amount,
        policy_outcome=PolicyOutcome.ALLOW,
        facts_provenance=LOCAL,
        evidence_supported=True,
    )
    assert (auth.status is AuthorizationStatus.GRANTED) == (action is FinalAction.ALLOW)


# ---- conflicting rules -----------------------------------------------------------------------
def test_conflicting_rules_resolve_to_the_most_severe_regardless_of_order():
    rules = [
        {"id": "a", "when": [{"field": "amount", "op": ">", "value": 0}], "outcome": "STEP_UP"},
        {"id": "b", "when": [{"field": "amount", "op": ">", "value": 0}], "outcome": "BLOCK"},
        {
            "id": "c",
            "when": [{"field": "amount", "op": ">", "value": 0}],
            "outcome": "REQUIRE_HUMAN_REVIEW",
        },
    ]
    for order in (rules, rules[::-1], rules[1:] + rules[:1]):
        d = evaluate(policy_from_dict(_doc(order)), {"amount": 5})
        assert d.outcome is PolicyOutcome.BLOCK and set(d.matched_rules) == {"a", "b", "c"}


# ---- capability registry as a security boundary ----------------------------------------------
@pytest.mark.parametrize("cap", sorted(CONSEQUENTIAL, key=lambda c: c.value))
def test_every_consequential_capability_is_closed_to_ai_and_external_actors(cap):
    s = capabilities.spec(cap)
    assert ActorKind.AI_AGENT not in s.allowed_actors
    assert ActorKind.EXTERNAL not in s.allowed_actors
    for actor in (ActorKind.AI_AGENT, ActorKind.EXTERNAL):
        for outcome in PolicyOutcome:
            a = authorize(
                cap,
                actor=actor,
                amount=1,
                policy_outcome=outcome,
                facts_provenance=LOCAL,
                evidence_supported=True,
            )
            assert a.status is AuthorizationStatus.DENIED, (cap, actor, outcome)
    # the automated path needs verified evidence, and a human-reserved one needs a human
    a = authorize(
        cap,
        actor=ActorKind.SYSTEM,
        amount=1,
        policy_outcome=PolicyOutcome.ALLOW,
        facts_provenance=LOCAL,
        evidence_supported=False,
    )
    assert a.status is AuthorizationStatus.DENIED
    a = authorize(
        cap,
        actor=ActorKind.SYSTEM,
        amount=1,
        policy_outcome=PolicyOutcome.ALLOW,
        facts_provenance=LOCAL,
        evidence_supported=True,
    )
    human_only = s.required_authorization.value in ("HUMAN_REVIEWER", "SENIOR_REVIEWER")
    if ActorKind.SYSTEM not in s.allowed_actors:
        assert a.status is AuthorizationStatus.DENIED
    elif human_only:
        assert a.status is AuthorizationStatus.PENDING_HUMAN
    # a BLOCK is a DENY for everyone
    for actor in ActorKind:
        b = authorize(
            cap,
            actor=actor,
            amount=1,
            policy_outcome=PolicyOutcome.BLOCK,
            facts_provenance=LOCAL,
            evidence_supported=True,
        )
        assert b.status is AuthorizationStatus.DENIED


def test_registry_attributes_are_consistent():
    for cap, s in REGISTRY.items():
        assert s.capability is cap
        if s.financial_effect or s.irreversible:
            assert s.consequential
        if s.consequential:
            assert s.required_authorization.value != "NONE", cap
        if s.human_review_threshold is not None:
            assert s.human_review_threshold >= 0
    assert set(REGISTRY) == set(Capability)
    assert capabilities.spec(Capability.SKIP_REVIEW).allowed_actors == frozenset()


def test_unknown_capability_and_actor_are_denied_not_crashed():
    a = authorize(
        "GRANT_ALL",  # type: ignore[arg-type]
        actor=ActorKind.SYSTEM,
        amount=1,
        policy_outcome=PolicyOutcome.ALLOW,
        facts_provenance=LOCAL,
        evidence_supported=True,
    )
    assert a.status is AuthorizationStatus.DENIED and "unregistered" in a.reason
    a = authorize(
        Capability.APPROVE_REFUND,
        actor="ROOT",  # type: ignore[arg-type]
        amount=1,
        policy_outcome=PolicyOutcome.ALLOW,
        facts_provenance=LOCAL,
        evidence_supported=True,
    )
    assert a.status is AuthorizationStatus.DENIED


def test_without_authorization_or_policy_a_run_is_a_what_if_and_is_never_recorded():
    for missing in (AUTHORIZATION, POLICY):
        b = _dispute(LEDGER, RunOptions(controls=FULL - {missing}))
        assert not b.decision.authoritative
    app = SentinelApp()
    b = app.evaluate_dispute(CLAIM, LEDGER, options=RunOptions(controls=FULL - {AUTHORIZATION}))
    assert app.store.decision(b.decision.decision_id) is None and len(app.runtime.audit) == 0


# ---- tampered policy files and hash mismatch --------------------------------------------------
@pytest.fixture()
def policy_dir(tmp_path):
    d = tmp_path / "policies"
    shutil.copytree(POLICY_DIR, d)
    return d


def test_the_shipped_policies_are_pinned():
    pinned = json.loads((POLICY_DIR / MANIFEST).read_text())["policies"]
    assert set(pinned) == {p.key for p in DEFAULT_REGISTRY.all()}
    PolicyRegistry().load_dir(POLICY_DIR)  # verifies


def test_a_policy_edited_in_place_fails_closed(policy_dir):
    f = policy_dir / "dispute-refund.v3.json"
    doc = json.loads(f.read_text())
    for r in doc["rules"]:
        if r["id"] == "review-over-auto-limit":
            r["when"][0]["value"] = 5_000_000  # quietly raise the auto-limit
    f.write_text(json.dumps(doc))
    reg = PolicyRegistry()
    with pytest.raises(PolicyIntegrityError, match="dispute-refund@v3 does not match"):
        reg.load_dir(policy_dir)
    assert reg.all() == []  # nothing registered
    with pytest.raises(PolicyIntegrityError, match="already pinned"):
        pin_manifest(policy_dir)  # re-pinning an edited version is refused


def test_a_deleted_or_unpinned_version_fails_closed(policy_dir):
    (policy_dir / "dispute-refund.v1.json").unlink()
    with pytest.raises(PolicyIntegrityError, match="dispute-refund@v1 is pinned but its file"):
        PolicyRegistry().load_dir(policy_dir)
    shutil.copy(POLICY_DIR / "dispute-refund.v1.json", policy_dir / "dispute-refund.v1.json")
    doc = json.loads((policy_dir / "dispute-refund.v4.json").read_text())
    doc["version"] = 5
    (policy_dir / "dispute-refund.v5.json").write_text(json.dumps(doc))
    with pytest.raises(PolicyIntegrityError, match="dispute-refund@v5 is not pinned"):
        PolicyRegistry().load_dir(policy_dir)
    assert pin_manifest(policy_dir) == ["dispute-refund@v5"]  # a NEW version can be pinned
    assert PolicyRegistry().load_dir(policy_dir) == len(DEFAULT_REGISTRY.all()) + 1


def test_a_corrupt_or_missing_manifest_fails_closed(policy_dir):
    (policy_dir / MANIFEST).write_text("{not json")
    with pytest.raises(PolicyIntegrityError, match="unreadable"):
        PolicyRegistry().load_dir(policy_dir)
    (policy_dir / MANIFEST).unlink()
    with pytest.raises(PolicyIntegrityError, match="missing policy manifest"):
        PolicyRegistry().load_dir(policy_dir, pinned=True)


def test_a_store_that_recorded_other_content_for_a_version_refuses_to_open(tmp_path):
    db = str(tmp_path / "s.db")
    SentinelApp(SentinelStore(db))  # records the shipped policy content
    store = SentinelStore(db)
    doc = DEFAULT_REGISTRY.active("dispute-refund").to_dict()
    doc["rules"] = doc["rules"][1:]
    store.save_policy_version("dispute-refund", doc["version"], "dispute", doc)
    with pytest.raises(PolicyIntegrityError, match="dispute-refund@v4: the store holds"):
        SentinelApp(SentinelStore(db))


# ---- malformed trusted records ----------------------------------------------------------------
@pytest.mark.parametrize(
    "amount", ["ten lakh", "", None, -50_000, "-1", float("inf"), "inf", float("nan"), True]
)
def test_a_malformed_ledger_amount_goes_to_a_human_never_under_the_limit(amount):
    b = _dispute({**LEDGER, "amount": amount})
    assert b.decision.final_action is FinalAction.REQUIRE_HUMAN_REVIEW and not b.decision.executed
    assert (
        "malformed" in b.decision.reason
        or "malformed" in " ".join(b.decision.policy.explanations)
        or b.decision.evidence_verdict.value == "INSUFFICIENT"
    )


def test_a_missing_ledger_amount_goes_to_a_human():
    ledger = {k: v for k, v in LEDGER.items() if k != "amount"}
    assert _dispute(ledger).decision.final_action is FinalAction.REQUIRE_HUMAN_REVIEW


def test_malformed_acquirer_records_go_to_a_human():
    for bad in ({"prior_flags": "none"}, {"domain_age_days": -3}, {"business_age_days": "old"}):
        records = {"registration_status": "verified", "domain_age_days": 400, **bad}
        b = run_kyb(Runtime(persist=False), KYBRequest(UntrustedContent("We sell shoes."), records))
        assert b.decision.final_action is FinalAction.REQUIRE_HUMAN_REVIEW, bad
        assert not b.decision.executed


def test_well_formed_currency_strings_still_parse():
    for amount in ("₹12,000", "Rs. 12000", "12000.0", 12000.0):
        assert _dispute({**LEDGER, "amount": amount}).decision.final_action is FinalAction.ALLOW
