"""Reviewer identity, authority limits and four-eyes approval (issue #13).

INV-REVIEW-1  A caller cannot self-declare an authority level: who acts, their role and
              their limit come from the reviewer registry via the credential.
INV-REVIEW-2  A four-eyes capability cannot be approved by one identity, whatever the
              number of requests.
INV-REVIEW-3  Nobody can act as the system (or a model) through the case API.

Regressions for the trust audit: "mallory" escalated a case as HUMAN_REVIEWER, then
approved it as a self-declared SENIOR_REVIEWER; `claude`, `ѕentinel` and `Sentinel-Bot`
passed the reserved-name blacklist; any caller could write `sentinel`-attributed case
events into the audit chain.
"""

from __future__ import annotations

import hmac
import json
from dataclasses import replace

import pytest

from sentinel.api.server import REVIEWER_TOKEN, build_routes
from sentinel.app import SentinelApp
from sentinel.cases.identity import ReviewerRegistry, ReviewerRegistryError, token_digest
from sentinel.cases.rules import CaseTrigger
from sentinel.cases.service import CaseService, ReviewerNotAuthorized
from sentinel.domain.enums import Capability, CasePriority, CaseStatus
from sentinel.security import capabilities
from tests.reviewers import ALICE, BOB, SAM, SENIOR, registry, reviewer
from tests.test_cases import _decision


def _case(svc, capability=Capability.APPROVE_REFUND, amount=60_000):
    d = replace(
        _decision("never arrived", {"amount": amount, "delivery_status": "not_delivered"}),
        requested_capability=capability,
        amount=amount,
    )
    return svc.open(CaseTrigger("test", CasePriority.P2, "t"), d)


# ---- the registry ----------------------------------------------------------------------------
def test_a_credential_is_shown_once_and_stored_only_hashed():
    reg, token = ReviewerRegistry().add("alice", "Alice", "HUMAN_REVIEWER", 100_000)
    doc = reg.dumps()
    assert token.startswith("srv_") and token not in doc and token_digest(token) in doc
    who = reg.authenticate(token)
    assert who is not None and (who.reviewer_id, who.role, who.authority_limit) == (
        "alice",
        "HUMAN_REVIEWER",
        100_000,
    )
    for bad in (None, "", token + "x", token[:-1], "srv_" + "A" * 43, "x" * 500):
        assert reg.authenticate(bad) is None
    assert ReviewerRegistry.from_json(json.loads(doc)).authenticate(token) == who


def test_a_deactivated_credential_no_longer_authenticates():
    reg, token = ReviewerRegistry().add("alice", "Alice", "HUMAN_REVIEWER", 1)
    assert reg.deactivate("alice").authenticate(token) is None


def test_matching_compares_every_entry(monkeypatch):
    reg, tokens = registry(*[(f"r{i:02d}", "HUMAN_REVIEWER", 1) for i in range(8)])
    calls = []
    real = hmac.compare_digest
    monkeypatch.setattr(hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    assert reg.authenticate(tokens["r00"]).reviewer_id == "r00"
    assert len(calls) == 8  # no early exit on a match: timing does not say which entry


@pytest.mark.parametrize(
    "change",
    [
        {"role": "ADMIN"},
        {"reviewer_id": "sentinel"},
        {"reviewer_id": "Alice"},
        {"reviewer_id": "ѕentinel"},  # Cyrillic s
        {"authority_limit": -1},
        {"authority_limit": True},
        {"authority_limit": "1000"},
        {"active": "yes"},
        {"token_sha256": "abc"},
        {"extra": 1},
        {"name": ""},
    ],
)
def test_a_malformed_registry_fails_closed(change):
    reg, _ = ReviewerRegistry().add("alice", "Alice", "HUMAN_REVIEWER", 1)
    doc = reg.to_json()
    doc["reviewers"][0].update(change)
    with pytest.raises(ReviewerRegistryError):
        ReviewerRegistry.from_json(doc)


def test_ids_and_credentials_are_unique():
    reg, _ = registry(("alice", "HUMAN_REVIEWER", 1), ("bob", "HUMAN_REVIEWER", 1))
    doc = reg.to_json()
    doc["reviewers"][1]["token_sha256"] = doc["reviewers"][0]["token_sha256"]
    with pytest.raises(ReviewerRegistryError, match="shared"):
        ReviewerRegistry.from_json(doc)
    doc = reg.to_json()
    doc["reviewers"][1]["reviewer_id"] = "alice"
    with pytest.raises(ReviewerRegistryError, match="duplicate"):
        ReviewerRegistry.from_json(doc)
    with pytest.raises(ReviewerRegistryError, match="exists"):
        reg.add("alice", "Alice again", "SENIOR_REVIEWER", 1)


# ---- INV-REVIEW-1: no self-declared authority -------------------------------------------------
def _api(app):
    r = build_routes(app)

    def post(path, body, token=None):
        REVIEWER_TOKEN.set(token)
        fn, params = r.match("POST", path)
        return fn({}, body, params)

    return post


def test_inv_review_1_the_role_is_the_registrys_not_the_requests():
    """The audit: mallory escalated as HUMAN_REVIEWER, then approved as a self-declared
    SENIOR_REVIEWER. Now the role is the credential's, and a body naming one is refused."""
    from sentinel.api.schemas import ValidationError
    from sentinel.api.server import ApiError

    reg, tok = registry(("mallory", "HUMAN_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    c = _case(app.runtime.cases, Capability.APPROVE_REFUND)
    post = _api(app)
    esc = post(f"/v1/cases/{c.case_id}/decision", {"outcome": "escalate"}, tok["mallory"])
    assert esc["status"] == "ESCALATED"
    with pytest.raises(ValidationError, match="credential"):
        post(
            f"/v1/cases/{c.case_id}/decision",
            {"outcome": "approve", "role": "SENIOR_REVIEWER"},
            tok["mallory"],
        )
    with pytest.raises(ApiError) as e:
        post(f"/v1/cases/{c.case_id}/decision", {"outcome": "approve"}, tok["mallory"])
    assert e.value.status == 403 and "SENIOR_REVIEWER" in e.value.message
    with pytest.raises(ApiError) as e:  # and no credential at all
        post(f"/v1/cases/{c.case_id}/decision", {"outcome": "approve"})
    assert e.value.status == 401
    assert app.runtime.cases.get(c.case_id).status is CaseStatus.ESCALATED


def test_an_approval_needs_an_authority_limit_that_covers_the_amount():
    svc = CaseService()
    c = _case(svc, amount=60_000)
    small = reviewer("junior", limit=50_000)
    with pytest.raises(ReviewerNotAuthorized, match="up to 50,000"):
        svc.record_human_decision(c.case_id, by=small, outcome="approve")
    assert svc.record_human_decision(c.case_id, by=small, outcome="deny").resolution == "deny"


# ---- INV-REVIEW-2: four eyes ------------------------------------------------------------------
@pytest.mark.parametrize(
    "capability, amount, required",
    [
        (Capability.APPROVE_REFUND, 60_000, 1),
        (Capability.APPROVE_REFUND, 100_000, 2),
        (Capability.CHANGE_PAYOUT, 0, 2),
        (Capability.RELEASE_FUNDS, 0, 2),
    ],
)
def test_the_registry_decides_how_many_approvals_a_case_needs(capability, amount, required):
    assert capabilities.spec(capability).approvals_required(amount) == required
    assert _case(CaseService(), capability, amount).approvals_required == required


def test_inv_review_2_one_identity_cannot_supply_both_approvals():
    svc = CaseService()
    c = _case(svc, Capability.APPROVE_REFUND, 150_000)
    c = svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")
    assert c.status is CaseStatus.WAITING_HUMAN and c.resolution is None
    for _ in range(3):  # however many times
        with pytest.raises(ReviewerNotAuthorized, match="four eyes"):
            svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")
    c = svc.record_human_decision(c.case_id, by=BOB, outcome="approve")
    assert c.status is CaseStatus.RESOLVED and c.resolution == "approve"
    assert [h.reviewer for h in c.human_decisions] == ["alice", "bob"]


def test_a_deny_needs_one_reviewer_and_an_escalation_restarts_the_count():
    svc = CaseService()
    c = _case(svc, Capability.APPROVE_REFUND, 150_000)
    svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")
    assert svc.record_human_decision(c.case_id, by=BOB, outcome="deny").resolution == "deny"
    c = _case(svc, Capability.APPROVE_REFUND, 150_000)
    svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")
    svc.record_human_decision(c.case_id, by=BOB, outcome="escalate")
    c = svc.record_human_decision(c.case_id, by=SAM, outcome="approve")
    assert c.status is CaseStatus.ESCALATED  # alice's approval was for the earlier level
    c = svc.record_human_decision(c.case_id, by=SENIOR, outcome="approve")
    assert c.status is CaseStatus.RESOLVED


# ---- INV-REVIEW-3: nobody is the system --------------------------------------------------------
@pytest.mark.parametrize("field", ["actor", "reviewer", "role", "reviewer_id"])
def test_inv_review_3_no_case_route_takes_an_identity_from_the_body(field):
    from sentinel.api.schemas import ValidationError

    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    c = _case(app.runtime.cases)
    post = _api(app)
    for path, body in (
        ("/v1/cases", {"case_type": "dispute", "title": "t"}),
        (f"/v1/cases/{c.case_id}/transition", {"status": "INVESTIGATING"}),
        (f"/v1/cases/{c.case_id}/decision", {"outcome": "deny"}),
    ):
        with pytest.raises(ValidationError):
            post(path, {**body, field: "sentinel"}, tok["alice"])


def test_the_audit_chain_records_the_resolved_identity_and_never_the_token():
    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    post = _api(app)
    created = post("/v1/cases", {"case_type": "dispute", "title": "t"}, tok["alice"])
    post(f"/v1/cases/{created['case_id']}/transition", {"status": "TRIAGE"}, tok["alice"])
    post(f"/v1/cases/{created['case_id']}/decision", {"outcome": "deny"}, tok["alice"])
    evs = [e for e in app.runtime.audit.events() if e.case_id == created["case_id"]]
    assert [e.action for e in evs] == ["CASE_OPENED", "CASE_TRIAGE", "HUMAN_DENY"]
    who = reg.get("alice")
    for e in evs:
        assert e.actor == "alice" and e.detail["reviewer_id"] == "alice"
        assert (
            e.detail["credential_id"] == who.credential_id and e.detail["role"] == "HUMAN_REVIEWER"
        )
        assert tok["alice"] not in json.dumps(e.to_dict())
    assert app.verify_audit().ok


def test_without_a_registry_nobody_can_act_on_a_case():
    from sentinel.api.server import ApiError

    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80)
    post = _api(app)
    with pytest.raises(ApiError) as e:
        post("/v1/cases", {"case_type": "dispute", "title": "t"}, "srv_anything")
    assert e.value.status == 401
