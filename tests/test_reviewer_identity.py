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
    for k in ("token_sha256", "credential_id"):  # one credential under two ids
        doc["reviewers"][1][k] = doc["reviewers"][0][k]
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


# ---- regressions: the adversarial review of reviewer identity ---------------------------------
def test_r1_an_escalation_cannot_be_undone_by_the_level_below():
    """A HUMAN_REVIEWER escalated a case, moved it back to INVESTIGATING and approved it
    alone. Now an escalated case is moved on by a senior, and stays a senior's to decide."""
    svc = CaseService()
    c = _case(svc, amount=60_000)
    svc.record_human_decision(c.case_id, by=ALICE, outcome="escalate")
    with pytest.raises(ReviewerNotAuthorized, match="SENIOR"):
        svc.transition(c.case_id, CaseStatus.INVESTIGATING, by=ALICE)
    svc.transition(c.case_id, CaseStatus.INVESTIGATING, by=SAM)  # the senior takes it back
    for outcome in ("approve", "deny"):
        with pytest.raises(ReviewerNotAuthorized, match="SENIOR"):
            svc.record_human_decision(c.case_id, by=ALICE, outcome=outcome)
    assert svc.record_human_decision(c.case_id, by=SAM, outcome="approve").resolution == "approve"


def test_r1_an_escalation_by_transition_hands_the_case_up_too():
    svc = CaseService()
    c = _case(svc, amount=60_000)
    svc.transition(c.case_id, CaseStatus.INVESTIGATING, by=ALICE)
    svc.transition(c.case_id, CaseStatus.ESCALATED, by=ALICE)
    with pytest.raises(ReviewerNotAuthorized):
        svc.transition(c.case_id, CaseStatus.INVESTIGATING, by=BOB)
    with pytest.raises(ReviewerNotAuthorized):
        svc.record_human_decision(c.case_id, by=BOB, outcome="approve")


def test_r2_an_escalation_by_transition_restarts_the_four_eyes_count():
    svc = CaseService()
    c = _case(svc, Capability.APPROVE_REFUND, 150_000)
    svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")  # 1 of 2
    svc.transition(c.case_id, CaseStatus.ESCALATED, by=ALICE)
    c = svc.record_human_decision(c.case_id, by=SAM, outcome="approve")
    assert c.status is CaseStatus.ESCALATED and c.resolution is None  # 1 of 2 again
    assert c.events[-1].detail["approvals"] == 1
    c = svc.record_human_decision(c.case_id, by=SENIOR, outcome="approve")
    assert c.resolution == "approve"


def test_r3_a_case_stored_before_amounts_were_recorded_fails_closed(tmp_path):
    """A pre-upgrade row had no amount and no approvals_required: it loaded as amount 0 with
    one approval, so a reviewer with a 1,000 limit resolved a 900,000 refund alone."""
    from sentinel.data.store import UNBOUNDED_AMOUNT, SentinelStore, SqliteCaseRepository

    store = SentinelStore(str(tmp_path / "s.db"))
    repo = SqliteCaseRepository(store)
    svc = CaseService(repo)
    c = _case(svc, Capability.APPROVE_REFUND, 900_000)
    legacy = json.loads(store._one("SELECT payload FROM cases WHERE case_id = ?", (c.case_id,))[0])
    del legacy["amount"], legacy["approvals_required"]
    store._exec("UPDATE cases SET payload = ? WHERE case_id = ?", (json.dumps(legacy), c.case_id))
    loaded = repo.get(c.case_id)
    assert loaded.amount == UNBOUNDED_AMOUNT  # its decision is not in this store: unknown
    with pytest.raises(ReviewerNotAuthorized, match="may approve up to"):
        svc.record_human_decision(c.case_id, by=reviewer("junior", limit=1_000), outcome="approve")
    # with no stored count, the registry's count for the amount applies (four eyes here)
    big = reviewer("big", limit=UNBOUNDED_AMOUNT)
    assert svc.record_human_decision(c.case_id, by=big, outcome="approve").resolution is None


def test_r3_a_legacy_case_takes_its_decisions_amount_when_the_store_has_it(tmp_path):
    from sentinel.data.store import SentinelStore, SqliteCaseRepository

    store = SentinelStore(str(tmp_path / "s.db"))
    repo = SqliteCaseRepository(store)
    c = _case(CaseService(repo), Capability.APPROVE_REFUND, 900_000)
    store._exec(
        "INSERT INTO decisions (decision_id, amount) VALUES (?, ?)", (c.decision_ids[0], 900_000)
    )
    legacy = json.loads(store._one("SELECT payload FROM cases WHERE case_id = ?", (c.case_id,))[0])
    del legacy["amount"], legacy["approvals_required"]
    store._exec("UPDATE cases SET payload = ? WHERE case_id = ?", (json.dumps(legacy), c.case_id))
    loaded = repo.get(c.case_id)
    assert loaded.amount == 900_000 and loaded.approvals_required == 1  # the stored count ...
    assert service_required(loaded) == 2  # ... never below the registry's for the amount


def service_required(case):
    from sentinel.cases.service import _approvals_required

    return _approvals_required(case)


def test_r4_a_deactivated_reviewers_pending_approval_no_longer_counts():
    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9), ("bob", "HUMAN_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    c = _case(app.runtime.cases, Capability.APPROVE_REFUND, 150_000)
    post = _api(app)
    post(f"/v1/cases/{c.case_id}/decision", {"outcome": "approve"}, tok["alice"])  # 1 of 2
    app.reviewers = app.reviewers.deactivate("alice")
    after = post(f"/v1/cases/{c.case_id}/decision", {"outcome": "approve"}, tok["bob"])
    assert after["status"] == "WAITING_HUMAN" and after["resolution"] is None


def test_r5_account_capabilities_are_bounded_by_role_and_four_eyes_not_amount():
    """Account-security decisions carry no amount, so an authority limit cannot bound them;
    every one needs two distinct approvals, and RELEASE_FUNDS / ALTER_RISK a senior."""
    for cap in (Capability.CHANGE_PAYOUT, Capability.RELEASE_FUNDS, Capability.ALTER_RISK):
        assert capabilities.spec(cap).approvals_required(0) == 2
    svc = CaseService()
    c = _case(svc, Capability.RELEASE_FUNDS, 0)
    if c.status is CaseStatus.OPEN:
        svc.transition(c.case_id, CaseStatus.TRIAGE, by=SAM)
    with pytest.raises(ReviewerNotAuthorized, match="SENIOR"):
        svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")
    svc.record_human_decision(c.case_id, by=SAM, outcome="approve")
    with pytest.raises(ReviewerNotAuthorized, match="four eyes"):
        svc.record_human_decision(c.case_id, by=SAM, outcome="approve")


@pytest.mark.parametrize(
    "rid",
    ["claude", "gpt-4o", "gemini", "copilot", "sentinel-bot", "sentinel.system", "system-admin",
     "ai-reviewer", "model.risk", "auto-approver", "dispute-triage-agent"],
)
def test_r6_ids_that_name_the_system_or_a_model_are_refused(rid):
    with pytest.raises(ReviewerRegistryError, match="neither"):
        ReviewerRegistry().add(rid, "x", "HUMAN_REVIEWER", 1)


@pytest.mark.parametrize(
    "change",
    [
        {"credential_id": ""},
        {"credential_id": None},
        {"credential_id": "cred-000000000000"},  # not this credential's
        {"name": None},
        {"name": ["a"]},
        {"reviewer_id": None},
    ],
)
def test_r7_registry_fields_are_typed_and_the_credential_id_is_bound(change):
    reg, _ = ReviewerRegistry().add("alice", "Alice", "HUMAN_REVIEWER", 1)
    doc = reg.to_json()
    doc["reviewers"][0].update(change)
    with pytest.raises(ReviewerRegistryError):
        ReviewerRegistry.from_json(doc)


def test_r7_the_token_cannot_be_the_credential_id():
    reg, token = ReviewerRegistry().add("alice", "Alice", "HUMAN_REVIEWER", 1)
    doc = reg.to_json()
    doc["reviewers"][0]["credential_id"] = token
    with pytest.raises(ReviewerRegistryError):
        ReviewerRegistry.from_json(doc)


@pytest.mark.parametrize("field", ["Role", "Reviewer", " reviewer", "by", "authority_limit", "x"])
def test_case_routes_refuse_any_field_they_do_not_take(field):
    from sentinel.api.schemas import ValidationError

    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    c = _case(app.runtime.cases)
    with pytest.raises(ValidationError, match="unknown fields"):
        _api(app)(f"/v1/cases/{c.case_id}/decision", {"outcome": "deny", field: 1}, tok["alice"])


def test_a_duplicated_reviewer_header_is_refused():
    import http.client

    from sentinel.api.server import make_server

    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9), ("sam", "SENIOR_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=3, customers=10, merchants=4, transactions=80, reviewers=reg)
    srv = make_server(app, "127.0.0.1", 0)
    import threading

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        conn.putrequest("POST", "/v1/cases")
        body = json.dumps({"case_type": "dispute", "title": "t"}).encode()
        for h, v in (
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
            ("X-Reviewer-Token", tok["alice"]),
            ("X-Reviewer-Token", tok["sam"]),
        ):
            conn.putheader(h, v)
        conn.endheaders(body)
        assert conn.getresponse().status == 400
    finally:
        srv.shutdown()
