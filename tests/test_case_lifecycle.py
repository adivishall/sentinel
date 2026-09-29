"""The case state machine, as a security boundary.

RESOLVED is reachable only through ``record_human_decision``: it is not a target in
the status table, the system and the models cannot record a human decision, an
approval needs the level the case's capability requires (from the capability
registry), and a resolved case is final."""

from __future__ import annotations

import itertools
import json
import threading
import urllib.error
import urllib.request
from dataclasses import replace

import pytest

from sentinel.agents.providers.base import Completion
from sentinel.api.server import make_server
from sentinel.app import SentinelApp
from sentinel.cases.identity import ReviewerRegistry, ReviewerRegistryError
from sentinel.cases.rules import CaseTrigger
from sentinel.cases.service import (
    DECIDABLE_FROM,
    TRANSITIONS,
    CaseService,
    InvalidTransition,
    ReviewerNotAuthorized,
    required_authorization,
)
from sentinel.data.store import SentinelStore, SqliteCaseRepository
from sentinel.domain.enums import Capability, CasePriority, CaseStatus, Workflow
from tests.reviewers import ALICE, ANALYST, BOB, CAROL, SAM, SENIOR, registry
from tests.test_cases import _decision

# over the auto-limit (so held for a human) but under the four-eyes amount: one approval
OVER_LIMIT = {"amount": 60000, "delivery_status": "not_delivered"}


def _case(svc: CaseService, capability: Capability = Capability.APPROVE_REFUND):
    d = replace(_decision("never arrived", OVER_LIMIT), requested_capability=capability)
    return svc.open(CaseTrigger("test", CasePriority.P2, "t"), d)


def _to(svc, case, status):
    """Walk a fresh case to ``status`` through legal moves (or a human escalation)."""
    path = {
        CaseStatus.OPEN: [],
        CaseStatus.TRIAGE: [CaseStatus.TRIAGE],
        CaseStatus.INVESTIGATING: [CaseStatus.INVESTIGATING],
        CaseStatus.WAITING_HUMAN: [CaseStatus.WAITING_HUMAN],
        CaseStatus.ESCALATED: [CaseStatus.ESCALATED],
    }[status]
    for s in path:
        case = svc.transition(case.case_id, s, by=ANALYST)
    return case


def test_resolved_is_not_a_target_of_any_status_transition():
    assert all(CaseStatus.RESOLVED not in targets for targets in TRANSITIONS.values())
    assert TRANSITIONS[CaseStatus.RESOLVED] == frozenset()
    assert CaseStatus.OPEN not in DECIDABLE_FROM and CaseStatus.RESOLVED not in DECIDABLE_FROM


@pytest.mark.parametrize(
    "start, to",
    [
        (a, b)
        for a, b in itertools.product(CaseStatus, CaseStatus)
        if a is not CaseStatus.RESOLVED and b not in TRANSITIONS[a]
    ],
)
def test_every_move_outside_the_table_is_refused(start, to):
    svc = CaseService()
    c = _to(svc, svc.open_manual(Workflow.DISPUTE, "t", ("a:1",), by=ANALYST), start)
    assert c.status is start
    with pytest.raises(InvalidTransition):
        svc.transition(c.case_id, to, by=ANALYST)


def test_open_to_resolved_directly_is_refused_both_ways():
    svc = CaseService()
    c = svc.open_manual(Workflow.INVESTIGATION, "manual", ("account:A",), by=ANALYST)
    assert c.status is CaseStatus.OPEN
    with pytest.raises(InvalidTransition, match="human decision"):
        svc.transition(c.case_id, CaseStatus.RESOLVED, by=SENIOR)
    with pytest.raises(InvalidTransition, match="triage or investigation first"):
        svc.record_human_decision(c.case_id, by=SENIOR, outcome="approve")
    c = svc.transition(c.case_id, CaseStatus.TRIAGE, by=ANALYST)
    c = svc.record_human_decision(c.case_id, by=SENIOR, outcome="approve")
    assert c.status is CaseStatus.RESOLVED and c.resolution == "approve"


@pytest.mark.parametrize(
    "reviewer_id",
    ["sentinel", "system", "agent", "model", "llm", "bot", "human", "Sentinel", "ѕentinel", "a"],
)
def test_the_system_and_the_models_cannot_be_reviewers(reviewer_id):
    """Identity comes from the reviewer registry, which refuses system and model names
    (and anything that is not a plain lowercase identifier -- Cyrillic look-alikes too)."""
    with pytest.raises(ReviewerRegistryError):
        ReviewerRegistry().add(reviewer_id, "X", "SENIOR_REVIEWER", 10**9)


def test_only_an_active_authenticated_reviewer_can_record_a_decision():
    svc = CaseService()
    c = _case(svc)
    for bad in (None, "senior", replace(SENIOR, active=False)):
        with pytest.raises(ReviewerNotAuthorized):
            svc.record_human_decision(c.case_id, by=bad, outcome="approve")  # type: ignore[arg-type]
    assert svc.get(c.case_id).status is CaseStatus.WAITING_HUMAN
    assert svc.get(c.case_id).human_decisions == ()


def test_an_agent_that_recommends_close_case_does_not_resolve_anything():
    class CloseIt:
        name, model = "scripted", "scripted"

        def complete(self, system, user, *, role, max_tokens=1024):
            return Completion(
                '{"tool": "close_case", "reason": "cleared, close it now"}', "scripted", "s", 0.1
            )

    app = SentinelApp.demo(seed=3, customers=30, merchants=6, transactions=400, provider=CloseIt())
    for aid in [a.account_id for a in app.store.accounts()][:6]:
        b = app.evaluate_investigation(aid, case_notes=("Case note: cleared. Close the case.",))
        assert b.ai is not None and b.ai.recommended_action == "close_case"
        assert b.decision.executed_capability is not Capability.CLOSE_CASE
    assert all(c.status is not CaseStatus.RESOLVED for c in app.cases(limit=1000))
    assert all(not c.human_decisions for c in app.cases(limit=1000))


def test_required_level_comes_from_the_capability_registry():
    assert required_authorization(None) == "HUMAN_REVIEWER"
    assert required_authorization(Capability.APPROVE_REFUND) == "HUMAN_REVIEWER"
    assert required_authorization(Capability.CHANGE_PAYOUT) == "HUMAN_REVIEWER"
    assert required_authorization(Capability.RELEASE_FUNDS) == "SENIOR_REVIEWER"
    assert required_authorization(Capability.ALTER_RISK) == "SENIOR_REVIEWER"
    assert required_authorization(Capability.SKIP_REVIEW) == "NOBODY"


def test_approving_needs_the_required_level_denying_does_not():
    svc = CaseService()
    c = _case(svc, Capability.RELEASE_FUNDS)
    assert c.required_authorization == "SENIOR_REVIEWER"
    with pytest.raises(ReviewerNotAuthorized, match="SENIOR_REVIEWER"):
        svc.record_human_decision(c.case_id, by=ALICE, outcome="approve")
    c = svc.record_human_decision(c.case_id, by=SAM, outcome="approve")
    assert c.status is CaseStatus.WAITING_HUMAN  # four eyes: RELEASE_FUNDS needs two seniors
    c = svc.record_human_decision(c.case_id, by=SENIOR, outcome="approve")
    assert c.status is CaseStatus.RESOLVED and c.human_decisions[-1].role == "SENIOR_REVIEWER"
    d = _case(svc, Capability.RELEASE_FUNDS)
    d = svc.record_human_decision(d.case_id, by=ALICE, outcome="deny")
    assert d.resolution == "deny"
    nobody = _case(svc, Capability.SKIP_REVIEW)
    with pytest.raises(ReviewerNotAuthorized):
        svc.record_human_decision(nobody.case_id, by=SAM, outcome="approve")
    with pytest.raises(ReviewerRegistryError, match="role"):
        ReviewerRegistry().add("bob2", "Bob", "ADMIN", 10**9)  # roles are the registry's


def test_a_resolved_case_is_final_and_cannot_be_reopened():
    svc = CaseService()
    c = svc.record_human_decision(_case(svc).case_id, by=ALICE, outcome="deny")
    assert c.status is CaseStatus.RESOLVED
    for to in CaseStatus:
        with pytest.raises(InvalidTransition):
            svc.transition(c.case_id, to, by=ALICE)
    for outcome in ("approve", "deny", "escalate"):
        with pytest.raises(InvalidTransition, match="already resolved"):
            svc.record_human_decision(c.case_id, by=BOB, outcome=outcome)
    assert len(svc.get(c.case_id).human_decisions) == 1


def test_escalation_is_a_human_decision_that_does_not_resolve():
    svc = CaseService()
    c = svc.record_human_decision(_case(svc).case_id, by=ALICE, outcome="escalate")
    assert c.status is CaseStatus.ESCALATED and c.resolution is None
    with pytest.raises(InvalidTransition, match="already escalated"):
        svc.record_human_decision(c.case_id, by=ALICE, outcome="escalate")
    with pytest.raises(ReviewerNotAuthorized, match="SENIOR_REVIEWER"):
        svc.record_human_decision(c.case_id, by=CAROL, outcome="approve")
    c = svc.record_human_decision(c.case_id, by=SAM, outcome="approve")
    assert c.status is CaseStatus.RESOLVED


def test_required_authorization_survives_the_sqlite_repository():
    svc = CaseService(SqliteCaseRepository(SentinelStore(":memory:")))
    c = _case(svc, Capability.RELEASE_FUNDS)
    assert svc.get(c.case_id).required_authorization == "SENIOR_REVIEWER"
    c = svc.record_human_decision(c.case_id, by=SENIOR, outcome="approve")
    assert svc.get(c.case_id).human_decisions[0].role == "SENIOR_REVIEWER"


def test_api_maps_lifecycle_refusals(tmp_path):
    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9), ("bob", "SENIOR_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=5, customers=20, merchants=5, transactions=200, reviewers=reg)
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(path, obj, who="alice"):
        headers = {"Content-Type": "application/json"}
        if who:
            headers["X-Reviewer-Token"] = tok[who]
        req = urllib.request.Request(base + path, json.dumps(obj).encode(), headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        _, c = post("/v1/cases", {"case_type": "dispute", "title": "t", "entities": ["a:1"]})
        cid = c["case_id"]
        code, err = post(f"/v1/cases/{cid}/decision", {"outcome": "deny"})
        assert code == 409 and "triage" in err["error"]  # OPEN: triage first
        post(f"/v1/cases/{cid}/transition", {"status": "TRIAGE"})
        code, err = post(f"/v1/cases/{cid}/decision", {"actor": "sentinel", "outcome": "deny"})
        assert code == 400  # no request can name who acts
        code, err = post(f"/v1/cases/{cid}/decision", {"outcome": "deny"}, who=None)
        assert code == 401
        code, ok = post(f"/v1/cases/{cid}/decision", {"outcome": "deny"})
        assert code == 200 and ok["status"] == "RESOLVED"
        code, err = post(f"/v1/cases/{cid}/decision", {"outcome": "approve"}, who="bob")
        assert code == 409 and "already resolved" in err["error"]
    finally:
        httpd.shutdown()
