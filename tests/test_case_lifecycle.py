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
from tests.test_cases import _decision

OVER_LIMIT = {"amount": 185000, "delivery_status": "not_delivered"}


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
        case = svc.transition(case.case_id, s, actor="analyst")
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
    c = _to(svc, svc.open_manual(Workflow.DISPUTE, "t", ("a:1",)), start)
    assert c.status is start
    with pytest.raises(InvalidTransition):
        svc.transition(c.case_id, to, actor="analyst")


def test_open_to_resolved_directly_is_refused_both_ways():
    svc = CaseService()
    c = svc.open_manual(Workflow.INVESTIGATION, "manual", ("account:A",))
    assert c.status is CaseStatus.OPEN
    with pytest.raises(InvalidTransition, match="human decision"):
        svc.transition(c.case_id, CaseStatus.RESOLVED, actor="senior")
    with pytest.raises(InvalidTransition, match="triage or investigation first"):
        svc.record_human_decision(c.case_id, reviewer="senior", outcome="approve")
    c = svc.transition(c.case_id, CaseStatus.TRIAGE, actor="analyst")
    c = svc.record_human_decision(c.case_id, reviewer="senior", outcome="approve")
    assert c.status is CaseStatus.RESOLVED and c.resolution == "approve"


@pytest.mark.parametrize(
    "reviewer",
    [
        "sentinel",
        "SYSTEM",
        " agent ",
        "model",
        "agent:aml",
        "ai:auto-closer",
        "Dispute Triage Agent",
        "",
    ],
)
def test_the_system_and_the_models_cannot_record_a_human_decision(reviewer):
    svc = CaseService()
    c = _case(svc)  # WAITING_HUMAN; its AI recommendation came from "Dispute Triage Agent"
    with pytest.raises(ReviewerNotAuthorized):
        svc.record_human_decision(c.case_id, reviewer=reviewer, outcome="approve")
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
        svc.record_human_decision(c.case_id, reviewer="alice", outcome="approve")
    c = svc.record_human_decision(
        c.case_id, reviewer="bob", outcome="approve", role="SENIOR_REVIEWER"
    )
    assert c.status is CaseStatus.RESOLVED and c.human_decisions[-1].role == "SENIOR_REVIEWER"
    d = _case(svc, Capability.RELEASE_FUNDS)
    d = svc.record_human_decision(d.case_id, reviewer="alice", outcome="deny")
    assert d.resolution == "deny"
    nobody = _case(svc, Capability.SKIP_REVIEW)
    with pytest.raises(ReviewerNotAuthorized):
        svc.record_human_decision(
            nobody.case_id, reviewer="bob", outcome="approve", role="SENIOR_REVIEWER"
        )
    with pytest.raises(ValueError, match="role"):
        svc.record_human_decision(nobody.case_id, reviewer="bob", outcome="deny", role="ADMIN")


def test_a_resolved_case_is_final_and_cannot_be_reopened():
    svc = CaseService()
    c = svc.record_human_decision(_case(svc).case_id, reviewer="alice", outcome="deny")
    assert c.status is CaseStatus.RESOLVED
    for to in CaseStatus:
        with pytest.raises(InvalidTransition):
            svc.transition(c.case_id, to, actor="alice")
    for outcome in ("approve", "deny", "escalate"):
        with pytest.raises(InvalidTransition, match="already resolved"):
            svc.record_human_decision(c.case_id, reviewer="bob", outcome=outcome)
    assert len(svc.get(c.case_id).human_decisions) == 1


def test_escalation_is_a_human_decision_that_does_not_resolve():
    svc = CaseService()
    c = svc.record_human_decision(_case(svc).case_id, reviewer="alice", outcome="escalate")
    assert c.status is CaseStatus.ESCALATED and c.resolution is None
    with pytest.raises(InvalidTransition, match="already escalated"):
        svc.record_human_decision(c.case_id, reviewer="alice", outcome="escalate")
    with pytest.raises(ReviewerNotAuthorized, match="SENIOR_REVIEWER"):
        svc.record_human_decision(c.case_id, reviewer="carol", outcome="approve")
    c = svc.record_human_decision(
        c.case_id, reviewer="carol", outcome="approve", role="SENIOR_REVIEWER"
    )
    assert c.status is CaseStatus.RESOLVED


def test_required_authorization_survives_the_sqlite_repository():
    svc = CaseService(SqliteCaseRepository(SentinelStore(":memory:")))
    c = _case(svc, Capability.RELEASE_FUNDS)
    assert svc.get(c.case_id).required_authorization == "SENIOR_REVIEWER"
    c = svc.record_human_decision(
        c.case_id, reviewer="b", outcome="approve", role="SENIOR_REVIEWER"
    )
    assert svc.get(c.case_id).human_decisions[0].role == "SENIOR_REVIEWER"


def test_api_maps_lifecycle_refusals(tmp_path):
    app = SentinelApp.demo(seed=5, customers=20, merchants=5, transactions=200)
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(path, obj):
        req = urllib.request.Request(
            base + path, json.dumps(obj).encode(), {"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    try:
        _, c = post("/v1/cases", {"case_type": "dispute", "title": "t", "entities": ["a:1"]})
        cid = c["case_id"]
        code, err = post(f"/v1/cases/{cid}/decision", {"reviewer": "alice", "outcome": "deny"})
        assert code == 409 and "triage" in err["error"]  # OPEN: triage first
        post(f"/v1/cases/{cid}/transition", {"status": "TRIAGE", "actor": "analyst"})
        code, err = post(f"/v1/cases/{cid}/decision", {"reviewer": "sentinel", "outcome": "deny"})
        assert code == 403
        code, ok = post(f"/v1/cases/{cid}/decision", {"reviewer": "alice", "outcome": "deny"})
        assert code == 200 and ok["status"] == "RESOLVED"
        code, err = post(f"/v1/cases/{cid}/decision", {"reviewer": "bob", "outcome": "approve"})
        assert code == 409 and "already resolved" in err["error"]
    finally:
        httpd.shutdown()
