"""Decision lineage and replay drift classes (Phases 16-17)."""

from __future__ import annotations

from sentinel.api.server import build_routes
from sentinel.app import SentinelApp
from sentinel.domain.enums import CaseStatus
from sentinel.replay.engine import ReplayOverrides
from tests.reviewers import registry


def test_a_decisions_lineage_answers_every_question():
    reg, tok = registry(("alice", "HUMAN_REVIEWER", 10**9))
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600, reviewers=reg)
    held = None
    for d in app.store.all_disputes():
        b = app.evaluate_dispute("", dispute_id=d.dispute_id)
        if b.case is not None and b.decision.final_action.value == "REQUIRE_HUMAN_REVIEW":
            held = b
            break
    assert held is not None
    c = app.runtime.cases.get(held.case.case_id)
    if c.status is CaseStatus.OPEN:
        app.runtime.cases.transition(c.case_id, CaseStatus.TRIAGE, by=reg.get("alice"))
    app.runtime.cases.record_human_decision(c.case_id, by=reg.get("alice"), outcome="deny")
    lin = app.decision_lineage(held.decision.decision_id)
    assert set(lin) == {
        "decision_id",
        "what",
        "when",
        "facts",
        "evidence",
        "risk",
        "ai",
        "policy",
        "capability",
        "authorised_by",
        "outcome",
        "audit",
    }
    assert lin["facts"]["provenance"]["status"] == "VERIFIED_EXTERNAL"
    assert lin["policy"]["release"] == "VERIFIED" and lin["policy"]["activation"]
    assert lin["risk"]["model_digest"] and lin["ai"]["trust"].startswith("MODEL_GENERATED")
    assert lin["authorised_by"]["humans"][0]["reviewer"] == "alice"
    assert lin["authorised_by"]["humans"][0]["credential_id"].startswith("cred-")
    assert lin["audit"]["sequence"] is not None and lin["audit"]["anchoring"] == "not_anchored"
    fn, params = build_routes(app).match(
        "GET", f"/v1/decisions/{held.decision.decision_id}/lineage"
    )
    assert fn({}, None, params)["decision_id"] == held.decision.decision_id


def test_replay_names_its_drift():
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    did = app.evaluate_dispute(
        "", dispute_id=app.store.all_disputes()[0].dispute_id
    ).decision.decision_id
    same = app.replay(did, ReplayOverrides())
    assert same.drift == [] and same.drift_class == "none"
    rule = app.runtime.policies.active("dispute-refund").rules[-1].rule_id
    r = app.replay(did, ReplayOverrides(rule_values={rule: 1}))
    assert "policy_release_artifact" in r.drift  # an override is not a released document
    assert r.to_dict()["drift_class"] == r.drift_class
