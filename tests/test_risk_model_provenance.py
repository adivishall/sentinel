"""Risk-model provenance (Phase 15): an assessment pins the configuration that scored it,
and replay reports when a model version's configuration changed under the same label."""

from __future__ import annotations

from dataclasses import replace

from sentinel.app import SentinelApp
from sentinel.replay.engine import ReplayOverrides
from sentinel.risk import scoring


def test_every_assessment_records_its_models_configuration_digest():
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    t = app.store.transactions(limit=1)[0]
    b = app.evaluate_transaction(t.transaction_id)
    model = scoring.ACTIVE["transaction"]
    assert b.risk.model_version == model.version and b.risk.model_digest == model.digest
    assert len(model.digest) == 64
    ev = app.audit_event(b.decision.decision_id)
    assert ev["detail"]["risk_model_digest"] == model.digest
    other = replace(model, weights={**model.weights, "velocity_burst": 1})
    assert other.digest != model.digest  # same label, other weights: another digest


def test_replay_reports_a_risk_model_whose_configuration_changed(monkeypatch):
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    t = app.store.transactions(limit=1)[0]
    did = app.evaluate_transaction(t.transaction_id).decision.decision_id
    assert "risk model" not in app.replay(did, ReplayOverrides()).explanation
    model = scoring.ACTIVE["transaction"]
    edited = replace(model, weights={**model.weights, "velocity_burst": 1})
    monkeypatch.setitem(scoring.MODELS, model.version, edited)  # edited in place, same label
    r = app.replay(did, ReplayOverrides())
    assert "no longer has the configuration recorded" in r.explanation
    assert r.versions["risk_model"]["configuration_changed"]["current"] == edited.digest
