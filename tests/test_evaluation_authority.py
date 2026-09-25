"""Evaluation authority (``sentinel.decision.authority``): a caller may request an
evaluation; it may not weaken one.

Every downgrade vector found in the release-candidate review is pinned here, at each
layer it could enter: the engine (``_finish`` refuses to record a downgraded run),
the application (what-if runs go to a runtime that never persists), the API (every
evaluate route refuses every what-if switch) and the CLI (the authoritative commands
do not have the flags)."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import replace

import pytest

from sentinel.api.server import make_server
from sentinel.app import SentinelApp
from sentinel.cli.main import main as cli_main
from sentinel.decision.authority import ControlDowngrade, downgrades
from sentinel.decision.composer import FULL, NONE
from sentinel.decision.workflows import (
    DisputeRequest,
    RunOptions,
    Runtime,
    run_dispute,
)
from sentinel.policy import DEFAULT_REGISTRY
from sentinel.policy.models import Rule
from sentinel.risk import scoring
from sentinel.security.provenance import UntrustedContent

REFUNDED = {
    "amount": 18000,
    "delivery_status": "not_delivered",
    "policy_auto_limit": 50000,
    "refund_state": "refunded",
}
CLAIM = "My order never arrived, please refund."
WHAT_IF = [
    RunOptions(controls=NONE),
    RunOptions(controls=FULL - {"policy"}),
    RunOptions(policy_version=1),
    RunOptions(risk_model=scoring.get_model("disp-1.0")),
]


# ---- version classes ------------------------------------------------------------------------
def test_active_and_historical_versions_are_explicit():
    for pid in {p.policy_id for p in DEFAULT_REGISTRY.all()}:
        versions = DEFAULT_REGISTRY.versions(pid)
        assert DEFAULT_REGISTRY.active(pid).version == versions[-1]
        assert DEFAULT_REGISTRY.historical(pid) == versions[:-1]
    assert DEFAULT_REGISTRY.historical("dispute-refund") == [1, 2]
    assert scoring.ACTIVE["transaction"].version == "txn-2.0"
    for surface, model in scoring.ACTIVE.items():
        assert scoring.surface_of(model) == surface
    assert {scoring.surface_of(m) for m in scoring.MODELS.values()} == set(scoring.ACTIVE)


# ---- engine ---------------------------------------------------------------------------------
@pytest.mark.parametrize("opts", WHAT_IF, ids=["no-controls", "no-policy", "policy-v1", "model"])
def test_a_persisting_runtime_refuses_to_record_a_downgraded_run(opts):
    rt = Runtime()  # persist=True: this runtime writes audit events and opens cases
    if opts.risk_model is not None:  # disp-1.0 IS the active dispute model: use a what-if one
        opts = replace(opts, risk_model=replace(scoring.DISPUTE_V1, version="disp-0.9"))
    with pytest.raises(ControlDowngrade):
        run_dispute(rt, DisputeRequest(UntrustedContent(CLAIM), REFUNDED), opts)
    assert len(rt.audit) == 0 and rt.cases.list() == []


def test_the_same_run_is_fine_when_nothing_is_persisted():
    b = run_dispute(
        Runtime(persist=False),
        DisputeRequest(UntrustedContent(CLAIM), REFUNDED),
        RunOptions(policy_version=1),
    )
    assert b.decision.executed and not b.decision.authoritative  # v1: the defect, as a what-if


def test_downgrades_reads_the_inputs_not_the_options():
    """A policy object whose content differs from the registered active version (edited in
    memory, or a same-numbered policy from elsewhere) is not authoritative either."""
    b = run_dispute(Runtime(persist=False), DisputeRequest(UntrustedContent(CLAIM), REFUNDED))
    assert b.inputs is not None and downgrades(b.inputs, DEFAULT_REGISTRY) == ()
    active = b.inputs.policy
    weakened = replace(
        active, rules=tuple(r for r in active.rules if r.rule_id != "block-already-refunded")
    )
    assert weakened.version == active.version and weakened.content_hash != active.content_hash
    found = downgrades(replace(b.inputs, policy=weakened), DEFAULT_REGISTRY)
    assert found and "content differs" in found[0]
    extra = replace(active, rules=active.rules + (Rule("x", (), active.default_outcome, ""),))
    assert downgrades(replace(b.inputs, policy=extra), DEFAULT_REGISTRY)


def test_a_risk_model_is_only_applied_to_its_own_surface():
    txn = scoring.get_model("txn-1.0")
    with pytest.raises(ValueError, match="transaction surface"):
        scoring.model_for("login", txn)
    assert scoring.model_for("transaction", None) is scoring.ACTIVE["transaction"]
    assert scoring.model_for("transaction", txn) is txn


# ---- application ------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def app():
    a = SentinelApp.demo(seed=42, customers=40, merchants=8, transactions=500)
    a.analyze(transactions=10, disputes=5, applications=3, sessions=5, accounts=2)
    return a


def _counts(app):
    return app.store.count("decisions"), len(app.runtime.audit), len(app.cases(limit=10_000))


def test_app_routes_what_if_runs_to_a_runtime_that_never_persists(app):
    before = _counts(app)
    for opts in (RunOptions(controls=NONE), RunOptions(policy_version=1)):
        b = app.evaluate_dispute(CLAIM, REFUNDED, options=opts)
        assert not b.decision.authoritative and b.audit_event is None and b.case is None
    t = app.store.transactions(limit=1)[0]
    b = app.evaluate_transaction(t, options=RunOptions(risk_model=scoring.get_model("txn-1.0")))
    assert not b.decision.authoritative and b.risk is not None
    assert b.risk.model_version == "txn-1.0"
    assert _counts(app) == before
    real = app.evaluate_dispute(CLAIM, REFUNDED)  # the authoritative run
    assert real.decision.authoritative and real.audit_event is not None
    assert real.decision.final_action.value == "DENY" and not real.decision.executed
    assert app.store.decision(real.decision.decision_id) is not None


def test_simulator_and_scenarios_never_record_their_what_if_side(app):
    n_dec, n_audit, _ = _counts(app)
    r = app.simulate_attack("direct_injection", compare=True)
    assert r["without_sentinel"]["decision"]["authoritative"] is False
    assert r["with_sentinel"]["decision"]["authoritative"] is True
    # exactly one new decision (the WITH side) and one audit event
    assert app.store.count("decisions") == n_dec + 1 and len(app.runtime.audit) == n_audit + 1
    before = _counts(app)
    app.run_scenario("transaction_burst", options=RunOptions(policy_version=1))
    app.simulate_attack("direct_injection", options=RunOptions(controls=NONE))
    assert _counts(app) == before


def test_no_stored_decision_ever_executed_with_fewer_controls(app):
    for d in app.store.decisions(limit=100_000):
        assert set(d["controls"]) >= FULL, d["decision_id"]
        assert d["policy"]["version"] == DEFAULT_REGISTRY.active(d["policy"]["policy_id"]).version


def test_merchant_workflow_refuses_a_risk_model(app):
    with pytest.raises(ValueError, match="merchant onboarding"):
        app.evaluate_merchant(
            "apply",
            {"registration_status": "verified"},
            options=RunOptions(risk_model=scoring.get_model("txn-1.0")),
        )


# ---- API ------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def server(app):
    httpd = make_server(app, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _post(url, obj):
    req = urllib.request.Request(
        url, json.dumps(obj).encode(), {"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _bodies(app):
    return {
        "/v1/transactions/evaluate": {
            "transaction_id": app.store.transactions(limit=1)[0].transaction_id
        },
        "/v1/disputes/evaluate": {"narrative": CLAIM, "ledger": REFUNDED},
        "/v1/merchants/evaluate": {
            "application": "We sell shoes.",
            "records": {"registration_status": "verified"},
        },
        "/v1/accounts/evaluate": {"session_id": app.store.sessions(limit=1)[0].session_id},
        "/v1/investigations/evaluate": {"account_id": app.store.accounts()[0].account_id},
    }


SWITCHES = [
    {"unguarded": True},
    {"options": {"unguarded": True}},
    {"options": {"controls": ["risk", "policy"]}},
    {"options": {"controls": []}},
    {"options": {"policy_version": 1}},
    {"options": {"risk_model": "txn-1.0"}},
]


@pytest.mark.parametrize("switch", SWITCHES, ids=lambda s: json.dumps(s))
def test_every_evaluate_route_refuses_every_what_if_switch(server, app, switch):
    before = _counts(app)
    for route, body in _bodies(app).items():
        code, err = _post(server + route, {**body, **switch})
        assert code == 403, (route, switch, err)
        assert "what-if" in err["error"]
    assert _counts(app) == before


def test_evaluate_routes_accept_user_options_and_reject_unknown_ones(server, app):
    for route, body in _bodies(app).items():
        code, d = _post(server + route, {**body, "options": {"hardened": True, "skip_agent": True}})
        assert code == 200 and d["authoritative"] is True, (route, d)
        code, err = _post(server + route, {**body, "options": {"bypass_policy": True}})
        assert code == 400 and "unknown options" in err["error"]
    code, err = _post(
        server + "/v1/investigations/evaluate",
        {"account_id": app.store.accounts()[0].account_id, "as_of": "2026-01-01T00:00:00"},
    )
    assert code == 403 and "as_of" in err["error"]


def test_what_if_routes_accept_the_switches_and_record_nothing(server, app):
    before = _counts(app)
    code, sim = _post(
        server + "/v1/attacks/simulate",
        {"kind": "direct_injection", "options": {"policy_version": 1}},
    )
    assert code == 200 and sim["decision"]["authoritative"] is False
    code, sc = _post(
        server + "/v1/scenarios/transaction_burst/run", {"options": {"risk_model": "txn-1.0"}}
    )
    assert code == 200
    assert _counts(app) == before
    # a model for another surface is a client error, not a silent misapplication
    code, err = _post(
        server + "/v1/scenarios/transaction_burst/run", {"options": {"risk_model": "acct-1.0"}}
    )
    assert code == 400 and "surface" in err["error"]


# ---- CLI ------------------------------------------------------------------------------------
AUTHORITATIVE_COMMANDS = [
    ["transaction", "evaluate", "TX-X"],
    ["dispute", "evaluate", "--id", "DSP-X"],
    ["merchant", "evaluate", "--id", "KYB-X"],
    ["account", "evaluate", "SES-X"],
    ["investigation", "evaluate", "ACC-X"],
]


@pytest.mark.parametrize("cmd", AUTHORITATIVE_COMMANDS, ids=lambda c: c[0])
@pytest.mark.parametrize(
    "flag", [["--unguarded"], ["--policy-version", "1"], ["--risk-model", "txn-1.0"]]
)
def test_cli_authoritative_commands_have_no_what_if_flags(tmp_path, capsys, cmd, flag):
    with pytest.raises(SystemExit) as e:
        cli_main(["--db", str(tmp_path / "x.db"), *cmd, *flag])
    assert e.value.code == 2 and "unrecognized arguments" in capsys.readouterr().err
