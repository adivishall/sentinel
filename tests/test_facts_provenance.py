"""Demo / simulation input vs system-of-record input.

Sentinel adjudicates claims against trusted facts; it does not independently verify
those facts. Every decision therefore says where its facts came from
(``Decision.facts_source``), the decision's audit event records it, the API returns
it and the console shows it:

    system_of_record  read by id from the record store (here: the synthetic SQLite store)
    caller_supplied   demo / simulation input -- facts in the request body
    demo_fixture      demo / simulation input -- a shipped attack or scenario preset

These tests exist so that the distinction cannot quietly disappear."""

from __future__ import annotations

import json
import pathlib
import threading
import urllib.request
from dataclasses import replace

import pytest

from sentinel.api.server import make_server
from sentinel.app import SentinelApp
from sentinel.domain.enums import FactsSource

SOR, CALLER, FIXTURE = (
    FactsSource.SYSTEM_OF_RECORD.value,
    FactsSource.CALLER_SUPPLIED.value,
    FactsSource.DEMO_FIXTURE.value,
)
LEDGER = {"amount": 12000, "delivery_status": "not_delivered", "policy_auto_limit": 50000}


@pytest.fixture(scope="module")
def app():
    a = SentinelApp.demo(seed=9, customers=40, merchants=8, transactions=500)
    a.analyze(transactions=5, disputes=3, applications=2, sessions=3, accounts=1)
    return a


def test_every_source_is_described_and_published():
    for f in FactsSource:
        assert f.describe and len(f.describe) > 30
    assert "no real ledger integration" in FactsSource.SYSTEM_OF_RECORD.describe
    assert "not read them from any system of record" in FactsSource.CALLER_SUPPLIED.describe


def test_each_entry_point_labels_its_facts(app):
    st = app.store
    d = st.disputes(limit=1)[0]
    t = st.transactions(limit=1)[0]
    k = st.kyb_applications(limit=1)[0]
    s = st.sessions(limit=1)[0]
    cases = [
        (app.evaluate_dispute("", dispute_id=d.dispute_id), SOR),
        (app.evaluate_dispute("It never arrived.", LEDGER), CALLER),
        (app.evaluate_dispute_conversation(("It never arrived.",), LEDGER), CALLER),
        (app.evaluate_transaction(t.transaction_id), SOR),
        (app.evaluate_transaction(t), SOR),  # the stored record itself
        (app.evaluate_transaction(replace(t, amount=t.amount + 1)), CALLER),  # an edited copy
        (app.evaluate_merchant("", application_id=k.application_id), SOR),
        (app.evaluate_merchant("We sell shoes.", {"registration_status": "verified"}), CALLER),
        (app.evaluate_account(s.session_id), SOR),
        (app.evaluate_account(replace(s, country="RO")), CALLER),
        (app.evaluate_investigation(st.accounts()[0].account_id), SOR),
    ]
    for b, want in cases:
        assert b.decision.facts_source == want, (b.decision.workflow, want)
    sim = app.simulate_attack("document_injection", compare=True)
    assert sim["with_sentinel"]["decision"]["facts_source"] == FIXTURE
    assert sim["without_sentinel"]["decision"]["facts_source"] == FIXTURE


def test_the_audit_chain_and_the_stored_decision_record_it(app):
    b = app.evaluate_dispute("It never arrived.", LEDGER)
    ev = app.audit_event(b.decision.decision_id)
    assert ev is not None and ev["detail"]["facts_source"] == CALLER
    assert app.store.decision(b.decision.decision_id)["facts_source"] == CALLER
    assert app.verify_audit().ok


def test_the_review_packet_and_system_info_explain_it(app):
    case = next(c for c in app.cases(limit=200) if c.decision_ids)
    pk = app.review_packet(case.case_id)
    assert pk is not None and pk["facts_source"]["source"] in (SOR, CALLER, FIXTURE)
    assert pk["facts_source"]["meaning"] == FactsSource(pk["facts_source"]["source"]).describe
    assert set(app.system_info()["facts_sources"]) == {SOR, CALLER, FIXTURE}


def test_a_past_as_of_investigation_is_a_backtest_never_recorded(app):
    n = app.store.count("decisions"), len(app.runtime.audit)
    b = app.evaluate_investigation(app.store.accounts()[0].account_id, as_of="2026-06-01T00:00:00")
    assert not b.decision.authoritative
    assert (app.store.count("decisions"), len(app.runtime.audit)) == n


def test_the_api_returns_it_for_every_input_form(app):
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(path, body):
        req = urllib.request.Request(
            base + path, json.dumps(body).encode(), {"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    st = app.store
    t = st.transactions(limit=1)[0]
    try:
        assert (
            post("/v1/disputes/evaluate", {"narrative": "never arrived", "ledger": LEDGER})[
                "facts_source"
            ]
            == CALLER
        )
        assert (
            post("/v1/disputes/evaluate", {"dispute_id": st.disputes(limit=1)[0].dispute_id})[
                "facts_source"
            ]
            == SOR
        )
        assert (
            post("/v1/transactions/evaluate", {"transaction_id": t.transaction_id})["facts_source"]
            == SOR
        )
        assert (
            post("/v1/merchants/evaluate", {"application": "x", "records": {"prior_flags": 0}})[
                "facts_source"
            ]
            == CALLER
        )
        assert (
            post("/v1/attacks/simulate", {"kind": "direct_injection"})["decision"]["facts_source"]
            == FIXTURE
        )
    finally:
        httpd.shutdown()


def test_the_console_shows_it():
    js = (pathlib.Path(__file__).parents[1] / "ui" / "app.js").read_text()
    assert "factsChip(d.facts_source)" in js and "SYSTEM OF RECORD" in js
    assert "CALLER-SUPPLIED" in js and "DEMO FIXTURE" in js
