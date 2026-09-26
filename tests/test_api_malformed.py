"""Every POST route answers malformed input with a controlled 4xx, never a 500.

A 500 is where a validator was skipped; on a decision API it is also where a
half-validated request could reach the engine. This throws the same battery of
wrong types, missing fields, non-finite numbers and hostile values at every route."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from sentinel.api.server import make_server
from sentinel.app import SentinelApp

BODIES = [
    None,  # not JSON at all
    [],
    "x",
    5,
    {},
    {"options": "x"},
    {"options": {"hardened": "yes"}},
    {"narrative": 5, "ledger": []},
    {"narrative": "a", "ledger": {"amount": 1e309}},
    {"messages": ["a"], "ledger": {"amount": "∞"}},
    {"transaction": {"amount": "x"}},
    {"transaction": {}},
    {"session": {}},
    {"records": "x", "application": "a"},
    {"messages": "x"},
    {"decision_id": 5},
    {"decision_id": "DEC-x", "policy_version": "one"},
    {"rule_values": "x", "decision_id": "DEC-x"},
    {"reviewer": "", "outcome": "approve"},
    {"status": "NOPE", "actor": "a"},
    {"kind": 5},
    {"text": ["x"]},
    {"policy_id": 5},
    {"context": [], "policy_id": "dispute-refund"},
    {"account_id": ["x"]},
    {"transaction_id": {"a": 1}},
    {"dispute_id": 5},
    {"case_type": "nope", "title": "t"},
    {"requested_capability": "GRANT_ALL", "session_id": "SES-x"},
]


@pytest.fixture(scope="module")
def server():
    app = SentinelApp.demo(seed=4, customers=30, merchants=6, transactions=300)
    app.analyze(transactions=3, disputes=2, applications=1, sessions=1, accounts=1)
    httpd = make_server(app, "127.0.0.1", 0)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    from sentinel.domain.enums import Workflow

    cid = app.runtime.cases.open_manual(Workflow.DISPUTE, "probe", ("account:A",)).case_id
    yield f"http://127.0.0.1:{httpd.server_address[1]}", cid
    httpd.shutdown()


ROUTES = [
    "/v1/transactions/evaluate",
    "/v1/disputes/evaluate",
    "/v1/merchants/evaluate",
    "/v1/accounts/evaluate",
    "/v1/investigations/evaluate",
    "/v1/ai/security/evaluate",
    "/v1/policies/evaluate",
    "/v1/policies/validate",
    "/v1/policies/lint",
    "/v1/replay",
    "/v1/cases",
    "/v1/attacks/simulate",
    "/v1/scenarios/transaction_burst/run",
    "/v1/cases/{cid}/transition",
    "/v1/cases/{cid}/decision",
]


def _code(url, body):
    data = json.dumps(body).encode() if body is not None else b"{not json"
    req = urllib.request.Request(url, data, {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


@pytest.mark.parametrize("route", ROUTES)
def test_no_malformed_body_reaches_a_500(server, route):
    base, cid = server
    url = base + route.format(cid=cid)
    bad = [b for b in BODIES if _code(url, b) >= 500]
    assert not bad, (route, bad)


@pytest.mark.parametrize(
    "path",
    [
        "/v1/transactions/%00",
        "/v1/risk/nope/x",
        "/v1/graph/account/x?depth=abc",
        "/v1/decisions?limit=abc",
        "/v1/cases?status=NOPE",
        "/v1/policies/dispute-refund?version=abc",
        "/v1/audit/events?limit=-5",
        "/v1/risk/transaction/../../etc",
    ],
)
def test_odd_get_parameters_are_client_errors(server, path):
    base, _ = server
    try:
        with urllib.request.urlopen(base + path, timeout=20) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    assert code < 500, (path, code)
