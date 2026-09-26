"""The console may only call routes the API serves, and it may contain no decision
logic. Every literal /v1 path in ui/app.js must match a route, with the method the
console uses."""

from __future__ import annotations

import re
from pathlib import Path

from sentinel.api.server import build_routes
from sentinel.app import SentinelApp

JS = Path("ui/app.js").read_text(encoding="utf-8")


def _calls():
    out = []
    for m in re.finditer(r"API\.(get|post)\(\s*[`\"']([^`\"']+)[`\"']", JS):
        method, path = m.group(1).upper(), m.group(2)
        path = re.sub(r"\$\{[^}]+\}", "X-1", path).split("?")[0]
        out.append((method, path))
    for m in re.finditer(r"fetch\(\s*\"(/v1/[^\"]+)\"", JS):
        out.append(("GET", m.group(1).split("?")[0]))
    return sorted(set(out))


def test_every_console_call_has_a_route():
    router = build_routes(SentinelApp(persist=False))
    missing = [(m, p) for m, p in _calls() if router.match(m, p) is None]
    assert _calls() and not missing, missing


def test_console_has_no_decision_logic():
    for forbidden in (
        "SIGNALS",
        "supports(",
        "policy_auto_limit >",
        "THRESHOLD",
        "risk_score >=",
        "weights",
    ):
        assert forbidden not in JS, forbidden


CSS = Path("ui/styles.css").read_text(encoding="utf-8")


def test_console_layout_and_links_that_broke_once():
    # a clickable table row carries class "row"; the generic flex .row broke every table
    assert "tr.row{display:table-row}" in CSS
    # the replay example button must not carry data-dec (the global handler opened a drawer)
    assert 'id="rp-example" data-example=' in JS and 'id="rp-example" data-dec=' not in JS
    # shareable views used for the README screenshots
    for view in ("aisecurity", "replay", "transactions", "investigations"):
        assert f'key === "{view}"' in JS
    assert 'arg === "example"' in JS and "wireAttacks(arg)" in JS
