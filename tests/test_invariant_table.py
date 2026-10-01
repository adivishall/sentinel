"""The invariant table (docs/INVARIANTS.md) and INV-REPLAY-1.

Every test the table names must exist, so the document cannot drift from the suite."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from sentinel.app import SentinelApp
from sentinel.replay.engine import ReplayOverrides

ROOT = Path(__file__).resolve().parent.parent


def _named_tests() -> list[tuple[str, str, str]]:
    text = (ROOT / "docs" / "INVARIANTS.md").read_text(encoding="utf-8")
    out = []
    for row in text.splitlines():
        m = re.match(r"\| (INV-[A-Z]+-\d+) \|", row)
        if m:
            for file, fn in re.findall(r"`(tests/[\w/]+\.py)::(\w+)`", row):
                out.append((m.group(1), file, fn))
    return out


def test_the_table_names_every_invariant():
    names = {inv for inv, _, _ in _named_tests()}
    for inv in (
        "INV-PROV-1",
        "INV-PROV-2",
        "INV-POLICY-1",
        "INV-REVIEW-1",
        "INV-REVIEW-2",
        "INV-CAP-1",
        "INV-TEMP-1",
        "INV-REPLAY-1",
        "INV-AUDIT-1",
        "INV-AUDIT-2",
        "INV-API-1",
        "INV-DEMO-1",
    ):
        assert inv in names, inv


@pytest.mark.parametrize("inv, file, fn", _named_tests())
def test_every_test_the_table_names_exists(inv, file, fn):
    tree = ast.parse((ROOT / file).read_text(encoding="utf-8"))
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert fn in defined, f"{inv}: {file}::{fn} does not exist"


def test_inv_replay_1_replay_never_changes_the_original():
    app = SentinelApp.demo(seed=7, customers=40, merchants=10, transactions=600)
    did = app.evaluate_dispute(
        "", dispute_id=app.store.all_disputes()[0].dispute_id
    ).decision.decision_id
    before = (
        json.dumps(app.store.decision(did), sort_keys=True, default=str),
        json.dumps(app.store.decision_snapshot(did), sort_keys=True, default=str),
        json.dumps(app.runtime.audit.get(did).to_dict(), sort_keys=True, default=str),
    )
    n = len(app.runtime.audit)
    rule = app.runtime.policies.active("dispute-refund").rules[-1].rule_id
    for ov in (
        ReplayOverrides(),
        ReplayOverrides(policy_version=1),
        ReplayOverrides(rule_values={rule: 1}),
        ReplayOverrides(risk_model="disp-1.0"),
    ):
        app.replay(did, ov)
    after = (
        json.dumps(app.store.decision(did), sort_keys=True, default=str),
        json.dumps(app.store.decision_snapshot(did), sort_keys=True, default=str),
        json.dumps(app.runtime.audit.get(did).to_dict(), sort_keys=True, default=str),
    )
    assert after == before and app.verify_audit().ok
    # each replay is itself recorded -- as a new event, after the original
    added = app.runtime.audit.events()[n:]
    assert [e.action.split(":")[0] for e in added] == ["REPLAY"] * 4
