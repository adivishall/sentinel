"""The system-of-record boundary (sentinel.data.providers): the decision logic never
reads storage, and the shipped store satisfies the three interfaces it reads through."""

from __future__ import annotations

import ast
from pathlib import Path

from sentinel.data.providers import (
    FactProvider,
    RecordProvider,
    RiskContextProvider,
    synthetic_sqlite_provider,
)
from sentinel.data.store import SentinelStore

ROOT = Path(__file__).resolve().parent.parent / "sentinel"


def test_the_shipped_store_is_all_three_providers():
    store = SentinelStore(":memory:")
    records, facts, context = synthetic_sqlite_provider(store)
    assert isinstance(records, RecordProvider)
    assert isinstance(facts, FactProvider)
    assert isinstance(context, RiskContextProvider)


def test_decision_logic_never_imports_storage():
    """A system-of-record adapter replaces the providers, not a decision rule: nothing in
    the decision, risk, evidence, policy or security packages imports the store."""
    for pkg in ("decision", "risk", "evidence", "policy", "security"):
        for f in (ROOT / pkg).rglob("*.py"):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    assert not node.module.startswith("sentinel.data.store"), f
                if isinstance(node, ast.Import):
                    assert not any(a.name.startswith("sentinel.data.store") for a in node.names), f
