"""Time-aware graph edges, as-of queries and the windowed circular-transfer search."""

from __future__ import annotations

from datetime import datetime, timedelta

from sentinel.domain.entities import Transaction
from sentinel.risk import monitoring
from sentinel.risk.behavioral import BehavioralBaseline
from sentinel.risk.graph import EntityGraph, Node

T0 = datetime(2026, 9, 1, 12, 0)


def _iso(days: float = 0, hours: float = 0) -> str:
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


# ---- windowed cycles -----------------------------------------------------------------
def _ring(ts_a: str, ts_b: str, ts_c: str) -> EntityGraph:
    g = EntityGraph()
    g.link("account", "A", "TRANSFERRED_TO", "account", "B", ts=ts_a)
    g.link("account", "B", "TRANSFERRED_TO", "account", "C", ts=ts_b)
    g.link("account", "C", "TRANSFERRED_TO", "account", "A", ts=ts_c)
    return g


def test_cycle_inside_window_is_found_and_outside_is_not():
    g = _ring(_iso(-5), _iso(-3), _iso(-1))
    inside = g.find_cycles_from(
        Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30), until=_iso()
    )
    assert inside and [n.id for n in inside[0]] == ["A", "B", "C", "A"]
    # one hop is 200 days old: no cycle within the window, still a cycle with no window
    old = _ring(_iso(-200), _iso(-3), _iso(-1))
    assert old.find_cycles_from(Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30)) == []
    assert old.find_cycles_from(Node("account", "A"), "TRANSFERRED_TO")


def test_cycle_window_boundaries_are_inclusive():
    g = _ring(_iso(-30), _iso(-15), _iso(0))
    assert g.find_cycles_from(
        Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30), until=_iso(0)
    )
    assert not g.find_cycles_from(
        Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30, hours=1), until=_iso(0)
    )
    assert not g.find_cycles_from(
        Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30), until=_iso(0, hours=-1)
    )


def test_multiple_cycles_are_deterministic_and_legit_repeats_are_not_cycles():
    g = _ring(_iso(-5), _iso(-3), _iso(-1))
    g.link("account", "A", "TRANSFERRED_TO", "account", "D", ts=_iso(-4))
    g.link("account", "D", "TRANSFERRED_TO", "account", "A", ts=_iso(-2))
    c1 = g.find_cycles_from(Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30))
    c2 = g.find_cycles_from(Node("account", "A"), "TRANSFERRED_TO", since=_iso(-30))
    assert c1 == c2 and len(c1) == 2 and c1[0] == [Node("account", n) for n in ("A", "D", "A")]
    # repeated one-way salary-style transfers never form a cycle
    h = EntityGraph()
    for i in range(6):
        h.link("account", "EMP", "TRANSFERRED_TO", "account", "LANDLORD", ts=_iso(-30 * i))
    assert h.find_cycles_from(Node("account", "EMP"), "TRANSFERRED_TO") == []


def test_monitoring_circular_indicator_respects_the_window():
    hist = [
        Transaction(f"TX-{i}", "A", "M-1", "INS-1", "DEV-1", 2000, "INR", _iso(-200 + i), "IN")
        for i in range(20)
    ]
    base = BehavioralBaseline.from_history("A", hist)
    recent = _ring(_iso(-5), _iso(-3), _iso(-1))
    stale = _ring(_iso(-100), _iso(-90), _iso(-80))
    for g, expect in ((recent, True), (stale, False)):
        ctx = monitoring.MonitoringContext("A", tuple(hist), base, {}, g, _iso())
        a = monitoring.assess_account_activity(ctx)
        assert (any(f.code == "circular_transfers" for f in a.factors)) is expect
        assert a.features["cycle_window_days"] == 30


# ---- as-of edges and profiles --------------------------------------------------------
def test_graph_queries_honour_as_of():
    g = EntityGraph()
    g.link("account", "A", "USES", "device", "D", ts=_iso(-10))
    g.link("account", "B", "USES", "device", "D", ts=_iso(-1))
    assert g.accounts_sharing_device("D", as_of=_iso(-5)) == ["A"]
    assert g.accounts_sharing_device("D") == ["A", "B"]
    assert g.linked_accounts("A", as_of=_iso(-5)) == set()
    assert g.linked_accounts("A") == {"B"}
    assert g.device_first_used("A", "D") == _iso(-10) and g.device_first_used("A", "X") is None
