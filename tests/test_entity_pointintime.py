"""Point-in-time entity profiles: nothing after the as-of moment is visible."""

from __future__ import annotations

from datetime import datetime, timedelta

from sentinel.domain.entities import Account, Device, Dispute, Merchant, Transaction
from sentinel.risk.entity import EntityRiskEngine
from sentinel.risk.graph import EntityGraph

T0 = datetime(2026, 9, 1, 12, 0)


def _iso(days: float = 0, hours: float = 0) -> str:
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


def _engine() -> EntityRiskEngine:
    g = EntityGraph()
    accounts = {"A": Account("A", "C", _iso(-400)), "B": Account("B", "C2", _iso(-400))}
    merchants = {"M": Merchant("M", "Shop", "5411", "low", "IN", "O", "shop.in", _iso(-800))}
    devices = {"D": Device("D", "fp", _iso(-300)), "D2": Device("D2", "fp2", _iso(-1))}
    txns = {}
    for i in range(10):
        t = Transaction(f"TX-{i}", "A", "M", "INS", "D", 3000, "INR", _iso(-20 + i), "IN")
        txns[t.transaction_id] = t
    disputes = {  # two disputes filed 2 days AFTER the last transaction
        f"DSP-{i}": Dispute(f"DSP-{i}", f"TX-{i}", "A", 3000, _iso(-9)) for i in range(2)
    }
    g.link("account", "A", "USES", "device", "D", ts=_iso(-300))
    g.link("account", "B", "USES", "device", "D", ts=_iso(-2))
    g.link("account", "B", "USES", "device", "D2", ts=_iso(-1))
    g.link("account", "A", "USES", "device", "D2", ts=_iso(-1))
    for t in txns.values():
        g.link("account", "A", "MADE", "transaction", t.transaction_id, ts=t.timestamp)
        g.link("transaction", t.transaction_id, "PAID", "merchant", "M", ts=t.timestamp)
    return EntityRiskEngine(g, {}, accounts, merchants, devices, txns, disputes, _iso())


def test_merchant_profile_ignores_future_disputes():
    eng = _engine()
    before = eng.merchant_risk("M", as_of=_iso(-12))  # disputes not filed yet
    after = eng.merchant_risk("M")  # now: 2 disputes over 10 transactions = 20%
    assert not any(f.code.startswith("dispute_ratio") for f in before.factors)
    assert any(f.code == "dispute_ratio_high" for f in after.factors)
    assert before.as_of == _iso(-12) and after.as_of == _iso()


def test_account_profile_ignores_future_disputes_and_device_links():
    eng = _engine()
    early = eng.account_risk("A", as_of=_iso(-12))
    now = eng.account_risk("A")
    assert not any(f.code.startswith("prior_disputes") for f in early.factors)
    assert any(f.code == "prior_disputes_many" for f in now.factors)
    assert early.linked_entities == () and now.linked_entities == ("B",)
    # a device first seen yesterday is "new" today, not 12 days ago (it did not exist)
    assert any(f.code == "device_new" for f in eng.device_risk("D2").factors)
    assert not any(f.code == "device_new" for f in eng.device_risk("D2", as_of=_iso(-12)).factors)


def test_profiles_are_deterministic_per_as_of_and_cached():
    eng = _engine()
    a1, a2 = eng.account_risk("A", as_of=_iso(-12)), eng.account_risk("A", as_of=_iso(-12))
    assert a1 == a2 and a1 is a2
