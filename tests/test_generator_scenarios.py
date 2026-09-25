"""The synthetic generator produces the signals its scenarios describe."""

from __future__ import annotations

from datetime import datetime, timedelta

from sentinel.data.generator import generate

T0 = datetime(2026, 9, 1, 12, 0)


def _iso(days: float = 0, hours: float = 0) -> str:
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


# ---- generator: the takeover device is genuinely new ----------------------------------
def test_takeover_transactions_carry_new_device_and_scenario_devices_exist_at_scenario_time():
    from sentinel.app import SentinelApp
    from sentinel.risk import transaction as txn_risk

    app = SentinelApp.demo(seed=42, customers=60, merchants=12, transactions=900, persist=False)
    ato = [t for t in app.store.all_transactions() if t.label == "fraud:account_takeover"]
    assert ato
    for t in ato:
        ra = txn_risk.assess_transaction(t, app.transaction_context(t))
        codes = {f.code for f in ra.factors}
        assert "new_device" in codes, (t.transaction_id, codes)
        assert t.device_id not in app.store.account_devices(t.account_id)
    ds = generate(42, 60, 12, 900)
    first_seen = {d.device_id: d.first_seen for d in ds.devices}
    for s in ds.scenarios:
        if s.scenario in ("account_takeover", "graph_linked_fraud"):
            dev = next(e for e in s.entity_ids if e.startswith("DEV-"))
            txs = [t for t in ds.transactions if t.transaction_id in s.entity_ids]
            assert all(first_seen[dev] <= t.timestamp for t in txs)


# ---- generator: the world is internally consistent ------------------------------------
def _default_world():
    return generate()


def test_no_record_is_impossible_in_the_default_world():
    """Nothing happens before the entity it needs existed, nothing after the clock, and
    no scenario tag points at a record the dormant scenario deleted."""
    ds = _default_world()
    idx = ds.by_id()
    registered = {m.merchant_id: m.registered_at for m in ds.merchants}
    for t in ds.transactions:
        assert registered[t.merchant_id] <= t.timestamp <= ds.as_of, t.transaction_id
        if t.channel == "pos":  # an in-store purchase is handed over on the spot
            assert t.delivery_status == "delivered", t.transaction_id
    disputed: set[str] = set()
    for d in ds.disputes:
        tx = idx["transaction"][d.transaction_id]
        assert tx.timestamp <= d.submitted_at <= ds.as_of, d.dispute_id
        assert d.transaction_id not in disputed, d.dispute_id  # disputed once
        disputed.add(d.transaction_id)
    assert all(dev.first_seen <= ds.as_of for dev in ds.devices)
    assert all(k.submitted_at >= registered[k.merchant_id] for k in ds.kyb_applications)
    known = set(idx["transaction"]) | set(idx["dispute"]) | set(idx["device"])
    known |= set(idx["account"]) | set(idx["merchant"])
    for s in ds.scenarios:
        assert all(e in known for e in s.entity_ids), s.scenario


def test_fraud_timestamps_are_not_built_from_midnight():
    ds = _default_world()
    fraud = [t for t in ds.transactions if t.label.startswith("fraud:")]
    assert fraud
    on_the_minute = sum(1 for t in fraud if t.timestamp.endswith(":00"))
    assert on_the_minute / len(fraud) < 0.2


def test_legitimate_behaviour_carries_the_same_signals_as_fraud():
    """A signal that only ever appears on fraud is a label, not a signal: ordinary
    accounts also use unregistered devices, shop in bursts, travel, fail a second
    factor now and then, and get refunds on disputes the merchant accepted."""
    ds = _default_world()
    legit = [t for t in ds.transactions if t.label == "legit"]
    assert any(t.device_id not in ds.account_devices[t.account_id] for t in legit)
    times: dict[str, list[datetime]] = {}
    for t in legit:
        if t.channel != "transfer":
            times.setdefault(t.account_id, []).append(datetime.fromisoformat(t.timestamp))
    assert any(
        ts[i + 2] - ts[i] <= timedelta(minutes=30)
        for ts in map(sorted, times.values())
        for i in range(len(ts) - 2)
    )
    home = {
        a.account_id: next(c.home_country for c in ds.customers if c.customer_id == a.customer_id)
        for a in ds.accounts
    }
    assert any(t.country != home[t.account_id] for t in legit)
    takeovers = sum(1 for s in ds.scenarios if s.scenario == "account_takeover")
    assert sum(1 for s in ds.sessions if not s.mfa_passed) > takeovers
    assert sum(1 for s in ds.sessions if s.events) > takeovers
    assert any(d.refund_state == "refunded" and d.label == "legit" for d in ds.disputes)
