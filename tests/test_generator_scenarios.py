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
