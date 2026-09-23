"""Risk engine: explainable, deterministic, replayable scoring over trusted records."""

from datetime import datetime, timedelta

from sentinel.domain.entities import (
    Account,
    Device,
    Dispute,
    LoginSession,
    Merchant,
    PaymentInstrument,
    Transaction,
)
from sentinel.domain.enums import RiskLevel
from sentinel.risk import account_security, monitoring, scoring, transaction
from sentinel.risk.behavioral import BehavioralBaseline
from sentinel.risk.dispute import assess_dispute
from sentinel.risk.entity import EntityRiskEngine
from sentinel.risk.graph import EntityGraph, Node
from sentinel.security.trust_boundary import DisputeFacts

T0 = datetime(2026, 9, 1, 10, 0)


def _ts(days=0, hours=0):
    return (T0 + timedelta(days=days, hours=hours)).isoformat()


def _txn(
    i,
    amount=2000,
    *,
    account="ACC-1",
    merchant="M-1",
    device="DEV-1",
    country="IN",
    days=0,
    hours=0,
    channel="ecommerce",
    auth="otp",
    instrument="INS-1",
    counterparty=None,
):
    return Transaction(
        f"TX-{i}",
        account,
        merchant,
        instrument,
        device,
        amount,
        "INR",
        _ts(days, hours),
        country,
        channel,
        auth,
        "delivered",
        counterparty,
    )


def _history(n=40):
    # 40 transactions over 40 days, ~₹2,000 ± small noise, same device/merchant/country, 10:00 or 11:00
    return [_txn(i, 2000 + (i % 5) * 100, days=-40 + i, hours=(i % 2)) for i in range(n)]


def _baseline():
    return BehavioralBaseline.from_history("ACC-1", _history())


def _ctx(**over):
    base = dict(
        baseline=_baseline(),
        account=Account("ACC-1", "CUST-1", _ts(-400)),
        merchant=Merchant("M-1", "Shop", "5411", "low", "IN", "OWN-1", "shop.in", _ts(-800)),
        instrument=PaymentInstrument("INS-1", "ACC-1", "card", "1234", _ts(-300)),
        recent=(),
        known_devices=frozenset({"DEV-1"}),
    )
    base.update(over)
    return transaction.TransactionContext(**base)


# ---- baselines ----------------------------------------------------------------
def test_baseline_statistics_and_deviations():
    b = _baseline()
    assert b.n == 40 and 2000 <= b.mean_amount <= 2400 and b.stddev_amount > 0
    assert (
        "IN" in b.common_countries and "DEV-1" in b.common_devices and "M-1" in b.common_merchants
    )
    assert b.usual_hours == frozenset({10, 11})
    assert b.amount_z(2200) < 2 and b.amount_z(50_000) > 4
    assert not b.knows_device("DEV-9") and not b.is_usual_hour(3)
    assert BehavioralBaseline.empty("x").amount_z(10) == 0.0
    assert "average_transaction_amount" in b.to_dict()


# ---- scoring ------------------------------------------------------------------
def test_normal_transaction_is_low_risk_and_explainable():
    a = transaction.assess_transaction(_txn(99, 2100), _ctx())
    assert a.level is RiskLevel.LOW and a.score < 25, a.explain()
    assert a.model_version == "txn-1.0" and a.recommended_action == "ALLOW"


def test_account_takeover_pattern_is_critical():
    ctx = _ctx(known_devices=frozenset({"DEV-1"}), last_country="IN", last_country_ts=_ts(hours=-1))
    t = _txn(100, 180_000, device="DEV-NEW", country="RO", auth="password")
    a = transaction.assess_transaction(t, ctx)
    codes = {f.code for f in a.factors}
    assert {
        "amount_anomaly_extreme",
        "new_device",
        "impossible_travel",
        "auth_weak",
    } <= codes, codes
    assert a.level is RiskLevel.CRITICAL and a.recommended_action == "BLOCK"
    assert sum(f.points for f in a.factors) >= a.score  # capped at 100
    text = a.explain()
    assert "/ 100" in text and "New device" in text


def test_velocity_spike_detected():
    recent = tuple(_txn(200 + i, 1500, hours=-0.5 + i * 0.05) for i in range(6))
    a = transaction.assess_transaction(_txn(300, 1500), _ctx(recent=recent))
    assert any(f.code == "velocity_spike" for f in a.factors)


def test_score_is_deterministic_and_rescorable_under_other_model():
    ctx = _ctx()
    t = _txn(101, 60_000, device="DEV-NEW", country="US")
    a = transaction.assess_transaction(t, ctx)
    b = transaction.assess_transaction(t, ctx)
    assert a.score == b.score and [f.code for f in a.factors] == [f.code for f in b.factors]
    r = transaction.rescore(a.features, t.transaction_id, scoring.TRANSACTION_V1_1)
    assert r.model_version == "txn-1.1" and r.score != a.score  # geography weighted differently


def test_thin_baseline_uses_ratio():
    ctx = _ctx(baseline=BehavioralBaseline.from_history("ACC-1", _history(3)))
    a = transaction.assess_transaction(_txn(102, 90_000), ctx)
    assert any(f.code == "amount_ratio_small_baseline" for f in a.factors)


# ---- graph + entity profiles --------------------------------------------------
def _world():
    g = EntityGraph()
    accounts = {f"ACC-{i}": Account(f"ACC-{i}", f"CUST-{i}", _ts(-200)) for i in range(1, 5)}
    accounts["ACC-4"] = Account("ACC-4", "CUST-4", _ts(-5), status="frozen")
    devices = {
        "DEV-SHARED": Device("DEV-SHARED", "fp", _ts(-30)),
        "DEV-1": Device("DEV-1", "fp1", _ts(-300)),
    }
    merchants = {
        "M-1": Merchant("M-1", "Good", "5411", "low", "IN", "OWN-1", "good.in", _ts(-900)),
        "M-BAD": Merchant(
            "M-BAD", "Shady", "7995", "high", "IN", "OWN-2", "shady.in", _ts(-20), "unverified", 2
        ),
        "M-SIB": Merchant(
            "M-SIB", "Sibling", "5999", "low", "IN", "OWN-2", "sib.in", _ts(-400), "verified", 0
        ),
    }
    txns = {}
    for i in range(20):
        t = _txn(i, 3000, account="ACC-1", merchant="M-BAD" if i < 8 else "M-1", days=-i)
        txns[t.transaction_id] = t
    disputes = {f"D-{i}": Dispute(f"D-{i}", f"TX-{i}", "ACC-1", 3000, _ts(-i)) for i in range(2)}
    for a in accounts.values():
        g.link("customer", a.customer_id, "OWNS", "account", a.account_id)
    for acc in ("ACC-1", "ACC-2", "ACC-3"):
        g.link("account", acc, "USES", "device", "DEV-SHARED")
    g.link("account", "ACC-4", "USES", "device", "DEV-SHARED")
    g.link("account", "ACC-1", "USES", "device", "DEV-1")
    for m in merchants.values():
        g.link("merchant", m.merchant_id, "OWNED_BY", "owner", m.owner_id)
    for t in txns.values():
        g.link("account", t.account_id, "MADE", "transaction", t.transaction_id)
        g.link("transaction", t.transaction_id, "PAID", "merchant", t.merchant_id)
    return g, EntityRiskEngine(g, {}, accounts, merchants, devices, txns, disputes, _ts())


def test_graph_queries():
    g, _ = _world()
    assert set(g.accounts_sharing_device("DEV-SHARED")) == {"ACC-1", "ACC-2", "ACC-3", "ACC-4"}
    assert set(g.merchants_for_owner("OWN-2")) == {"M-BAD", "M-SIB"}
    assert len(g.transactions_for_account("ACC-1")) == 20
    assert g.linked_accounts("ACC-1") == {"ACC-2", "ACC-3", "ACC-4"}
    nodes, edges = g.neighborhood(Node("device", "DEV-SHARED"), depth=1)
    assert len(nodes) >= 5 and edges
    d = g.to_dict(Node("account", "ACC-1"), depth=1)
    assert d["root"] == "account:ACC-1" and d["nodes"] and d["edges"]


def test_entity_profiles_are_ordered_and_explainable():
    _, eng = _world()
    dev = eng.device_risk("DEV-SHARED")
    assert {"shared_device", "linked_frozen_account"} <= {f.code for f in dev.factors}
    bad = eng.merchant_risk("M-BAD")
    assert {
        "dispute_ratio_high",
        "mcc_high",
        "registration_unverified",
        "prior_flags",
        "merchant_young",
    } <= {f.code for f in bad.factors}
    assert bad.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    sib = eng.merchant_risk("M-SIB")
    assert any(f.code == "owner_linked_flagged" for f in sib.factors)
    acc = eng.account_risk("ACC-1")
    assert any(f.code == "prior_disputes_many" for f in acc.factors)
    assert any(f.code.startswith("linked_device") for f in acc.factors)
    cust = eng.customer_risk("CUST-1")
    assert cust.score == acc.score
    worst, who = eng.linked_entity_risk("ACC-2", "DEV-SHARED")
    assert worst > 0 and who


# ---- account security ----------------------------------------------------------
def test_account_security_signals():
    s = LoginSession(
        "S-1",
        "ACC-1",
        "DEV-NEW",
        "1.2.3.4",
        "RO",
        _ts(),
        mfa_passed=False,
        events=("payout_change", "mfa_change"),
    )
    ctx = account_security.AccountSecurityContext(
        frozenset({"DEV-1"}), frozenset({"IN"}), last_country="IN", hours_since_last_login=0.5
    )
    a = account_security.assess_login(s, ctx)
    codes = {f.code for f in a.factors}
    assert {
        "new_device",
        "new_country",
        "impossible_travel",
        "payout_change",
        "mfa_change",
        "mfa_not_passed",
    } <= codes
    assert a.level is RiskLevel.CRITICAL
    ok = account_security.assess_login(
        LoginSession("S-2", "ACC-1", "DEV-1", "1.2.3.4", "IN", _ts()), ctx
    )
    assert ok.level is RiskLevel.LOW


# ---- monitoring ------------------------------------------------------------------
def test_monitoring_patterns():
    g = EntityGraph()
    g.link("account", "ACC-1", "TRANSFERRED_TO", "account", "ACC-2")
    g.link("account", "ACC-2", "TRANSFERRED_TO", "account", "ACC-3")
    g.link("account", "ACC-3", "TRANSFERRED_TO", "account", "ACC-1")
    hist = [_txn(i, 2000, days=-200 + i) for i in range(20)]
    burst = [
        _txn(100 + i, 45_000, days=-3, hours=i, channel="transfer", counterparty="ACC-2")
        for i in range(4)
    ]
    geo = [
        _txn(200 + i, 1000, days=-2, hours=i, country=c) for i, c in enumerate(("IN", "AE", "GB"))
    ]
    inbound = (
        _txn(
            300,
            200_000,
            days=-3,
            hours=-1,
            account="ACC-9",
            channel="transfer",
            counterparty="ACC-1",
        ),
    )
    ctx = monitoring.MonitoringContext(
        "ACC-1",
        tuple(hist + burst + geo),
        BehavioralBaseline.from_history("ACC-1", hist),
        {},
        g,
        _ts(),
        inbound=inbound,
    )
    a = monitoring.assess_account_activity(ctx)
    codes = {f.code for f in a.factors}
    assert {
        "structuring_like",
        "circular_transfers",
        "geo_shift",
        "rapid_movement",
        "dormant_activation",
    } <= codes, codes
    assert a.level is RiskLevel.CRITICAL
    assert a.features["circular_cycles"][0][0] == "ACC-1"


def test_dispute_risk():
    f = DisputeFacts.from_ledger(
        {"amount": 92_000, "prior_disputes_90d": 3, "delivery_status": "delivered"}
    )
    a = assess_dispute("D-1", f, contradicted=True, account_risk_score=60, security_flagged=True)
    assert {
        "prior_disputes_many",
        "amount_over_auto_limit",
        "claim_contradicted",
        "account_risk_high",
        "security_flagged",
    } == {x.code for x in a.factors}
    assert a.level is RiskLevel.CRITICAL
