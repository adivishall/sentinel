"""Transaction risk: extract features from *trusted* records, then score them
with a versioned model. The narrative / descriptor text never enters here."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sentinel.domain.entities import Account, Merchant, PaymentInstrument, Transaction
from sentinel.domain.risk import RiskAssessment
from sentinel.risk import scoring
from sentinel.risk.behavioral import BehavioralBaseline, parse_ts
from sentinel.risk.scoring import Features, RiskModel, Rule


@dataclass(frozen=True)
class TransactionContext:
    """Everything the model may look at. All fields are trusted records."""

    baseline: BehavioralBaseline
    account: Account | None
    merchant: Merchant | None
    instrument: PaymentInstrument | None
    recent: tuple[Transaction, ...] = field(default_factory=tuple)  # last 24h for the account
    known_devices: frozenset[str] = frozenset()
    merchant_risk_score: int = 0
    linked_entity_risk: int = 0
    linked_entity_ids: tuple[str, ...] = field(default_factory=tuple)
    last_country: str | None = None
    last_country_ts: str | None = None
    device_shared_accounts: int = 0
    device_first_used: str | None = None  # when this device was first seen on the account


def extract_features(txn: Transaction, ctx: TransactionContext) -> dict[str, object]:
    ts = parse_ts(txn.timestamp)
    b = ctx.baseline
    one_hour = ts - timedelta(hours=1)
    recent_1h = [t for t in ctx.recent if one_hour <= parse_ts(t.timestamp) < ts]
    same_merchant_1h = [t for t in recent_1h if t.merchant_id == txn.merchant_id]
    account_age = (ts - datetime.fromisoformat(ctx.account.opened_at)).days if ctx.account else 0
    instrument_age = (
        (ts - datetime.fromisoformat(ctx.instrument.added_at)).days if ctx.instrument else 0
    )
    impossible = False
    if ctx.last_country and ctx.last_country_ts and ctx.last_country != txn.country:
        hours = (ts - parse_ts(ctx.last_country_ts)).total_seconds() / 3600
        impossible = 0 <= hours < 2
    device_age_hours: float | None = None
    if ctx.device_first_used and ctx.device_first_used <= txn.timestamp:
        device_age_hours = round((ts - parse_ts(ctx.device_first_used)).total_seconds() / 3600, 2)
    return {
        "amount": txn.amount,
        "amount_z": b.amount_z(txn.amount),
        "amount_ratio": b.amount_ratio(txn.amount),
        "baseline_n": b.n,
        "baseline_mean": b.mean_amount,
        "baseline_daily_count": b.daily_count,
        "velocity_1h": len(recent_1h),
        "same_merchant_1h": len(same_merchant_1h),
        "is_new_device": txn.device_id not in ctx.known_devices
        and not b.knows_device(txn.device_id),
        "device_age_hours": device_age_hours,
        "device_shared_accounts": ctx.device_shared_accounts,
        "is_new_country": not b.knows_country(txn.country),
        "impossible_travel": impossible,
        "merchant_mcc_risk": ctx.merchant.mcc_risk if ctx.merchant else "unknown",
        "merchant_risk_score": ctx.merchant_risk_score,
        "is_new_merchant": b.n > 0 and not b.knows_merchant(txn.merchant_id),
        "account_age_days": account_age,
        "instrument_age_days": instrument_age,
        "auth_strength": txn.auth_strength,
        "chargeback_rate": b.chargeback_rate,
        "hour": ts.hour,
        "unusual_hour": b.n >= 10 and not b.is_usual_hour(ts.hour),
        "linked_entity_risk": ctx.linked_entity_risk,
        "linked_entity_ids": list(ctx.linked_entity_ids),
        "country": txn.country,
        "evidence_ids": {},
    }


def _f(features: Features, key: str, default: object = 0) -> object:
    return features.get(key, default)


def _num(features: Features, key: str) -> float:
    v = features.get(key, 0)
    return float(v) if isinstance(v, (int, float)) else 0.0


def _amount_extreme(f: Features, m: RiskModel) -> str | None:
    z = _num(f, "amount_z")
    return (
        f"{z:.1f}σ above baseline (mean ₹{_num(f, 'baseline_mean'):,.0f})"
        if z >= m.t("z_extreme", 4)
        else None
    )


def _amount_high(f: Features, m: RiskModel) -> str | None:
    z = _num(f, "amount_z")
    return f"{z:.1f}σ above baseline" if m.t("z_high", 3) <= z < m.t("z_extreme", 4) else None


def _amount_moderate(f: Features, m: RiskModel) -> str | None:
    z = _num(f, "amount_z")
    return f"{z:.1f}σ above baseline" if m.t("z_moderate", 2) <= z < m.t("z_high", 3) else None


def _amount_ratio(f: Features, m: RiskModel) -> str | None:
    if _num(f, "baseline_n") < 5 and _num(f, "amount_ratio") >= 10:
        return f"{_num(f, 'amount_ratio'):.0f}x the (thin) baseline mean"
    return None


def _velocity_spike(f: Features, m: RiskModel) -> str | None:
    v, d = _num(f, "velocity_1h"), _num(f, "baseline_daily_count")
    return (
        f"{int(v)} transactions in the last hour"
        if v >= max(5.0, m.t("velocity_spike_x", 5) * d)
        else None
    )


def _velocity_elevated(f: Features, m: RiskModel) -> str | None:
    v, d = _num(f, "velocity_1h"), _num(f, "baseline_daily_count")
    if v >= max(5.0, m.t("velocity_spike_x", 5) * d):
        return None
    return (
        f"{int(v)} transactions in the last hour"
        if v >= max(3.0, m.t("velocity_x", 3) * d)
        else None
    )


def _velocity_burst(f: Features, m: RiskModel) -> str | None:
    v = _num(f, "velocity_1h")
    return f"{int(v)} transactions in the last hour" if v >= 8 else None


def _young_shared(f: Features, m: RiskModel) -> str | None:
    if _num(f, "account_age_days") < 30 and _num(f, "device_shared_accounts") >= 3:
        return f"account {int(_num(f, 'account_age_days'))} days old on a device shared by {int(_num(f, 'device_shared_accounts'))} accounts"
    return None


def _bool(key: str, detail: str) -> Rule:
    return (key, detail, lambda f, m: detail if f.get(key) else None)  # type: ignore[return-value]


RULES: tuple[Rule, ...] = (
    ("amount_anomaly_extreme", "Amount far above account baseline", _amount_extreme),
    ("amount_anomaly_high", "Amount well above account baseline", _amount_high),
    ("amount_anomaly_moderate", "Amount above account baseline", _amount_moderate),
    ("amount_ratio_small_baseline", "Amount far above thin baseline", _amount_ratio),
    ("velocity_burst", "Transaction burst", _velocity_burst),
    ("velocity_spike", "Transaction velocity spike", _velocity_spike),
    ("velocity_elevated", "Elevated transaction velocity", _velocity_elevated),
    (
        "new_device",
        "New device",
        lambda f, m: (
            (
                "device never seen on this account"
                if f.get("device_age_hours") is None
                else f"device first seen on this account {_num(f, 'device_age_hours'):.1f}h ago"
            )
            if f.get("is_new_device")
            else None
        ),
    ),
    ("young_account_shared_device", "Young account on a shared device", _young_shared),
    (
        "shared_device",
        "Device shared across accounts",
        lambda f, m: (
            f"{f.get('device_shared_accounts')} accounts"
            if _num(f, "device_shared_accounts") >= 3
            else None
        ),
    ),
    (
        "impossible_travel",
        "Impossible travel",
        lambda f, m: "country changed within 2 hours" if f.get("impossible_travel") else None,
    ),
    (
        "new_country",
        "Unusual geography",
        lambda f, m: (
            f"{f.get('country')} not in usual countries" if f.get("is_new_country") else None
        ),
    ),
    (
        "merchant_risk_critical",
        "Critical-risk merchant",
        lambda f, m: (
            f"merchant score {int(_num(f, 'merchant_risk_score'))}"
            if _num(f, "merchant_risk_score") >= 75
            else None
        ),
    ),
    (
        "merchant_risk_high",
        "High-risk merchant",
        lambda f, m: (
            f"merchant score {int(_num(f, 'merchant_risk_score'))}"
            if 50 <= _num(f, "merchant_risk_score") < 75
            else (
                "high-risk MCC"
                if f.get("merchant_mcc_risk") == "high" and _num(f, "merchant_risk_score") < 50
                else None
            )
        ),
    ),
    (
        "merchant_risk_medium",
        "Medium-risk merchant",
        lambda f, m: (
            "medium-risk MCC"
            if f.get("merchant_mcc_risk") == "medium" and _num(f, "merchant_risk_score") < 50
            else None
        ),
    ),
    (
        "account_age_new",
        "Very new account",
        lambda f, m: (
            f"{int(_num(f, 'account_age_days'))} days old"
            if _num(f, "account_age_days") < 7
            else None
        ),
    ),
    (
        "account_age_young",
        "Young account",
        lambda f, m: (
            f"{int(_num(f, 'account_age_days'))} days old"
            if 7 <= _num(f, "account_age_days") < 30
            else None
        ),
    ),
    (
        "new_instrument",
        "New payment instrument",
        lambda f, m: "instrument added < 1 day ago" if _num(f, "instrument_age_days") < 1 else None,
    ),
    (
        "auth_none",
        "No authentication",
        lambda f, m: "no customer authentication" if f.get("auth_strength") == "none" else None,
    ),
    (
        "auth_weak",
        "Weak authentication",
        lambda f, m: "password only" if f.get("auth_strength") == "password" else None,
    ),
    (
        "chargeback_high",
        "High chargeback history",
        lambda f, m: (
            f"{_num(f, 'chargeback_rate'):.1%} chargeback rate"
            if _num(f, "chargeback_rate") >= 0.1
            else None
        ),
    ),
    (
        "chargeback_some",
        "Some chargeback history",
        lambda f, m: (
            f"{_num(f, 'chargeback_rate'):.1%} chargeback rate"
            if 0.03 <= _num(f, "chargeback_rate") < 0.1
            else None
        ),
    ),
    (
        "unusual_hour",
        "Unusual time of day",
        lambda f, m: f"{f.get('hour')}:00 outside usual hours" if f.get("unusual_hour") else None,
    ),
    (
        "new_merchant",
        "Merchant new for this account",
        lambda f, m: "not among usual merchants" if f.get("is_new_merchant") else None,
    ),
    (
        "repeat_merchant_burst",
        "Repeated merchant burst",
        lambda f, m: (
            f"{int(_num(f, 'same_merchant_1h'))} at same merchant in 1h"
            if _num(f, "same_merchant_1h") >= 3
            else None
        ),
    ),
    ("linked_entity_critical", "Linked entity critical risk", lambda f, m: ", ".join(f.get("linked_entity_ids", []) or []) if _num(f, "linked_entity_risk") >= 75 else None),  # type: ignore[arg-type]
    ("linked_entity_high", "Linked entity high risk", lambda f, m: ", ".join(f.get("linked_entity_ids", []) or []) if 50 <= _num(f, "linked_entity_risk") < 75 else None),  # type: ignore[arg-type]
    ("linked_entity_medium", "Linked entity medium risk", lambda f, m: ", ".join(f.get("linked_entity_ids", []) or []) if 25 <= _num(f, "linked_entity_risk") < 50 else None),  # type: ignore[arg-type]
)


def assess_transaction(
    txn: Transaction, ctx: TransactionContext, model: RiskModel = scoring.TRANSACTION_V1
) -> RiskAssessment:
    features = extract_features(txn, ctx)
    return scoring.build_assessment(
        entity_type="transaction",
        entity_id=txn.transaction_id,
        features=features,
        model=model,
        rules=RULES,
    )


def rescore(features: Features, entity_id: str, model: RiskModel) -> RiskAssessment:
    """Re-score a stored feature snapshot under another model version (replay)."""
    return scoring.build_assessment(
        entity_type="transaction", entity_id=entity_id, features=features, model=model, rules=RULES
    )
