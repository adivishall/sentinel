"""Synthetic transaction monitoring / investigation simulation.

An *educational* layer that recognises structured patterns commonly discussed
in transaction monitoring -- structuring-like behaviour, rapid movement,
velocity, geography shifts, high-risk merchant exposure, circular transfers,
dormant-account activation. It makes **no** claim of regulatory compliance,
sanctions screening, or production effectiveness. Indicators are structured;
an AI agent may summarise them but never alters them."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta

from sentinel.domain.entities import Merchant, Transaction
from sentinel.domain.risk import RiskAssessment
from sentinel.risk import scoring
from sentinel.risk.behavioral import BehavioralBaseline, parse_ts
from sentinel.risk.graph import EntityGraph, Node
from sentinel.risk.scoring import Features, RiskModel, Rule


@dataclass(frozen=True)
class MonitoringContext:
    account_id: str
    transactions: tuple[Transaction, ...]  # this account's, chronological
    baseline: BehavioralBaseline
    merchants: dict[str, Merchant]
    graph: EntityGraph
    as_of: str
    window_days: int = 30
    inbound: tuple[Transaction, ...] = field(default_factory=tuple)  # transfers INTO this account
    linked_accounts: tuple[str, ...] = field(
        default_factory=tuple
    )  # via shared device / instrument
    linked_risk: int = 0  # worst precomputed risk among linked accounts / devices
    shared_device_accounts: int = 0  # accounts sharing this account's devices


def extract_features(
    ctx: MonitoringContext, model: RiskModel = scoring.MONITORING_V1
) -> dict[str, object]:
    as_of = parse_ts(ctx.as_of)
    start = as_of - timedelta(days=ctx.window_days)
    window = [t for t in ctx.transactions if start <= parse_ts(t.timestamp) <= as_of]
    threshold = model.t("reporting_threshold", 50_000)
    band = model.t("structuring_band", 0.8)

    # structuring-like: >=3 transfers just below the threshold within 7 days
    transfers = [t for t in window if t.channel == "transfer"]
    near = [t for t in transfers if band * threshold <= t.amount < threshold]
    structuring_ids: list[str] = []
    for i, t in enumerate(near):
        t0 = parse_ts(t.timestamp)
        cluster = [u for u in near[i:] if parse_ts(u.timestamp) - t0 <= timedelta(days=7)]
        if len(cluster) >= 3:
            structuring_ids = [u.transaction_id for u in cluster]
            break

    # rapid movement: inbound then >=80% moved out within 24h
    rapid_ids: list[str] = []
    for inb in ctx.inbound:
        t0 = parse_ts(inb.timestamp)
        out = [u for u in transfers if t0 <= parse_ts(u.timestamp) <= t0 + timedelta(hours=24)]
        if out and sum(u.amount for u in out) >= 0.8 * inb.amount:
            rapid_ids = [inb.transaction_id] + [u.transaction_id for u in out]
            break

    # velocity vs baseline
    daily = len(window) / max(1, ctx.window_days)
    velocity_x = daily / ctx.baseline.daily_count if ctx.baseline.daily_count else 0.0

    # geography shift: >=3 countries in any 7-day span
    geo_shift = False
    for i, t in enumerate(window):
        t0 = parse_ts(t.timestamp)
        countries = {
            u.country for u in window[i:] if parse_ts(u.timestamp) - t0 <= timedelta(days=7)
        }
        if len(countries) >= 3:
            geo_shift = True
            break

    # high-risk merchant exposure by spend share
    spend = sum(t.amount for t in window if t.channel != "transfer")
    hi = sum(
        t.amount
        for t in window
        if t.channel != "transfer"
        and ctx.merchants.get(t.merchant_id)
        and ctx.merchants[t.merchant_id].mcc_risk == "high"
    )
    exposure = hi / spend if spend else 0.0

    # circular transfers through the transfer graph
    cycles = ctx.graph.find_cycles_from(Node("account", ctx.account_id), "TRANSFERRED_TO")

    # dormant activation: >= dormant_days of silence, then >=5 txns in 3 days
    dormant = False
    prior = [t for t in ctx.transactions if parse_ts(t.timestamp) < start]
    if prior and window:
        gap = (parse_ts(window[0].timestamp) - parse_ts(prior[-1].timestamp)).days
        burst = [
            t
            for t in window
            if parse_ts(t.timestamp) - parse_ts(window[0].timestamp) <= timedelta(days=3)
        ]
        dormant = gap >= model.t("dormant_days", 90) and len(burst) >= 5

    return {
        "window_transactions": len(window),
        "structuring_ids": structuring_ids,
        "rapid_ids": rapid_ids,
        "velocity_x": round(velocity_x, 2),
        "geo_shift": geo_shift,
        "countries": dict(Counter(t.country for t in window)),
        "high_risk_exposure": round(exposure, 3),
        "circular_cycles": [[n.id for n in c] for c in cycles[:3]],
        "dormant_activation": dormant,
        "linked_accounts": list(ctx.linked_accounts),
        "linked_risk": ctx.linked_risk,
        "shared_device_accounts": ctx.shared_device_accounts,
        "evidence_ids": {},
    }


def _ids(f: Features, key: str) -> list[str]:
    v = f.get(key, [])
    return list(v) if isinstance(v, list) else []


RULES: tuple[Rule, ...] = (
    (
        "structuring_like",
        "Structuring-like transfers below threshold",
        lambda f, m: (
            f"{len(_ids(f, 'structuring_ids'))} transfers just below ₹{int(m.t('reporting_threshold', 50000)):,} within 7 days"
            if _ids(f, "structuring_ids")
            else None
        ),
    ),
    (
        "rapid_movement",
        "Rapid movement of funds",
        lambda f, m: (
            "≥80% of an inbound transfer moved out within 24h" if _ids(f, "rapid_ids") else None
        ),
    ),
    ("velocity", "Unusual transaction velocity", lambda f, m: f"{float(f.get('velocity_x', 0) or 0):.1f}x baseline daily count" if float(f.get("velocity_x", 0) or 0) >= 3 else None),  # type: ignore[arg-type]
    (
        "geo_shift",
        "Sudden geography shifts",
        lambda f, m: "3+ countries within 7 days" if f.get("geo_shift") else None,
    ),
    ("high_risk_merchant_exposure", "High-risk merchant exposure", lambda f, m: f"{float(f.get('high_risk_exposure', 0) or 0):.0%} of spend" if float(f.get("high_risk_exposure", 0) or 0) >= 0.4 else None),  # type: ignore[arg-type]
    ("circular_transfers", "Circular transfers", lambda f, m: " → ".join(_ids(f, "circular_cycles")[0]) if _ids(f, "circular_cycles") else None),  # type: ignore[arg-type]
    (
        "dormant_activation",
        "Dormant account activation",
        lambda f, m: "long silence followed by a burst" if f.get("dormant_activation") else None,
    ),
    (
        "shared_device_ring",
        "Shares a device with other accounts",
        lambda f, m: (
            f"{f.get('shared_device_accounts')} accounts on the same device"
            if float(str(f.get("shared_device_accounts", 0) or 0)) >= 3
            else None
        ),
    ),
    (
        "linked_entity_risk",
        "Linked entity risk",
        lambda f, m: (
            ", ".join(_ids(f, "linked_accounts")[:3]) or "linked device"
            if float(str(f.get("linked_risk", 0) or 0)) >= 50
            else None
        ),
    ),
)


def assess_account_activity(
    ctx: MonitoringContext, model: RiskModel = scoring.MONITORING_V1
) -> RiskAssessment:
    features = extract_features(ctx, model)
    return scoring.build_assessment(
        entity_type="account", entity_id=ctx.account_id, features=features, model=model, rules=RULES
    )
