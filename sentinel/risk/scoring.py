"""Versioned risk models: a weight table turning raw features into an
explainable, capped 0-100 score.

Keeping the model as *data* (weights + thresholds) is what makes replay
possible: a stored feature snapshot can be re-scored under a different model
version without re-reading any source system.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from sentinel.domain.enums import RiskLevel
from sentinel.domain.ids import new_id, now_iso
from sentinel.domain.risk import RiskAssessment, RiskFactor

Features = Mapping[str, object]


def num(features: Features, key: str) -> float:
    """A numeric feature as ``float``; ``0.0`` when it is missing or not a number.
    Every rule table reads features through this so the engines agree on coercion."""
    v = features.get(key, 0)
    return float(v) if isinstance(v, (int, float)) else 0.0


@dataclass(frozen=True)
class RiskModel:
    version: str
    weights: dict[str, int]
    thresholds: dict[str, float] = field(default_factory=dict)
    description: str = ""

    def w(self, code: str) -> int:
        return self.weights.get(code, 0)

    def t(self, code: str, default: float) -> float:
        return self.thresholds.get(code, default)


# ---- Sentinel transaction risk model, version 1.0 (demo values) -----------------
TRANSACTION_V1 = RiskModel(
    version="txn-1.0",
    weights={
        "amount_anomaly_extreme": 22,
        "amount_anomaly_high": 16,
        "amount_anomaly_moderate": 10,
        "amount_ratio_small_baseline": 12,
        "velocity_spike": 20,
        "velocity_elevated": 10,
        "velocity_burst": 30,
        "young_account_shared_device": 14,
        "new_device": 17,
        "shared_device": 8,
        "impossible_travel": 20,
        "new_country": 15,
        "merchant_risk_critical": 15,
        "merchant_risk_high": 10,
        "merchant_risk_medium": 5,
        "account_age_new": 10,
        "account_age_young": 5,
        "new_instrument": 6,
        "auth_none": 12,
        "auth_weak": 8,
        "chargeback_high": 10,
        "chargeback_some": 5,
        "unusual_hour": 6,
        "new_merchant": 4,
        "repeat_merchant_burst": 6,
        "linked_entity_critical": 12,
        "linked_entity_high": 8,
        "linked_entity_medium": 4,
    },
    thresholds={
        "z_extreme": 4.0,
        "z_high": 3.0,
        "z_moderate": 2.0,
        "velocity_x": 3.0,
        "velocity_spike_x": 5.0,
    },
    description="Initial transaction model.",
)

# Version 1.1: geography weighted up, device weighted down, moderate-amount
# threshold raised. Exists so replay can show a *model* change, not just a policy change.
TRANSACTION_V1_1 = RiskModel(
    version="txn-1.1",
    weights={
        **TRANSACTION_V1.weights,
        "new_device": 12,
        "new_country": 18,
        "impossible_travel": 24,
    },
    thresholds={**TRANSACTION_V1.thresholds, "z_moderate": 2.5},
    description="Geography weighted up, device weighted down, moderate-amount threshold 2.5σ.",
)

# Version 2.0: adds velocity in a short window and inter-arrival timing (bursts are
# visible from the 4th transaction instead of the 9th), trusted account-security
# events in the 24 h before the transaction (a payout change or a failed second
# factor shortly before a purchase is the takeover pattern), and payout-instrument
# sharing across accounts (the ring pattern). Weights are Sentinel heuristics,
# documented in docs/RISK_ENGINE.md; nothing here is an industry standard.
TRANSACTION_V2 = RiskModel(
    version="txn-2.0",
    weights={
        **TRANSACTION_V1.weights,
        "rapid_fire": 20,
        "rapid_succession": 15,
        "recent_account_changes": 20,
        "recent_failed_mfa": 8,
        "shared_payout_instrument": 20,
    },
    thresholds={
        **TRANSACTION_V1.thresholds,
        "rapid_window_minutes": 10,
        "rapid_fire_count": 3,
        "rapid_gap_minutes": 15,
        "baseline_gap_hours": 6,
        "security_event_hours": 24,
    },
    description=(
        "v1 plus short-window velocity, inter-arrival timing, recent trusted "
        "account-security events and shared payout instruments."
    ),
)

TRANSACTION_DEFAULT = TRANSACTION_V2

# Which component of the score a factor belongs to (for the auditable breakdown).
FACTOR_GROUPS: dict[str, str] = {
    "amount_anomaly_extreme": "anomaly",
    "amount_anomaly_high": "anomaly",
    "amount_anomaly_moderate": "anomaly",
    "amount_ratio_small_baseline": "anomaly",
    "unusual_hour": "anomaly",
    "new_merchant": "anomaly",
    "repeat_merchant_burst": "anomaly",
    "velocity_spike": "velocity",
    "velocity_elevated": "velocity",
    "velocity_burst": "velocity",
    "rapid_fire": "velocity",
    "rapid_succession": "velocity",
    "new_device": "device_geo",
    "shared_device": "device_geo",
    "young_account_shared_device": "device_geo",
    "impossible_travel": "device_geo",
    "new_country": "device_geo",
    "new_instrument": "device_geo",
    "merchant_risk_critical": "entity",
    "merchant_risk_high": "entity",
    "merchant_risk_medium": "entity",
    "linked_entity_critical": "entity",
    "linked_entity_high": "entity",
    "linked_entity_medium": "entity",
    "shared_payout_instrument": "entity",
    "chargeback_high": "entity",
    "chargeback_some": "entity",
    "account_age_new": "entity",
    "account_age_young": "entity",
    "auth_none": "security",
    "auth_weak": "security",
    "recent_account_changes": "security",
    "recent_failed_mfa": "security",
}

ACCOUNT_SECURITY_V1 = RiskModel(
    version="acct-1.0",
    weights={
        "new_device": 17,
        "new_country": 15,
        "impossible_travel": 25,
        "credential_change": 12,
        "mfa_change": 15,
        "payout_change": 25,
        "session_anomaly": 8,
        "velocity": 10,
        "mfa_not_passed": 15,
        "device_history_thin": 5,
    },
    thresholds={"velocity_1h": 5},
)

MONITORING_V1 = RiskModel(
    version="mon-1.0",
    weights={
        "structuring_like": 55,
        "rapid_movement": 40,
        "velocity": 20,
        "velocity_burst_24h": 30,
        "geo_shift": 15,
        "high_risk_merchant_exposure": 15,
        "circular_transfers": 45,
        "dormant_activation": 50,
        "shared_device_ring": 20,
        "linked_entity_risk": 20,
    },
    thresholds={
        "reporting_threshold": 50_000,
        "structuring_band": 0.8,
        "dormant_days": 90,
        "cycle_window_days": 30,  # every hop of a circular transfer must fall in this window
    },
    description="Single strong pattern -> HIGH; combinations -> CRITICAL. Sentinel demo values.",
)

DISPUTE_V1 = RiskModel(
    version="disp-1.0",
    weights={
        "prior_disputes_many": 20,
        "prior_disputes_some": 8,
        "amount_over_auto_limit": 15,
        "claim_contradicted": 25,
        "account_risk_high": 15,
        "account_risk_medium": 6,
        "security_flagged": 10,
    },
)

MODELS: dict[str, RiskModel] = {
    m.version: m
    for m in (
        TRANSACTION_V1,
        TRANSACTION_V1_1,
        TRANSACTION_V2,
        ACCOUNT_SECURITY_V1,
        MONITORING_V1,
        DISPUTE_V1,
    )
}


def get_model(version: str) -> RiskModel:
    return MODELS[version]


# A factor rule: (code, label, applies(features, model) -> detail | None)
Rule = tuple[str, str, Callable[[Features, RiskModel], str | None]]


def score_features(
    features: Features, model: RiskModel, rules: tuple[Rule, ...]
) -> tuple[int, tuple[RiskFactor, ...]]:
    factors: list[RiskFactor] = []
    for code, label, applies in rules:
        detail = applies(features, model)
        if detail is not None and model.w(code) != 0:
            ev = features.get("evidence_ids", {})
            ev_ids = tuple(ev.get(code, ())) if isinstance(ev, dict) else ()
            factors.append(RiskFactor(code, label, model.w(code), detail, ev_ids))
    total = max(0, min(100, sum(f.points for f in factors)))
    return total, tuple(factors)


def recommended_action(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "ALLOW",
        RiskLevel.MEDIUM: "STEP_UP",
        RiskLevel.HIGH: "REQUIRE_REVIEW",
        RiskLevel.CRITICAL: "BLOCK",
    }[level]


def build_assessment(
    *,
    entity_type: str,
    entity_id: str,
    features: Features,
    model: RiskModel,
    rules: tuple[Rule, ...],
) -> RiskAssessment:
    score, factors = score_features(features, model, rules)
    level = RiskLevel.from_score(score)
    plain = {k: v for k, v in features.items() if k != "evidence_ids"}
    components: dict[str, int] = {}
    for f in factors:
        g = FACTOR_GROUPS.get(f.code, "other")
        components[g] = components.get(g, 0) + f.points
    return RiskAssessment(
        assessment_id=new_id("RISK"),
        entity_type=entity_type,
        entity_id=entity_id,
        score=score,
        level=level,
        factors=factors,
        recommended_action=recommended_action(level),
        model_version=model.version,
        features=dict(plain),
        computed_at=now_iso(),
        components=components,
    )
