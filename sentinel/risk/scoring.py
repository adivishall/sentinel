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
        "velocity_spike": 13,
        "velocity_elevated": 8,
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
        "structuring_like": 30,
        "rapid_movement": 25,
        "velocity": 12,
        "geo_shift": 12,
        "high_risk_merchant_exposure": 15,
        "circular_transfers": 30,
        "dormant_activation": 20,
        "shared_device_ring": 15,
        "linked_entity_risk": 20,
    },
    thresholds={"reporting_threshold": 50_000, "structuring_band": 0.8, "dormant_days": 90},
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
    for m in (TRANSACTION_V1, TRANSACTION_V1_1, ACCOUNT_SECURITY_V1, MONITORING_V1, DISPUTE_V1)
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
    )
