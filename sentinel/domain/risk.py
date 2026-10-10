"""Risk assessment objects. Every point on a score traces to a named factor,
and every factor names the evidence it read."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.enums import RiskLevel


@dataclass(frozen=True)
class RiskFactor:
    code: str  # e.g. "amount_anomaly"
    label: str  # human-readable
    points: int
    detail: str = ""
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RiskAssessment:
    assessment_id: str
    entity_type: str  # transaction | account | merchant | device | customer | dispute | login
    entity_id: str
    score: int
    level: RiskLevel
    factors: tuple[RiskFactor, ...]
    recommended_action: str  # ALLOW | STEP_UP | REQUIRE_REVIEW | BLOCK  (a recommendation)
    model_version: str
    features: dict[str, object] = field(default_factory=dict)  # raw signals (for replay)
    computed_at: str = ""
    # Uncapped points per component (anomaly / velocity / device_geo / entity / security);
    # the score is their sum capped to 0-100, so the breakdown is auditable.
    components: dict[str, int] = field(default_factory=dict)
    # SHA-256 of the risk model's configuration (version, weights, thresholds) that scored it
    model_digest: str = ""

    def explain(self) -> str:
        lines = [f"Risk Score: {self.score} ({self.level})  model {self.model_version}"]
        for f in sorted(self.factors, key=lambda x: -x.points):
            sign = "+" if f.points >= 0 else ""
            lines.append(f"{sign}{f.points:>3} {f.label}" + (f" -- {f.detail}" if f.detail else ""))
        lines.append("-" * 32)
        if self.components:
            lines.append(
                "components: "
                + ", ".join(f"{k} {v:+d}" for k, v in sorted(self.components.items()))
            )
        raw = sum(f.points for f in self.factors)
        lines.append(f"{self.score} / 100" + (f"  (uncapped {raw})" if raw != self.score else ""))
        return "\n".join(lines)


@dataclass(frozen=True)
class EntityRiskProfile:
    entity_type: str
    entity_id: str
    score: int
    level: RiskLevel
    factors: tuple[RiskFactor, ...]
    linked_entities: tuple[str, ...] = field(default_factory=tuple)
    model_version: str = ""
    as_of: str = ""  # the profile is point-in-time: only records at or before this moment
