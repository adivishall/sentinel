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

    def explain(self) -> str:
        lines = [f"Risk Score: {self.score} ({self.level})"]
        for f in sorted(self.factors, key=lambda x: -x.points):
            sign = "+" if f.points >= 0 else ""
            lines.append(f"{sign}{f.points:>3} {f.label}" + (f" -- {f.detail}" if f.detail else ""))
        lines.append("-" * 32)
        lines.append(f"{self.score} / 100")
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
