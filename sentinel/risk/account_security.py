"""Account security: login / session risk from trusted session records.

Signals: new_device, new_country, impossible_travel, credential_change,
mfa_change, payout_change, session_anomaly, velocity, device_history. The
decision (ALLOW / STEP_UP / REQUIRE_REVIEW / TEMPORARY_HOLD / BLOCK) is made by
policy over this assessment, never by the customer's message."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.entities import LoginSession
from sentinel.domain.risk import RiskAssessment
from sentinel.risk import scoring
from sentinel.risk.scoring import RiskModel, Rule


@dataclass(frozen=True)
class AccountSecurityContext:
    known_devices: frozenset[str]
    known_countries: frozenset[str]
    last_country: str | None = None
    hours_since_last_login: float | None = None
    logins_last_hour: int = 0
    device_count: int = 1
    account_frozen: bool = False


def extract_features(session: LoginSession, ctx: AccountSecurityContext) -> dict[str, object]:
    events = set(session.events)
    impossible = (
        ctx.last_country is not None
        and ctx.last_country != session.country
        and ctx.hours_since_last_login is not None
        and ctx.hours_since_last_login < 2
    )
    return {
        "new_device": session.device_id not in ctx.known_devices,
        "new_country": bool(ctx.known_countries) and session.country not in ctx.known_countries,
        "impossible_travel": impossible,
        "credential_change": "credential_change" in events,
        "mfa_change": "mfa_change" in events,
        "payout_change": "payout_change" in events,
        "session_anomaly": "session_anomaly" in events,
        "logins_last_hour": ctx.logins_last_hour,
        "mfa_passed": session.mfa_passed,
        "device_count": ctx.device_count,
        "account_frozen": ctx.account_frozen,
        "country": session.country,
        "evidence_ids": {},
    }


def _flag(key: str, label: str, detail: str) -> Rule:
    return (key, label, lambda f, m: detail if f.get(key) else None)  # type: ignore[return-value]


RULES: tuple[Rule, ...] = (
    _flag("new_device", "New device", "device never seen on this account"),
    _flag("new_country", "New country", "login from a country not seen before"),
    _flag("impossible_travel", "Impossible travel", "country changed within 2 hours"),
    _flag("credential_change", "Credential change", "password / email changed this session"),
    _flag("mfa_change", "MFA change", "second factor changed this session"),
    _flag("payout_change", "Payout destination change", "payout / settlement account changed"),
    _flag("session_anomaly", "Session anomaly", "unusual session behaviour"),
    (
        "velocity",
        "Login velocity",
        lambda f, m: (
            f"{f.get('logins_last_hour')} logins in the last hour"
            if float(str(f.get("logins_last_hour", 0) or 0)) >= m.t("velocity_1h", 5)
            else None
        ),
    ),
    (
        "mfa_not_passed",
        "MFA not passed",
        lambda f, m: "second factor not completed" if not f.get("mfa_passed", True) else None,
    ),
    (
        "device_history_thin",
        "Thin device history",
        lambda f, m: (
            "single known device"
            if float(str(f.get("device_count", 1) or 1)) <= 1 and f.get("new_device")
            else None
        ),
    ),
)


def assess_login(
    session: LoginSession,
    ctx: AccountSecurityContext,
    model: RiskModel = scoring.ACCOUNT_SECURITY_V1,
) -> RiskAssessment:
    features = extract_features(session, ctx)
    return scoring.build_assessment(
        entity_type="login",
        entity_id=session.session_id,
        features=features,
        model=model,
        rules=RULES,
    )
