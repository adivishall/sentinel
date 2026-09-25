"""Typed request validation for the API. No framework: explicit, small,
fail-closed validators that produce 400s with a precise message."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.decision import composer
from sentinel.decision.workflows import PROVENANCE, RunOptions
from sentinel.domain.entities import LoginSession, Transaction
from sentinel.domain.enums import Capability, TrustClass
from sentinel.risk import scoring
from sentinel.security.provenance import UntrustedContent

MAX_TEXT = 20_000
ALL_CONTROLS = composer.FULL | {PROVENANCE}

# USER-CONTROLLABLE: a caller may set these on any route; they change only the model call.
USER_OPTIONS = frozenset({"hardened", "skip_agent"})
# SYSTEM-CONTROLLED on the authoritative path: what-if switches. Only the attack simulator,
# scenario runs and replay accept them, and the engine never records a run that used them
# (sentinel.decision.authority). The evaluate routes refuse them with 403.
WHAT_IF_OPTIONS = frozenset({"controls", "unguarded", "policy_version", "risk_model"})


class ValidationError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def obj(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("request body must be a JSON object")
    return payload


def req_str(d: dict[str, Any], key: str, *, alt: str | None = None, max_len: int = MAX_TEXT) -> str:
    v = d.get(key, d.get(alt) if alt else None)
    if v is None:
        raise ValidationError(f"missing required field: {key!r}")
    if not isinstance(v, str):
        raise ValidationError(f"{key!r} must be a string")
    if len(v) > max_len:
        raise ValidationError(f"{key!r} too long (> {max_len} chars)", 413)
    return v


def opt_str(
    d: dict[str, Any], key: str, default: str | None = None, max_len: int = MAX_TEXT
) -> str | None:
    v = d.get(key, default)
    if v is None:
        return None
    if not isinstance(v, str):
        raise ValidationError(f"{key!r} must be a string")
    if len(v) > max_len:
        raise ValidationError(f"{key!r} too long (> {max_len} chars)", 413)
    return v


def opt_int(
    d: dict[str, Any],
    key: str,
    default: int | None = None,
    *,
    lo: int | None = None,
    hi: int | None = None,
) -> int | None:
    v = d.get(key, default)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValidationError(f"{key!r} must be an integer")
    if lo is not None and v < lo or hi is not None and v > hi:
        raise ValidationError(f"{key!r} out of range")
    return v


def opt_bool(d: dict[str, Any], key: str, default: bool = False) -> bool:
    v = d.get(key, default)
    if not isinstance(v, bool):
        raise ValidationError(f"{key!r} must be a boolean")
    return v


def req_obj(d: dict[str, Any], key: str, *, alt: str | None = None) -> dict[str, Any]:
    v = d.get(key, d.get(alt) if alt else None)
    if not isinstance(v, dict):
        raise ValidationError(f"{key!r} must be a JSON object")
    return v


def opt_str_list(d: dict[str, Any], key: str, max_items: int = 20) -> tuple[str, ...]:
    v = d.get(key, [])
    if v is None:
        return ()
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValidationError(f"{key!r} must be a list of strings")
    if len(v) > max_items:
        raise ValidationError(f"{key!r} has too many items (> {max_items})")
    for x in v:
        if len(x) > MAX_TEXT:
            raise ValidationError(f"item in {key!r} too long", 413)
    return tuple(v)


def untrusted_list(d: dict[str, Any], key: str = "contents") -> tuple[UntrustedContent, ...]:
    v = d.get(key, [])
    if not isinstance(v, list):
        raise ValidationError(f"{key!r} must be a list")
    out = []
    for i, item in enumerate(v):
        if isinstance(item, str):
            out.append(UntrustedContent(item[:MAX_TEXT]))
            continue
        if not isinstance(item, dict):
            raise ValidationError(f"{key}[{i}] must be a string or object")
        text = req_str(item, "text")
        trust_s = str(item.get("trust", "USER_CONTROLLED"))
        try:
            trust = TrustClass(trust_s)
        except ValueError:
            raise ValidationError(f"{key}[{i}].trust invalid: {trust_s!r}") from None
        if trust.is_trusted:
            raise ValidationError(f"{key}[{i}].trust cannot be a trusted class")
        out.append(
            UntrustedContent(
                text,
                trust,
                str(item.get("source", "external"))[:80],
                str(item.get("kind", "text"))[:20],
            )
        )
    return tuple(out)


def what_if_keys(d: dict[str, Any]) -> list[str]:
    """The what-if switches a request body carries (top-level ``unguarded`` included)."""
    raw = d.get("options")
    o: dict[str, Any] = raw if isinstance(raw, dict) else {}
    found = [f"options.{k}" for k in sorted(WHAT_IF_OPTIONS) if k in o]
    return found + (["unguarded"] if "unguarded" in d else [])


def run_options(d: dict[str, Any]) -> RunOptions:
    o = d.get("options", {})
    if not isinstance(o, dict):
        raise ValidationError("'options' must be an object")
    unknown = set(o) - USER_OPTIONS - WHAT_IF_OPTIONS
    if unknown:  # fail closed: an option we do not know is not silently ignored
        raise ValidationError(
            f"unknown options {sorted(unknown)}; allowed {sorted(USER_OPTIONS | WHAT_IF_OPTIONS)}"
        )
    controls: frozenset[str] = ALL_CONTROLS
    if "controls" in o:
        c = o["controls"]
        if not isinstance(c, list) or not all(isinstance(x, str) for x in c):
            raise ValidationError("options.controls must be a list of strings")
        bad = set(c) - ALL_CONTROLS
        if bad:
            raise ValidationError(f"unknown controls {sorted(bad)}; allowed {sorted(ALL_CONTROLS)}")
        controls = frozenset(c)
    if opt_bool(o, "unguarded", False) or opt_bool(d, "unguarded", False):
        controls = frozenset()
    rm = opt_str(o, "risk_model")
    model = None
    if rm:
        if rm not in scoring.MODELS:
            raise ValidationError(f"unknown risk_model {rm!r}; have {sorted(scoring.MODELS)}")
        model = scoring.MODELS[rm]
    return RunOptions(
        controls=controls,
        policy_version=opt_int(o, "policy_version", None, lo=1),
        risk_model=model,
        hardened=opt_bool(o, "hardened", False),
        skip_agent=opt_bool(o, "skip_agent", False),
    )


def capability(d: dict[str, Any], key: str) -> Capability | None:
    v = opt_str(d, key)
    if v is None:
        return None
    try:
        return Capability(v)
    except ValueError:
        raise ValidationError(f"{key!r} invalid capability {v!r}") from None


def transaction(d: dict[str, Any]) -> Transaction:
    t = req_obj(d, "transaction")
    try:
        return Transaction(
            transaction_id=req_str(t, "transaction_id", max_len=64),
            account_id=req_str(t, "account_id", max_len=64),
            merchant_id=req_str(t, "merchant_id", max_len=64),
            instrument_id=str(t.get("instrument_id", "unknown"))[:64],
            device_id=str(t.get("device_id", "unknown"))[:64],
            amount=int(t["amount"]),
            currency=str(t.get("currency", "INR"))[:8],
            timestamp=req_str(t, "timestamp", max_len=40),
            country=str(t.get("country", "IN"))[:4],
            channel=str(t.get("channel", "ecommerce"))[:20],
            auth_strength=str(t.get("auth_strength", "otp"))[:20],
            delivery_status=str(t.get("delivery_status", "delivered"))[:20],
            counterparty_account_id=(
                str(t["counterparty_account_id"])[:64] if t.get("counterparty_account_id") else None
            ),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ValidationError(f"invalid transaction: {e}") from None


def login_session(d: dict[str, Any]) -> LoginSession:
    s = req_obj(d, "session")
    try:
        return LoginSession(
            session_id=req_str(s, "session_id", max_len=64),
            account_id=req_str(s, "account_id", max_len=64),
            device_id=str(s.get("device_id", "unknown"))[:64],
            ip=str(s.get("ip", "0.0.0.0"))[:45],
            country=str(s.get("country", "IN"))[:4],
            started_at=req_str(s, "started_at", max_len=40),
            mfa_passed=bool(s.get("mfa_passed", True)),
            events=tuple(str(x)[:40] for x in s.get("events", []))[:10],
        )
    except (KeyError, TypeError, ValueError) as e:
        raise ValidationError(f"invalid session: {e}") from None


@dataclass(frozen=True)
class ReplayBody:
    decision_id: str
    policy_version: int | None
    risk_model: str | None
    rule_values: dict[str, object] = field(default_factory=dict)
    ai_recommendation: str | None = None
    ai_capability: Capability | None = None
    controls: frozenset[str] | None = None


def replay_body(d: dict[str, Any]) -> ReplayBody:
    rv = d.get("rule_values", {})
    if not isinstance(rv, dict) or not all(
        isinstance(k, str) and isinstance(v, (int, float, str, bool)) for k, v in rv.items()
    ):
        raise ValidationError("'rule_values' must map rule ids to scalar values")
    rm = opt_str(d, "risk_model")
    if rm and rm not in scoring.MODELS:
        raise ValidationError(f"unknown risk_model {rm!r}")
    controls = None
    if "controls" in d:
        c = d["controls"]
        if not isinstance(c, list) or set(c) - ALL_CONTROLS:
            raise ValidationError("'controls' must be a list of known control names")
        controls = frozenset(c)
    return ReplayBody(
        req_str(d, "decision_id", max_len=64),
        opt_int(d, "policy_version", None, lo=1),
        rm,
        dict(rv),
        opt_str(d, "ai_recommendation", max_len=40),
        capability(d, "ai_capability"),
        controls,
    )
