"""Orchestrates the firewall layers around a back-office agent.

  raw submission
     -> [L1] provenance-tag untrusted spans
     -> [L2] detect injection in untrusted spans
     -> agent runs on the (sanitised) prompt
     -> [L3] re-decide over structured facts   (authoritative; immune to prose)
     -> [L4] enforce capability limits
     -> final effect + full audit trail

`layers` selects which are active, so the ablation can measure each one's real
contribution instead of guessing. With L3 off, the (possibly hijacked) agent's
own decision stands unless L2 caught an injection -- which is exactly how an
adjudication-gaming attack (a false claim with no injection) slips through
detection-only defences.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

import llm
from agents.tools import Effect
from firewall import adjudicate, audit, detect, limits, provenance
from firewall.logging_config import get_logger
from firewall.normalize import InvalidSubmission, validate

ALL = ("L1", "L2", "L3", "L4")
_log = get_logger("firewall.pipeline")

# verdict (approve/deny/escalate) -> (effect action, irreversible) per surface.
DISPUTE_EFFECT_MAP = {
    "approve": ("approve_refund", True),
    "deny": ("deny", False),
    "escalate": ("escalate", False),
}
KYB_EFFECT_MAP = {
    "approve": ("approve_merchant", True),
    "deny": ("reject_merchant", False),
    "escalate": ("manual_review", False),
}


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _hash(text: object) -> str:
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[:16]


def _threat_level(score: float, injection: bool) -> str:
    if not injection:
        return "low" if score > 0 else "none"
    if score >= 0.85:
        return "high"
    return "medium"


@dataclass
class Decision:
    """Stable, serialisable record of a single firewall decision.

    The same object drives the CLI output, the audit trail, the API response and
    the test assertions -- there is no parallel representation. ``to_dict`` is the
    canonical wire/audit form.
    """

    effect: Effect
    blocked_by: str | None = None
    trail: list = field(default_factory=list)
    # --- structured decision record -------------------------------------------
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    session_id: str | None = None
    surface: str = "dispute"
    input_hash: str = ""
    threat_level: str = "none"
    detection: dict = field(default_factory=dict)
    agent_result: dict = field(default_factory=dict)
    adjudication: dict = field(default_factory=dict)
    capability_decision: str | None = None
    audit_id: str = ""
    timestamp: str = field(default_factory=_now)
    model: dict = field(default_factory=dict)

    def log(self, layer, detail):
        self.trail.append({"layer": layer, "detail": detail})

    @property
    def final_action(self) -> str:
        return self.effect.action

    @property
    def reason(self) -> str:
        return self.effect.reason

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "surface": self.surface,
            "input_hash": self.input_hash,
            "threat_level": self.threat_level,
            "detection": self.detection,
            "agent_result": self.agent_result,
            "adjudication": self.adjudication,
            "capability_decision": self.capability_decision,
            "final_action": self.final_action,
            "amount": self.effect.amount,
            "irreversible": self.effect.irreversible,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "model": self.model,
            "effect": asdict(self.effect),
            "trail": self.trail,
        }


def run_guarded(
    agent_run,
    submission: str,
    ledger: dict,
    layers=ALL,
    *,
    adjudicator=adjudicate.adjudicate,
    effect_map=DISPUTE_EFFECT_MAP,
    surface: str = "dispute",
    persist_audit: bool = False,
) -> Decision:
    layers = set(layers)
    d = Decision(effect=Effect("pending"), surface=surface, model=_model_meta())

    # Fail safe: unusable input never silently approves -- it escalates to a human.
    try:
        validate(submission)
    except InvalidSubmission as e:
        _log.warning("invalid submission", extra={"detail": str(e)})
        d.effect = Effect("escalate", 0, f"Invalid submission: {e}")
        d.blocked_by = "L0_validate"
        d.log("L0_validate", {"error": str(e)})
        return _finalize(d, layers, persist_audit)

    d.input_hash = _hash(submission)

    # L1 provenance
    if "L1" in layers:
        prompt = provenance.wrap_untrusted(submission, source=ledger.get("source", "external"))
        d.log("L1_provenance", "untrusted span delimited and labelled as data")
    else:
        prompt = submission

    # L2 injection detection
    l2_blocked = False
    if "L2" in layers:
        inj, sc, hits = detect.is_injection(submission)
        d.detection = {"injection": inj, "score": round(sc, 2), "hits": hits}
        d.threat_level = _threat_level(sc, inj)
        d.log("L2_detect", d.detection)
        l2_blocked = inj

    # agent runs
    agent_effect, call = agent_run(prompt)
    d.agent_result = dict(call)
    d.log("agent", {"raw_decision": call})

    # decision
    if "L3" in layers:
        verdict = adjudicator(submission, ledger)
        d.adjudication = {
            "verdict": verdict["verdict"],
            "why": verdict["why"],
            "facts": verdict["facts"],
        }
        d.log("L3_adjudicate", d.adjudication)
        action, irreversible = effect_map[verdict["verdict"]]
        amt = verdict["facts"].get("amount", 0)
        decided = Effect(
            action,
            amt if verdict["verdict"] == "approve" else 0,
            verdict["why"],
            irreversible=irreversible,
        )
        if agent_effect.action != decided.action:
            d.blocked_by = "L3_adjudicate"
    elif l2_blocked:
        decided = Effect("escalate", 0, "Injection detected in untrusted input.")
        d.blocked_by = "L2_detect"
    else:
        decided = agent_effect  # no L3, no injection caught -> agent's word stands

    d.effect = decided

    # L4 capability limits
    if "L4" in layers:
        d.effect, cap = limits.enforce(d.effect, ledger)
        if cap:
            d.capability_decision = cap
            d.log("L4_limits", cap)
            d.blocked_by = d.blocked_by or "L4_limits"

    return _finalize(d, layers, persist_audit)


def _model_meta() -> dict:
    return {"mode": llm.mode(), "model": llm.MODEL if llm.mode() == "live" else "offline-simulator"}


def _finalize(d: Decision, layers: set, persist_audit: bool) -> Decision:
    """Emit the structured log line and (optionally) the persisted audit event."""
    d.audit_id = d.request_id
    _log.info(
        "decision",
        extra={
            "detail": {
                "request_id": d.request_id,
                "action": d.effect.action,
                "threat_level": d.threat_level,
                "blocked_by": d.blocked_by,
                "layers": sorted(layers),
            }
        },
    )
    if persist_audit:
        audit.record(d.to_dict())
    return d


def run_unguarded(agent_run, submission: str, ledger: dict) -> Decision:
    """Baseline: agent acts directly on raw attacker text."""
    d = Decision(effect=Effect("pending"), model=_model_meta())
    d.input_hash = _hash(submission)
    effect, call = agent_run(submission)
    d.agent_result = dict(call) if isinstance(call, dict) else {}
    d.log("agent_unguarded", {"raw_decision": call})
    d.effect = effect
    return d
