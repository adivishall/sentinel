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

from dataclasses import dataclass, field

from agents.tools import Effect
from firewall import adjudicate, detect, limits, provenance
from firewall.logging_config import get_logger
from firewall.normalize import InvalidSubmission, validate

ALL = ("L1", "L2", "L3", "L4")
_log = get_logger("firewall.pipeline")


@dataclass
class Decision:
    effect: Effect
    blocked_by: str | None = None
    trail: list = field(default_factory=list)

    def log(self, layer, detail):
        self.trail.append({"layer": layer, "detail": detail})


def run_guarded(agent_run, submission: str, ledger: dict, layers=ALL) -> Decision:
    layers = set(layers)
    d = Decision(effect=Effect("pending"))

    # Fail safe: unusable input never silently approves -- it escalates to a human.
    try:
        validate(submission)
    except InvalidSubmission as e:
        _log.warning("invalid submission", extra={"detail": str(e)})
        d.effect = Effect("escalate", 0, f"Invalid submission: {e}")
        d.blocked_by = "L0_validate"
        d.log("L0_validate", {"error": str(e)})
        return d

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
        d.log("L2_detect", {"injection": inj, "score": round(sc, 2), "hits": hits})
        l2_blocked = inj

    # agent runs
    agent_effect, call = agent_run(prompt)
    d.log("agent", {"raw_decision": call})

    # decision
    if "L3" in layers:
        verdict = adjudicate.adjudicate(submission, ledger)
        d.log(
            "L3_adjudicate",
            {"verdict": verdict["verdict"], "why": verdict["why"], "facts": verdict["facts"]},
        )
        vmap = {"approve": "approve_refund", "deny": "deny", "escalate": "escalate"}
        amt = verdict["facts"]["amount"]
        decided = Effect(
            vmap[verdict["verdict"]],
            amt if verdict["verdict"] == "approve" else 0,
            verdict["why"],
            irreversible=(verdict["verdict"] == "approve"),
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
            d.log("L4_limits", cap)
            d.blocked_by = d.blocked_by or "L4_limits"

    # Log the FINAL decision, after every layer (incl. L4) has run.
    _log.info(
        "decision",
        extra={
            "detail": {
                "action": d.effect.action,
                "blocked_by": d.blocked_by,
                "layers": sorted(layers),
            }
        },
    )
    return d


def run_unguarded(agent_run, submission: str, ledger: dict) -> Decision:
    """Baseline: agent acts directly on raw attacker text."""
    d = Decision(effect=Effect("pending"))
    effect, call = agent_run(submission)
    d.log("agent_unguarded", {"raw_decision": call})
    d.effect = effect
    return d
