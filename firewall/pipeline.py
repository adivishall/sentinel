"""Orchestrates the four firewall layers around a back-office agent.

  raw submission
     -> [L1] provenance-tag untrusted spans
     -> [L2] detect injection in untrusted spans   (block early if strong)
     -> agent runs on the SANITISED prompt
     -> [L3] re-decide over structured facts        (immune to narrative)
     -> [L4] enforce capability limits
     -> final effect + full audit trail
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from firewall import provenance, detect, adjudicate, limits
from agents.tools import Effect

@dataclass
class Decision:
    effect: Effect
    blocked_by: str | None = None
    trail: list = field(default_factory=list)
    def log(self, layer, detail): self.trail.append({"layer": layer, "detail": detail})

def run_guarded(agent_run, submission: str, ledger: dict) -> Decision:
    """agent_run: callable(str) -> (Effect, call_dict). ledger: trusted facts."""
    d = Decision(effect=Effect("pending"))

    # L1 provenance
    wrapped = provenance.wrap_untrusted(submission, source=ledger.get("source", "external"))
    d.log("L1_provenance", "untrusted span delimited and labelled as data")

    # L2 injection detection
    inj, sc, hits = detect.is_injection(submission)
    d.log("L2_detect", {"injection": inj, "score": round(sc, 2), "hits": hits})
    if inj:
        d.effect = Effect("escalate", 0, "Injection detected in untrusted input.")
        d.blocked_by = "L2_detect"
        # We still run L3 so the audit shows the SAFE decision on the merits.

    # agent runs on sanitised prompt (provenance-wrapped)
    agent_effect, call = agent_run(wrapped)
    d.log("agent", {"raw_decision": call})

    # L3 structured-facts adjudication -- the authoritative decision
    verdict = adjudicate.adjudicate(submission, ledger)
    d.log("L3_adjudicate", {"verdict": verdict["verdict"], "why": verdict["why"],
                            "facts": verdict["facts"]})
    vmap = {"approve": "approve_refund", "deny": "deny", "escalate": "escalate"}
    amt = verdict["facts"]["amount"]
    adj_effect = Effect(vmap[verdict["verdict"]], amt if verdict["verdict"] == "approve" else 0,
                        verdict["why"], irreversible=(verdict["verdict"] == "approve"))

    # The firewall's decision is the adjudicator's, not the (possibly hijacked) agent's.
    d.effect = adj_effect
    if d.blocked_by is None and agent_effect.action != adj_effect.action:
        d.blocked_by = "L3_adjudicate"

    # L4 capability limits
    d.effect, cap = limits.enforce(d.effect, ledger)
    if cap:
        d.log("L4_limits", cap)
        d.blocked_by = d.blocked_by or "L4_limits"

    return d

def run_unguarded(agent_run, submission: str, ledger: dict) -> Decision:
    """Baseline: agent acts directly on raw attacker text."""
    d = Decision(effect=Effect("pending"))
    effect, call = agent_run(submission)
    d.log("agent_unguarded", {"raw_decision": call})
    d.effect = effect
    return d
