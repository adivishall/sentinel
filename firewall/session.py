"""Multi-turn session model.

Multi-turn escalation is an attack class: an attacker builds rapport over several
harmless turns, then lands the payload later (or splits it across turns). A
firewall that only inspects the latest message is blind to this.

A ``Session`` accumulates the untrusted turns and evaluates the **whole
transcript** against the (fixed, trusted) ledger on every turn. Two consequences
matter for security:

* L2 detection scans the cumulative transcript, so a payload split across turns
  is still visible.
* L3 always decides on the bank's verified facts, which no amount of prior
  "you already agreed" can change -- so the authoritative decision never depends
  on the conversation's persuasion.

The session also tracks a cumulative risk level (the peak threat seen so far).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from firewall import adjudicate, pipeline
from firewall.pipeline import Decision

_RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


@dataclass
class Session:
    agent_run: Callable
    ledger: dict
    surface: str = "dispute"
    adjudicator: Callable | None = None
    effect_map: dict = field(default_factory=lambda: pipeline.DISPUTE_EFFECT_MAP)
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    messages: list = field(default_factory=list)
    cumulative_risk: str = "none"
    last_decision: Decision | None = None

    def add(self, text: str, *, persist_audit: bool = False) -> Decision:
        """Append an untrusted turn and re-evaluate the whole transcript."""
        self.messages.append(text)
        transcript = "\n".join(f"Turn {i + 1}: {m}" for i, m in enumerate(self.messages))
        adj = self.adjudicator if self.adjudicator is not None else adjudicate.adjudicate
        d = pipeline.run_guarded(
            self.agent_run,
            transcript,
            self.ledger,
            adjudicator=adj,
            effect_map=self.effect_map,
            surface=self.surface,
            persist_audit=persist_audit,
        )
        d.session_id = self.session_id
        if _RISK_ORDER.get(d.threat_level, 0) > _RISK_ORDER.get(self.cumulative_risk, 0):
            self.cumulative_risk = d.threat_level
        self.last_decision = d
        return d

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "surface": self.surface,
            "turns": len(self.messages),
            "cumulative_risk": self.cumulative_risk,
            "final_decision": self.last_decision.to_dict() if self.last_decision else None,
        }
