"""Multi-turn dispute sessions.

Multi-turn escalation is an attack class: rapport over harmless turns, then
the payload -- or a payload split across turns. A ``DisputeSession`` keeps the
untrusted turns and re-evaluates the **whole transcript** against the fixed
trusted ledger on every turn, so security never depends on the latest message
alone. The trusted-evidence verdict cannot be moved by any number of prior
"you already agreed" turns."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from sentinel.decision.workflows import (
    DecisionBundle,
    DisputeRequest,
    RunOptions,
    Runtime,
    run_dispute,
)
from sentinel.domain.enums import FactsSource, Severity, TrustClass
from sentinel.domain.ids import new_id
from sentinel.security.gateway import Conversation
from sentinel.security.provenance import UntrustedContent


@dataclass
class DisputeSession:
    runtime: Runtime
    ledger: Mapping[str, object]
    dispute_id: str = field(default_factory=lambda: new_id("DSP"))
    session_id: str = field(default_factory=lambda: new_id("SES"))
    conversation: Conversation = field(default_factory=Conversation)
    cumulative_severity: Severity = Severity.NONE
    last: DecisionBundle | None = None
    options: RunOptions = RunOptions()
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED

    def add(
        self,
        text: str,
        *,
        source: str = "cardholder",
        trust: TrustClass = TrustClass.USER_CONTROLLED,
    ) -> DecisionBundle:
        self.conversation = self.conversation.add(UntrustedContent(text, trust, source))
        transcript = self.conversation.transcript()
        req = DisputeRequest(
            narrative=transcript,
            ledger=self.ledger,
            dispute_id=self.dispute_id,
            conversation=self.conversation,
            facts_source=self.facts_source,
        )
        opts = RunOptions(**{**self.options.__dict__, "session_id": self.session_id})
        b = run_dispute(self.runtime, req, opts)
        if b.security.severity.rank > self.cumulative_severity.rank:
            self.cumulative_severity = b.security.severity
        self.last = b
        return b

    @property
    def turns(self) -> int:
        return len(self.conversation.turns)

    def to_dict(self) -> dict[str, object]:
        from sentinel.domain.serialization import to_dict

        return {
            "session_id": self.session_id,
            "dispute_id": self.dispute_id,
            "turns": self.turns,
            "cumulative_severity": self.cumulative_severity.value,
            "final_decision": to_dict(self.last.decision) if self.last else None,
        }
