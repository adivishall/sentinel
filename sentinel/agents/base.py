"""Agent = a system prompt + a tool surface + a provider role.

``tool_surface`` is the set of capabilities the agent is permitted to
*request*. Requesting one outside it is a capability-escalation finding. Note
that even in-surface requests (a dispute agent asking for APPROVE_REFUND) are
only ever recommendations -- the agent has no authority; that is the point."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.agents.providers import LLMProvider, get_provider
from sentinel.agents.tools import interpret, parse_tool_call
from sentinel.domain.decisions import AIRecommendation
from sentinel.domain.enums import Capability


@dataclass(frozen=True)
class AgentSpec:
    name: str
    role: str
    system_prompt: str
    tool_surface: frozenset[Capability]
    fallback_tool: str


class Agent:
    def __init__(self, spec: AgentSpec, provider: LLMProvider | None = None) -> None:
        self.spec = spec
        self._provider = provider

    @property
    def provider(self) -> LLMProvider:
        return self._provider or get_provider()

    @property
    def name(self) -> str:
        return self.spec.name

    def recommend(self, prompt: str, *, role: str | None = None) -> AIRecommendation:
        p = self.provider
        c = p.complete(self.spec.system_prompt, prompt, role=role or self.spec.role)
        call = parse_tool_call(c.text, self.spec.fallback_tool)
        return interpret(
            call, agent=self.spec.name, provider=c.provider, model=c.model, latency_ms=c.latency_ms
        )
