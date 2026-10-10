from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

# How a completion ended, in Sentinel's terms. Only "ok" is parsed as a tool call; every
# other outcome is a labelled fail-safe recommendation (the agent's fallback tool), never
# a "model denied" or a "model approved".
OK, TRUNCATED, REFUSAL, EMPTY, OTHER = "ok", "truncated", "refusal", "empty", "other"


@dataclass(frozen=True)
class Completion:
    text: str
    provider: str
    model: str  # the model that answered (served), or the requested one if unknown
    latency_ms: float = 0.0
    input_tokens: int | None = None
    output_tokens: int | None = None
    requested_model: str | None = None
    served_model: str | None = None  # what the API says answered (response.model)
    sdk_version: str | None = None
    request_id: str | None = None
    stop_reason: str | None = None  # end_turn | max_tokens | refusal | ... (as the API says)
    stop_category: str | None = None  # a refusal's category, when the API gives one
    cache_read_input_tokens: int | None = None
    cache_creation_input_tokens: int | None = None
    settings: dict[str, object] = field(default_factory=dict)
    outcome: str = OK  # ok | truncated | refusal | empty | other


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(
        self, system: str, user: str, *, role: str, max_tokens: int = 1024
    ) -> Completion: ...
