from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Completion:
    text: str
    provider: str
    model: str
    latency_ms: float = 0.0
    input_tokens: int | None = None
    output_tokens: int | None = None


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(
        self, system: str, user: str, *, role: str, max_tokens: int = 1024
    ) -> Completion: ...
