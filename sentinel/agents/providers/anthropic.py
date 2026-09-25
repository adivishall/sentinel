"""AnthropicProvider -- real Claude agents, identical Sentinel controls.

Deliberately minimal (no temperature/thinking params) so it works across SDK
versions. The SDK retries 429/5xx automatically; callers add fail-safe parsing.
"""

from __future__ import annotations

import os
import time
from typing import Any

from sentinel.agents.providers.base import Completion

DEFAULT_MODEL = "claude-opus-5"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None) -> None:
        self.model = model or os.environ.get("SENTINEL_MODEL", DEFAULT_MODEL)
        self._client: Any = None
        self._input_tokens = 0
        self._output_tokens = 0
        self._calls = 0

    def usage(self) -> dict[str, int]:
        """Token totals over every call so far (the SDK reports usage per response)."""
        return {
            "input_tokens": self._input_tokens,
            "output_tokens": self._output_tokens,
            "calls": self._calls,
        }

    def _client_or_raise(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:  # pragma: no cover - needs the optional SDK
                raise RuntimeError(
                    "Live mode needs the Anthropic SDK: pip install 'anthropic' "
                    "(or: pip install -e '.[live]')."
                ) from e
            self._client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
        return self._client

    def complete(self, system: str, user: str, *, role: str, max_tokens: int = 1024) -> Completion:
        client = self._client_or_raise()
        t0 = time.perf_counter()
        resp = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        usage = getattr(resp, "usage", None)
        self._calls += 1
        self._input_tokens += int(getattr(usage, "input_tokens", 0) or 0)
        self._output_tokens += int(getattr(usage, "output_tokens", 0) or 0)
        return Completion(
            text,
            self.name,
            self.model,
            (time.perf_counter() - t0) * 1000,
            getattr(usage, "input_tokens", None),
            getattr(usage, "output_tokens", None),
        )
