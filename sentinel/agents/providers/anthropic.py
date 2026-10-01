"""AnthropicProvider -- real Claude agents, identical Sentinel controls.

Written against the current Messages API (anthropic SDK 1.x; the request shape is the
same on 0.x except ``output_config``). Thinking is the model's default (adaptive on
current models; a thinking budget is not sent). ``output_config.effort`` sets depth.

Every completion records what a reproducible evaluation needs: requested and served
model, SDK version, request id, stop reason (and a refusal's category), latency, tokens
including cache tokens, and the settings sent. How it ended decides what the agent may
do with it: only ``end_turn`` is parsed; ``max_tokens`` (truncated), ``refusal``, an
empty reply or any other stop is a labelled fail-safe -- never "the model denied". SDK
errors (rate limits, timeouts, a bad model id) propagate to the caller.
"""

from __future__ import annotations

import os
import time
from collections import Counter, deque
from typing import Any

from sentinel.agents.providers.base import EMPTY, OK, OTHER, REFUSAL, TRUNCATED, Completion

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT = "low"
TIMEOUT_S = 60.0
_OUTCOME = {"end_turn": OK, "max_tokens": TRUNCATED, "refusal": REFUSAL}


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str | None = None, effort: str | None = None) -> None:
        self.model = model or os.environ.get("SENTINEL_MODEL", DEFAULT_MODEL)
        self.effort = effort or os.environ.get("SENTINEL_EFFORT", DEFAULT_EFFORT)
        self._client: Any = None
        self.sdk_version: str | None = None
        self._input_tokens = 0
        self._output_tokens = 0
        self._cache_read = 0
        self._cache_write = 0
        self._calls = 0
        self.stop_reasons: Counter[str] = Counter()
        self.outcomes: Counter[str] = Counter()
        # the latest completions, for an evaluation to attribute per case (bounded)
        self.log: deque[Completion] = deque(maxlen=1000)

    def usage(self) -> dict[str, int]:
        """Token totals over every call so far (the SDK reports usage per response)."""
        return {
            "input_tokens": self._input_tokens,
            "output_tokens": self._output_tokens,
            "cache_read_input_tokens": self._cache_read,
            "cache_creation_input_tokens": self._cache_write,
            "calls": self._calls,
        }

    def drain(self) -> list[Completion]:
        out = list(self.log)
        self.log.clear()
        return out

    def _client_or_raise(self) -> Any:
        if self._client is None:
            try:
                import anthropic
            except ImportError as e:  # pragma: no cover - needs the optional SDK
                raise RuntimeError(
                    "Live mode needs the Anthropic SDK: pip install -e '.[live]'"
                ) from e
            self.sdk_version = getattr(anthropic, "__version__", None)
            # reads ANTHROPIC_API_KEY; the SDK retries 408/409/429/5xx itself
            self._client = anthropic.Anthropic(timeout=TIMEOUT_S, max_retries=2)
        return self._client

    def complete(self, system: str, user: str, *, role: str, max_tokens: int = 1024) -> Completion:
        client = self._client_or_raise()
        settings: dict[str, object] = {
            "max_tokens": max_tokens,
            "effort": self.effort,
            "thinking": "model default (adaptive)",
            "temperature": None,
        }
        t0 = time.perf_counter()
        resp = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort},
        )
        latency = (time.perf_counter() - t0) * 1000
        text = "".join(
            getattr(b, "text", "") for b in (resp.content or []) if getattr(b, "type", "") == "text"
        )
        stop = getattr(resp, "stop_reason", None)
        outcome = _OUTCOME.get(stop or "", OTHER)
        if outcome == OK and not text.strip():
            outcome = EMPTY
        category = None
        if stop == "refusal":
            details = getattr(resp, "stop_details", None)
            category = getattr(details, "category", None) if details is not None else None
        usage = getattr(resp, "usage", None)

        def tok(name: str) -> int | None:
            v = getattr(usage, name, None) if usage is not None else None
            return int(v) if isinstance(v, int) and not isinstance(v, bool) else None

        served = getattr(resp, "model", None)
        c = Completion(
            text,
            self.name,
            str(served or self.model),
            latency,
            tok("input_tokens"),
            tok("output_tokens"),
            requested_model=self.model,
            served_model=str(served) if served else None,
            sdk_version=self.sdk_version,
            request_id=getattr(resp, "_request_id", None),
            stop_reason=stop,
            stop_category=str(category) if category else None,
            cache_read_input_tokens=tok("cache_read_input_tokens"),
            cache_creation_input_tokens=tok("cache_creation_input_tokens"),
            settings=settings,
            outcome=outcome,
        )
        self._calls += 1
        self._input_tokens += c.input_tokens or 0
        self._output_tokens += c.output_tokens or 0
        self._cache_read += c.cache_read_input_tokens or 0
        self._cache_write += c.cache_creation_input_tokens or 0
        self.stop_reasons[stop or "none"] += 1
        self.outcomes[outcome] += 1
        self.log.append(c)
        return c
