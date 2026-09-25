"""Provider selection. Offline is the default and needs no key or network."""

from __future__ import annotations

import os

from sentinel.agents.providers.base import LLMProvider
from sentinel.agents.providers.offline import OfflineProvider

_OFFLINE = OfflineProvider()
_live: LLMProvider | None = None


def have_key() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def mode() -> str:
    if os.environ.get("SENTINEL_FORCE_OFFLINE") == "1":
        return "offline"
    return "live" if have_key() else "offline"


def get_provider() -> LLMProvider:
    global _live
    if mode() == "live":
        if _live is None:
            from sentinel.agents.providers.anthropic import AnthropicProvider

            _live = AnthropicProvider()
        return _live
    return _OFFLINE
