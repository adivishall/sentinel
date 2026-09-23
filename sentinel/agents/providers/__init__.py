"""LLMProvider abstraction: OfflineProvider (deterministic) and AnthropicProvider."""

from sentinel.agents.providers.base import Completion, LLMProvider
from sentinel.agents.providers.registry import get_provider, mode

__all__ = ["Completion", "LLMProvider", "get_provider", "mode"]
