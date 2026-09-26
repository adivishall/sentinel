"""The live provider, verified offline against a stub SDK.

No key, no network and no live result: a fake ``anthropic`` module stands in for the
SDK so the provider's request shape, response parsing and token accounting, the agent
path and the live-evaluation pipeline are exercised end to end. The stub always asks
for a refund, like a persuaded model; the numbers it produces are not results and are
never written to ``results/``."""

from __future__ import annotations

import json
import sys
import types
from types import SimpleNamespace

import pytest

from sentinel.agents.base import Agent
from sentinel.agents.catalog import SPECS
from sentinel.agents.providers.anthropic import DEFAULT_MODEL, AnthropicProvider
from sentinel.domain.enums import Capability, TrustClass
from sentinel.evaluation import models


class _Messages:
    def __init__(self, log: list[dict]) -> None:
        self.log = log

    def create(self, **kw):
        self.log.append(kw)
        text = json.dumps({"tool": "approve_refund", "amount": 18000, "reason": "customer says so"})
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            usage=SimpleNamespace(input_tokens=120, output_tokens=30),
        )


@pytest.fixture()
def fake_sdk(monkeypatch):
    log: list[dict] = []
    mod = types.ModuleType("anthropic")
    mod.Anthropic = lambda: SimpleNamespace(messages=_Messages(log))  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    return log


def test_request_shape_parsing_and_token_accounting(fake_sdk):
    p = AnthropicProvider()
    assert p.model == DEFAULT_MODEL
    c = p.complete("system prompt", "user text", role="dispute", max_tokens=256)
    req = fake_sdk[0]
    assert req["model"] == DEFAULT_MODEL and req["system"] == "system prompt"
    assert req["messages"] == [{"role": "user", "content": "user text"}]
    assert req["max_tokens"] == 256
    assert "approve_refund" in c.text and c.provider == "anthropic"
    p.complete("s", "u", role="dispute")
    assert p.usage() == {"input_tokens": 240, "output_tokens": 60, "calls": 2}


def test_live_output_is_a_model_generated_recommendation(fake_sdk):
    rec = Agent(SPECS["dispute"], AnthropicProvider()).recommend("My parcel never arrived.")
    assert rec.trust is TrustClass.MODEL_GENERATED
    assert rec.requested_capability is Capability.APPROVE_REFUND and rec.provider == "anthropic"


def test_the_live_evaluation_pipeline_runs_and_reports_tokens(fake_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.delenv("SENTINEL_FORCE_OFFLINE", raising=False)
    r = models.run(sample=12, provider="anthropic")
    row = r["results"][0]
    assert row["status"] == "ok" and row["provider"] == "anthropic"
    assert row["asr_guarded"] == 0.0  # the architecture, not the model, holds
    assert row["input_tokens"] > 0 and row["output_tokens"] > 0
    assert all(x["provider"] == "anthropic" for x in r["rows"])


def test_without_a_key_the_live_row_is_not_run(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = models.run(sample=4, provider="anthropic")
    assert r["results"][0]["status"] == "not_run" and r["rows"] == []


def test_a_missing_sdk_is_an_error_row_not_a_number(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.delenv("SENTINEL_FORCE_OFFLINE", raising=False)
    monkeypatch.setitem(sys.modules, "anthropic", None)  # import fails
    r = models.run(sample=4, provider="anthropic")
    row = r["results"][0]
    assert row["status"] == "error" and "asr_guarded" not in row
