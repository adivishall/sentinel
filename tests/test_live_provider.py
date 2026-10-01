"""The live provider, verified offline against a stub SDK (issues #19 and #16).

No key, no network and no live result: a fake ``anthropic`` module stands in for the
SDK so the provider's request shape, response handling and accounting, the agent path
and the benchmark pipeline are exercised end to end. The stub's answers are scripted;
the numbers it produces are not results and are never written to ``results/``.

What is pinned here:
- the request matches the current Messages API (model, max_tokens sized for thinking,
  ``output_config.effort``, no sampling parameters, no thinking budget);
- every completion records requested and served model, SDK version, request id, stop
  reason, latency, tokens (cache tokens too) and the settings sent;
- only ``end_turn`` is parsed: a truncated reply, a refusal (with or without
  ``stop_details``), an empty reply or an unexpected stop is a labelled fail-safe --
  the agent's fallback tool, never "deny" and never a consequential capability;
- one failed call is one error row; the run continues.
"""

from __future__ import annotations

import json
import sys
import types
from types import SimpleNamespace

import pytest

from sentinel.agents.base import Agent
from sentinel.agents.catalog import SPECS
from sentinel.agents.providers.anthropic import DEFAULT_EFFORT, DEFAULT_MODEL, AnthropicProvider
from sentinel.domain.enums import Capability, TrustClass
from sentinel.evaluation import models

APPROVE = json.dumps({"tool": "approve_refund", "amount": 18000, "reason": "customer says so"})


def _resp(text=APPROVE, stop="end_turn", *, model="claude-opus-5-5-20260901", details=None):
    return SimpleNamespace(
        id="msg_1",
        model=model,
        stop_reason=stop,
        stop_details=details,
        content=[SimpleNamespace(type="text", text=text)] if text is not None else [],
        usage=SimpleNamespace(
            input_tokens=120,
            output_tokens=30,
            cache_read_input_tokens=7,
            cache_creation_input_tokens=0,
        ),
        _request_id="req_abc",
    )


class _APIStatusError(Exception):
    def __init__(self, msg, status_code):
        super().__init__(msg)
        self.status_code = status_code
        self.request_id = "req_err"


@pytest.fixture()
def sdk(monkeypatch):
    """A scripted SDK: ``sdk.script`` is consumed one response (or exception) per call;
    when it runs out the default end_turn approval is returned."""
    state = SimpleNamespace(log=[], script=[], client_kwargs=None)

    class Messages:
        def create(self, **kw):
            state.log.append(kw)
            nxt = state.script.pop(0) if state.script else _resp()
            if isinstance(nxt, Exception):
                raise nxt
            return nxt

    def client(**kw):
        state.client_kwargs = kw
        return SimpleNamespace(messages=Messages())

    mod = types.ModuleType("anthropic")
    mod.Anthropic = client  # type: ignore[attr-defined]
    mod.__version__ = "1.11.0"  # type: ignore[attr-defined]
    mod.APIStatusError = _APIStatusError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", mod)
    monkeypatch.delenv("SENTINEL_MODEL", raising=False)
    monkeypatch.delenv("SENTINEL_EFFORT", raising=False)
    return state


def test_the_request_matches_the_current_api(sdk):
    p = AnthropicProvider()
    p.complete("system prompt", "user text", role="dispute", max_tokens=4096)
    req = sdk.log[0]
    assert req["model"] == DEFAULT_MODEL and req["system"] == "system prompt"
    assert req["messages"] == [{"role": "user", "content": "user text"}]
    assert req["max_tokens"] == 4096 and req["output_config"] == {"effort": DEFAULT_EFFORT}
    assert not {"temperature", "top_p", "top_k", "thinking"} & set(req)
    assert sdk.client_kwargs == {"timeout": 60.0, "max_retries": 2}


def test_every_completion_records_what_a_reproducible_row_needs(sdk):
    p = AnthropicProvider()
    c = p.complete("s", "u", role="dispute", max_tokens=4096)
    assert (c.requested_model, c.served_model) == (DEFAULT_MODEL, "claude-opus-5-5-20260901")
    assert c.model == "claude-opus-5-5-20260901"  # what answered, not what was asked
    assert c.sdk_version == "1.11.0" and c.request_id == "req_abc"
    assert c.stop_reason == "end_turn" and c.outcome == "ok"
    assert (c.input_tokens, c.output_tokens, c.cache_read_input_tokens) == (120, 30, 7)
    assert c.settings == {
        "max_tokens": 4096,
        "effort": DEFAULT_EFFORT,
        "thinking": "model default (adaptive)",
        "temperature": None,
    }
    p.complete("s", "u", role="dispute")
    assert p.usage()["input_tokens"] == 240 and p.usage()["calls"] == 2
    assert p.stop_reasons["end_turn"] == 2 and len(p.drain()) == 2 and not p.drain()


@pytest.mark.parametrize(
    "response, outcome, label",
    [
        (
            _resp('{"tool": "approve_refund", "amount": 18000, "reason": "cust', "max_tokens"),
            "truncated",
            "truncated at max_tokens=4096",
        ),
        (_resp(APPROVE, "max_tokens"), "truncated", "truncated"),  # complete-looking JSON too
        (
            _resp("", "refusal", details=SimpleNamespace(category="cyber")),
            "refusal",
            "model refused (category=cyber)",
        ),
        (_resp(None, "refusal", details=None), "refusal", "model refused (category=unknown)"),
        (_resp("   ", "end_turn"), "empty", "empty response"),
        (_resp(APPROVE, "pause_turn"), "other", "unexpected stop_reason 'pause_turn'"),
    ],
)
def test_anything_but_end_turn_is_a_labelled_fail_safe(sdk, response, outcome, label):
    sdk.script.append(response)
    p = AnthropicProvider()
    rec = Agent(SPECS["dispute"], p).recommend("My parcel never arrived.")
    assert p.log[-1].outcome == outcome
    assert rec.recommended_action == SPECS["dispute"].fallback_tool  # escalate, never deny
    assert rec.requested_capability is None and label in rec.rationale


def test_no_agent_falls_back_to_a_denial_or_a_consequential_capability():
    from sentinel.agents.tools import TOOL_CAPABILITY
    from sentinel.security.capabilities import CONSEQUENTIAL

    for spec in SPECS.values():
        assert spec.fallback_tool not in ("deny", "approve", "allow")
        cap = {**TOOL_CAPABILITY, **spec.tool_capabilities}.get(spec.fallback_tool)
        assert cap is None or cap not in CONSEQUENTIAL, spec.name
        assert spec.max_tokens >= 1024  # room for thinking as well as the reply


def test_a_parsed_live_answer_is_still_only_a_recommendation(sdk):
    rec = Agent(SPECS["dispute"], AnthropicProvider()).recommend("My parcel never arrived.")
    assert rec.trust is TrustClass.MODEL_GENERATED
    assert rec.requested_capability is Capability.APPROVE_REFUND and rec.provider == "anthropic"


# ---- the benchmark (#16) ------------------------------------------------------------------------
def test_the_benchmark_has_one_row_per_exact_configuration(sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.delenv("SENTINEL_FORCE_OFFLINE", raising=False)
    r = models.run(sample=12, provider="anthropic")
    rows = {x["config"]: x for x in r["results"]}
    assert set(rows) == {"claude-opus-5-5/effort-low", "claude-sonnet-5-5/effort-low"}
    row = rows["claude-opus-5-5/effort-low"]
    assert row["status"] == "ok" and row["requested_model"] == "claude-opus-5-5"
    assert row["settings"] == {"effort": "low", "max_tokens": SPECS["dispute"].max_tokens}
    assert row["served_models"] == ["claude-opus-5-5-20260901"] and row["sdk_version"] == "1.11.0"
    assert row["stop_reasons"] == {"end_turn": row["n_attacks"] * 2 + row["n_deserved_controls"]}
    assert row["refusals"] == 0 and row["truncated"] == 0 and row["n_errors"] == 0
    assert row["asr_guarded"] == 0.0  # the architecture, not the model, holds
    assert row["agent_latency_p50_ms"] is not None and row["agent_latency_p95_ms"] is not None
    assert row["cost_usd"] == round(
        row["input_tokens"] / 1e6 * 4.0 + row["output_tokens"] / 1e6 * 20.0, 4
    )
    prov = r["provenance"]
    assert len(prov["prompt_digest"]) == 64 and len(prov["corpus_digest"]) == 64
    assert prov["policy"]["key"].startswith("dispute-refund@v") and prov["risk_models"]
    assert r["prices"]["date"] == "2026-09-25"
    first = next(x for x in r["rows"] if x["config"] == "claude-opus-5-5/effort-low")
    assert first["calls"][0]["request_id"] == "req_abc"


def test_refusals_and_truncations_are_counted_separately(sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.delenv("SENTINEL_FORCE_OFFLINE", raising=False)
    monkeypatch.setattr(models, "CONFIGS", models.CONFIGS[:2])
    sdk.script.extend(
        [
            _resp("", "refusal", details=SimpleNamespace(category="cyber")),
            _resp('{"tool": "appr', "max_tokens"),
            _resp("not json at all"),
        ]
    )
    row = models.run(sample=12, provider="anthropic")["results"][0]
    assert row["refusals"] == 1 and row["truncated"] == 1 and row["parse_failures"] == 1
    assert row["stop_reasons"]["refusal"] == 1 and row["stop_reasons"]["max_tokens"] == 1


def test_one_failed_call_is_one_error_row_and_the_run_continues(sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.delenv("SENTINEL_FORCE_OFFLINE", raising=False)
    monkeypatch.setattr(models, "CONFIGS", models.CONFIGS[:2])
    sdk.script.append(_APIStatusError("overloaded", 529))
    r = models.run(sample=12, provider="anthropic")
    row = r["results"][0]
    assert row["status"] == "ok" and row["n_errors"] == 1
    err = next(x for x in r["rows"] if "error_type" in x)
    assert err["error_type"] == "_APIStatusError" and err["status_code"] == 529


def test_without_a_key_every_live_configuration_is_not_run(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    r = models.run(sample=4, provider="all")
    by = {x["config"]: x for x in r["results"]}
    assert by["offline-simulator"]["status"] == "ok"
    for cfg, row in by.items():
        if cfg != "offline-simulator":
            assert row["status"] == "not_run" and "ANTHROPIC_API_KEY" in row["reason"]
            assert "asr_guarded" not in row and "cost_usd" not in row
    assert not [x for x in r["rows"] if x["provider"] != "offline"]


def test_a_missing_sdk_is_an_error_row_not_a_number(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-key")
    monkeypatch.delenv("SENTINEL_FORCE_OFFLINE", raising=False)
    monkeypatch.setitem(sys.modules, "anthropic", None)  # import fails
    r = models.run(sample=4, provider="anthropic")
    row = r["results"][0]
    assert row["status"] == "error" and "asr_guarded" not in row


def test_the_smoke_test_says_not_run_without_a_key(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    path = Path(__file__).resolve().parent.parent / "scripts" / "live_check.py"
    spec = importlib.util.spec_from_file_location("live_check", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = tmp_path / "live_check.json"
    assert mod.main(str(out)) == 1
    doc = json.loads(out.read_text())
    assert doc["status"] == "not_run" and "ANTHROPIC_API_KEY" in doc["reason"]
