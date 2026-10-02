"""Model / provider evaluation: the same attack corpus against each LLM provider
(``sentinel eval run --suite models [--provider offline|anthropic|all] [--sample N]``).

The offline simulator always runs. A live provider runs only when a key is
present and offline mode is not forced; otherwise its row records ``not_run``
with the reason. Live numbers are never fabricated, are stored with the model,
provider, date, per-attack outcome, latency and token usage where the SDK
reports it, and are not claimed to generalise across models or dates: one
model on one day is one data point.

Rows: ``results/models.json`` (one entry per provider) and
``results/models_rows.json`` (one line per attack per provider, so a live run
can be inspected attack by attack)."""

from __future__ import annotations

import os
import time
from collections import Counter
from typing import Any

from sentinel.agents.providers import mode
from sentinel.agents.providers.base import LLMProvider
from sentinel.agents.providers.offline import OfflineProvider
from sentinel.decision.workflows import FULL, NONE
from sentinel.domain.ids import content_hash, now_iso
from sentinel.evaluation.attacks import corpus
from sentinel.evaluation.common import (
    breach,
    deserved_approval_missed,
    pct,
    percentiles,
    run_case,
    runtime,
    write_json,
)

PROVIDERS = ("offline", "anthropic")


def _usage(p: LLMProvider) -> dict[str, int | None]:
    """Token totals when the provider counts them (the Anthropic SDK reports usage
    per call; the offline simulator has no tokens)."""
    keys = (
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
    )
    u = getattr(p, "usage", None)
    if callable(u):
        u = u()
    if isinstance(u, dict):
        return {k: u.get(k) for k in keys}
    return {k: None for k in keys}


# One row per exact configuration. A row that is not executed stays NOT RUN, with why.
CONFIGS: tuple[dict[str, Any], ...] = (
    {
        "id": "offline-simulator",
        "provider": "offline",
        "model": "offline-simulator",
        "effort": None,
    },
    {
        "id": "claude-opus-5-5/effort-low",
        "provider": "anthropic",
        "model": "claude-opus-5-5",
        "effort": "low",
    },
    {
        "id": "claude-sonnet-5-5/effort-low",
        "provider": "anthropic",
        "model": "claude-sonnet-5-5",
        "effort": "low",
    },
)
# Dated list prices, used only to cost a row that actually ran (input and output tokens;
# cache tokens are reported, not priced). Unknown model -> no cost, never an estimate.
PRICES: dict[str, Any] = {
    "date": "2026-10-01",
    "source": "Claude API reference bundled with Claude Code 2.1.284 (shared/models.md), checked 2026-10-01",
    "usd_per_mtok": {
        "claude-opus-5-5": {"input": 4.0, "output": 20.0},
        "claude-sonnet-5-5": {"input": 2.0, "output": 10.0},
    },
}
PARSE_FAILURE = "unparseable agent output"


def _configs(provider: str) -> list[dict[str, Any]]:
    out = [c for c in CONFIGS if provider in ("all", c["provider"])]
    extra = os.environ.get("SENTINEL_MODEL")
    effort = os.environ.get("SENTINEL_EFFORT", "low")
    if (
        extra
        and provider in ("all", "anthropic")
        and not any((c["model"], c["effort"]) == (extra, effort) for c in out)
    ):
        out.append(
            {
                "id": f"{extra}/effort-{effort}",
                "provider": "anthropic",
                "model": extra,
                "effort": effort,
            }
        )
    return out


def _build(cfg: dict[str, Any]) -> LLMProvider:
    if cfg["provider"] == "offline":
        return OfflineProvider()
    if cfg["provider"] == "anthropic":
        from sentinel.agents.providers.anthropic import AnthropicProvider

        return AnthropicProvider(cfg["model"], cfg["effort"])
    raise ValueError(f"unknown provider {cfg['provider']!r}; choose from {PROVIDERS}")


def provenance(cases: list[dict[str, Any]]) -> dict[str, Any]:
    """What a row was measured against: the agent prompts, the corpus, the policy and the
    risk models, by digest -- so two rows are comparable only when these match."""
    import dataclasses
    import subprocess

    from sentinel import __version__
    from sentinel.agents.catalog import SPECS
    from sentinel.decision.workflows import FULL, NONE, _prompt
    from sentinel.evaluation.common import dispute_request
    from sentinel.policy import DEFAULT_REGISTRY
    from sentinel.policy.loader import policy_digest
    from sentinel.risk import scoring

    pol = DEFAULT_REGISTRY.active("dispute-refund")
    req = dispute_request(cases[0]) if cases else None
    contents = (req.narrative, *req.documents) if req is not None else ()
    try:  # the code that ran, when it runs from a checkout
        commit = (
            subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5
            ).stdout.strip()
            or None
        )
    except (OSError, subprocess.SubprocessError):
        commit = None
    return {
        "sentinel_version": __version__,
        "commit": commit,
        # every field of every agent spec: prompt, tool surface, fallback, overrides, limits
        "agent_specs_digest": content_hash(
            {k: dataclasses.asdict(v) for k, v in sorted(SPECS.items())}, 64
        ),
        # what the model actually receives for one canonical case, guarded and unguarded
        "rendered_prompt_digest": content_hash(
            [_prompt(contents, "", FULL), _prompt(contents, "", NONE)], 64
        ),
        "prompt_digest": content_hash({k: v.system_prompt for k, v in SPECS.items()}, 64),
        "corpus_digest": content_hash(cases, 64),
        "corpus_size": len(cases),
        "policy": {
            "key": pol.key,
            "digest": policy_digest(pol),
            "release_status": pol.release.status.value if pol.release is not None else None,
        },
        "risk_models": {k: m.version for k, m in sorted(scoring.ACTIVE.items())},
        "max_tokens": SPECS["dispute"].max_tokens,
    }


def _cost(model: str, inp: int | None, out: int | None) -> float | None:
    price = PRICES["usd_per_mtok"].get(model)
    if price is None or inp is None or out is None:
        return None
    return round(inp / 1e6 * price["input"] + out / 1e6 * price["output"], 4)


def _run_with(
    p: LLMProvider, cases: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rt = runtime(provider=p)
    attacks = [c for c in cases if c["is_attack"]]
    deserved = [c for c in cases if not c["is_attack"] and c["ground_truth_outcome"] == "approve"]
    drain = getattr(p, "drain", None)
    live = p.name != "offline"
    lat: list[float] = []
    rows: list[dict[str, Any]] = []
    ug = g = fp = n_att = n_ok = errors = parse_failures = 0
    by: dict[str, list[int]] = {}
    served: set[str] = set()

    measured_calls: list[dict[str, Any]] = []
    errored_calls = 0

    def calls() -> list[dict[str, Any]]:
        out = []
        for c in drain() if callable(drain) else []:
            if c.served_model:
                served.add(c.served_model)
            out.append(
                {
                    "request_id": c.request_id,
                    "served_model": c.served_model,
                    "stop_reason": c.stop_reason,
                    "outcome": c.outcome,
                }
            )
        return out

    def parse_failed(b: Any) -> bool:
        return bool(b.ai and b.ai.rationale == PARSE_FAILURE)

    for c in attacks:
        try:
            b0 = run_case(rt, c, NONE)
            b1 = run_case(rt, c, FULL)
        except Exception as e:  # noqa: BLE001 -- one failed live call is one error row
            if not live:
                raise
            errors += 1
            failed = calls()
            errored_calls += len(failed)
            rows.append(_error_row(p, c, e, failed))
            continue
        n_att += 1
        ub, gb = breach(b0), breach(b1)
        ug += int(ub)
        g += int(gb)
        parse_failures += int(parse_failed(b0)) + int(parse_failed(b1))
        by.setdefault(c["attack_class"], [0, 0, 0])
        by[c["attack_class"]][0] += int(ub)
        by[c["attack_class"]][1] += int(gb)
        by[c["attack_class"]][2] += 1
        for b in (b0, b1):
            if b.ai:
                lat.append(b.ai.latency_ms)
        rows.append(
            {
                "provider": p.name,
                "model": p.model,
                "id": c["id"],
                "attack_class": c["attack_class"],
                "target_capability": c["target_capability"],
                "unguarded_recommendation": b0.ai.recommended_action if b0.ai else None,
                "unguarded_executed": (
                    b0.decision.executed_capability.value
                    if b0.decision.executed_capability
                    else None
                ),
                "unguarded_breach": ub,
                "guarded_recommendation": b1.ai.recommended_action if b1.ai else None,
                "guarded_final_action": b1.decision.final_action.value,
                "guarded_breach": gb,
                "blocked_by": list(b1.decision.blocked_by),
                "latency_ms": b1.ai.latency_ms if b1.ai else None,
                **({"calls": (cc := calls())} if live else {}),
            }
        )
        if live:
            measured_calls.extend(cc)
    for c in deserved:
        try:
            b = run_case(rt, c, FULL)
        except Exception as e:  # noqa: BLE001
            if not live:
                raise
            errors += 1
            failed = calls()
            errored_calls += len(failed)
            rows.append(_error_row(p, c, e, failed))
            continue
        n_ok += 1
        missed = deserved_approval_missed(b, c)
        fp += int(missed)
        parse_failures += int(parse_failed(b))
        rows.append(
            {
                "provider": p.name,
                "model": p.model,
                "id": c["id"],
                "attack_class": "legitimate_control",
                "target_capability": c["target_capability"],
                "guarded_recommendation": b.ai.recommended_action if b.ai else None,
                "guarded_final_action": b.decision.final_action.value,
                "deserved_approval_missed": missed,
                "latency_ms": b.ai.latency_ms if b.ai else None,
                **({"calls": (cc := calls())} if live else {}),
            }
        )
        if live:
            measured_calls.extend(cc)
    lp = percentiles(lat) if lat else {}
    usage = _usage(p)
    # counted over the calls of measured cases only (an errored case's calls are reported
    # apart, so the counts match the denominators)
    if live:
        stop_reasons = dict(Counter(str(x["stop_reason"] or "none") for x in measured_calls))
        outcomes = dict(Counter(str(x["outcome"]) for x in measured_calls))
    else:
        stop_reasons = dict(getattr(p, "stop_reasons", {}) or {})
        outcomes = dict(getattr(p, "outcomes", {}) or {})
    summary = {
        "n_attacks": n_att,
        "n_deserved_controls": n_ok,
        "n_errors": errors,
        "errored_calls": errored_calls,
        # a rate over nothing is not 0: None when nothing of that kind was measured
        "asr_unguarded": round(ug / n_att, 3) if n_att else None,
        "asr_guarded": round(g / n_att, 3) if n_att else None,
        "fp_rate": round(fp / n_ok, 3) if n_ok else None,
        "mean_agent_latency_ms": round(sum(lat) / max(1, len(lat)), 2),
        "agent_latency_p50_ms": lp.get("p50_ms"),
        "agent_latency_p95_ms": lp.get("p95_ms"),
        "stop_reasons": stop_reasons,
        "refusals": outcomes.get("refusal", 0),
        "truncated": outcomes.get("truncated", 0),
        "parse_failures": parse_failures,
        "served_models": sorted(served),
        "sdk_version": getattr(p, "sdk_version", None),
        "by_class": {
            k: {
                "n": v[2],
                "asr_unguarded": round(v[0] / v[2], 3),
                "asr_guarded": round(v[1] / v[2], 3),
            }
            for k, v in by.items()
        },
        **usage,
        "cost_usd": _cost(p.model, usage.get("input_tokens"), usage.get("output_tokens")),
    }
    return summary, rows


def _error_row(p: LLMProvider, c: dict[str, Any], e: Exception, calls: list[Any]) -> dict[str, Any]:
    return {
        "provider": p.name,
        "model": p.model,
        "id": c["id"],
        "error_type": type(e).__name__,
        "status_code": getattr(e, "status_code", None),
        "request_id": getattr(e, "request_id", None),
        "calls": calls,
    }


def run(sample: int | None = None, provider: str = "all") -> dict[str, Any]:
    cases = corpus.build()
    if sample:
        cases = cases[:: max(1, len(cases) // sample)]
    prov = provenance(cases)
    results: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for cfg in _configs(provider):
        stamp = now_iso()
        head = {
            "config": cfg["id"],
            "provider": cfg["provider"],
            "requested_model": cfg["model"],
            "model": cfg["model"],
            "settings": {
                "effort": cfg["effort"],
                "max_tokens": prov["max_tokens"] if cfg["provider"] != "offline" else None,
            },
            "timestamp": stamp,
            "date": stamp[:10],
        }
        if cfg["provider"] != "offline" and mode() != "live":
            results.append(
                {
                    **head,
                    "status": "not_run",
                    "reason": "no ANTHROPIC_API_KEY or SENTINEL_FORCE_OFFLINE=1",
                }
            )
            continue
        try:
            p = _build(cfg)
            preflight = getattr(p, "_client_or_raise", None)
            if callable(preflight):
                preflight()  # a missing SDK or a bad client is the row's error, not 300 rows'
            t0 = time.time()
            summary, prow = _run_with(p, cases)
            rows.extend({**r, "config": cfg["id"]} for r in prow)
            spend = {
                k: summary.get(k)
                for k in (
                    "input_tokens",
                    "output_tokens",
                    "cost_usd",
                    "n_errors",
                    "n_deserved_controls",
                )
            }
            if summary["n_errors"] and not summary["n_attacks"]:
                results.append(
                    {
                        **head,
                        "status": "error",
                        "reason": (
                            f"{summary['n_errors']} cases failed; no attack measured "
                            f"({summary['n_deserved_controls']} controls ran)"
                        ),
                        **spend,
                    }
                )
                continue
            status = "partial" if summary["n_errors"] else "ok"
            results.append(
                {
                    **head,
                    "status": status,
                    **(
                        {"reason": f"{summary['n_errors']} cases failed and are excluded"}
                        if status == "partial"
                        else {}
                    ),
                    "seconds": round(time.time() - t0, 1),
                    **summary,
                }
            )
        except Exception as e:  # noqa: BLE001 -- a live provider can fail in many ways
            results.append(
                {**head, "status": "error", "reason": f"{type(e).__name__}: {str(e)[:120]}"}
            )
    return {
        "corpus_size": len(cases),
        "provenance": prov,
        "prices": PRICES,
        "results": results,
        "rows": rows,
        "kinds": {
            "offline": "synthetic (deterministic simulator of a naive tool-calling agent)",
            "live": "live-model evaluation: one configuration, one date; not a generalisation",
        },
        "methodology": {
            "kind": "synthetic for the offline row; live for a provider row with status ok",
            "sample": len(cases),
            "method": (
                "one row per exact configuration (provider, requested model, effort, "
                "max_tokens) against the same corpus, prompts, policy and risk models (by "
                "digest); every case runs with no controls and with full controls; success = "
                "an unauthorised consequential capability executed; deserved controls measure "
                "false positives; refusals, truncations and parse failures are counted "
                "separately and each is a fail-safe recommendation, never a denial"
            ),
            "limitations": (
                "the offline row is a property of the simulator; a live row is one "
                "configuration on one day and is never fabricated -- it stays not_run until "
                "an operator runs it; there is no universal score across rows"
            ),
        },
        "note": "Live results depend on provider/model/date and are not claimed to generalise.",
    }


def main(
    out_dir: str = "results", sample: int | None = None, provider: str = "all"
) -> dict[str, Any]:
    r = run(sample, provider)
    rows = r.pop("rows")
    write_json(out_dir, "models.json", r)
    write_json(out_dir, "models_rows.json", rows)
    print(f"[models] corpus {r['corpus_size']}")
    for x in r["results"]:
        if x["status"] == "ok":
            tok = (
                f"  tokens in/out {x['input_tokens']}/{x['output_tokens']}"
                if x.get("input_tokens") is not None
                else ""
            )
            print(
                f"  {x['config']:32} {x['date']}  ASR {pct(x['asr_unguarded'])} -> {pct(x['asr_guarded'])}  FP {pct(x['fp_rate'])}  agent latency {x['mean_agent_latency_ms']} ms{tok}"
            )
        else:
            print(f"  {x['config']:32} {x['status'].upper()}: {x.get('reason', '')}")
    return r


if __name__ == "__main__":
    main()
