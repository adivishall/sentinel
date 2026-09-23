"""Model / provider evaluation: the same corpus against each LLM provider.

The offline simulator always runs. A live provider runs only when a key is
present and offline mode is not forced; otherwise the entry records
``not_run`` with the reason -- live numbers are never fabricated and are not
claimed to generalise across models."""

from __future__ import annotations

import os
import time
from typing import Any

from sentinel.agents.providers import get_provider, mode
from sentinel.decision.workflows import FULL, NONE, Runtime
from sentinel.domain.ids import now_iso
from sentinel.evaluation.attacks import corpus
from sentinel.evaluation.common import breach, deserved_approval_missed, pct, run_case, write_json


def _run_with(rt: Runtime, cases: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [c for c in cases if c["is_attack"]]
    deserved = [c for c in cases if not c["is_attack"] and c["ground_truth_outcome"] == "approve"]
    lat: list[float] = []
    ug = g = fp = 0
    by: dict[str, list[int]] = {}
    for c in attacks:
        b0 = run_case(rt, c, NONE)
        b1 = run_case(rt, c, FULL)
        ug += int(breach(b0))
        g += int(breach(b1))
        by.setdefault(c["attack_class"], [0, 0, 0])
        by[c["attack_class"]][0] += int(breach(b0))
        by[c["attack_class"]][1] += int(breach(b1))
        by[c["attack_class"]][2] += 1
        for b in (b0, b1):
            if b.ai:
                lat.append(b.ai.latency_ms)
    for c in deserved:
        fp += int(deserved_approval_missed(run_case(rt, c, FULL), c))
    return {
        "n_attacks": len(attacks),
        "asr_unguarded": round(ug / len(attacks), 3),
        "asr_guarded": round(g / len(attacks), 3),
        "fp_rate": round(fp / max(1, len(deserved)), 3),
        "mean_agent_latency_ms": round(sum(lat) / max(1, len(lat)), 2),
        "by_class": {
            k: {"asr_unguarded": round(v[0] / v[2], 3), "asr_guarded": round(v[1] / v[2], 3)}
            for k, v in by.items()
        },
    }


def run(sample: int | None = None) -> dict[str, Any]:
    cases = corpus.build()
    if sample:
        cases = cases[:: max(1, len(cases) // sample)]
    results: list[dict[str, Any]] = []
    offline = get_provider() if mode() == "offline" else None
    from sentinel.agents.providers.offline import OfflineProvider

    rt = Runtime(persist=False, provider=offline or OfflineProvider())
    t0 = time.time()
    r = _run_with(rt, cases)
    results.append(
        {
            "provider": "offline",
            "model": "offline-simulator",
            "timestamp": now_iso(),
            "status": "ok",
            "seconds": round(time.time() - t0, 1),
            **r,
        }
    )
    if mode() == "live":
        from sentinel.agents.providers.anthropic import AnthropicProvider

        p = AnthropicProvider()
        try:
            t0 = time.time()
            r = _run_with(Runtime(persist=False, provider=p), cases)
            results.append(
                {
                    "provider": "anthropic",
                    "model": p.model,
                    "timestamp": now_iso(),
                    "status": "ok",
                    "seconds": round(time.time() - t0, 1),
                    **r,
                }
            )
        except Exception as e:  # noqa: BLE001
            results.append(
                {
                    "provider": "anthropic",
                    "model": p.model,
                    "timestamp": now_iso(),
                    "status": "error",
                    "reason": type(e).__name__,
                }
            )
    else:
        results.append(
            {
                "provider": "anthropic",
                "model": os.environ.get("SENTINEL_MODEL", "claude-opus-5"),
                "timestamp": now_iso(),
                "status": "not_run",
                "reason": "no ANTHROPIC_API_KEY or SENTINEL_FORCE_OFFLINE=1",
            }
        )
    return {
        "corpus_size": len(cases),
        "results": results,
        "note": "Live results depend on provider/model/date and are not claimed to generalise.",
    }


def main(out_dir: str = "results", sample: int | None = None) -> dict[str, Any]:
    r = run(sample)
    write_json(out_dir, "models.json", r)
    print(f"[models] corpus {r['corpus_size']}")
    for x in r["results"]:
        if x["status"] == "ok":
            print(
                f"  {x['provider']:10} {x['model']:24} ASR {pct(x['asr_unguarded'])} -> {pct(x['asr_guarded'])}  FP {pct(x['fp_rate'])}  agent latency {x['mean_agent_latency_ms']} ms"
            )
        else:
            print(f"  {x['provider']:10} {x['model']:24} {x['status']}: {x.get('reason', '')}")
    return r


if __name__ == "__main__":
    main()
