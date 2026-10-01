"""Preflight for live mode: one tiny Claude call to confirm the key, the model and the
SDK work before spending on a full run.

It writes ``results/live_check.json``: what was asked, what answered (served model, SDK
version, request id, stop reason, latency, tokens) -- never the key. Without a key, or
with ``SENTINEL_FORCE_OFFLINE=1``, it writes ``status: not_run`` with the reason and
exits 1: a smoke test that did not run is recorded as not run, never as a pass."""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.agents.providers.registry import have_key, mode  # noqa: E402
from sentinel.domain.ids import now_iso  # noqa: E402

OUT = os.path.join("results", "live_check.json")


def _write(path: str, doc: dict[str, object]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def main(out: str = OUT) -> int:
    stamp = now_iso()
    if mode() != "live":
        reason = "no ANTHROPIC_API_KEY" if not have_key() else "SENTINEL_FORCE_OFFLINE=1 is set"
        _write(out, {"status": "not_run", "reason": reason, "timestamp": stamp})
        print(f"live check NOT RUN: {reason} (recorded in {out})")
        return 1
    from sentinel.agents.providers.anthropic import AnthropicProvider

    p = AnthropicProvider()
    print(
        f"Model: {p.model}  effort: {p.effort}   (override with SENTINEL_MODEL / SENTINEL_EFFORT)"
    )
    try:
        c = p.complete("Reply with the single word OK.", "ping", role="ping", max_tokens=1024)
        doc: dict[str, object] = {
            "status": "ok" if c.outcome == "ok" else c.outcome,
            "timestamp": stamp,
            "requested_model": c.requested_model,
            "served_model": c.served_model,
            "sdk_version": c.sdk_version,
            "request_id": c.request_id,
            "stop_reason": c.stop_reason,
            "latency_ms": round(c.latency_ms, 1),  # the call alone, not SDK import / client setup
            "input_tokens": c.input_tokens,
            "output_tokens": c.output_tokens,
            "cache_read_input_tokens": c.cache_read_input_tokens,
            "settings": c.settings,
        }
        _write(out, doc)
        print(
            f"live call {doc['status']} in {doc['latency_ms']} ms -- served {c.served_model}, "
            f"stop {c.stop_reason}, request {c.request_id} (recorded in {out})"
        )
        return 0 if c.outcome == "ok" else 1
    except Exception as e:  # noqa: BLE001
        _write(
            out,
            {
                "status": "error",
                "timestamp": stamp,
                "requested_model": p.model,
                "error_type": type(e).__name__,
                "status_code": getattr(e, "status_code", None),
            },
        )
        print(f"live call FAILED: {type(e).__name__}: {str(e)[:200]}")
        print("Check the key is valid and the model id is available to your account.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
