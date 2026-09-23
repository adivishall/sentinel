"""Preflight for live mode: one tiny Claude call to confirm the key + model work
before you spend on a full run. Exits non-zero with a clear message on failure."""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel.agents.providers.registry import have_key, mode  # noqa: E402


def main() -> int:
    if mode() != "live":
        if not have_key():
            print(
                'No ANTHROPIC_API_KEY found. Set it, e.g.:\n  export ANTHROPIC_API_KEY="sk-ant-..."'
            )
        else:
            print("SENTINEL_FORCE_OFFLINE=1 is set — unset it to run live.")
        return 1
    from sentinel.agents.providers.anthropic import AnthropicProvider

    p = AnthropicProvider()
    print(f"Model: {p.model}   (override with SENTINEL_MODEL)")
    try:
        t0 = time.perf_counter()
        out = p.complete("Reply with the single word OK.", "ping", role="ping", max_tokens=16)
        print(
            f"Live call OK in {(time.perf_counter() - t0) * 1000:.0f} ms — response: {out.text.strip()[:40]!r}"
        )
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"Live call FAILED: {type(e).__name__}: {e}")
        print("Check the key is valid and the model id is available to your account.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
