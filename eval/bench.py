"""Micro-benchmark: firewall throughput and per-decision latency (offline mode).
Isolates the firewall's own cost from agent/LLM cost, so the numbers reflect the
overhead Sentinel adds on top of whatever model a bank already runs."""

from __future__ import annotations

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import red.corpus as corpus
from agents import dispute_triage
from firewall import pipeline


def bench(n_iters: int = 20):
    cases = corpus.build()
    lat = []
    for _ in range(n_iters):
        for c in cases:
            t0 = time.perf_counter()
            pipeline.run_guarded(dispute_triage.run, c["submission"], c["ledger"])
            lat.append((time.perf_counter() - t0) * 1000)  # ms
    lat.sort()
    total = len(lat)
    return {
        "decisions": total,
        "mean_ms": round(statistics.mean(lat), 3),
        "p50_ms": round(lat[total // 2], 3),
        "p95_ms": round(lat[int(total * 0.95)], 3),
        "p99_ms": round(lat[int(total * 0.99)], 3),
        "throughput_per_sec": round(1000 / statistics.mean(lat)),
    }


if __name__ == "__main__":
    r = bench()
    print("Firewall overhead (offline, agent cognition excluded):")
    for k, v in r.items():
        print(f"  {k:20} {v}")
