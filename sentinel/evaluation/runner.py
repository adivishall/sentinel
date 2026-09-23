"""Unified benchmark runner: ``sentinel eval run --suite full``."""

from __future__ import annotations

import time
from typing import Any

from sentinel.evaluation import (
    ablation,
    baselines,
    bench,
    charts,
    financial,
    harness,
    heldout,
    integrity,
    kyb,
    models,
)
from sentinel.evaluation.attacks import corpus
from sentinel.evaluation.common import write_json

SUITES = (
    "security",
    "heldout",
    "kyb",
    "baselines",
    "ablation",
    "financial",
    "integrity",
    "performance",
    "models",
    "charts",
)


def run_suite(name: str = "full", out_dir: str = "results", full: bool = False) -> dict[str, Any]:
    t0 = time.time()
    results: dict[str, Any] = {}
    names = list(SUITES) if name == "full" else [name]
    if "security" in names or name == "full":
        corpus.write()
    for n in names:
        if n == "security":
            results[n] = harness.main(out_dir)
        elif n == "heldout":
            results[n] = heldout.main(out_dir)
        elif n == "kyb":
            results[n] = kyb.main(out_dir)
        elif n == "baselines":
            results[n] = baselines.main(out_dir)
        elif n == "ablation":
            results[n] = ablation.main(out_dir)
        elif n == "financial":
            results[n] = financial.main(out_dir, full=full)
        elif n == "integrity":
            results[n] = integrity.main(out_dir)
        elif n == "performance":
            results[n] = bench.main(out_dir)
        elif n == "models":
            results[n] = models.main(out_dir)
        elif n == "charts":
            results[n] = {"charts": charts.main(out_dir)}
        else:
            raise SystemExit(f"unknown suite {n!r}; choose from full, {', '.join(SUITES)}")
    if name == "full":
        s, h, k, b, a, f, i, p = (
            results.get(x, {})
            for x in (
                "security",
                "heldout",
                "kyb",
                "baselines",
                "ablation",
                "financial",
                "integrity",
                "performance",
            )
        )
        summary = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "seconds": round(time.time() - t0, 1),
            "security": {
                k2: s.get(k2)
                for k2 in (
                    "n_attacks",
                    "n_controls",
                    "asr_unguarded",
                    "asr_guarded",
                    "detection_recall",
                    "fp_rate",
                    "capability_escalation_rate_unguarded",
                    "capability_escalation_executed_guarded",
                )
            },
            "heldout": {
                k2: h.get(k2)
                for k2 in (
                    "n_attacks",
                    "n_deserved_controls",
                    "asr_unguarded",
                    "asr_guarded",
                    "detection_recall",
                    "fp_rate",
                )
            },
            "kyb": k,
            "baselines": {k2: b.get(k2) for k2 in ("no_defence", "hardened_prompt", "sentinel")},
            "ablation": {k2: v.get("asr") for k2, v in a.items()},
            "financial": {
                k2: f.get(k2)
                for k2 in (
                    "precision",
                    "recall",
                    "false_positive_rate",
                    "false_negative_rate",
                    "prevalence",
                )
            }
            | {"transactions": f.get("dataset", {}).get("transactions")},
            "integrity": {
                k2: i.get(k2)
                for k2 in (
                    "text_influence_permissive_protected",
                    "model_influence_protected",
                    "legit_plus_injection_loosened",
                    "text_influence_permissive_unguarded",
                )
            },
            "performance": {k2: v.get("p95_ms") for k2, v in p.get("components", {}).items()},
        }
        write_json(out_dir, "summary.json", summary)
        results["summary"] = summary
        print(f"[full] done in {summary['seconds']}s -> {out_dir}/summary.json")
    return results
