"""Unified benchmark runner: ``sentinel eval run --suite full``."""

from __future__ import annotations

import time
from typing import Any

from sentinel.evaluation import (
    ablation,
    baselines,
    bench,
    charts,
    claims,
    financial,
    harness,
    heldout,
    integrity,
    kyb,
    models,
    redteam,
    surfaces,
    temporal,
)
from sentinel.evaluation.attacks import corpus
from sentinel.evaluation.common import write_json

SUITES = (
    "security",
    "heldout",
    "surfaces",
    "kyb",
    "baselines",
    "ablation",
    "financial",
    "integrity",
    "temporal",
    "claims",
    "performance",
    "models",
    "redteam",
    "charts",
)


def run_suite(
    name: str = "full",
    out_dir: str = "results",
    full: bool = False,
    provider: str = "all",
    sample: int | None = None,
) -> dict[str, Any]:
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
        elif n == "surfaces":
            results[n] = surfaces.main(out_dir)
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
        elif n == "temporal":
            results[n] = temporal.main(out_dir)
        elif n == "claims":
            results[n] = claims.main(out_dir)
        elif n == "performance":
            results[n] = bench.main(out_dir)
        elif n == "models":
            results[n] = models.main(out_dir, sample=sample, provider=provider)
        elif n == "redteam":
            results[n] = redteam.main(out_dir, sample=sample)
        elif n == "charts":
            results[n] = {"charts": charts.main(out_dir)}
        else:
            raise SystemExit(f"unknown suite {n!r}; choose from full, {', '.join(SUITES)}")
    if name == "full":
        s, h, k, b, a, f, i, p, tl, sf = (
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
                "temporal",
                "surfaces",
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
            "surfaces": {
                k2: sf.get(k2)
                for k2 in (
                    "n_attacks",
                    "asr_unguarded",
                    "asr_guarded",
                    "detection_recall",
                    "loosened_vs_baseline",
                )
            },
            "kyb": {
                k2: k.get(k2)
                for k2 in (
                    "attacks",
                    "controls",
                    "asr_unguarded",
                    "asr_guarded",
                    "fp_rate",
                    "fp_rate_benign_input",
                    "fn_rate",
                    "borderline_to_review",
                    "manual_review_rate",
                )
            },
            "baselines": {k2: b.get(k2) for k2 in ("no_defence", "hardened_prompt", "sentinel")},
            "ablation": {k2: v.get("asr") for k2, v in a.items() if k2 != "methodology"},
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
            | {
                "transactions": f.get("dataset", {}).get("transactions"),
                "seed_range": f.get("seed_range"),
            },
            "integrity": {
                k2: i.get(k2)
                for k2 in (
                    "text_influence_permissive_protected",
                    "model_influence_protected",
                    "legit_plus_injection_loosened",
                    "text_influence_permissive_unguarded",
                    "text_beyond_ledger_ceiling",
                    "executed_without_ledger_support",
                    "attack_text_approved_on_supporting_ledger",
                )
            },
            "temporal": {
                k2: tl.get(k2)
                for k2 in (
                    "decisions_tested",
                    "leakage_count",
                    "leakage_rate",
                    "leakage_upper_95",
                    "truncation_mismatch_rate",
                    "perturbation_transaction_change_rate",
                    "perturbation_monitoring_change_rate",
                )
            },
            "performance": {k2: v.get("p95_ms") for k2, v in p.get("components", {}).items()},
            "claims": {
                k2: results.get("claims", {}).get(k2)
                for k2 in (
                    "n",
                    "coverage",
                    "false_positive_rate",
                    "misclassification_rate",
                    "abstain_rate",
                    "adversarial_wrong_type_rate",
                )
            },
        }
        write_json(out_dir, "summary.json", summary)
        results["summary"] = summary
        print(f"[full] done in {summary['seconds']}s -> {out_dir}/summary.json")
    return results
