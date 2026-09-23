"""Financial risk evaluation on the labelled synthetic dataset.

Labels come from the generator's injected scenarios and are read here ONLY.
"Positive" = risk level HIGH or CRITICAL (the levels that trigger review or
block). Reported: precision, recall, FPR, FNR, per-scenario recall, and a
calibration table (observed fraud rate per risk band). Synthetic data; the
numbers characterise the rule model on this generator, nothing more."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from typing import Any

from sentinel.app import SentinelApp
from sentinel.decision.workflows import RunOptions
from sentinel.domain.enums import RiskLevel
from sentinel.evaluation.common import pct, write_json
from sentinel.risk import scoring
from sentinel.risk import transaction as txn_risk


def run(
    seed: int = 42,
    customers: int = 150,
    merchants: int = 30,
    transactions: int = 3000,
    *,
    model: str = "txn-1.0",
    policy_sample: int = 400,
) -> dict[str, Any]:
    app = SentinelApp.demo(seed, customers, merchants, transactions, persist=False)
    m = scoring.get_model(model)
    rows = []
    for t in app.store.all_transactions():
        ra = txn_risk.assess_transaction(t, app.transaction_context(t), m)
        rows.append((t, ra))
    tp = fp = fn = tn = 0
    per_scn: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    band: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    hist: Counter[int] = Counter()
    factor_counts: Counter[str] = Counter()
    for t, ra in rows:
        fraud = t.label.startswith("fraud")
        positive = ra.level.rank >= RiskLevel.HIGH.rank
        if fraud and positive:
            tp += 1
        elif fraud:
            fn += 1
        elif positive:
            fp += 1
        else:
            tn += 1
        if fraud:
            per_scn[t.label][1] += 1
            per_scn[t.label][0] += int(positive)
        band[ra.level.value][1] += 1
        band[ra.level.value][0] += int(fraud)
        hist[ra.score // 10 * 10] += 1
        for f in ra.factors:
            factor_counts[f.code] += 1
    n = len(rows)
    # policy-level outcomes on a sample (full pipeline, no agent)
    sample = [t for t, _ in rows[-policy_sample:]]
    fraud_allowed = legit_blocked = fraud_n = legit_n = 0
    outcomes: Counter[str] = Counter()
    for t in sample:
        d = app.evaluate_transaction(t, options=RunOptions(skip_agent=True, risk_model=m)).decision
        outcomes[d.final_action.value] += 1
        if t.label.startswith("fraud"):
            fraud_n += 1
            fraud_allowed += int(d.executed)
        else:
            legit_n += 1
            legit_blocked += int(d.final_action.value in ("BLOCK", "DENY"))
    return {
        "dataset": {
            "seed": seed,
            "customers": customers,
            "merchants": merchants,
            "transactions": n,
        },
        "risk_model": model,
        "positive_definition": "risk level HIGH or CRITICAL",
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(tp / max(1, tp + fp), 3),
        "recall": round(tp / max(1, tp + fn), 3),
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "false_negative_rate": round(fn / max(1, tp + fn), 3),
        "prevalence": round((tp + fn) / max(1, n), 4),
        "recall_by_scenario": {
            k: {"n": v[1], "recall": round(v[0] / v[1], 3)} for k, v in sorted(per_scn.items())
        },
        "calibration": {
            k: {"n": v[1], "observed_fraud_rate": round(v[0] / v[1], 4)} for k, v in band.items()
        },
        "score_histogram": {str(k): v for k, v in sorted(hist.items())},
        "factor_frequency": dict(factor_counts.most_common(15)),
        "policy_sample": {
            "n": len(sample),
            "outcomes": dict(outcomes),
            "fraud_allowed_rate": round(fraud_allowed / max(1, fraud_n), 3),
            "legit_blocked_or_denied_rate": round(legit_blocked / max(1, legit_n), 4),
            "policy": "transaction-authorization@latest",
        },
    }


def main(out_dir: str = "results", full: bool = False) -> dict[str, Any]:
    t0 = time.time()
    r = run(customers=400, merchants=60, transactions=12000) if full else run()
    r["seconds"] = round(time.time() - t0, 1)
    write_json(out_dir, "financial.json", r)
    print(
        f"[financial] {r['dataset']['transactions']} synthetic transactions, model {r['risk_model']} ({r['seconds']}s)"
    )
    print(
        f"  precision {pct(r['precision'])}  recall {pct(r['recall'])}  FPR {pct(r['false_positive_rate'])}  FNR {pct(r['false_negative_rate'])}  prevalence {pct(r['prevalence'])}"
    )
    print("  recall by scenario:", {k: v["recall"] for k, v in r["recall_by_scenario"].items()})
    print(
        "  calibration (fraud rate by band):",
        {k: v["observed_fraud_rate"] for k, v in r["calibration"].items()},
    )
    ps = r["policy_sample"]
    print(
        f"  policy sample n={ps['n']}: fraud allowed {pct(ps['fraud_allowed_rate'])}, legit blocked/denied {pct(ps['legit_blocked_or_denied_rate'])}"
    )
    return r


if __name__ == "__main__":
    main()
