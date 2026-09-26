"""Financial risk evaluation on the labelled synthetic dataset.

Labels come from the generator's injected scenarios and are read here ONLY.
Risk exists at three levels and each scenario is evaluated at the level that
is supposed to catch it:

  transaction  account takeover, bursts, graph-linked ring transactions
  account      structuring-like transfers, dormant activation, rings, bursts
               (transaction monitoring over the account's activity)
  merchant     merchant abuse (entity profile)

"Positive" = risk level HIGH or CRITICAL (the levels that trigger review or
block). Reported per level: precision, recall, FPR, FNR, per-scenario recall,
plus a calibration table (observed fraud rate per band) and policy outcomes on
a sample. Synthetic data; the numbers characterise the rule model on this
generator, nothing more.

The rule weights were hand-tuned while looking at the seed-42 dataset, so the
seed-42 figures are development figures. The same suite therefore also runs on
held-out seeds the weights were never inspected against, and reports the range;
a large gap between development and held-out seeds would mean the weights fit
one dataset rather than the scenario patterns."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

from sentinel.app import SentinelApp
from sentinel.decision.workflows import RunOptions
from sentinel.domain.enums import RiskLevel
from sentinel.evaluation.common import pct, write_json
from sentinel.evaluation.methodology import methodology
from sentinel.risk import monitoring, scoring
from sentinel.risk import transaction as txn_risk

TXN_SCENARIOS = ("fraud:account_takeover", "fraud:burst", "fraud:graph_linked")
ACCOUNT_SCENARIOS = (
    "fraud:structuring",
    "fraud:dormant_activation",
    "fraud:graph_linked",
    "fraud:burst",
)

# What each synthetic label means and at which level it is supposed to be caught.
GROUND_TRUTH: dict[str, dict[str, str]] = {
    "fraud:account_takeover": {
        "level": "transaction",
        "definition": "two purchases from a new device in a new country within an hour of a home-country purchase, after a session with credential + payout changes and a failed second factor",
    },
    "fraud:burst": {
        "level": "transaction + account",
        "definition": "8-12 purchases three minutes apart on an account that normally transacts every few days",
    },
    "fraud:graph_linked": {
        "level": "transaction + account",
        "definition": "three 17-day-old accounts on one device and one payout bank account, five purchases each at high-risk merchants, then transfers in a circle",
    },
    "fraud:structuring": {
        "level": "account",
        "definition": "four transfers just under the reporting threshold within a week",
    },
    "fraud:dormant_activation": {
        "level": "account",
        "definition": "120 days of silence then six purchases in two days",
    },
    "exposure:merchant_abuse": {
        "level": "merchant",
        "definition": "purchases at a merchant with an injected 30% dispute ratio; the transactions themselves are not fraud",
    },
    "legit:high_value": {
        "level": "decisioning",
        "definition": "a genuine purchase above the auto-approval limit on a home device; policy must route it to a human, not block it",
    },
}

# The signal families a fraud/risk engineer expects each scenario to trip.
EXPECTED_SIGNALS: dict[str, tuple[str, ...]] = {
    "fraud:account_takeover": (
        "new_device",
        "new_country",
        "impossible_travel",
        "recent_account_changes",
        "recent_failed_mfa",
        "amount_anomaly_extreme",
    ),
    "fraud:burst": (
        "rapid_fire",
        "rapid_succession",
        "velocity_elevated",
        "velocity_spike",
        "velocity_burst",
    ),
    "fraud:graph_linked": (
        "young_account_shared_device",
        "shared_device",
        "shared_payout_instrument",
        "account_age_young",
        "auth_weak",
    ),
}


def _prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(tp / max(1, tp + fp), 3),
        "recall": round(tp / max(1, tp + fn), 3),
        "false_positive_rate": round(fp / max(1, fp + tn), 4),
        "false_negative_rate": round(fn / max(1, tp + fn), 3),
    }


HELD_OUT_SEEDS: tuple[int, ...] = (7, 2024)
LEVELS = ("transaction_level", "account_level", "merchant_level")


def _range(runs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Min / max of each headline metric per level across the seeds."""
    out: dict[str, Any] = {}
    for level in LEVELS:
        out[level] = {}
        for metric in ("precision", "recall", "false_positive_rate"):
            vals = [r[level][metric] for r in runs.values()]
            out[level][metric] = {"min": min(vals), "max": max(vals)}
    return out


def run(
    seed: int = 42,
    customers: int = 150,
    merchants: int = 30,
    transactions: int = 3000,
    *,
    model: str = scoring.TRANSACTION_DEFAULT.version,
    policy_sample: int = 400,
    held_out_seeds: tuple[int, ...] = HELD_OUT_SEEDS,
) -> dict[str, Any]:
    dev = _evaluate(
        seed, customers, merchants, transactions, model=model, policy_sample=policy_sample
    )
    held: dict[str, dict[str, Any]] = {}
    for s in held_out_seeds:
        if s == seed:
            continue
        r = _evaluate(s, customers, merchants, transactions, model=model, policy_sample=0)
        held[str(s)] = {level: r[level] for level in LEVELS} | {
            "recall_by_scenario": r["recall_by_scenario"]
        }
    dev["seeds"] = {"development": seed, "held_out": [int(k) for k in held]}
    dev["held_out_seeds"] = held
    dev["seed_range"] = _range({"dev": dev, **held})
    return dev


def _burst_positions(app: SentinelApp, model: Any, rows: list[Any]) -> dict[str, Any]:
    """Transaction-level recall on bursts by the transaction's position in its burst, and
    split by whether the velocity rule COULD see it at authorization time (at least
    ``rapid_fire_count`` earlier transactions on the account inside the rapid window).
    A burst's first transactions look like ordinary purchases when they are authorised:
    the burst does not exist yet. The account-level monitor, which sees the whole window,
    is the control for them (``account_level.recall_by_scenario``)."""
    need = int(model.t("rapid_fire_count", 3))
    window = timedelta(minutes=model.t("rapid_window_minutes", 10))
    flagged = {t.transaction_id: ra.level.rank >= RiskLevel.HIGH.rank for t, ra in rows}
    by_acct: dict[str, list[datetime]] = defaultdict(list)
    for t, _ in rows:
        by_acct[t.account_id].append(datetime.fromisoformat(t.timestamp))
    by_pos: dict[int, list[int]] = defaultdict(lambda: [0, 0])
    visible = [0, 0]
    hidden = [0, 0]
    for tag in app.store.scenarios():
        if tag["scenario"] != "transaction_burst":
            continue
        txs = sorted(
            (x for x in (app.store.transaction(e) for e in tag["entity_ids"]) if x is not None),
            key=lambda x: x.timestamp,
        )
        for i, t in enumerate(txs, start=1):
            at = datetime.fromisoformat(t.timestamp)
            prior = sum(1 for x in by_acct[t.account_id] if at - window <= x < at)
            hit = int(flagged.get(t.transaction_id, False))
            by_pos[i][0] += hit
            by_pos[i][1] += 1
            bucket = visible if prior >= need else hidden
            bucket[0] += hit
            bucket[1] += 1
    return {
        "definition": (
            f"velocity-visible = at least {need} earlier transactions on the account in the "
            f"{int(window.total_seconds() // 60)} minutes before (the rapid-fire rule's input)"
        ),
        "by_position": {str(k): {"flagged": v[0], "n": v[1]} for k, v in sorted(by_pos.items())},
        "velocity_visible": {"flagged": visible[0], "n": visible[1]},
        "not_yet_visible": {"flagged": hidden[0], "n": hidden[1]},
    }


def _evaluate(
    seed: int,
    customers: int,
    merchants: int,
    transactions: int,
    *,
    model: str,
    policy_sample: int,
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
    # breakdowns: (group key) -> [fraud positives, fraud, legit positives, legit]
    by_channel: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    by_segment: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    by_tier: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0, 0])
    segment_of = {a.account_id: (app.store.customer(a.customer_id) or a).segment for a in app.store.accounts()}  # type: ignore[union-attr]
    tier_of = {m.merchant_id: m.mcc_risk for m in app.store.merchants()}
    missed_rows: list[dict[str, Any]] = []
    signal_hits: dict[str, Counter[str]] = defaultdict(Counter)
    signal_hits_missed: dict[str, Counter[str]] = defaultdict(Counter)
    fp_rows: list[dict[str, Any]] = []
    # per-signal statistics: how often each factor fires on fraud vs legitimate transactions
    sig_fraud: Counter[str] = Counter()
    sig_legit: Counter[str] = Counter()
    n_fraud_total = n_legit_total = 0
    for t, ra in rows:
        fraud = t.label in TXN_SCENARIOS
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
            n_fraud_total += 1
            for f in ra.factors:
                sig_fraud[f.code] += 1
        else:
            n_legit_total += 1
            for f in ra.factors:
                sig_legit[f.code] += 1
        if fraud:
            per_scn[t.label][1] += 1
            per_scn[t.label][0] += int(positive)
            for f in ra.factors:
                (signal_hits if positive else signal_hits_missed)[t.label][f.code] += 1
            if not positive:
                missed_rows.append(
                    {
                        "transaction_id": t.transaction_id,
                        "scenario": t.label,
                        "score": ra.score,
                        "level": ra.level.value,
                        "factors": [f"{f.code}:{f.points:+d}" for f in ra.factors],
                        "components": ra.components,
                        "missing_expected": [
                            s
                            for s in EXPECTED_SIGNALS.get(t.label, ())
                            if s not in {f.code for f in ra.factors}
                        ],
                    }
                )
        elif positive:
            fp_rows.append(
                {
                    "transaction_id": t.transaction_id,
                    "label": t.label,
                    "score": ra.score,
                    "factors": [f"{f.code}:{f.points:+d}" for f in ra.factors],
                }
            )
        for grp, key in (
            (by_channel, t.channel),
            (by_segment, segment_of.get(t.account_id, "unknown")),
            (by_tier, tier_of.get(t.merchant_id, "unknown")),
        ):
            g = grp[key]
            g[1 if fraud else 3] += 1
            g[0 if fraud else 2] += int(positive)
        band[ra.level.value][1] += 1
        band[ra.level.value][0] += int(fraud)
        hist[ra.score // 10 * 10] += 1
        for f in ra.factors:
            factor_counts[f.code] += 1
    n = len(rows)
    burst = _burst_positions(app, m, rows)
    groups = scoring.FACTOR_GROUPS
    signal_stats: dict[str, dict[str, Any]] = {}
    for code in sorted(
        set(sig_fraud) | set(sig_legit), key=lambda c: -(sig_fraud[c] + sig_legit[c])
    ):
        f_, l_ = sig_fraud[code], sig_legit[code]
        signal_stats[code] = {
            "family": groups.get(code, "other"),
            "points": m.w(code),
            "fired_on_fraud": f_,
            "fired_on_legit": l_,
            "fraud_fire_rate": round(f_ / max(1, n_fraud_total), 4),
            "legit_fire_rate": round(l_ / max(1, n_legit_total), 4),
            "precision_when_fired": round(f_ / max(1, f_ + l_), 3),
        }
    family_stats: dict[str, dict[str, Any]] = {}
    for fam in dict.fromkeys(groups.values()):
        codes = [c for c, g in groups.items() if g == fam]
        ff = sum(sig_fraud[c] for c in codes)
        ll = sum(sig_legit[c] for c in codes)
        family_stats[fam] = {
            "factors": codes,
            "fired_on_fraud": ff,
            "fired_on_legit": ll,
            "precision_when_fired": round(ff / max(1, ff + ll), 3),
        }

    def _grp(d: dict[str, list[int]]) -> dict[str, Any]:
        return {
            k: {
                "n": v[1] + v[3],
                "fraud_n": v[1],
                "recall": round(v[0] / v[1], 3) if v[1] else None,
                "legit_n": v[3],
                "false_positive_rate": round(v[2] / v[3], 4) if v[3] else None,
            }
            for k, v in sorted(d.items())
        }

    # ---- account level: transaction monitoring over every account ---------------------
    labels_by_account: dict[str, set[str]] = defaultdict(set)
    for t, _ in rows:
        if t.label in ACCOUNT_SCENARIOS:
            labels_by_account[t.account_id].add(t.label)
    atp = afp = afn = atn = 0
    acc_scn: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    acc_band: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for a in app.store.accounts():
        ra = monitoring.assess_account_activity(app.monitoring_context(a.account_id))
        positive = ra.level.rank >= RiskLevel.HIGH.rank
        fraud = a.account_id in labels_by_account
        if fraud and positive:
            atp += 1
        elif fraud:
            afn += 1
        elif positive:
            afp += 1
        else:
            atn += 1
        for lab in labels_by_account.get(a.account_id, ()):
            acc_scn[lab][1] += 1
            acc_scn[lab][0] += int(positive)
        acc_band[ra.level.value][1] += 1
        acc_band[ra.level.value][0] += int(fraud)

    # ---- merchant level: bad merchants (abused, shell or repeatedly flagged) should profile HIGH+
    abused = {
        s["entity_ids"][0] for s in app.store.scenarios() if s["scenario"] == "merchant_abuse"
    }
    for merchant in app.store.merchants():
        if merchant.registration_status == "shell" or merchant.prior_flags >= 2:
            abused.add(merchant.merchant_id)
    mtp = mfp = mfn = mtn = 0
    for merchant in app.store.merchants():
        prof = app.world.engine.merchant_risk(merchant.merchant_id)
        positive = prof.level.rank >= RiskLevel.HIGH.rank
        bad = merchant.merchant_id in abused
        if bad and positive:
            mtp += 1
        elif bad:
            mfn += 1
        elif positive:
            mfp += 1
        else:
            mtn += 1

    # policy-level outcomes on a sample (full pipeline, no agent)
    sample = [t for t, _ in rows[-policy_sample:]] if policy_sample else []
    fraud_allowed = legit_blocked = fraud_n = legit_n = 0
    outcomes: Counter[str] = Counter()
    for t in sample:
        d = app.evaluate_transaction(t, options=RunOptions(skip_agent=True, risk_model=m)).decision
        outcomes[d.final_action.value] += 1
        if t.label in TXN_SCENARIOS:
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
        "ground_truth": GROUND_TRUTH,
        "stages": {
            "screening": "transaction-level risk band on every transaction (transaction_level)",
            "decisioning": "policy outcome of the full pipeline on a sample (policy_sample)",
            "investigation_triage": "account-level monitoring over the account's activity (account_level)",
        },
        "transaction_level": {
            **_prf(tp, fp, fn, tn),
            "scenarios": list(TXN_SCENARIOS),
            "prevalence": round((tp + fn) / max(1, n), 4),
            "by_channel": _grp(by_channel),
            "by_account_segment": _grp(by_segment),
            "by_merchant_tier": _grp(by_tier),
            "miss_breakdown": {
                scn: {
                    "n": per_scn[scn][1],
                    "detected": per_scn[scn][0],
                    "missed": per_scn[scn][1] - per_scn[scn][0],
                    "dominant_signals_detected": dict(signal_hits[scn].most_common(6)),
                    "dominant_signals_missed": dict(signal_hits_missed[scn].most_common(6)),
                    "expected_signals": list(EXPECTED_SIGNALS.get(scn, ())),
                }
                for scn in sorted(per_scn)
            },
            "missed_examples": missed_rows[:40],
            "false_positive_examples": fp_rows[:20],
            "signal_stats": signal_stats,
            "family_stats": family_stats,
            "fraud_n": n_fraud_total,
            "legit_n": n_legit_total,
            "burst_by_position": burst,
        },
        "account_level": {
            **_prf(atp, afp, afn, atn),
            "scenarios": list(ACCOUNT_SCENARIOS),
            "recall_by_scenario": {
                k: {"n": v[1], "recall": round(v[0] / v[1], 3)} for k, v in sorted(acc_scn.items())
            },
            "calibration": {
                k: {"n": v[1], "observed_fraud_rate": round(v[0] / v[1], 4)}
                for k, v in acc_band.items()
            },
        },
        "merchant_level": {
            **_prf(mtp, mfp, mfn, mtn),
            "bad_merchants": len(abused),
            "definition": "abused (scenario) or shell registration or >= 2 prior flags",
        },
        **_prf(tp, fp, fn, tn),
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
    r["methodology"] = methodology("financial", r)
    write_json(out_dir, "financial.json", r)
    print(
        f"[financial] {r['dataset']['transactions']} synthetic transactions, model {r['risk_model']} ({r['seconds']}s)"
    )
    for level in ("transaction_level", "account_level", "merchant_level"):
        x = r[level]
        print(
            f"  {level:18} precision {pct(x['precision'])}  recall {pct(x['recall'])}  FPR {pct(x['false_positive_rate'])}  FNR {pct(x['false_negative_rate'])}  (tp {x['tp']} fp {x['fp']} fn {x['fn']} tn {x['tn']})"
        )
    print(
        "  transaction recall by scenario:",
        {k: v["recall"] for k, v in r["recall_by_scenario"].items()},
    )
    print(
        "  account recall by scenario:",
        {k: v["recall"] for k, v in r["account_level"]["recall_by_scenario"].items()},
    )
    print(
        "  calibration (fraud rate by band):",
        {k: v["observed_fraud_rate"] for k, v in r["calibration"].items()},
    )
    ps = r["policy_sample"]
    print(
        f"  policy sample n={ps['n']}: fraud allowed {pct(ps['fraud_allowed_rate'])}, legit blocked/denied {pct(ps['legit_blocked_or_denied_rate'])}"
    )
    for s, h in r["held_out_seeds"].items():
        for level in LEVELS:
            x = h[level]
            print(
                f"  held-out seed {s} {level:18} precision {pct(x['precision'])}  recall {pct(x['recall'])}  FPR {pct(x['false_positive_rate'])}  (tp {x['tp']} fp {x['fp']} fn {x['fn']} tn {x['tn']})"
            )
    return r


if __name__ == "__main__":
    main()
