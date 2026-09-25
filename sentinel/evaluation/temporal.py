"""Temporal-leakage benchmark: a decision at T1 must be a function of records at or
before T1 only.

Two measurements, both expected to be exactly 0 and reported as a named
data-integrity benchmark (``sentinel eval run --suite temporal``):

  A. Truncation equivalence. For a sample of transactions at T1, score each one
     against (i) the full dataset and (ii) a copy of the dataset truncated to
     records with timestamp <= T1. The feature snapshot, score and factors must
     be identical. Any difference means something after T1 leaked in.
  B. Future perturbation. Append synthetic events for the same account at
     T1 + 1 day, + 30 days and + 90 days -- a dispute, a burst of transactions
     on a new device, a circular transfer, a login with a payout change -- and
     score the T1 transaction and the account monitor at T1 again. Nothing may
     change.

Both use the application layer's real context builders, so they exercise the
store queries, the graph as-of filters and the entity engine together.
"""

from __future__ import annotations

import copy
import time
from datetime import timedelta
from typing import Any

from sentinel.app import SentinelApp
from sentinel.data.generator import Dataset, generate
from sentinel.domain.entities import Device, Dispute, LoginSession, Transaction
from sentinel.evaluation.common import write_json
from sentinel.risk import monitoring
from sentinel.risk import transaction as txn_risk
from sentinel.risk.behavioral import parse_ts

FUTURE_OFFSETS_DAYS = (1, 30, 90)


def _snapshot(app: SentinelApp, t: Transaction) -> dict[str, Any]:
    ra = txn_risk.assess_transaction(t, app.transaction_context(t))
    return {
        "score": ra.score,
        "level": ra.level.value,
        "factors": [(f.code, f.points) for f in ra.factors],
        "features": {k: v for k, v in ra.features.items() if k != "evidence_ids"},
    }


def _monitor(app: SentinelApp, account_id: str, as_of: str) -> dict[str, Any]:
    ra = monitoring.assess_account_activity(app.monitoring_context(account_id, as_of))
    return {
        "score": ra.score,
        "factors": [(f.code, f.points) for f in ra.factors],
        "features": {k: v for k, v in ra.features.items() if k != "evidence_ids"},
    }


def truncate(ds: Dataset, until: str) -> Dataset:
    """A copy of the dataset with every dated record after ``until`` removed."""
    out = copy.copy(ds)
    out.transactions = [t for t in ds.transactions if t.timestamp <= until]
    out.disputes = [d for d in ds.disputes if d.submitted_at <= until]
    out.sessions = [s for s in ds.sessions if s.started_at <= until]
    out.devices = [d for d in ds.devices if d.first_seen <= until]
    out.instruments = [i for i in ds.instruments if i.added_at <= until]
    out.account_devices = {
        a: [d for d in devs if d in {x.device_id for x in out.devices}]
        for a, devs in ds.account_devices.items()
    }
    return out


def perturb(ds: Dataset, account_id: str, t1: str, offsets_days: tuple[int, ...]) -> Dataset:
    """Append future events for ``account_id`` after ``t1``."""
    out = copy.copy(ds)
    out.transactions = list(ds.transactions)
    out.disputes = list(ds.disputes)
    out.sessions = list(ds.sessions)
    out.devices = list(ds.devices)
    base = parse_ts(t1)
    merchant = next(t.merchant_id for t in ds.transactions if t.account_id == account_id)
    instrument = next(t.instrument_id for t in ds.transactions if t.account_id == account_id)
    other = next(a.account_id for a in ds.accounts if a.account_id != account_id)
    for k, off in enumerate(offsets_days):
        when = base + timedelta(days=off)
        dev = Device(f"DEV-FUTURE-{k}", f"fp-future-{k}", when.isoformat(), "web")
        out.devices.append(dev)
        for j in range(8):  # a burst on a brand-new device
            out.transactions.append(
                Transaction(
                    f"TX-FUTURE-{k}-{j}",
                    account_id,
                    merchant,
                    instrument,
                    dev.device_id,
                    250_000,
                    "INR",
                    (when + timedelta(minutes=3 * j)).isoformat(),
                    "RO",
                    "ecommerce",
                    "none",
                    "delivered",
                    None,
                    "future:perturbation",
                )
            )
        out.transactions.append(  # a transfer that closes a cycle with another account
            Transaction(
                f"TX-FUTURE-{k}-cycle",
                account_id,
                merchant,
                instrument,
                dev.device_id,
                49_000,
                "INR",
                (when + timedelta(hours=1)).isoformat(),
                "IN",
                "transfer",
                "otp",
                "n/a",
                other,
                "future:perturbation",
            )
        )
        out.transactions.append(
            Transaction(
                f"TX-FUTURE-{k}-back",
                other,
                merchant,
                instrument,
                dev.device_id,
                49_000,
                "INR",
                (when + timedelta(hours=2)).isoformat(),
                "IN",
                "transfer",
                "otp",
                "n/a",
                account_id,
                "future:perturbation",
            )
        )
        out.disputes.append(
            Dispute(
                f"DSP-FUTURE-{k}",
                f"TX-FUTURE-{k}-0",
                account_id,
                250_000,
                (when + timedelta(days=2)).isoformat(),
                "non_receipt",
                "future:perturbation",
            )
        )
        out.sessions.append(
            LoginSession(
                f"SES-FUTURE-{k}",
                account_id,
                dev.device_id,
                "203.0.113.9",
                "RO",
                (when - timedelta(minutes=30)).isoformat(),
                mfa_passed=False,
                events=("credential_change", "payout_change"),
            )
        )
    out.transactions.sort(key=lambda t: t.timestamp)
    return out


def _sample(ds: Dataset, n: int) -> list[Transaction]:
    """Fraud-labelled and legitimate transactions spread across the timeline, chosen
    away from the dataset's edges so future events fit before ``as_of``."""
    txns = [t for t in ds.transactions if t.channel != "transfer"]
    fraud = [t for t in txns if t.label.startswith("fraud:")]
    legit = [t for t in txns if t.label == "legit"]
    step = max(1, len(legit) // max(1, n // 2))
    picked = fraud[: n // 2] + legit[::step][: n - n // 2]
    return sorted(picked, key=lambda t: t.timestamp)


def run(seed: int = 42, sample: int = 24) -> dict[str, Any]:
    t0 = time.time()
    ds = generate(seed, 120, 24, 2400)
    full = SentinelApp(persist=False)
    full.load_dataset(ds)
    picked = _sample(ds, sample)
    # A: truncation equivalence
    a_diff: list[dict[str, Any]] = []
    a_diff_fields: dict[str, int] = {}
    for t in picked:
        ref = _snapshot(full, t)
        trunc = SentinelApp(persist=False)
        trunc.load_dataset(truncate(ds, t.timestamp))
        got = _snapshot(trunc, t)
        if ref != got:
            fields = sorted(
                k for k in ref["features"] if ref["features"].get(k) != got["features"].get(k)
            )
            for k in fields:
                a_diff_fields[k] = a_diff_fields.get(k, 0) + 1
            a_diff.append(
                {
                    "transaction_id": t.transaction_id,
                    "full": (ref["score"], ref["factors"]),
                    "truncated": (got["score"], got["factors"]),
                    "fields": fields,
                }
            )
    # B: future perturbation
    b_txn_changed = b_mon_changed = 0
    b_examples: list[dict[str, Any]] = []
    for t in picked:
        ref_txn = _snapshot(full, t)
        ref_mon = _monitor(full, t.account_id, t.timestamp)
        pert = SentinelApp(persist=False)
        pert.load_dataset(perturb(ds, t.account_id, t.timestamp, FUTURE_OFFSETS_DAYS))
        got_txn = _snapshot(pert, t)
        got_mon = _monitor(pert, t.account_id, t.timestamp)
        if ref_txn != got_txn:
            b_txn_changed += 1
            b_examples.append({"transaction_id": t.transaction_id, "kind": "transaction"})
        if ref_mon != got_mon:
            b_mon_changed += 1
            b_examples.append({"transaction_id": t.transaction_id, "kind": "monitoring"})
    n = len(picked)
    return {
        "benchmark": "temporal-leakage",
        "dataset": {"seed": seed, "transactions": len(ds.transactions), "sample": n},
        "future_offsets_days": list(FUTURE_OFFSETS_DAYS),
        "truncation_mismatch_rate": round(len(a_diff) / max(1, n), 3),
        "truncation_mismatches": a_diff[:10],
        "truncation_mismatch_fields": a_diff_fields,
        "perturbation_transaction_change_rate": round(b_txn_changed / max(1, n), 3),
        "perturbation_monitoring_change_rate": round(b_mon_changed / max(1, n), 3),
        "perturbation_examples": b_examples[:10],
        "expected": "all rates 0.0: a decision at T1 reads only records at or before T1",
        "seconds": round(time.time() - t0, 1),
    }


def main(out_dir: str = "results") -> dict[str, Any]:
    r = run()
    write_json(out_dir, "temporal.json", r)
    print(
        f"[temporal] {r['dataset']['sample']} sampled transactions, seed {r['dataset']['seed']} ({r['seconds']}s)"
    )
    print(
        f"  truncation mismatch  {r['truncation_mismatch_rate'] * 100:5.1f}%   (full dataset vs dataset cut at T1)"
    )
    print(
        f"  future perturbation  txn {r['perturbation_transaction_change_rate'] * 100:5.1f}%   monitoring {r['perturbation_monitoring_change_rate'] * 100:5.1f}%   (events at T1+{'/'.join(str(d) for d in FUTURE_OFFSETS_DAYS)} days)"
    )
    if r["truncation_mismatch_fields"]:
        print("  leaking fields:", r["truncation_mismatch_fields"])
    return r


if __name__ == "__main__":
    main()
