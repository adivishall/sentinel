"""Temporal-leakage benchmark: a decision at T1 must be a function of records at or
before T1 only (``sentinel eval run --suite temporal``).

Two measurements, both expected to be exactly 0 and reported as a named
data-integrity benchmark:

  A. Truncation equivalence. For a stratified sample of transactions at T1, score
     each one against (i) the full dataset and (ii) a copy of the dataset truncated
     to records with timestamp <= T1. The feature snapshot, score and factors must
     be identical. Any difference means something after T1 leaked in.
  B. Future perturbation, one kind at a time. For the same sample, append future
     records for the account at T1 + 1, 7, 30 and 90 days -- separately for each
     kind below -- and score the T1 transaction and the account monitor at T1
     again. Nothing may change, and the report says which kind would have leaked.

     dispute          a dispute filed on the account's latest earlier purchase
     device_burst     a new device and an eight-purchase burst abroad on it
     merchant         a new flagged high-risk merchant and five purchases there
     graph            a new account on the same payout instrument and a circular
                      transfer through it
     session          a login with credential and payout changes that failed MFA
     risk_assessment  stored HIGH risk assessments for the account, the merchant
                      and a future transaction

Both use the application layer's real context builders, so they exercise the
store queries, the graph as-of filters and the entity engine together. The
data is synthetic (the generator's seed-42 world); the benchmark is a
deterministic check over that world, not a proof over every possible record.
"""

from __future__ import annotations

import copy
import time
from datetime import timedelta
from typing import Any

from sentinel.app import SentinelApp
from sentinel.data.generator import Dataset, generate
from sentinel.domain.entities import (
    Account,
    Device,
    Dispute,
    LoginSession,
    Merchant,
    Transaction,
)
from sentinel.domain.enums import RiskLevel
from sentinel.domain.risk import RiskAssessment, RiskFactor
from sentinel.evaluation.common import write_json
from sentinel.risk import monitoring
from sentinel.risk import transaction as txn_risk
from sentinel.risk.behavioral import parse_ts

FUTURE_OFFSETS_DAYS = (1, 7, 30, 90)
KINDS: dict[str, str] = {
    "dispute": "a dispute filed on the account's latest earlier purchase",
    "device_burst": "a new device and an eight-purchase burst abroad on it",
    "merchant": "a new flagged high-risk merchant and five purchases there",
    "graph": "a new account on the same payout instrument and a circular transfer through it",
    "session": "a login with credential and payout changes that failed MFA",
    "risk_assessment": "stored HIGH risk assessments for the account, the merchant and a future transaction",
}


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


def _copy(ds: Dataset) -> Dataset:
    out = copy.copy(ds)
    out.transactions = list(ds.transactions)
    out.disputes = list(ds.disputes)
    out.sessions = list(ds.sessions)
    out.devices = list(ds.devices)
    out.merchants = list(ds.merchants)
    out.accounts = list(ds.accounts)
    return out


def _txn(
    tid: str,
    account: str,
    merchant: str,
    instrument: str,
    device: str,
    when: str,
    *,
    amount: int = 250_000,
    country: str = "RO",
    channel: str = "ecommerce",
    auth_strength: str = "none",
    delivery_status: str = "delivered",
    counterparty_account_id: str | None = None,
) -> Transaction:
    return Transaction(
        tid,
        account,
        merchant,
        instrument,
        device,
        amount,
        "INR",
        when,
        country,
        channel,
        auth_strength,
        delivery_status,
        counterparty_account_id,
        "future:perturbation",
    )


def perturb(
    ds: Dataset, account_id: str, t1: str, offsets_days: tuple[int, ...], kind: str
) -> tuple[Dataset, int]:
    """Append future events of one ``kind`` for ``account_id`` after ``t1``. Returns the
    dataset copy and the number of records added."""
    out = _copy(ds)
    base = parse_ts(t1)
    own = [t for t in ds.transactions if t.account_id == account_id]
    merchant = own[0].merchant_id
    instrument = own[0].instrument_id
    device = own[0].device_id
    earlier = [t for t in own if t.timestamp <= t1]
    last_before = earlier[-1] if earlier else own[0]
    other = next(a.account_id for a in ds.accounts if a.account_id != account_id)
    acct = next(a for a in ds.accounts if a.account_id == account_id)
    added = 0
    for k, off in enumerate(offsets_days):
        when = base + timedelta(days=off)
        tag = f"{kind}-{k}"
        if kind == "dispute":
            out.disputes.append(
                Dispute(
                    f"DSP-FUTURE-{tag}",
                    last_before.transaction_id,
                    account_id,
                    last_before.amount,
                    when.isoformat(),
                    "non_receipt",
                    "future:perturbation",
                )
            )
            added += 1
        elif kind == "device_burst":
            dev = Device(f"DEV-FUTURE-{tag}", f"fp-future-{tag}", when.isoformat(), "web")
            out.devices.append(dev)
            added += 1
            for j in range(8):
                out.transactions.append(
                    _txn(
                        f"TX-FUTURE-{tag}-{j}",
                        account_id,
                        merchant,
                        instrument,
                        dev.device_id,
                        (when + timedelta(minutes=3 * j)).isoformat(),
                    )
                )
                added += 1
        elif kind == "merchant":
            m = Merchant(
                f"MER-FUTURE-{tag}",
                "Future Ltd",
                "7995",
                "high",
                "IN",
                f"OWN-FUTURE-{tag}",
                f"future-{tag}.example",
                when.isoformat(),
                "shell",
                3,
            )
            out.merchants.append(m)
            added += 1
            for j in range(5):
                out.transactions.append(
                    _txn(
                        f"TX-FUTURE-{tag}-{j}",
                        account_id,
                        m.merchant_id,
                        instrument,
                        device,
                        (when + timedelta(hours=j)).isoformat(),
                        country="IN",
                        auth_strength="otp",
                        amount=9_000,
                    )
                )
                added += 1
        elif kind == "graph":
            twin = Account(
                f"ACC-FUTURE-{tag}",
                acct.customer_id,
                when.isoformat(),
                "active",
                acct.payout_instrument_id,
                False,
            )
            out.accounts.append(twin)
            added += 1
            out.transactions.append(
                _txn(
                    f"TX-FUTURE-{tag}-cycle",
                    account_id,
                    merchant,
                    instrument,
                    device,
                    (when + timedelta(hours=1)).isoformat(),
                    amount=49_000,
                    country="IN",
                    channel="transfer",
                    auth_strength="otp",
                    delivery_status="n/a",
                    counterparty_account_id=other,
                )
            )
            out.transactions.append(
                _txn(
                    f"TX-FUTURE-{tag}-back",
                    other,
                    merchant,
                    instrument,
                    device,
                    (when + timedelta(hours=2)).isoformat(),
                    amount=49_000,
                    country="IN",
                    channel="transfer",
                    auth_strength="otp",
                    delivery_status="n/a",
                    counterparty_account_id=account_id,
                )
            )
            added += 2
        elif kind == "session":
            out.sessions.append(
                LoginSession(
                    f"SES-FUTURE-{tag}",
                    account_id,
                    device,
                    "203.0.113.9",
                    "RO",
                    when.isoformat(),
                    mfa_passed=False,
                    events=("credential_change", "payout_change"),
                )
            )
            added += 1
        elif kind == "risk_assessment":
            pass  # applied after load (stored assessments are not dataset records)
        else:
            raise ValueError(kind)
    out.transactions.sort(key=lambda t: t.timestamp)
    return out, added


def perturb_all(ds: Dataset, account_id: str, t1: str, offsets_days: tuple[int, ...]) -> Dataset:
    """Every dataset-level kind applied together (the per-feature tests use this)."""
    out = ds
    for kind in KINDS:
        if kind == "risk_assessment":
            continue
        out, _ = perturb(out, account_id, t1, offsets_days, kind)
    return out


def _store_future_assessments(
    app: SentinelApp, t: Transaction, offsets_days: tuple[int, ...]
) -> int:
    """Persist HIGH assessments dated after T1 for the account, the merchant and a
    future transaction id; the context builders must never read them."""
    base = parse_ts(t.timestamp)
    n = 0
    for k, off in enumerate(offsets_days):
        when = (base + timedelta(days=off)).isoformat()
        for etype, eid in (
            ("account", t.account_id),
            ("merchant", t.merchant_id),
            ("transaction", f"TX-FUTURE-ra-{k}"),
        ):
            app.store.save_risk_assessment(
                RiskAssessment(
                    f"RISK-FUTURE-{etype}-{k}",
                    etype,
                    eid,
                    90,
                    RiskLevel.CRITICAL,
                    (RiskFactor("future", "future signal", 90, "perturbation"),),
                    "BLOCK",
                    "future-1.0",
                    {},
                    when,
                )
            )
            n += 1
    return n


def _sample(ds: Dataset, n: int) -> list[Transaction]:
    """Fraud-labelled and legitimate transactions spread across the timeline."""
    txns = [t for t in ds.transactions if t.channel != "transfer"]
    fraud = [t for t in txns if t.label.startswith("fraud:")]
    legit = [t for t in txns if t.label == "legit"]
    half = n // 2
    fstep = max(1, len(fraud) // max(1, half))
    lstep = max(1, len(legit) // max(1, n - half))
    picked = fraud[::fstep][:half] + legit[::lstep][: n - half]
    return sorted(picked, key=lambda t: t.timestamp)


def run(seed: int = 42, sample: int = 96, kinds: tuple[str, ...] = tuple(KINDS)) -> dict[str, Any]:
    t0 = time.time()
    ds = generate(seed, 120, 24, 2400)
    full = SentinelApp(persist=False)
    full.load_dataset(ds)
    picked = _sample(ds, sample)
    n = len(picked)
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
    # B: future perturbation, one kind at a time
    by_kind: dict[str, dict[str, Any]] = {}
    b_examples: list[dict[str, Any]] = []
    total_records = 0
    b_txn_changed = b_mon_changed = 0
    for kind in kinds:
        txn_changed = mon_changed = records = 0
        for t in picked:
            ref_txn = _snapshot(full, t)
            ref_mon = _monitor(full, t.account_id, t.timestamp)
            pds, added = perturb(ds, t.account_id, t.timestamp, FUTURE_OFFSETS_DAYS, kind)
            pert = SentinelApp(persist=False)
            pert.load_dataset(pds)
            if kind == "risk_assessment":
                added += _store_future_assessments(pert, t, FUTURE_OFFSETS_DAYS)
            records += added
            got_txn = _snapshot(pert, t)
            got_mon = _monitor(pert, t.account_id, t.timestamp)
            if ref_txn != got_txn:
                txn_changed += 1
                b_examples.append(
                    {"transaction_id": t.transaction_id, "kind": kind, "check": "transaction"}
                )
            if ref_mon != got_mon:
                mon_changed += 1
                b_examples.append(
                    {"transaction_id": t.transaction_id, "kind": kind, "check": "monitoring"}
                )
        by_kind[kind] = {
            "description": KINDS[kind],
            "n": n,
            "future_records": records,
            "transaction_changed": txn_changed,
            "monitoring_changed": mon_changed,
            "transaction_change_rate": round(txn_changed / max(1, n), 3),
            "monitoring_change_rate": round(mon_changed / max(1, n), 3),
        }
        total_records += records
        b_txn_changed += txn_changed
        b_mon_changed += mon_changed
    comparisons = n * len(kinds)
    return {
        "benchmark": "temporal-leakage",
        "dataset": {"seed": seed, "transactions": len(ds.transactions), "sample": n},
        "future_offsets_days": list(FUTURE_OFFSETS_DAYS),
        "kinds": list(kinds),
        "comparisons": comparisons,
        "future_records": total_records,
        "truncation_mismatch_rate": round(len(a_diff) / max(1, n), 3),
        "truncation_mismatches": a_diff[:10],
        "truncation_mismatch_fields": a_diff_fields,
        "perturbation_transaction_change_rate": round(b_txn_changed / max(1, comparisons), 3),
        "perturbation_monitoring_change_rate": round(b_mon_changed / max(1, comparisons), 3),
        "perturbation_by_kind": by_kind,
        "perturbation_examples": b_examples[:10],
        "expected": "all rates 0.0: a decision at T1 reads only records at or before T1",
        "methodology": {
            "kind": "structural (synthetic data)",
            "sample": n,
            "seed": seed,
            "method": (
                "each sampled transaction is re-scored with the dataset truncated to its timestamp, "
                "then with one kind of future record appended at every offset; the feature "
                "snapshot, score and factors must be byte-identical; the account monitor at T1 "
                "is checked the same way"
            ),
            "limitations": (
                "a deterministic spot check over the generator's world (stratified sample, "
                "six record kinds, four offsets applied together per kind); the per-feature "
                "tests cover the mechanisms, but this is not a proof over every record"
            ),
        },
        "seconds": round(time.time() - t0, 1),
    }


def main(out_dir: str = "results", sample: int = 96) -> dict[str, Any]:
    r = run(sample=sample)
    write_json(out_dir, "temporal.json", r)
    print(
        f"[temporal] {r['dataset']['sample']} sampled transactions, {r['comparisons']} perturbation "
        f"comparisons, {r['future_records']} future records, seed {r['dataset']['seed']} ({r['seconds']}s)"
    )
    print(
        f"  truncation mismatch  {r['truncation_mismatch_rate'] * 100:5.1f}%   (full dataset vs dataset cut at T1)"
    )
    print(
        f"  future perturbation  txn {r['perturbation_transaction_change_rate'] * 100:5.1f}%   monitoring {r['perturbation_monitoring_change_rate'] * 100:5.1f}%   (events at T1+{'/'.join(str(d) for d in FUTURE_OFFSETS_DAYS)} days)"
    )
    for kind, v in r["perturbation_by_kind"].items():
        print(
            f"    {kind:16} txn changed {v['transaction_changed']:3}/{v['n']}  monitoring changed {v['monitoring_changed']:3}/{v['n']}  ({v['future_records']} records)"
        )
    if r["truncation_mismatch_fields"]:
        print("  leaking fields:", r["truncation_mismatch_fields"])
    return r


if __name__ == "__main__":
    main()
