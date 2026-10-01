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
     account_status   the account frozen after T1 (a current-state field)
     payout_change    new bank accounts added after T1 and the payout moved to one
     risk_assessment  stored HIGH risk assessments for the account, the merchant
                      and a future transaction
     security_event   stored CRITICAL AI-security events dated after T1

Both use the application layer's real context builders, so they exercise the
store queries, the graph as-of filters and the entity engine together. The
data is synthetic (the generator's seed-42 world); the benchmark is a
deterministic check over that world, not a proof over every possible record.
"""

from __future__ import annotations

import copy
import time
from dataclasses import replace
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
    PaymentInstrument,
    Transaction,
)
from sentinel.domain.enums import RiskLevel, Severity, ThreatClass, TrustClass
from sentinel.domain.risk import RiskAssessment, RiskFactor
from sentinel.domain.security import SecurityEvent
from sentinel.evaluation.common import write_json
from sentinel.evaluation.methodology import methodology
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
    "account_status": "the account frozen after T1 (a current-state field)",
    "payout_change": "new bank accounts added after T1 and the payout moved to one of them",
    "risk_assessment": "stored HIGH risk assessments for the account, the merchant and a future transaction",
    "security_event": "stored CRITICAL AI-security events dated after T1",
}
_STORED_KINDS = ("risk_assessment", "security_event")  # applied to the store after load


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
    out.instruments = list(ds.instruments)
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
        elif kind == "account_status":
            if k == 0:  # one status field: frozen from the earliest offset on
                out.accounts = [
                    (
                        replace(a, status="frozen", status_since=when.isoformat())
                        if a.account_id == account_id
                        else a
                    )
                    for a in out.accounts
                ]
                added += 1
        elif kind == "payout_change":
            ins = PaymentInstrument(
                f"INS-FUTURE-{tag}", account_id, "bank_account", "0000", when.isoformat()
            )
            out.instruments.append(ins)
            out.accounts = [
                (
                    replace(a, payout_instrument_id=ins.instrument_id)
                    if a.account_id == account_id
                    else a
                )
                for a in out.accounts
            ]
            added += 1
        elif kind in _STORED_KINDS:
            pass  # applied after load (stored records are not dataset records)
        else:
            raise ValueError(kind)
    out.transactions.sort(key=lambda t: t.timestamp)
    return out, added


def perturb_all(ds: Dataset, account_id: str, t1: str, offsets_days: tuple[int, ...]) -> Dataset:
    """Every dataset-level kind applied together (the per-feature tests use this)."""
    out = ds
    for kind in KINDS:
        if kind in _STORED_KINDS:
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


def _store_future_security_events(
    app: SentinelApp, t: Transaction, offsets_days: tuple[int, ...]
) -> int:
    base = parse_ts(t.timestamp)
    for k, off in enumerate(offsets_days):
        app.store.save_security_event(
            SecurityEvent(
                f"SEC-FUTURE-{k}",
                "transaction",
                "transaction",
                Severity.CRITICAL,
                (ThreatClass.DIRECT_INJECTION,),
                (),
                TrustClass.USER_CONTROLLED,
                "future",
                None,
                "approve",
                None,
                None,
                "BLOCK",
                decision_id=f"DEC-FUTURE-{t.account_id}-{k}",
                created_at=(base + timedelta(days=off)).isoformat(),
            )
        )
    return len(offsets_days)


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


def upper_95(failures: int, n: int) -> float | None:
    """One-sided 95% upper bound on a failure rate with ``failures`` in ``n`` trials:
    exact (Clopper-Pearson) for zero failures, ``1 - 0.05 ** (1 / n)``; otherwise
    ``None`` (report the observed rate and investigate -- a leak is a bug, not a rate)."""
    if n <= 0 or failures:
        return None
    return 1 - 0.05 ** (1 / n)


def _world(seed: int, sample: int) -> tuple[Dataset, SentinelApp, list[Transaction]]:
    ds = generate(seed, 120, 24, 2400)
    full = SentinelApp(persist=False)
    full.load_dataset(ds)
    return ds, full, _sample(ds, sample)


def run(
    seeds: tuple[int, ...] = (42, 7, 11, 23),
    sample: int = 128,
    kinds: tuple[str, ...] = tuple(KINDS),
) -> dict[str, Any]:
    """``sample`` transactions per seed. Every comparison is exact: a feature snapshot,
    score and factor list either match byte for byte or the case is a leak."""
    t0 = time.time()
    a_diff: list[dict[str, Any]] = []
    a_diff_fields: dict[str, int] = {}
    by_kind: dict[str, dict[str, Any]] = {
        k: {
            "description": KINDS[k],
            "n": 0,
            "future_records": 0,
            "transaction_changed": 0,
            "monitoring_changed": 0,
        }
        for k in kinds
    }
    b_examples: list[dict[str, Any]] = []
    datasets = []
    n_total = 0
    for seed in seeds:
        ds, full, picked = _world(seed, sample)
        datasets.append({"seed": seed, "transactions": len(ds.transactions), "sample": len(picked)})
        n_total += len(picked)
        # A: truncation equivalence
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
                        "seed": seed,
                        "transaction_id": t.transaction_id,
                        "full": (ref["score"], ref["factors"]),
                        "truncated": (got["score"], got["factors"]),
                        "fields": fields,
                    }
                )
        # B: future perturbation, one kind at a time
        for kind in kinds:
            row = by_kind[kind]
            for t in picked:
                ref_txn = _snapshot(full, t)
                ref_mon = _monitor(full, t.account_id, t.timestamp)
                pds, added = perturb(ds, t.account_id, t.timestamp, FUTURE_OFFSETS_DAYS, kind)
                pert = SentinelApp(persist=False)
                pert.load_dataset(pds)
                if kind == "risk_assessment":
                    added += _store_future_assessments(pert, t, FUTURE_OFFSETS_DAYS)
                if kind == "security_event":
                    added += _store_future_security_events(pert, t, FUTURE_OFFSETS_DAYS)
                row["n"] += 1
                row["future_records"] += added
                got_txn = _snapshot(pert, t)
                got_mon = _monitor(pert, t.account_id, t.timestamp)
                for check, ref, got in (
                    ("transaction", ref_txn, got_txn),
                    ("monitoring", ref_mon, got_mon),
                ):
                    if ref != got:
                        row[f"{check}_changed"] += 1
                        b_examples.append(
                            {
                                "seed": seed,
                                "transaction_id": t.transaction_id,
                                "kind": kind,
                                "check": check,
                                "fields": sorted(
                                    k
                                    for k in ref["features"]
                                    if ref["features"].get(k) != got["features"].get(k)
                                ),
                            }
                        )
    for row in by_kind.values():
        tested = 2 * row["n"]  # the transaction score and the account monitor, each sample
        leaks = row["transaction_changed"] + row["monitoring_changed"]
        row.update(
            {
                "tested": tested,
                "leakage_count": leaks,
                "leakage_rate": leaks / tested if tested else 0.0,
                "transaction_change_rate": row["transaction_changed"] / max(1, row["n"]),
                "monitoring_change_rate": row["monitoring_changed"] / max(1, row["n"]),
            }
        )
    comparisons = sum(r["n"] for r in by_kind.values())
    tested = sum(r["tested"] for r in by_kind.values()) + n_total  # + truncation checks
    leaks = sum(r["leakage_count"] for r in by_kind.values()) + len(a_diff)
    txn_changed = sum(r["transaction_changed"] for r in by_kind.values())
    mon_changed = sum(r["monitoring_changed"] for r in by_kind.values())
    return {
        "benchmark": "temporal-leakage",
        "dataset": {
            "seeds": list(seeds),
            "transactions": sum(d["transactions"] for d in datasets),
            "sample": n_total,
            "worlds": datasets,
        },
        "future_offsets_days": list(FUTURE_OFFSETS_DAYS),
        "kinds": list(kinds),
        "comparisons": comparisons,
        "decisions_tested": tested,
        "leakage_count": leaks,
        "leakage_rate": leaks / tested if tested else 0.0,
        "leakage_upper_95": upper_95(leaks, tested),
        "sample_leakage_upper_95": upper_95(len(a_diff), n_total),
        "future_records": sum(r["future_records"] for r in by_kind.values()),
        "truncation_mismatch_count": len(a_diff),
        "truncation_mismatch_rate": len(a_diff) / max(1, n_total),
        "truncation_mismatches": a_diff[:10],
        "truncation_mismatch_fields": a_diff_fields,
        "perturbation_transaction_change_rate": txn_changed / max(1, comparisons),
        "perturbation_monitoring_change_rate": mon_changed / max(1, comparisons),
        "perturbation_by_kind": by_kind,
        "perturbation_examples": b_examples[:10],
        "expected": "all counts 0: a decision at T1 reads only records at or before T1",
        "seconds": round(time.time() - t0, 1),
    }


def main(out_dir: str = "results", sample: int = 128) -> dict[str, Any]:
    r = run(sample=sample)
    r["methodology"] = methodology("temporal", r)
    write_json(out_dir, "temporal.json", r)
    d = r["dataset"]
    print(
        f"[temporal] seeds {d['seeds']}: {d['sample']} sampled transactions, "
        f"{r['decisions_tested']} decisions tested, {r['future_records']} future records "
        f"({r['seconds']}s)"
    )
    ub = r["leakage_upper_95"]
    print(
        f"  leakage {r['leakage_count']}/{r['decisions_tested']} = {r['leakage_rate']:.6f}"
        + (f"   (95% upper bound {ub:.4%})" if ub is not None else "   LEAK FOUND")
    )
    print(
        f"  truncation mismatch {r['truncation_mismatch_count']}/{d['sample']}   "
        "(full dataset vs dataset cut at T1)"
    )
    for kind, v in r["perturbation_by_kind"].items():
        print(
            f"    {kind:16} txn changed {v['transaction_changed']:3}/{v['n']}  monitoring changed "
            f"{v['monitoring_changed']:3}/{v['n']}  ({v['future_records']} records)"
        )
    if r["truncation_mismatch_fields"]:
        print("  leaking fields:", r["truncation_mismatch_fields"])
    for ex in r["perturbation_examples"]:
        print("  leak:", ex)
    return r


if __name__ == "__main__":
    main()
