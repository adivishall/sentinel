"""Generator chronology and realism, across seeds and scenario profiles.

A synthetic world is only a fair benchmark if (1) nothing happens before the entity it
needs existed or after the clock, and (2) no scenario is recognisable by a timing or
count the generator hard-coded rather than by behaviour. These properties are checked
on several seeds and profiles, not on the one world the benchmark happens to use."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

import pytest

from sentinel.data.generator import generate

WORLDS = [
    (1, "balanced"),
    (7, "fraud-heavy"),
    (42, "balanced"),
    (99, "attack-heavy"),
    (2024, "fraud-heavy"),
]


def _dt(s: str) -> datetime:
    return datetime.fromisoformat(s)


@pytest.fixture(scope="module", params=WORLDS, ids=lambda w: f"seed{w[0]}-{w[1]}")
def ds(request):
    seed, profile = request.param
    return generate(seed, 120, 24, 2500, profile=profile)


def test_every_record_happens_after_what_it_needs_and_before_the_clock(ds):
    idx = ds.by_id()
    registered = {m.merchant_id: m.registered_at for m in ds.merchants}
    opened = {a.account_id: a.opened_at for a in ds.accounts}
    seen = {d.device_id: d.first_seen for d in ds.devices}
    added = {i.instrument_id: i.added_at for i in ds.instruments}
    for t in ds.transactions:
        assert registered[t.merchant_id] <= t.timestamp <= ds.as_of, t.transaction_id
        assert opened[t.account_id] <= t.timestamp, t.transaction_id
        assert seen[t.device_id] <= t.timestamp and added[t.instrument_id] <= t.timestamp
    for d in ds.disputes:  # a dispute follows its (eligible) transaction and precedes the clock
        tx = idx["transaction"][d.transaction_id]
        assert tx.timestamp <= d.submitted_at <= ds.as_of, d.dispute_id
    assert len({d.transaction_id for d in ds.disputes}) == len(ds.disputes)
    for s in ds.sessions:
        assert opened[s.account_id] <= s.started_at <= ds.as_of
        assert seen[s.device_id] <= s.started_at
    for k in ds.kyb_applications:
        assert registered[k.merchant_id] <= k.submitted_at <= ds.as_of
    assert all(dev.first_seen <= ds.as_of for dev in ds.devices)


def test_dormant_accounts_really_were_silent(ds):
    for s in (s for s in ds.scenarios if s.scenario == "dormant_activation"):
        aid = s.entity_ids[0]
        burst = {e for e in s.entity_ids if e.startswith("TX-")}
        own = sorted(
            t.timestamp
            for t in ds.transactions
            if t.account_id == aid and t.transaction_id not in burst
        )
        first = min(t.timestamp for t in ds.transactions if t.transaction_id in burst)
        before = [x for x in own if x < first]
        if before:
            assert _dt(first) - _dt(before[-1]) >= timedelta(days=90), aid


def test_scenario_timings_and_counts_are_not_constants():
    """Pooled over worlds: the gap from the owner's last purchase to the takeover login,
    the takeover size, burst gaps and dormant sizes each take many values."""
    login_gaps, ato_sizes, burst_gaps, dormant_sizes = set(), set(), set(), set()
    for seed, profile in WORLDS:
        ds = generate(seed, 120, 24, 2500, profile=profile)
        tx = ds.by_id()["transaction"]
        for s in ds.scenarios:
            txs = sorted((tx[e] for e in s.entity_ids if e in tx), key=lambda t: t.timestamp)
            if s.scenario == "account_takeover":
                fraud = [t for t in txs if t.label == "fraud:account_takeover"]
                ato_sizes.add(len(fraud))
                logins = [
                    x for x in ds.sessions if x.account_id == s.entity_ids[0] and not x.mfa_passed
                ]
                if logins:
                    at = logins[-1].started_at
                    owner = [
                        t.timestamp
                        for t in ds.transactions
                        if t.account_id == s.entity_ids[0]
                        and t.label == "legit"
                        and t.timestamp < at
                    ]
                    if owner:
                        login_gaps.add(_dt(at) - _dt(max(owner)))
            if s.scenario == "transaction_burst":
                burst_gaps |= {
                    _dt(b.timestamp) - _dt(a.timestamp) for a, b in zip(txs, txs[1:], strict=False)
                }
            if s.scenario == "dormant_activation":
                dormant_sizes.add(len(txs))
    assert len(login_gaps) >= 5 and len(ato_sizes) >= 3, (login_gaps, ato_sizes)
    assert len(burst_gaps) >= 20 and len(dormant_sizes) >= 3, dormant_sizes


def test_fraud_timestamps_look_like_legitimate_ones(ds):
    """No label is recoverable from the clock: fraud is not on round minutes, not in one
    hour of the day, and seconds are spread like legitimate traffic."""
    fraud = [t for t in ds.transactions if t.label.startswith("fraud:")]
    legit = [t for t in ds.transactions if t.label == "legit"]
    assert fraud and legit
    on_minute = sum(t.timestamp.endswith(":00") for t in fraud) / len(fraud)
    assert on_minute < 0.2
    hours = Counter(_dt(t.timestamp).hour for t in fraud)
    assert hours.most_common(1)[0][1] / len(fraud) < 0.5
    assert len({_dt(t.timestamp).second for t in fraud}) >= min(20, len(fraud) // 2)


def test_legitimate_behaviour_varies(ds):
    by_acct: dict[str, list] = {}
    for t in ds.transactions:
        if t.label == "legit" and t.channel != "transfer":
            by_acct.setdefault(t.account_id, []).append(t)
    busy = [ts for ts in by_acct.values() if len(ts) >= 10]
    assert busy
    for ts in busy[:20]:
        amounts = [t.amount for t in ts]
        assert len(set(amounts)) > len(amounts) // 2  # amounts are not a constant
        assert len({_dt(t.timestamp).hour for t in ts}) >= 3  # not one fixed hour


def test_generation_is_deterministic():
    a, b = generate(5, 60, 12, 800), generate(5, 60, 12, 800)
    assert [t.transaction_id for t in a.transactions] == [t.transaction_id for t in b.transactions]
    assert [(t.timestamp, t.amount) for t in a.transactions] == [
        (t.timestamp, t.amount) for t in b.transactions
    ]
