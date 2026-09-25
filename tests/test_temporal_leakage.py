"""Temporal-leakage tests: a decision at T1 reads only records at or before T1.

These parameterise the named benchmark (``sentinel eval run --suite temporal``)
over seeds and future offsets so a regression that lets future information
into a historical score fails here, not in an evaluation run."""

from __future__ import annotations

import pytest

from sentinel.app import SentinelApp
from sentinel.data.generator import generate
from sentinel.evaluation import temporal
from sentinel.risk import monitoring
from sentinel.risk import transaction as txn_risk


@pytest.fixture(scope="module")
def world():
    ds = generate(11, 80, 16, 1400)
    app = SentinelApp(persist=False)
    app.load_dataset(ds)
    picked = temporal._sample(ds, 8)
    return ds, app, picked


def _txn_view(app, t):
    ra = txn_risk.assess_transaction(t, app.transaction_context(t))
    return (
        ra.score,
        [(f.code, f.points) for f in ra.factors],
        {k: v for k, v in ra.features.items() if k != "evidence_ids"},
    )


def test_truncated_dataset_reproduces_every_sampled_score(world):
    ds, app, picked = world
    for t in picked:
        trunc = SentinelApp(persist=False)
        trunc.load_dataset(temporal.truncate(ds, t.timestamp))
        assert _txn_view(app, t) == _txn_view(trunc, t), t.transaction_id


@pytest.mark.parametrize("offsets", [(1,), (30,), (90,), (1, 30, 90)])
def test_future_events_never_change_a_historical_decision(world, offsets):
    ds, app, picked = world
    for t in picked[:4]:
        ref = _txn_view(app, t)
        mon_ref = monitoring.assess_account_activity(
            app.monitoring_context(t.account_id, t.timestamp)
        )
        pert = SentinelApp(persist=False)
        pert.load_dataset(temporal.perturb_all(ds, t.account_id, t.timestamp, offsets))
        assert _txn_view(pert, t) == ref, (t.transaction_id, offsets)
        mon = monitoring.assess_account_activity(pert.monitoring_context(t.account_id, t.timestamp))
        assert (mon.score, mon.factors) == (mon_ref.score, mon_ref.factors), (
            t.transaction_id,
            offsets,
        )
        # the future events ARE visible once the clock moves past them
        later = pert.store.transaction("TX-FUTURE-device_burst-0-3")
        assert later is not None and later.label == "future:perturbation"
        after = txn_risk.assess_transaction(later, pert.transaction_context(later))
        assert {"new_device", "rapid_fire"} <= {f.code for f in after.factors}


def test_entity_profiles_as_of_are_unaffected_by_future_records(world):
    ds, app, picked = world
    for t in picked[:4]:
        eng = app.world.engine
        before = (
            eng.merchant_risk(t.merchant_id, as_of=t.timestamp),
            eng.account_risk(t.account_id, as_of=t.timestamp),
            eng.device_risk(t.device_id, as_of=t.timestamp),
        )
        pert = SentinelApp(persist=False)
        pert.load_dataset(temporal.perturb_all(ds, t.account_id, t.timestamp, (1, 30)))
        peng = pert.world.engine
        after = (
            peng.merchant_risk(t.merchant_id, as_of=t.timestamp),
            peng.account_risk(t.account_id, as_of=t.timestamp),
            peng.device_risk(t.device_id, as_of=t.timestamp),
        )
        assert [(p.score, p.factors, p.linked_entities) for p in before] == [
            (p.score, p.factors, p.linked_entities) for p in after
        ]


def test_generator_never_dates_a_record_before_its_account_or_device_existed():
    ds = generate(5, 70, 14, 1200)
    opened = {a.account_id: a.opened_at for a in ds.accounts}
    seen = {d.device_id: d.first_seen for d in ds.devices}
    added = {i.instrument_id: i.added_at for i in ds.instruments}
    for t in ds.transactions:
        assert t.timestamp >= opened[t.account_id], t.transaction_id
        assert t.timestamp >= seen[t.device_id], t.transaction_id
        assert t.timestamp >= added[t.instrument_id], t.transaction_id
    for s in ds.sessions:
        assert s.started_at >= opened[s.account_id] and s.started_at >= seen[s.device_id]


def test_benchmark_reports_zero_leakage():
    r = temporal.run(seed=3, sample=10)
    assert r["truncation_mismatch_rate"] == 0.0, r["truncation_mismatches"]
    assert r["perturbation_transaction_change_rate"] == 0.0
    assert r["perturbation_monitoring_change_rate"] == 0.0
