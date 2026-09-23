"""Build a static snapshot of the console's data (computed by the real engine)
so the GitHub Pages demo can render read-only without a backend. The live
console (``sentinel serve``) never uses it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.domain.serialization import to_dict
from sentinel.presets import ATTACKS, SCENARIOS


def build_snapshot(app: Any, out: str = "ui/snapshot.json") -> str:
    if app.store.count("decisions") == 0:
        app.analyze(transactions=200, disputes=40, applications=20, sessions=40, accounts=12)
    from sentinel.api.server import (
        _account_view,
        _decision_view,
        _evaluations,
        _merchant_view,
        _texts,
    )

    tx_rows = app.store.transactions(limit=100)
    latest = {d["subject_id"]: d for d in app.store.decisions(workflow="transaction", limit=2000)}
    transactions = [
        {
            **to_dict(t),
            "decision": (
                {
                    k: latest[t.transaction_id].get(k)
                    for k in ("decision_id", "final_action", "risk_score", "risk_level", "case_id")
                }
                if t.transaction_id in latest
                else None
            ),
        }
        for t in tx_rows
    ]
    tx_views = {t.transaction_id: app.transaction_view(t.transaction_id) for t in tx_rows[:24]}
    cases = [to_dict(c) for c in app.cases(limit=100)]
    attacks = {k: app.simulate_attack(k) for k in ATTACKS}
    scenarios = {k: app.run_scenario(k) for k in SCENARIOS}
    accounts = app.store.accounts()[:60]
    merchants = app.store.merchants()[:60]
    snap = {
        "generated_by": "sentinel ui snapshot (real engine output, static copy)",
        "system": app.system_info(),
        "overview": app.overview(),
        "transactions": {"transactions": transactions, "total": app.store.count("transactions")},
        "transaction_views": tx_views,
        "disputes": {
            "disputes": [
                {**to_dict(d), **_texts(app, d.dispute_id), "decision": None}
                for d in app.store.disputes(limit=60)
            ]
        },
        "merchants": {
            "merchants": [
                {**to_dict(m), "risk": to_dict(app.world.engine.merchant_risk(m.merchant_id))}
                for m in merchants
            ]
        },
        "merchant_views": {
            m.merchant_id: _merchant_view(app, m.merchant_id) for m in merchants[:12]
        },
        "accounts": {
            "accounts": [
                {**to_dict(a), "risk": to_dict(app.world.engine.account_risk(a.account_id))}
                for a in accounts
            ]
        },
        "account_views": {a.account_id: _account_view(app, a.account_id) for a in accounts[:12]},
        "cases": {"cases": cases},
        "case_views": {
            c["case_id"]: {
                "case": c,
                "decisions": [
                    app.store.decision(d) for d in c["decision_ids"] if app.store.decision(d)
                ],
                "security_events": [],
            }
            for c in cases[:40]
        },
        "security_events": {"events": app.store.security_events(100)},
        "policies": {"policies": [p.to_dict() for p in app.runtime.policies.all()]},
        "audit": {
            "events": [e.to_dict() for e in app.runtime.audit.events()[-100:]][::-1],
            "head": app.runtime.audit.head,
            "length": len(app.runtime.audit),
        },
        "audit_verify": to_dict(app.verify_audit()),
        "decisions": {"decisions": app.store.decisions(limit=200)},
        "decision_views": {
            d["decision_id"]: _decision_view(app, d["decision_id"])
            for d in app.store.decisions(limit=40)
        },
        "replays": {"replays": app.store.replays(50)},
        "attacks": {"attacks": [to_dict(a) for a in ATTACKS.values()]},
        "attack_results": attacks,
        "scenarios": {
            "scenarios": [to_dict(s) for s in SCENARIOS.values()],
            "tags": app.store.scenarios(),
        },
        "scenario_results": scenarios,
        "evaluations": _evaluations(),
    }
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(snap, default=str))
    return out
