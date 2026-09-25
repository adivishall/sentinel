"""Build a static snapshot of the console's data (computed by the real engine)
so the GitHub Pages demo can render read-only without a backend. The live
console (``sentinel serve``) never uses it.

Every payload here comes from the same ``SentinelApp`` builders and API view
helpers the routes call, so the static copy cannot drift from the live API."""

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
    from sentinel.policy import lint
    from sentinel.security.capabilities import matrix

    transactions = app.transaction_list(limit=100)
    merchants = app.merchant_list(60)
    accounts = app.account_list(60)
    cases = [to_dict(c) for c in app.cases(limit=100)]
    attacks = {k: app.simulate_attack(k) for k in ATTACKS}
    compare = {k: app.simulate_attack(k, compare=True) for k in ATTACKS}
    scenarios = {k: app.run_scenario(k) for k in SCENARIOS}

    snap = {
        "generated_by": "sentinel ui snapshot (real engine output, static copy)",
        "system": app.system_info(),
        "overview": app.overview(),
        "transactions": transactions,
        "transaction_views": {
            t["transaction_id"]: app.transaction_view(t["transaction_id"])
            for t in transactions["transactions"][:24]
        },
        "disputes": {
            "disputes": [
                {**to_dict(d), **_texts(app, d.dispute_id), "decision": None}
                for d in app.store.disputes(limit=60)
            ]
        },
        "merchants": merchants,
        "merchant_views": {
            m["merchant_id"]: _merchant_view(app, m["merchant_id"])
            for m in merchants["merchants"][:12]
        },
        "accounts": accounts,
        "account_views": {
            a["account_id"]: _account_view(app, a["account_id"]) for a in accounts["accounts"][:12]
        },
        "cases": {"cases": cases},
        "case_views": {c["case_id"]: app.case_view(c["case_id"]) for c in cases[:40]},
        "case_reviews": {c["case_id"]: app.review_packet(c["case_id"]) for c in cases[:40]},
        "capabilities": {
            "capabilities": matrix(),
            "invariant": "no AI actor may execute a consequential capability; SKIP_REVIEW has no actor",
        },
        "policy_lint": {p.key: lint(p) for p in app.runtime.policies.all()},
        "attack_compare": compare,
        "security_events": {"events": app.store.security_events(100)},
        "policies": {"policies": [p.to_dict() for p in app.runtime.policies.all()]},
        "audit": {
            "events": [e.to_dict() for e in app.runtime.audit.tail(100)][::-1],
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
        "attacks": app.attack_catalog(),
        "attack_results": attacks,
        "scenarios": app.scenario_catalog(),
        "scenario_results": scenarios,
        "evaluations": _evaluations(),
    }
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(snap, default=str))
    return out
