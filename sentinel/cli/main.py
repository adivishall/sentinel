"""``sentinel`` -- the CLI. Every command calls the same SentinelApp the API
and console use.

    sentinel data generate --seed 42 --customers 500 --merchants 60 --transactions 20000
    sentinel analyze
    sentinel transaction evaluate TX-000123 | file.json
    sentinel dispute evaluate dispute.json | --id DSP-000001
    sentinel merchant evaluate application.json
    sentinel account evaluate SES-000001 | session.json
    sentinel investigation evaluate ACC-000001 --note "..."
    sentinel security attack --scenario document_injection [--unguarded]
    sentinel security evaluate "text" --agent dispute
    sentinel risk explain transaction TX-000123
    sentinel case list | case show CASE-... | case transition CASE-... INVESTIGATING | case decide CASE-... approve
    sentinel policy list | policy show dispute-refund --version 2 | policy evaluate ctx.json --policy dispute-refund
    sentinel audit verify | audit show ID | audit export audit.jsonl
    sentinel replay run DEC-... --policy-version 2 --risk-model txn-1.1 --rule review-critical-risk=70
    sentinel scenario list | scenario run account_takeover
    sentinel eval run --suite full
    sentinel bench
    sentinel serve --port 8000
    sentinel ui snapshot
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.domain.serialization import to_dict

DEFAULT_DB = os.environ.get("SENTINEL_DB", "data/sentinel.db")


def _app(args: argparse.Namespace) -> Any:
    from sentinel.app import SentinelApp

    path = getattr(args, "db", None) or DEFAULT_DB
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    app = SentinelApp.open(path)
    if app.store.count("transactions") == 0 and getattr(args, "command", "") not in ("data",):
        print(
            "[sentinel] empty store -> generating the default demo dataset (seed 42)",
            file=sys.stderr,
        )
        app.generate_dataset(42, 200, 40, 5000)
    return app


def _out(args: argparse.Namespace, obj: Any, text: str | None = None) -> None:
    if getattr(args, "json", False) or text is None:
        print(json.dumps(obj, indent=2, default=str))
    else:
        print(text)


def _decision_text(d: Any, extra: dict[str, Any] | None = None) -> str:
    lines = [
        f"Decision {d.decision_id}  [{d.workflow.value}]  subject {d.subject_type}:{d.subject_id}",
        f"  amount            ₹{d.amount:,}",
        f"  risk              {d.risk_score}/100 {d.risk_level.value}",
        f"  AI recommendation {d.ai_recommendation.recommended_action if d.ai_recommendation else 'n/a'} (MODEL_GENERATED)",
        f"  evidence          {d.evidence_verdict.value} ({d.contradiction_count} contradictions)",
        f"  security          {d.security_severity.value}",
        f"  policy            {d.policy.policy_id}@v{d.policy.version} -> {d.policy.outcome.value} {list(d.policy.matched_rules)}",
        f"  authorization     {d.authorization.status.value}: {d.authorization.reason}",
        f"  FINAL             {d.final_action.value}"
        + (f"  (executed {d.executed_capability.value})" if d.executed_capability else ""),
        f"  blocked by        {', '.join(d.blocked_by) or '-'}",
        f"  case / audit      {d.case_id or '-'} / {d.audit_event_id or '-'}",
    ]
    for k, v in (extra or {}).items():
        lines.append(f"  {k:<17} {v}")
    return "\n".join(lines)


def _load_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise SystemExit("expected a JSON object")
    return data


def _options(args: argparse.Namespace) -> Any:
    from sentinel.decision.workflows import RunOptions
    from sentinel.risk import scoring

    controls: frozenset[str] | None = frozenset() if getattr(args, "unguarded", False) else None
    kw: dict[str, Any] = {}
    if controls is not None:
        kw["controls"] = controls
    if getattr(args, "policy_version", None):
        kw["policy_version"] = args.policy_version
    if getattr(args, "risk_model", None):
        kw["risk_model"] = scoring.get_model(args.risk_model)
    if getattr(args, "hardened", False):
        kw["hardened"] = True
    if getattr(args, "no_agent", False):
        kw["skip_agent"] = True
    return RunOptions(**kw)


# ---- commands --------------------------------------------------------------------------------
def cmd_data(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.data_command == "generate":
        summary = app.generate_dataset(args.seed, args.customers, args.merchants, args.transactions)
        _out(args, summary, "\n".join(f"{k:<20} {v}" for k, v in summary.items()))
    elif args.data_command == "summary":
        _out(args, app.overview()["dataset"])
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    app = _app(args)
    n = app.analyze(
        transactions=args.transactions,
        disputes=args.disputes,
        applications=args.applications,
        sessions=args.sessions,
        accounts=args.accounts,
        skip_agent=args.no_agent,
    )
    _out(args, n, "analyzed: " + ", ".join(f"{k}={v}" for k, v in n.items()))
    return 0


def cmd_transaction(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.target.endswith(".json"):
        from sentinel.api import schemas as S

        data = _load_json(args.target)
        t = S.transaction(data if "transaction" in data else {"transaction": data})
        untrusted = S.untrusted_list(data, "untrusted")
        b = app.evaluate_transaction(t, untrusted=untrusted, options=_options(args))
    else:
        b = app.evaluate_transaction(args.target, options=_options(args))
    _out(
        args,
        to_dict(b.decision),
        _decision_text(
            b.decision,
            {
                "risk factors": "; ".join(
                    f"{f.points:+d} {f.label}" for f in (b.risk.factors if b.risk else ())
                )
                or "-"
            },
        ),
    )
    return 0


def cmd_dispute(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.id:
        b = app.evaluate_dispute("", dispute_id=args.id, options=_options(args))
    else:
        data = _load_json(args.file)
        docs = tuple(data.get("documents", [])) + (
            (data["document"],) if data.get("document") else ()
        )
        if data.get("messages"):
            b = app.evaluate_dispute_conversation(
                tuple(data["messages"]), data["ledger"], options=_options(args)
            )
        else:
            b = app.evaluate_dispute(
                data.get("narrative", data.get("submission", "")),
                data["ledger"],
                documents=docs,
                options=_options(args),
            )
    _out(
        args,
        to_dict(b.decision),
        _decision_text(b.decision, {"evidence": b.reconciliation.explanation}),
    )
    return 0


def cmd_merchant(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.id:
        b = app.evaluate_merchant("", application_id=args.id, options=_options(args))
    else:
        data = _load_json(args.file)
        docs = tuple(data.get("documents", [])) + (
            (data["document"],) if data.get("document") else ()
        )
        b = app.evaluate_merchant(
            data.get("application", ""),
            data["records"],
            merchant_id=data.get("merchant_id", ""),
            documents=docs,
            options=_options(args),
        )
    _out(
        args,
        to_dict(b.decision),
        _decision_text(b.decision, {"evidence": b.reconciliation.explanation}),
    )
    return 0


def cmd_account(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.target.endswith(".json"):
        from sentinel.api import schemas as S

        data = _load_json(args.target)
        s = S.login_session(data if "session" in data else {"session": data})
        b = app.evaluate_account(
            s,
            message=data.get("message"),
            requested_capability=S.capability(data, "requested_capability"),
            options=_options(args),
        )
    else:
        b = app.evaluate_account(args.target, message=args.message, options=_options(args))
    _out(args, to_dict(b.decision), _decision_text(b.decision))
    return 0


def cmd_investigation(args: argparse.Namespace) -> int:
    app = _app(args)
    b = app.evaluate_investigation(
        args.account_id, case_notes=tuple(args.note or ()), options=_options(args)
    )
    _out(
        args,
        to_dict(b.decision),
        _decision_text(
            b.decision,
            {
                "indicators": "; ".join(
                    f"{f.points:+d} {f.label}" for f in (b.risk.factors if b.risk else ())
                )
                or "-"
            },
        ),
    )
    return 0


def cmd_security(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.security_command == "attack":
        from sentinel.presets import ATTACKS

        if args.scenario == "list":
            for k, p in ATTACKS.items():
                print(f"{k:<30} {p.name:<32} {p.description}")
            return 0
        key = args.scenario.replace("-", "_")
        if key not in ATTACKS:
            raise SystemExit(
                f"unknown attack scenario {args.scenario!r}; try: {', '.join(ATTACKS)}"
            )
        sb = app.simulate_attack(
            key, narrative=args.text, document=args.document, options=_options(args)
        )
        if args.json:
            print(json.dumps(sb, indent=2, default=str))
            return 0
        print(f"Attack: {ATTACKS[key].name}")
        print("Attacker input:\n  " + (sb["attacker_input"] or "").replace("\n", "\n  "))
        if sb.get("attacker_document"):
            print("Attacker document:\n  " + sb["attacker_document"].replace("\n", "\n  "))
        print()
        for st in sb["stages"]:
            print(f"  {st['title']:<28} {st['value']}")
            print("        ↓")
        print(f"\n{sb['headline']}")
        return 0
    # evaluate
    from sentinel.domain.enums import TrustClass
    from sentinel.security.provenance import UntrustedContent

    trust = TrustClass(args.trust)
    res = app.evaluate_ai_security(
        (UntrustedContent(args.text, trust, args.source),),
        agent_key=args.agent,
        run_agent=not args.no_agent,
    )
    a = res.assessment
    _out(
        args,
        {
            "assessment": to_dict(a),
            "ai": to_dict(res.ai) if res.ai else None,
            "event": to_dict(res.event) if res.event else None,
        },
        f"severity {a.severity.value} score {a.score} classes {[t.value for t in a.threat_classes]}\nfindings: "
        + "; ".join(f"{f.signal}({f.weight})" for f in a.findings)
        + (f"\nAI: {res.ai.recommended_action} -> {res.ai.requested_capability}" if res.ai else ""),
    )
    return 0


def cmd_risk(args: argparse.Namespace) -> int:
    app = _app(args)
    r = app.entity_risk(args.entity_type, args.entity_id)
    if args.json:
        print(json.dumps(r, indent=2, default=str))
        return 0
    print(f"{args.entity_type} {args.entity_id}: {r['score']} / 100  {r['level']}")
    for f in sorted(r["factors"], key=lambda x: -x["points"]):
        print(f"  {f['points']:+3d}  {f['label']:<36} {f.get('detail', '')}")
    if r.get("linked_entities"):
        print("  linked:", ", ".join(r["linked_entities"][:8]))
    return 0


def cmd_case(args: argparse.Namespace) -> int:
    app = _app(args)
    from sentinel.domain.enums import CaseStatus

    if args.case_command == "list":
        rows = app.cases(args.status, args.limit)
        _out(
            args,
            [to_dict(c) for c in rows],
            "\n".join(
                f"{c.case_id:<20} {c.priority.value} {c.status.value:<14} {c.case_type.value:<20} {c.title}"
                for c in rows
            )
            or "no cases",
        )
    elif args.case_command == "show":
        c = app.case(args.case_id)
        if c is None:
            raise SystemExit("case not found")
        _out(args, to_dict(c), json.dumps(to_dict(c), indent=2, default=str))
    elif args.case_command == "transition":
        c = app.runtime.cases.transition(
            args.case_id, CaseStatus(args.status), actor=args.actor, note=args.note or ""
        )
        print(f"{c.case_id} -> {c.status.value}")
    elif args.case_command == "decide":
        c = app.runtime.cases.record_human_decision(
            args.case_id, reviewer=args.actor, outcome=args.outcome, note=args.note or ""
        )
        print(f"{c.case_id} -> {c.status.value} ({c.resolution})")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    app = _app(args)
    reg = app.runtime.policies
    if args.policy_command == "list":
        for p in reg.all():
            print(f"{p.key:<32} {p.workflow.value:<20} {len(p.rules)} rules  {p.description}")
    elif args.policy_command == "show":
        p = reg.get(args.policy_id, args.version)
        if args.json:
            print(json.dumps(p.to_dict(), indent=2))
        else:
            print(f"{p.key}  ({p.workflow.value})  {p.description}")
            for r in p.rules:
                print(f"  [{r.rule_id}] {r.describe()}  -- {r.reason}")
    elif args.policy_command == "evaluate":
        from sentinel.policy import evaluate

        ctx = _load_json(args.context)
        pol = reg.get(args.policy or str(ctx.pop("policy_id", "dispute-refund")), args.version)
        d = evaluate(pol, ctx)
        _out(
            args,
            to_dict(d),
            f"{pol.key} -> {d.outcome.value}\n" + "\n".join("  " + e for e in d.explanations),
        )
    elif args.policy_command == "validate":
        from sentinel.policy import load_policy

        p = load_policy(args.file)
        print(f"valid: {p.key} ({len(p.rules)} rules)")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.audit_command == "verify":
        v = app.verify_audit()
        _out(
            args,
            to_dict(v),
            f"audit chain: {'OK' if v.ok else 'TAMPERED'}  length={v.length}  head={v.head_hash[:16]}…"
            + ("" if v.ok else "\n  " + "\n  ".join(v.problems)),
        )
        return 0 if v.ok else 2
    if args.audit_command == "show":
        ev = app.audit_event(args.id)
        if ev is None:
            raise SystemExit("audit event not found")
        print(json.dumps(ev, indent=2, default=str))
    elif args.audit_command == "export":
        events = [e.to_dict() for e in app.runtime.audit.events()]
        with open(args.path, "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, sort_keys=True, separators=(",", ":"), default=str) + "\n")
        print(f"exported {len(events)} events -> {args.path}")
    elif args.audit_command == "list":
        for e in app.runtime.audit.events()[-args.limit :]:
            print(
                f"#{e.sequence:<5} {e.timestamp} {e.workflow:<20} {e.action:<22} {e.decision_id or '-':<20} {e.event_hash[:12]}"
            )
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    app = _app(args)
    from sentinel.domain.enums import Capability
    from sentinel.replay.engine import ReplayOverrides

    rules: dict[str, object] = {}
    for kv in args.rule or []:
        k, _, v = kv.partition("=")
        try:
            rules[k] = int(v)
        except ValueError:
            rules[k] = v
    ov = ReplayOverrides(
        args.policy_version,
        args.risk_model,
        rules,
        args.ai,
        Capability(args.ai_capability) if args.ai_capability else None,
        frozenset() if args.unguarded else None,
    )
    r = app.replay(args.decision_id, ov)
    payload = {
        "replay_id": r.replay_id,
        "decision_id": r.decision_id,
        "overrides": r.overrides,
        "original": r.original,
        "replayed": r.replayed,
        "changed": r.changed,
        "diffs": [to_dict(d) for d in r.diffs],
        "explanation": r.explanation,
        "policy_drift": r.policy_drift,
        "original_drift": r.original_drift,
    }
    _out(
        args,
        payload,
        f"Replay {r.replay_id} of {r.decision_id}\n  before: {r.original['final_action']} ({r.original['policy']}, risk {r.original['risk_score']})\n  after:  {r.replayed['final_action']} ({r.replayed['policy']}, risk {r.replayed['risk_score']})\n  {r.explanation}\n  diffs: "
        + (", ".join(f"{d.field}: {d.before} -> {d.after}" for d in r.diffs) or "none"),
    )
    return 0


def cmd_scenario(args: argparse.Namespace) -> int:
    app = _app(args)
    from sentinel.presets import SCENARIOS

    if args.scenario_command == "list":
        for k, s in SCENARIOS.items():
            print(f"{k:<24} {s.name:<36} expect: {s.expected}")
        return 0
    r = app.run_scenario(args.key, options=_options(args))
    if args.json:
        print(json.dumps(r, indent=2, default=str))
        return 0
    print(
        f"{r['scenario']['name']}: {r['scenario']['description']}\n  expected: {r['scenario']['expected']}"
    )
    for x in r["results"]:
        if x.get("final_action") is None:
            print(
                f"  {x['subject']:<28} risk {x['risk']['score']}/100 {x['risk']['level']}  "
                + "; ".join(f"{f['points']:+d} {f['label']}" for f in x["risk"]["factors"])
            )
        else:
            print(
                f"  {x['subject']:<28} {x['final_action']:<22} risk {x['risk_score']:>3} {x['risk_level']:<8} evidence {x['evidence_verdict']:<12} AI {x['ai_recommendation'] or '-':<16} case {x['case_id'] or '-'}"
            )
            if x.get("factors"):
                print("      " + "; ".join(x["factors"]))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from sentinel.evaluation.runner import run_suite

    res = run_suite(args.suite, out_dir=args.out, full=args.full)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from sentinel.evaluation.bench import main as bench_main

    bench_main(out_dir=args.out)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    app = _app(args)
    if args.analyze and app.store.count("decisions") == 0:
        print(
            "[sentinel] analyzing a slice of the dataset so the console has data...",
            file=sys.stderr,
        )
        app.analyze()
    from sentinel.api.server import serve

    serve(app, args.host, args.port)
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    app = _app(args)
    from sentinel.ui_snapshot import build_snapshot

    out = build_snapshot(app, args.out)
    print(f"wrote static console snapshot -> {out}")
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    print(f"sentinel {__version__}")
    return 0


# ---- parser ----------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel", description="Sentinel -- Financial Decision Security Infrastructure"
    )
    p.add_argument(
        "--db",
        default=None,
        help=f"SQLite store path (default {DEFAULT_DB}; ':memory:' for ephemeral)",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)

    def opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--unguarded", action="store_true", help="disable all controls (baseline behaviour)"
        )
        sp.add_argument("--hardened", action="store_true", help="use the hardened-prompt agent")
        sp.add_argument("--no-agent", action="store_true", help="skip the model call")
        sp.add_argument("--policy-version", type=int)
        sp.add_argument("--risk-model")

    d = sub.add_parser("data", help="synthetic dataset").add_subparsers(
        dest="data_command", required=True
    )
    g = d.add_parser("generate")
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--customers", type=int, default=500)
    g.add_argument("--merchants", type=int, default=60)
    g.add_argument("--transactions", type=int, default=20000)
    d.add_parser("summary")

    a = sub.add_parser(
        "analyze", help="run the engine over a slice of the dataset (populates the console)"
    )
    a.add_argument("--transactions", type=int, default=300)
    a.add_argument("--disputes", type=int, default=60)
    a.add_argument("--applications", type=int, default=30)
    a.add_argument("--sessions", type=int, default=60)
    a.add_argument("--accounts", type=int, default=20)
    a.add_argument("--no-agent", action="store_true")

    t = (
        sub.add_parser("transaction")
        .add_subparsers(dest="tx_command", required=True)
        .add_parser("evaluate")
    )
    t.add_argument("target", help="TX-id or a JSON file")
    opts(t)
    di = (
        sub.add_parser("dispute")
        .add_subparsers(dest="d_command", required=True)
        .add_parser("evaluate")
    )
    di.add_argument("file", nargs="?")
    di.add_argument("--id")
    opts(di)
    m = (
        sub.add_parser("merchant")
        .add_subparsers(dest="m_command", required=True)
        .add_parser("evaluate")
    )
    m.add_argument("file", nargs="?")
    m.add_argument("--id")
    opts(m)
    ac = (
        sub.add_parser("account")
        .add_subparsers(dest="a_command", required=True)
        .add_parser("evaluate")
    )
    ac.add_argument("target", help="SES-id or a JSON file")
    ac.add_argument("--message")
    opts(ac)
    inv = (
        sub.add_parser("investigation")
        .add_subparsers(dest="i_command", required=True)
        .add_parser("evaluate")
    )
    inv.add_argument("account_id")
    inv.add_argument("--note", action="append")
    opts(inv)

    sec = sub.add_parser("security").add_subparsers(dest="security_command", required=True)
    at = sec.add_parser("attack")
    at.add_argument("--scenario", default="document_injection", help="attack preset key, or 'list'")
    at.add_argument("--text", help="custom attacker text")
    at.add_argument("--document", help="custom attacker document")
    opts(at)
    se = sec.add_parser("evaluate")
    se.add_argument("text")
    se.add_argument("--agent", default="dispute")
    se.add_argument("--trust", default="USER_CONTROLLED")
    se.add_argument("--source", default="external")
    se.add_argument("--no-agent", action="store_true")

    rk = (
        sub.add_parser("risk")
        .add_subparsers(dest="risk_command", required=True)
        .add_parser("explain")
    )
    rk.add_argument(
        "entity_type", choices=["transaction", "account", "merchant", "device", "customer"]
    )
    rk.add_argument("entity_id")

    c = sub.add_parser("case").add_subparsers(dest="case_command", required=True)
    cl = c.add_parser("list")
    cl.add_argument("--status")
    cl.add_argument("--limit", type=int, default=50)
    c.add_parser("show").add_argument("case_id")
    ct = c.add_parser("transition")
    ct.add_argument("case_id")
    ct.add_argument("status")
    ct.add_argument("--actor", default="analyst")
    ct.add_argument("--note")
    cd = c.add_parser("decide")
    cd.add_argument("case_id")
    cd.add_argument("outcome", choices=["approve", "deny", "escalate"])
    cd.add_argument("--actor", default="reviewer")
    cd.add_argument("--note")

    po = sub.add_parser("policy").add_subparsers(dest="policy_command", required=True)
    po.add_parser("list")
    ps = po.add_parser("show")
    ps.add_argument("policy_id")
    ps.add_argument("--version", type=int)
    pe = po.add_parser("evaluate")
    pe.add_argument("context")
    pe.add_argument("--policy")
    pe.add_argument("--version", type=int)
    po.add_parser("validate").add_argument("file")

    au = sub.add_parser("audit").add_subparsers(dest="audit_command", required=True)
    au.add_parser("verify")
    au.add_parser("show").add_argument("id")
    au.add_parser("export").add_argument("path")
    au.add_parser("list").add_argument("--limit", type=int, default=20)

    rp = (
        sub.add_parser("replay")
        .add_subparsers(dest="replay_command", required=True)
        .add_parser("run")
    )
    rp.add_argument("decision_id")
    rp.add_argument("--policy-version", type=int)
    rp.add_argument("--risk-model")
    rp.add_argument("--rule", action="append", help="rule_id=value threshold override")
    rp.add_argument("--ai", help="override the recorded AI recommendation")
    rp.add_argument("--ai-capability")
    rp.add_argument("--unguarded", action="store_true")

    sc = sub.add_parser("scenario").add_subparsers(dest="scenario_command", required=True)
    sc.add_parser("list")
    sr = sc.add_parser("run")
    sr.add_argument("key")
    opts(sr)

    ev = sub.add_parser("eval").add_subparsers(dest="eval_command", required=True).add_parser("run")
    ev.add_argument(
        "--suite",
        default="full",
        choices=[
            "full",
            "security",
            "heldout",
            "kyb",
            "baselines",
            "ablation",
            "financial",
            "integrity",
            "performance",
            "models",
            "charts",
        ],
    )
    ev.add_argument("--out", default="results")
    ev.add_argument("--full", action="store_true", help="larger financial dataset")

    b = sub.add_parser("bench")
    b.add_argument("--out", default="results")

    sv = sub.add_parser("serve")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    sv.add_argument(
        "--analyze", action="store_true", help="run analyze first if the store has no decisions"
    )

    ui = (
        sub.add_parser("ui").add_subparsers(dest="ui_command", required=True).add_parser("snapshot")
    )
    ui.add_argument("--out", default="ui/snapshot.json")

    sub.add_parser("version")
    return p


COMMANDS = {
    "data": cmd_data,
    "analyze": cmd_analyze,
    "transaction": cmd_transaction,
    "dispute": cmd_dispute,
    "merchant": cmd_merchant,
    "account": cmd_account,
    "investigation": cmd_investigation,
    "security": cmd_security,
    "risk": cmd_risk,
    "case": cmd_case,
    "policy": cmd_policy,
    "audit": cmd_audit,
    "replay": cmd_replay,
    "scenario": cmd_scenario,
    "eval": cmd_eval,
    "bench": cmd_bench,
    "serve": cmd_serve,
    "ui": cmd_ui,
    "version": cmd_version,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except (ValueError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
