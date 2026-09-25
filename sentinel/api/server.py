"""Sentinel HTTP API -- versioned, typed, dependency-free.

    GET  /health   GET /version   GET /v1/system   GET /v1/overview
    POST /v1/transactions/evaluate   /v1/disputes/evaluate   /v1/merchants/evaluate
    POST /v1/accounts/evaluate       /v1/investigations/evaluate
    POST /v1/ai/security/evaluate    GET /v1/ai/security/events[/{id}]
    GET  /v1/cases  POST /v1/cases  GET /v1/cases/{id}  POST /v1/cases/{id}/transition|decision
    GET  /v1/audit  GET /v1/audit/verify  GET /v1/audit/{id}
    POST /v1/policies/evaluate  GET /v1/policies[/{id}]  GET /v1/policies/catalog
    GET  /v1/risk/{entity_type}/{id}   GET /v1/graph/{entity_type}/{id}
    GET  /v1/transactions[/{id}]  /v1/disputes  /v1/merchants[/{id}]  /v1/accounts[/{id}]
    GET  /v1/decisions[/{id}]   POST /v1/replay   GET /v1/replays
    GET  /v1/attacks  POST /v1/attacks/simulate   GET /v1/scenarios  POST /v1/scenarios/{key}/run
    GET  /v1/evaluations   GET /  (the console)

Every route calls ``SentinelApp``; there is no second implementation of any
decision. Optional bearer auth (SENTINEL_API_KEY), body-size cap, per-client
rate limit, request ids, structured logs, no stack traces to clients.
"""

from __future__ import annotations

import hmac
import json
import mimetypes
import os
import re
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from sentinel import __version__
from sentinel.api import schemas as S
from sentinel.app import SentinelApp
from sentinel.cases.service import InvalidTransition
from sentinel.domain.enums import CasePriority, CaseStatus, Workflow
from sentinel.domain.serialization import to_dict
from sentinel.observability import METRICS, get_logger, new_trace, request_id
from sentinel.policy import PolicyValidationError
from sentinel.policy import evaluate as policy_evaluate
from sentinel.policy.engine import PolicyEvaluationError
from sentinel.policy.models import FIELD_CATALOG
from sentinel.presets import ATTACKS, SCENARIOS
from sentinel.replay.engine import ReplayOverrides
from sentinel.risk import monitoring
from sentinel.security.capabilities import matrix as capability_matrix
from sentinel.security.gateway import Conversation
from sentinel.security.provenance import UntrustedContent

_log = get_logger("sentinel.api")
MAX_BODY = 256 * 1024
UI_DIR = Path(__file__).resolve().parents[2] / "ui"
RESULTS_DIR = Path(__file__).resolve().parents[2] / "results"


_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    413: "payload_too_large",
    429: "rate_limited",
    500: "internal_error",
}


def _error(status: int, message: str, rid: str | None) -> dict[str, Any]:
    return {"error": message, "code": _ERROR_CODES.get(status, "error"), "request_id": rid}


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class RateLimiter:
    """Fixed window per client: SENTINEL_RATE_LIMIT requests / minute (0 = off)."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            q = self._hits.setdefault(client, deque())
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            return True


def _authorized(headers: Any) -> bool:
    key = os.environ.get("SENTINEL_API_KEY")
    if not key:
        return True
    auth = headers.get("Authorization", "")
    presented = auth[7:].strip() if auth.startswith("Bearer ") else headers.get("X-API-Key", "")
    # constant-time comparison: the token check must not leak by timing
    return hmac.compare_digest(presented.strip().encode("utf-8"), key.encode("utf-8"))


class Router:
    def __init__(self) -> None:
        self.routes: list[tuple[str, re.Pattern[str], Any]] = []

    def add(self, method: str, pattern: str, fn: Any) -> None:
        self.routes.append((method, re.compile("^" + pattern + "$"), fn))

    def match(self, method: str, path: str) -> tuple[Any, dict[str, str]] | None:
        for m, rx, fn in self.routes:
            if m != method:
                continue
            mt = rx.match(path)
            if mt:
                return fn, mt.groupdict()
        return None


def _adjudication(b: Any) -> dict[str, Any]:
    """The explicit claim / trusted evidence / contradiction / adjudication objects a
    reviewer needs, separate from the decision they fed."""
    rec = b.reconciliation
    return {
        "claim": to_dict(rec.claim) if rec.claim else None,
        "trusted_evidence": [to_dict(e) for e in rec.evidence.verified()],
        "untrusted_claims": [to_dict(e) for e in rec.evidence.claims()],
        "contradictions": [to_dict(c) for c in rec.contradictions],
        "verdict": rec.verdict.value,
        "explanation": rec.explanation,
        "ai_recommendation": to_dict(b.ai) if b.ai else None,
        "policy": to_dict(b.decision.policy),
        "authorization": to_dict(b.decision.authorization),
        "final_action": b.decision.final_action.value,
    }


def _evaluate_options(d: dict[str, Any]) -> Any:
    """Options for the authoritative evaluate routes. Ablation controls (``unguarded``,
    ``options.controls``) are a lab feature: they are accepted here only when the operator
    sets ``SENTINEL_ALLOW_UNGUARDED=1``. The attack simulator and replay always accept them
    and record the control set on the decision and the audit event."""
    opts = S.run_options(d)
    if opts.controls != S.ALL_CONTROLS and os.environ.get("SENTINEL_ALLOW_UNGUARDED") != "1":
        raise ApiError(
            403,
            "reduced controls are not accepted on evaluate routes; use /v1/attacks/simulate or "
            "/v1/replay, or start the server with SENTINEL_ALLOW_UNGUARDED=1 for lab use",
        )
    return opts


def build_routes(app: SentinelApp) -> Router:
    r = Router()

    # ---- meta ---------------------------------------------------------------------------
    r.add("GET", "/health", lambda q, b, p: {"status": "ok", "mode": app.system_info()["mode"]})
    r.add(
        "GET",
        "/version",
        lambda q, b, p: {
            "name": "sentinel",
            "version": __version__,
            **{k: v for k, v in app.system_info().items() if k in ("mode", "provider", "model")},
        },
    )
    r.add("GET", "/v1/system", lambda q, b, p: app.system_info())
    r.add("GET", "/v1/overview", lambda q, b, p: app.overview())

    # ---- workflows -------------------------------------------------------------------------
    def tx_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        untrusted = S.untrusted_list(d, "untrusted")
        if "transaction" in d:
            t = S.transaction(d)
            return to_dict(app.evaluate_transaction(t, untrusted=untrusted, options=opts).decision)
        tid = S.req_str(d, "transaction_id", max_len=64)
        return to_dict(app.evaluate_transaction(tid, untrusted=untrusted, options=opts).decision)

    def dispute_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        docs = S.opt_str_list(d, "documents")
        if "document" in d and d["document"] is not None:
            docs = docs + (S.req_str(d, "document"),)
        messages = S.opt_str_list(d, "messages")
        if messages:
            ledger = S.req_obj(d, "ledger")
            return to_dict(
                app.evaluate_dispute_conversation(messages, ledger, options=opts).decision
            )
        if d.get("dispute_id") and "ledger" not in d:
            return to_dict(
                app.evaluate_dispute(
                    S.opt_str(d, "narrative", "") or "",
                    dispute_id=S.req_str(d, "dispute_id", max_len=64),
                    documents=docs,
                    options=opts,
                ).decision
            )
        narrative = S.req_str(d, "narrative", alt="submission")
        ledger = S.req_obj(d, "ledger")
        b = app.evaluate_dispute(
            narrative,
            ledger,
            documents=docs,
            source=S.opt_str(d, "source", "cardholder") or "cardholder",
            options=opts,
        )
        return {**to_dict(b.decision), "adjudication": _adjudication(b)}

    def merchant_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        docs = S.opt_str_list(d, "documents")
        if d.get("document"):
            docs = docs + (S.req_str(d, "document"),)
        if d.get("application_id") and "records" not in d:
            return to_dict(
                app.evaluate_merchant(
                    S.opt_str(d, "application", "") or "",
                    application_id=S.req_str(d, "application_id", max_len=64),
                    documents=docs,
                    options=opts,
                ).decision
            )
        return to_dict(
            app.evaluate_merchant(
                S.req_str(d, "application"),
                S.req_obj(d, "records"),
                merchant_id=S.opt_str(d, "merchant_id", "", 64) or "",
                documents=docs,
                options=opts,
            ).decision
        )

    def account_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        msg = S.opt_str(d, "message")
        cap = S.capability(d, "requested_capability")
        if "session" in d:
            return to_dict(
                app.evaluate_account(
                    S.login_session(d), message=msg, requested_capability=cap, options=opts
                ).decision
            )
        return to_dict(
            app.evaluate_account(
                S.req_str(d, "session_id", max_len=64),
                message=msg,
                requested_capability=cap,
                options=opts,
            ).decision
        )

    def investigation_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        return to_dict(
            app.evaluate_investigation(
                S.req_str(d, "account_id", max_len=64),
                case_notes=S.opt_str_list(d, "case_notes"),
                as_of=S.opt_str(d, "as_of", None, 40),
                options=_evaluate_options(d),
            ).decision
        )

    def ai_security_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        contents = S.untrusted_list(d, "contents")
        if "text" in d:
            contents = contents + (UntrustedContent(S.req_str(d, "text")),)
        messages = S.opt_str_list(d, "messages")
        convo = None
        if messages:
            convo = Conversation(tuple(UntrustedContent(m) for m in messages))
            contents = contents + (convo.transcript(),)
        if not contents:
            raise S.ValidationError("provide 'text', 'contents' or 'messages'")
        agent = S.opt_str(d, "agent", "dispute", 40) or "dispute"
        from sentinel.agents.catalog import SPECS

        if agent not in SPECS:
            raise S.ValidationError(f"unknown agent {agent!r}; have {sorted(SPECS)}")
        res = app.evaluate_ai_security(
            contents,
            agent_key=agent,
            run_agent=S.opt_bool(d, "run_agent", True),
            conversation=convo,
        )
        return {
            "assessment": to_dict(res.assessment),
            "ai_recommendation": to_dict(res.ai) if res.ai else None,
            "event": to_dict(res.event) if res.event else None,
            "audit_event": res.audit_event.to_dict() if res.audit_event else None,
        }

    r.add("POST", "/v1/transactions/evaluate", tx_eval)
    r.add("POST", "/v1/disputes/evaluate", dispute_eval)
    r.add("POST", "/v1/merchants/evaluate", merchant_eval)
    r.add("POST", "/v1/accounts/evaluate", account_eval)
    r.add("POST", "/v1/investigations/evaluate", investigation_eval)
    r.add("POST", "/v1/ai/security/evaluate", ai_security_eval)
    r.add(
        "GET",
        "/v1/ai/security/events",
        lambda q, b, p: {"events": app.store.security_events(_lim(q))},
    )
    r.add(
        "GET",
        "/v1/ai/security/events/(?P<id>[^/]+)",
        lambda q, b, p: _or404(app.store.security_event(p["id"]), "security event"),
    )

    # ---- reads -------------------------------------------------------------------------------
    def tx_list(q: Any, b: Any, p: Any) -> Any:
        rows = app.store.transactions(
            account_id=_q(q, "account_id"),
            merchant_id=_q(q, "merchant_id"),
            limit=_lim(q),
            offset=int(_q(q, "offset") or 0),
        )
        latest = {
            d["subject_id"]: d for d in app.store.decisions(workflow="transaction", limit=2000)
        }
        out = []
        for t in rows:
            d = latest.get(t.transaction_id)
            out.append(
                {
                    **to_dict(t),
                    "decision": (
                        {
                            "decision_id": d["decision_id"],
                            "final_action": d["final_action"],
                            "risk_score": d["risk_score"],
                            "risk_level": d["risk_level"],
                            "case_id": d.get("case_id"),
                        }
                        if d
                        else None
                    ),
                }
            )
        return {"transactions": out, "total": app.store.count("transactions")}

    r.add("GET", "/v1/transactions", tx_list)
    r.add(
        "GET",
        "/v1/transactions/(?P<id>[^/]+)",
        lambda q, b, p: _keyed(lambda: app.transaction_view(p["id"]), "transaction"),
    )
    r.add(
        "GET",
        "/v1/disputes",
        lambda q, b, p: {
            "disputes": [
                {
                    **to_dict(d),
                    **_texts(app, d.dispute_id),
                    "decision": _latest(app, "dispute", d.dispute_id),
                }
                for d in app.store.disputes(limit=_lim(q))
            ]
        },
    )
    r.add(
        "GET",
        "/v1/merchants",
        lambda q, b, p: {
            "merchants": [
                {**to_dict(m), "risk": to_dict(app.world.engine.merchant_risk(m.merchant_id))}
                for m in app.store.merchants()[: _lim(q)]
            ]
        },
    )
    r.add("GET", "/v1/merchants/(?P<id>[^/]+)", lambda q, b, p: _merchant_view(app, p["id"]))
    r.add(
        "GET",
        "/v1/accounts",
        lambda q, b, p: {
            "accounts": [
                {**to_dict(a), "risk": to_dict(app.world.engine.account_risk(a.account_id))}
                for a in app.store.accounts()[: _lim(q)]
            ]
        },
    )
    r.add("GET", "/v1/accounts/(?P<id>[^/]+)", lambda q, b, p: _account_view(app, p["id"]))
    r.add(
        "GET",
        "/v1/applications",
        lambda q, b, p: {
            "applications": [
                {
                    **to_dict(k),
                    **_texts(app, k.application_id, kyb=True),
                    "decision": _latest(app, "merchant_onboarding", k.merchant_id),
                }
                for k in app.store.kyb_applications(_lim(q))
            ]
        },
    )
    r.add(
        "GET",
        "/v1/sessions",
        lambda q, b, p: {
            "sessions": [
                {**to_dict(s), "decision": _latest(app, "account_security", s.session_id)}
                for s in app.store.sessions(limit=_lim(q))
            ]
        },
    )
    r.add(
        "GET",
        "/v1/risk/(?P<kind>[a-z]+)/(?P<id>[^/]+)",
        lambda q, b, p: _keyed(lambda: app.entity_risk(p["kind"], p["id"]), p["kind"]),
    )
    r.add(
        "GET",
        "/v1/graph/(?P<kind>[a-z]+)/(?P<id>[^/]+)",
        lambda q, b, p: app.graph_for(p["kind"], p["id"], int(_q(q, "depth") or 2)),
    )
    r.add(
        "GET",
        "/v1/decisions",
        lambda q, b, p: {
            "decisions": app.store.decisions(
                workflow=_q(q, "workflow"), subject_id=_q(q, "subject_id"), limit=_lim(q)
            )
        },
    )
    r.add("GET", "/v1/decisions/(?P<id>[^/]+)", lambda q, b, p: _decision_view(app, p["id"]))

    # ---- cases --------------------------------------------------------------------------------
    def case_create(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        try:
            wf = Workflow(S.req_str(d, "case_type", max_len=40))
            prio = CasePriority(S.opt_str(d, "priority", "P3", 4) or "P3")
        except ValueError as e:
            raise S.ValidationError(str(e)) from None
        c = app.runtime.cases.open_manual(
            wf,
            S.req_str(d, "title", max_len=200),
            S.opt_str_list(d, "entities"),
            prio,
            S.opt_str(d, "actor", "human", 60) or "human",
        )
        return to_dict(c)

    def case_transition(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        try:
            to = CaseStatus(S.req_str(d, "status", max_len=30))
            return to_dict(
                app.runtime.cases.transition(
                    p["id"],
                    to,
                    actor=S.req_str(d, "actor", max_len=60),
                    note=S.opt_str(d, "note", "", 500) or "",
                )
            )
        except ValueError as e:  # includes InvalidTransition
            raise ApiError(409 if isinstance(e, InvalidTransition) else 400, str(e)) from None
        except KeyError:
            raise ApiError(404, f"case {p['id']!r} not found") from None

    def case_decide(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        try:
            return to_dict(
                app.runtime.cases.record_human_decision(
                    p["id"],
                    reviewer=S.req_str(d, "reviewer", max_len=60),
                    outcome=S.req_str(d, "outcome", max_len=20),
                    note=S.opt_str(d, "note", "", 500) or "",
                )
            )
        except InvalidTransition as e:
            raise ApiError(409, str(e)) from None
        except ValueError as e:
            raise ApiError(400, str(e)) from None
        except KeyError:
            raise ApiError(404, f"case {p['id']!r} not found") from None

    r.add(
        "GET",
        "/v1/cases",
        lambda q, b, p: {"cases": [to_dict(c) for c in app.cases(_q(q, "status"), _lim(q))]},
    )
    r.add("POST", "/v1/cases", case_create)
    r.add("GET", "/v1/cases/(?P<id>[^/]+)", lambda q, b, p: _case_view(app, p["id"]))
    r.add(
        "GET",
        "/v1/cases/(?P<id>[^/]+)/review",
        lambda q, b, p: _or404(app.review_packet(p["id"]), "case"),
    )
    r.add("POST", "/v1/cases/(?P<id>[^/]+)/transition", case_transition)
    r.add("POST", "/v1/cases/(?P<id>[^/]+)/decision", case_decide)

    # ---- audit ---------------------------------------------------------------------------------
    r.add(
        "GET",
        "/v1/audit",
        lambda q, b, p: {
            "events": [e.to_dict() for e in app.runtime.audit.tail(_lim(q))][::-1],
            "head": app.runtime.audit.head,
            "length": len(app.runtime.audit),
        },
    )
    r.add("GET", "/v1/audit/verify", lambda q, b, p: to_dict(app.verify_audit()))
    r.add(
        "GET",
        "/v1/audit/(?P<id>[^/]+)",
        lambda q, b, p: _or404(app.audit_event(p["id"]), "audit event"),
    )

    # ---- policies --------------------------------------------------------------------------------
    def policy_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        try:
            pol = app.runtime.policies.get(
                S.req_str(d, "policy_id", max_len=60), S.opt_int(d, "version", None, lo=1)
            )
        except KeyError as e:
            raise ApiError(404, str(e)) from None
        ctx = S.req_obj(d, "context")
        try:
            return to_dict(policy_evaluate(pol, ctx))
        except PolicyEvaluationError as e:
            raise S.ValidationError(str(e)) from None

    def policy_validate(q: Any, b: Any, p: Any) -> Any:
        from sentinel.policy.loader import policy_from_dict

        try:
            pol = policy_from_dict(S.obj(b))
        except PolicyValidationError as e:
            raise S.ValidationError(str(e)) from None
        return {"valid": True, "policy": pol.to_dict()}

    r.add(
        "GET",
        "/v1/policies",
        lambda q, b, p: {"policies": [pp.to_dict() for pp in app.runtime.policies.all()]},
    )
    r.add(
        "GET",
        "/v1/policies/catalog",
        lambda q, b, p: {
            "fields": {k: {"type": t, "description": d} for k, (t, d) in FIELD_CATALOG.items()}
        },
    )
    r.add("POST", "/v1/policies/evaluate", policy_eval)
    r.add("POST", "/v1/policies/validate", policy_validate)

    def policy_lint(q: Any, b: Any, p: Any) -> Any:
        """Lint a policy document, or a shipped policy named by ``{policy_id, version?}``."""
        from sentinel.policy import lint
        from sentinel.policy.loader import policy_from_dict

        d = S.obj(b)
        if "rules" not in d and "policy_id" in d:
            pid = S.req_str(d, "policy_id", max_len=60)
            ver = d.get("version")
            try:
                pol = app.runtime.policies.get(pid, int(ver) if ver is not None else None)
            except (KeyError, ValueError, TypeError) as e:
                raise ApiError(404, str(e)) from None
        else:
            try:
                pol = policy_from_dict(d)
            except PolicyValidationError as e:
                raise S.ValidationError(str(e)) from None
        findings = lint(pol)
        return {"valid": True, "clean": not findings, "findings": findings, "policy": pol.key}

    r.add("POST", "/v1/policies/lint", policy_lint)
    r.add(
        "GET",
        "/v1/capabilities",
        lambda q, b, p: {
            "capabilities": capability_matrix(),
            "invariant": "no AI actor may execute a consequential capability; SKIP_REVIEW has no actor",
        },
    )
    r.add(
        "GET",
        "/v1/policies/(?P<id>[^/]+)",
        lambda q, b, p: _keyed(lambda: _policy_doc(app, p["id"], _q(q, "version")), "policy"),
    )

    # ---- replay ----------------------------------------------------------------------------------
    def replay(q: Any, b: Any, p: Any) -> Any:
        body = S.replay_body(S.obj(b))
        ov = ReplayOverrides(
            body.policy_version,
            body.risk_model,
            body.rule_values,
            body.ai_recommendation,
            body.ai_capability,
            body.controls,
        )
        try:
            res = app.replay(body.decision_id, ov)
        except KeyError as e:
            raise ApiError(404, str(e)) from None
        return {
            "replay_id": res.replay_id,
            "decision_id": res.decision_id,
            "overrides": res.overrides,
            "original": res.original,
            "replayed": res.replayed,
            "changed": res.changed,
            "diffs": [to_dict(d) for d in res.diffs],
            "explanation": res.explanation,
            "created_at": res.created_at,
            "policy_drift": res.policy_drift,
            "original_drift": res.original_drift,
        }

    r.add("POST", "/v1/replay", replay)
    r.add("GET", "/v1/replays", lambda q, b, p: {"replays": app.store.replays(_lim(q))})

    # ---- attack simulator + scenarios ---------------------------------------------------------------
    def simulate(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        kind = S.req_str(d, "kind", max_len=60)
        if kind not in ATTACKS:
            raise S.ValidationError(f"unknown attack {kind!r}; have {sorted(ATTACKS)}")
        return app.simulate_attack(
            kind,
            narrative=S.opt_str(d, "narrative"),
            document=S.opt_str(d, "document"),
            options=S.run_options(d),
            compare=S.opt_bool(d, "compare", False),
        )

    def scenario_run(q: Any, b: Any, p: Any) -> Any:
        if p["key"] not in SCENARIOS:
            raise ApiError(404, f"unknown scenario {p['key']!r}")
        return app.run_scenario(p["key"], options=S.run_options(S.obj(b) if b else {}))

    r.add("GET", "/v1/attacks", lambda q, b, p: {"attacks": [to_dict(a) for a in ATTACKS.values()]})
    r.add("POST", "/v1/attacks/simulate", simulate)
    r.add(
        "GET",
        "/v1/scenarios",
        lambda q, b, p: {
            "scenarios": [to_dict(s) for s in SCENARIOS.values()],
            "tags": app.store.scenarios(),
        },
    )
    r.add("POST", "/v1/scenarios/(?P<key>[a-z_]+)/run", scenario_run)
    r.add("GET", "/v1/evaluations", lambda q, b, p: _evaluations())
    return r


# ---- helpers ---------------------------------------------------------------------------
def _q(q: dict[str, list[str]], key: str) -> str | None:
    v = q.get(key)
    return v[0] if v else None


def _lim(q: dict[str, list[str]], default: int = 50, cap: int = 500) -> int:
    try:
        return max(1, min(cap, int(_q(q, "limit") or default)))
    except ValueError:
        return default


def _or404(obj: Any, what: str) -> Any:
    if obj is None:
        raise ApiError(404, f"{what} not found")
    return obj


def _keyed(fn: Any, what: str) -> Any:
    try:
        return fn()
    except KeyError as e:
        raise ApiError(404, f"{what} not found: {e}") from None


def _texts(app: SentinelApp, ident: str, kyb: bool = False) -> dict[str, Any]:
    found = app.store.kyb_application(ident) if kyb else app.store.dispute(ident)
    return {"texts": found[1]} if found else {"texts": {}}


def _latest(app: SentinelApp, workflow: str, subject_id: str) -> dict[str, Any] | None:
    rows = app.store.decisions(workflow=workflow, subject_id=subject_id, limit=1)
    if not rows:
        return None
    d = rows[0]
    return {
        k: d.get(k)
        for k in (
            "decision_id",
            "final_action",
            "risk_score",
            "risk_level",
            "evidence_verdict",
            "security_severity",
            "case_id",
        )
    }


def _decision_view(app: SentinelApp, did: str) -> Any:
    d = app.store.decision(did)
    if d is None:
        raise ApiError(404, "decision not found")
    return {
        "decision": d,
        "evidence": app.store.evidence_for(did),
        "audit_event": app.audit_event(did),
        "snapshot_available": app.store.decision_snapshot(did) is not None,
    }


def _case_view(app: SentinelApp, cid: str) -> Any:
    c = app.case(cid)
    if c is None:
        raise ApiError(404, "case not found")
    return {
        "case": to_dict(c),
        "decisions": [app.store.decision(d) for d in c.decision_ids if app.store.decision(d)],
        "security_events": [
            app.store.security_event(e) for e in c.security_event_ids if app.store.security_event(e)
        ],
    }


def _merchant_view(app: SentinelApp, mid: str) -> Any:
    m = app.store.merchant(mid)
    if m is None:
        raise ApiError(404, "merchant not found")
    from sentinel.risk.graph import Node

    return {
        "merchant": to_dict(m),
        "risk": to_dict(app.world.engine.merchant_risk(mid)),
        "graph": app.world.graph.to_dict(Node("merchant", mid), 2),
        "transactions": [to_dict(t) for t in app.store.transactions(merchant_id=mid, limit=25)],
        "applications": [
            {**to_dict(k), **_texts(app, k.application_id, kyb=True)}
            for k in app.store.kyb_applications(1000)
            if k.merchant_id == mid
        ],
        "decisions": app.store.decisions(workflow="merchant_onboarding", subject_id=mid, limit=5),
    }


def _account_view(app: SentinelApp, aid: str) -> Any:
    a = app.store.account(aid)
    if a is None:
        raise ApiError(404, "account not found")
    from sentinel.risk.graph import Node

    txns = app.store.transactions(account_id=aid, limit=25)
    linked = sorted(app.world.graph.linked_accounts(aid))
    return {
        "account": to_dict(a),
        "customer": to_dict(app.store.customer(a.customer_id)),
        "risk": to_dict(app.world.engine.account_risk(aid)),
        "graph": app.world.graph.to_dict(Node("account", aid), 2),
        "transactions": [to_dict(t) for t in txns],
        "sessions": [to_dict(s) for s in app.store.sessions(account_id=aid, limit=10)],
        "disputes": [to_dict(d) for d in app.store.disputes(account_id=aid, limit=10)],
        "decisions": app.store.decisions(subject_id=aid, limit=10),
        "linked_accounts": linked,
        "linked_risk": {x: to_dict(app.world.engine.account_risk(x)) for x in linked[:6]},
        "risk_evolution": app.store.risk_evolution(aid),
        "monitoring": (to_dict(monitoring.assess_account_activity(app.monitoring_context(aid)))),
    }


def _policy_doc(app: SentinelApp, policy_id: str, version: str | None) -> Any:
    v = int(version) if version else None
    return app.runtime.policies.get(policy_id, v).to_dict()


def _evaluations() -> Any:
    out: dict[str, Any] = {}
    if RESULTS_DIR.exists():
        for p in sorted(RESULTS_DIR.glob("*.json")):
            try:
                out[p.stem] = json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                continue
    return {"results": out, "available": sorted(out)}


# ---- HTTP handler ---------------------------------------------------------------------------
class SentinelHandler(BaseHTTPRequestHandler):
    server_version = f"Sentinel/{__version__}"
    app: SentinelApp
    router: Router
    limiter: RateLimiter

    def _send(self, status: int, obj: Any, rid: str | None = None) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        if rid:
            self.send_header("X-Request-ID", rid)
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path: str) -> bool:
        rel = "index.html" if path in ("", "/", "/index.html") else path.lstrip("/")
        if rel.startswith("ui/"):
            rel = rel[3:]
        try:
            target = (UI_DIR / rel).resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        if not target.is_relative_to(UI_DIR.resolve()) or not target.is_file():
            return False
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)
        return True

    def log_message(self, fmt: str, *args: Any) -> None:
        _log.info("http", extra={"detail": {"line": fmt % args}})

    def _dispatch(self, method: str) -> None:
        rid = new_trace()
        request_id.set(rid)
        t0 = time.perf_counter()
        url = urlparse(self.path)
        path = url.path.rstrip("/") or "/"
        query = parse_qs(url.query)
        client = self.client_address[0] if self.client_address else "?"
        if not self.limiter.allow(client):
            return self._send(429, _error(429, "rate limit exceeded", rid), rid)
        if method == "GET" and (
            path == "/"
            or path.startswith("/ui")
            or path.endswith((".html", ".js", ".css", ".png", ".svg", ".json"))
            and not path.startswith("/v1")
        ):
            if self._static(path):
                return None
        route = self.router.match(method, path)
        if route is None:
            return self._send(404, {**_error(404, "not found", rid), "path": path}, rid)
        fn, params = route
        if path not in ("/health", "/version") and not _authorized(self.headers):
            return self._send(401, _error(401, "unauthorized", rid), rid)
        body: Any = None
        if method == "POST":
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return self._send(400, _error(400, "invalid Content-Length", rid), rid)
            if length > MAX_BODY:
                return self._send(
                    413, _error(413, f"request too large (> {MAX_BODY} bytes)", rid), rid
                )
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError as e:
                return self._send(400, _error(400, f"invalid JSON: {e.msg}", rid), rid)
        try:
            result = fn(query, body, params)
            status = 200
        except S.ValidationError as e:
            result, status = _error(e.status, e.message, rid), e.status
        except ApiError as e:
            result, status = _error(e.status, e.message, rid), e.status
        except Exception as e:  # noqa: BLE001 - never leak a stack trace
            _log.warning(
                "handler failed",
                extra={"detail": {"path": path, "error": type(e).__name__, "request_id": rid}},
            )
            result, status = _error(500, "internal error", rid), 500
        METRICS.observe(
            f"http:{method} {path.split('/')[1] if path != '/' else 'root'}",
            (time.perf_counter() - t0) * 1000,
        )
        METRICS.inc(f"http.status.{status}")
        return self._send(status, result, rid)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


def make_server(app: SentinelApp, host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    handler = type(
        "BoundHandler",
        (SentinelHandler,),
        {
            "app": app,
            "router": build_routes(app),
            "limiter": RateLimiter(int(os.environ.get("SENTINEL_RATE_LIMIT", "600"))),
        },
    )
    return ThreadingHTTPServer((host, port), handler)


def serve(app: SentinelApp, host: str = "0.0.0.0", port: int = 8000) -> None:
    httpd = make_server(app, host, port)
    auth = "on" if os.environ.get("SENTINEL_API_KEY") else "off (open)"
    print(
        f"Sentinel v{__version__} API + console on http://{host}:{port}  mode={app.system_info()['mode']}  auth={auth}  db={app.store.path}"
    )
    if not os.environ.get("SENTINEL_API_KEY") and host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "WARNING: SENTINEL_API_KEY is unset and the API is bound to a non-loopback address. "
            "Every caller can submit 'trusted' ledger/record facts and read every decision. "
            "This is a lab configuration; set SENTINEL_API_KEY or bind to 127.0.0.1.",
            file=sys.stderr,
        )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
