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
decision. Secure by default: loopback unless an API key (SENTINEL_API_KEY or
SENTINEL_API_KEY_FILE) or an explicit, audited ``--insecure-demo``; bearer auth;
JSON-only, same-origin POSTs; security headers and a CSP on the console;
body-size cap, socket timeout, per-client rate limit, request ids, structured
logs, no stack traces to clients; an audited SERVER_START and SIGHUP reload.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import mimetypes
import os
import re
import signal
import socket
import sys
import threading
import time
from collections import deque
from contextvars import ContextVar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from sentinel import __version__
from sentinel.api import schemas as S
from sentinel.app import SentinelApp
from sentinel.cases.service import InvalidTransition, ReviewerNotAuthorized
from sentinel.decision.authority import ControlDowngrade
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
    415: "unsupported_media_type",
    421: "misdirected_request",
    429: "rate_limited",
    500: "internal_error",
    503: "unavailable",
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


# The reviewer credential of the request being served. Set by the dispatcher from the
# X-Reviewer-Token header only -- never from the URL or the body.
REVIEWER_TOKEN: ContextVar[str | None] = ContextVar("reviewer_token", default=None)
_IDENTITY_FIELDS = ("reviewer", "role", "actor", "reviewer_id")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise S.ValidationError(f"invalid JSON: duplicate key {k!r}")
        out[k] = v
    return out


MIN_API_KEY = 16  # characters; a shorter key does not protect a network-reachable service
_KEY_FILE_CACHE: dict[str, tuple[float, str]] = {}


def api_key() -> str | None:
    """The API key: ``SENTINEL_API_KEY``, or the contents of ``SENTINEL_API_KEY_FILE`` (a
    mounted secret, so the key is not in the process environment or ``docker inspect``).
    The file is read again when it changes, so rotating the secret in place takes effect
    without a restart. Surrounding whitespace is not part of a key; a blank key is none."""
    key = (os.environ.get("SENTINEL_API_KEY") or "").strip()
    if key:
        return key
    path = os.environ.get("SENTINEL_API_KEY_FILE")
    if not path:
        return None
    mtime = Path(path).stat().st_mtime
    cached = _KEY_FILE_CACHE.get(path)
    if cached is None or cached[0] != mtime:
        _KEY_FILE_CACHE[path] = (mtime, Path(path).read_text(encoding="utf-8").strip())
    return _KEY_FILE_CACHE[path][1] or None


def _authorized(headers: Any) -> bool:
    key = api_key()
    if not key:
        return True
    auth = headers.get("Authorization", "")
    presented = auth[7:].strip() if auth.startswith("Bearer ") else headers.get("X-API-Key", "")
    # constant-time over equal-length digests: neither the key nor its length leaks by timing
    return hmac.compare_digest(
        hashlib.sha256(presented.strip().encode("utf-8")).digest(),
        hashlib.sha256(key.encode("utf-8")).digest(),
    )


class InsecureBindError(RuntimeError):
    """A network-reachable bind with no API key and no explicit ``--insecure-demo``."""


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # a hostname, 0.0.0.0, "" -- reachable from elsewhere


def check_bind(host: str, *, insecure_demo: bool = False) -> str:
    """Refuse an authoritative service reachable from the network without authentication,
    unless the operator said ``--insecure-demo`` in so many words. Returns the bind class."""
    if is_loopback(host):
        return "loopback"
    key = api_key()
    if key and len(key) < MIN_API_KEY:
        raise InsecureBindError(
            f"SENTINEL_API_KEY is shorter than {MIN_API_KEY} characters; refusing to serve on "
            f"{host or 'all interfaces'}"
        )
    if not key and not insecure_demo:
        raise InsecureBindError(
            f"refusing to serve on {host or 'all interfaces'} without authentication: set "
            "SENTINEL_API_KEY (or SENTINEL_API_KEY_FILE), bind 127.0.0.1, or pass "
            "--insecure-demo (SENTINEL_INSECURE_DEMO=1) for a throwaway demo"
        )
    return "network"


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


def allowed_hosts() -> frozenset[str]:
    """Host names (no port) a request may address, beyond the loopback names:
    ``SENTINEL_ALLOWED_HOSTS`` -- the public name a TLS proxy serves the API under."""
    raw = os.environ.get("SENTINEL_ALLOWED_HOSTS", "")
    return frozenset(h.strip().lower() for h in raw.split(",") if h.strip())


def _hostname(netloc: str) -> str:
    """``host[:port]`` -> host, lowercased (an IPv6 literal keeps its brackets)."""
    netloc = netloc.strip().lower()
    if netloc.startswith("["):
        return netloc[: netloc.find("]") + 1] if "]" in netloc else netloc
    return netloc.rsplit(":", 1)[0] if netloc.count(":") == 1 else netloc


# The console is the only HTML served: same-origin scripts and API calls, no framing.
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'"
)
_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
)


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
    """Options for the authoritative evaluate routes. A caller may request an evaluation; it
    may not weaken one. Every what-if switch (``unguarded``, ``options.controls``,
    ``options.policy_version``, ``options.risk_model``) is refused here with 403 -- an older
    policy or risk model is not an authorization (v1 of dispute-refund has no double-refund
    rule; txn-1.0 lacks the burst signals). The attack simulator, scenario runs and replay
    accept them, and the engine never records those runs as decisions."""
    used = S.what_if_keys(d)
    if used:
        raise ApiError(
            403,
            f"{', '.join(used)} {'is a what-if switch' if len(used) == 1 else 'are what-if switches'} "
            "and not accepted on evaluate routes: "
            "the authoritative path always runs every control, the active policy and the "
            "active risk model. Use /v1/replay, /v1/attacks/simulate or /v1/scenarios/{key}/run "
            "for what-if analysis; their results are never recorded as decisions.",
        )
    return S.run_options(d)


def build_routes(app: SentinelApp) -> Router:
    r = Router()

    # ---- meta ---------------------------------------------------------------------------
    r.add("GET", "/health", lambda q, b, p: {"status": "ok", "mode": app.system_info()["mode"]})
    r.add(
        "GET",
        "/version",
        # unauthenticated: the version only (provider and model are on /v1/system)
        lambda q, b, p: {"name": "sentinel", "version": __version__},
    )
    r.add("GET", "/v1/system", lambda q, b, p: app.system_info())
    r.add("GET", "/v1/overview", lambda q, b, p: app.overview())

    # ---- workflows -------------------------------------------------------------------------
    def tx_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        untrusted = S.untrusted_list(d, "untrusted")
        env = S.envelope(d, exclusive=("transaction", "transaction_id"))
        if env is not None:
            return to_dict(
                app.evaluate_transaction(envelope=env, untrusted=untrusted, options=opts).decision
            )
        if "transaction" in d:
            t = S.transaction(d)
            return to_dict(app.evaluate_transaction(t, untrusted=untrusted, options=opts).decision)
        tid = S.req_id(d, "transaction_id")
        return to_dict(app.evaluate_transaction(tid, untrusted=untrusted, options=opts).decision)

    def dispute_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        docs = S.opt_str_list(d, "documents")
        if "document" in d and d["document"] is not None:
            docs = docs + (S.req_str(d, "document"),)
        messages = S.opt_str_list(d, "messages")
        env = S.envelope(d, exclusive=("ledger",))
        if messages:
            if env is not None:
                return to_dict(
                    app.evaluate_dispute_conversation(messages, envelope=env, options=opts).decision
                )
            ledger = S.req_obj(d, "ledger")
            return to_dict(
                app.evaluate_dispute_conversation(messages, ledger, options=opts).decision
            )
        if env is not None:  # an issuer's signed ledger, carried by the caller
            b = app.evaluate_dispute(
                S.req_str(d, "narrative", alt="submission"),
                envelope=env,
                dispute_id=S.opt_id(d, "dispute_id"),
                documents=docs,
                source=S.opt_str(d, "source", "cardholder", max_len=64) or "cardholder",
                options=opts,
            )
            return {**to_dict(b.decision), "adjudication": _adjudication(b)}
        if d.get("dispute_id") and "ledger" not in d:
            return to_dict(
                app.evaluate_dispute(
                    S.opt_str(d, "narrative", "") or "",
                    dispute_id=S.req_id(d, "dispute_id"),
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
            source=S.opt_str(d, "source", "cardholder", max_len=64) or "cardholder",
            options=opts,
        )
        return {**to_dict(b.decision), "adjudication": _adjudication(b)}

    def merchant_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        docs = S.opt_str_list(d, "documents")
        if d.get("document"):
            docs = docs + (S.req_str(d, "document"),)
        env = S.envelope(d, exclusive=("records", "application_id"))
        if env is not None:
            return to_dict(
                app.evaluate_merchant(
                    S.req_str(d, "application"),
                    envelope=env,
                    merchant_id=S.opt_id(d, "merchant_id") or "",
                    documents=docs,
                    options=opts,
                ).decision
            )
        if d.get("application_id") and "records" not in d:
            return to_dict(
                app.evaluate_merchant(
                    S.opt_str(d, "application", "") or "",
                    application_id=S.req_id(d, "application_id"),
                    documents=docs,
                    options=opts,
                ).decision
            )
        return to_dict(
            app.evaluate_merchant(
                S.req_str(d, "application"),
                S.req_obj(d, "records"),
                merchant_id=S.opt_id(d, "merchant_id") or "",
                documents=docs,
                options=opts,
            ).decision
        )

    def account_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        opts = _evaluate_options(d)
        msg = S.opt_str(d, "message")
        cap = S.capability(d, "requested_capability", workflow=Workflow.ACCOUNT_SECURITY)
        env = S.envelope(d, exclusive=("session", "session_id"))
        if env is not None:
            return to_dict(
                app.evaluate_account(
                    envelope=env, message=msg, requested_capability=cap, options=opts
                ).decision
            )
        if "session" in d:
            return to_dict(
                app.evaluate_account(
                    S.login_session(d), message=msg, requested_capability=cap, options=opts
                ).decision
            )
        return to_dict(
            app.evaluate_account(
                S.req_id(d, "session_id"),
                message=msg,
                requested_capability=cap,
                options=opts,
            ).decision
        )

    def investigation_eval(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        if "as_of" in d:  # a past as-of is a backtest, not an authoritative investigation
            raise ApiError(
                403, "as_of is a what-if switch; investigations run as of the dataset's now"
            )
        return to_dict(
            app.evaluate_investigation(
                S.req_str(d, "account_id", max_len=64),
                case_notes=S.opt_str_list(d, "case_notes"),
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
        return app.transaction_list(
            account_id=_q(q, "account_id"),
            merchant_id=_q(q, "merchant_id"),
            limit=_lim(q),
            offset=int(_q(q, "offset") or 0),
        )

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
    r.add("GET", "/v1/merchants", lambda q, b, p: app.merchant_list(_lim(q)))
    r.add("GET", "/v1/merchants/(?P<id>[^/]+)", lambda q, b, p: _merchant_view(app, p["id"]))
    r.add("GET", "/v1/accounts", lambda q, b, p: app.account_list(_lim(q)))
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
    def _reviewer(d: dict[str, Any], fields: frozenset[str]) -> Any:
        """The authenticated reviewer for a case action. Identity comes from the reviewer
        registry via the X-Reviewer-Token header. A body field the action does not take --
        one naming a reviewer or a role, or any other -- is refused rather than ignored."""
        named = [k for k in _IDENTITY_FIELDS if k in d]
        if named:
            raise S.ValidationError(
                f"{named} cannot be sent: who acts, and at what level, comes from the "
                "reviewer credential (X-Reviewer-Token), not from the request"
            )
        unknown = sorted(set(d) - fields)
        if unknown:
            raise S.ValidationError(f"unknown fields {unknown}; this action takes {sorted(fields)}")
        who = app.reviewers.authenticate(REVIEWER_TOKEN.get())
        if who is None:
            raise ApiError(
                401, "a case action needs an active reviewer credential (X-Reviewer-Token)"
            )
        return who

    def case_create(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        by = _reviewer(d, frozenset({"case_type", "title", "entities", "priority"}))
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
            by=by,
        )
        return to_dict(c)

    def case_transition(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        by = _reviewer(d, frozenset({"status", "note"}))
        try:
            to = CaseStatus(S.req_str(d, "status", max_len=30))
            return to_dict(
                app.runtime.cases.transition(
                    p["id"], to, by=by, note=S.opt_str(d, "note", "", 500) or ""
                )
            )
        except ReviewerNotAuthorized as e:
            raise ApiError(403, str(e)) from None
        except ValueError as e:  # includes InvalidTransition
            raise ApiError(409 if isinstance(e, InvalidTransition) else 400, str(e)) from None
        except KeyError:
            raise ApiError(404, f"case {p['id']!r} not found") from None

    def case_decide(q: Any, b: Any, p: Any) -> Any:
        d = S.obj(b)
        by = _reviewer(d, frozenset({"outcome", "note"}))
        try:
            return to_dict(
                app.runtime.cases.record_human_decision(
                    p["id"],
                    by=by,
                    outcome=S.req_str(d, "outcome", max_len=20),
                    note=S.opt_str(d, "note", "", 500) or "",
                )
            )
        except ReviewerNotAuthorized as e:
            raise ApiError(403, str(e)) from None
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
    r.add(
        "GET",
        "/v1/cases/(?P<id>[^/]+)",
        lambda q, b, p: _or404(app.case_view(p["id"]), "case"),
    )
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
        return res.to_dict()

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

    r.add("GET", "/v1/attacks", lambda q, b, p: app.attack_catalog())
    r.add("POST", "/v1/attacks/simulate", simulate)
    r.add("GET", "/v1/scenarios", lambda q, b, p: app.scenario_catalog())
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
    insecure_demo: bool = False
    loopback_bind: bool = True
    # seconds per socket read: a client that stalls is dropped (one that trickles a byte at
    # a time is the TLS proxy's to cut off; concurrent connections are capped below)
    timeout = 30

    def _common_headers(self) -> None:
        for k, v in _SECURITY_HEADERS:
            self.send_header(k, v)
        if self.insecure_demo:
            self.send_header("X-Sentinel-Insecure-Demo", "1")

    def _send(self, status: int, obj: Any, rid: str | None = None) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
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
        self._common_headers()
        if ctype == "text/html":
            self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        self.wfile.write(data)
        return True

    def _host_refused(self) -> bool:
        """DNS rebinding: a page on attacker.example can make its name resolve to
        127.0.0.1 and then talk to this server *same-origin*. Its requests still name its
        own host, so a loopback server answers only requests addressed to a loopback name
        (or to a name the operator listed in SENTINEL_ALLOWED_HOSTS)."""
        allowed = allowed_hosts()
        if not self.loopback_bind and not allowed:
            return False  # a network bind without a list: the API key is the control
        host = _hostname(self.headers.get("Host") or "")
        return host not in _LOOPBACK_HOSTS and host not in allowed

    def _cross_site(self) -> tuple[int, str] | None:
        """A state-changing request must be JSON and same-origin. A browser page elsewhere
        can send a text/plain POST without a preflight; requiring application/json forces
        the preflight this server never answers, and an Origin or Sec-Fetch-Site that names
        another site is refused outright (the loopback default is reachable from the
        operator's own browser)."""
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            return 415, "a request body must be application/json"
        if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
            return 403, "cross-site request refused"
        origin = self.headers.get("Origin")
        if origin is not None:
            host = (self.headers.get("Host") or "").lower()
            try:
                netloc = urlparse(origin).netloc.lower()
            except ValueError:  # e.g. "http://[" -- unparseable is not same-origin
                return 403, "cross-origin request refused"
            # same origin, or the public name a TLS proxy serves under (the proxy may
            # rewrite Host to the upstream address)
            if origin == "null" or (netloc != host and _hostname(netloc) not in allowed_hosts()):
                return 403, "cross-origin request refused"
        return None

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
        if self._host_refused():
            return self._send(
                421, _error(421, "this server does not answer for that host", rid), rid
            )
        if method == "GET" and (
            path == "/"
            or path.startswith("/ui")
            or path.endswith((".html", ".js", ".css", ".png", ".svg", ".json"))
            and not path.startswith("/v1")
        ):
            # the console's code is public; any data file (snapshot.json) is behind the key
            public = path in ("/", "/index.html", "/app.js", "/styles.css", "/ui/app.js")
            public = public or path in ("/ui", "/ui/index.html", "/ui/styles.css")
            if not public and not _authorized(self.headers):
                return self._send(401, _error(401, "unauthorized", rid), rid)
            if self._static(path):
                return None
        route = self.router.match(method, path)
        if route is None:
            return self._send(404, {**_error(404, "not found", rid), "path": path}, rid)
        fn, params = route
        if path not in ("/health", "/version") and not _authorized(self.headers):
            return self._send(401, _error(401, "unauthorized", rid), rid)
        presented = self.headers.get_all("X-Reviewer-Token") or []
        if len(presented) > 1:  # e.g. a proxy appended one: which one acts is ambiguous
            return self._send(400, _error(400, "more than one X-Reviewer-Token", rid), rid)
        REVIEWER_TOKEN.set(presented[0] if presented else None)
        body: Any = None
        if method == "POST":
            refusal = self._cross_site()
            if refusal is not None:
                return self._send(refusal[0], _error(refusal[0], refusal[1], rid), rid)
            try:
                length = int(self.headers.get("Content-Length", 0))
            except ValueError:
                return self._send(400, _error(400, "invalid Content-Length", rid), rid)
            if length < 0:
                return self._send(400, _error(400, "invalid Content-Length", rid), rid)
            if length > MAX_BODY:
                # Drain a bounded amount first: answering while the client is still sending
                # makes the client see a connection reset instead of the 413.
                left = min(length, 4 * MAX_BODY)
                while left > 0:
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        break
                    left -= len(chunk)
                self.close_connection = True
                return self._send(
                    413, _error(413, f"request too large (> {MAX_BODY} bytes)", rid), rid
                )
            raw = self.rfile.read(length) if length else b""
            try:
                # a duplicated key is refused, not silently resolved: two parsers could keep
                # different values (and a signed envelope must mean one thing)
                body = json.loads(raw or b"{}", object_pairs_hook=_no_duplicate_keys)
            except json.JSONDecodeError as e:
                return self._send(400, _error(400, f"invalid JSON: {e.msg}", rid), rid)
            except S.ValidationError as e:
                return self._send(400, _error(400, e.message, rid), rid)
            except ValueError as e:  # e.g. an integer longer than Python's parse limit
                return self._send(400, _error(400, f"invalid JSON: {e}", rid), rid)
        try:
            result = fn(query, body, params)
            status = 200
        except S.ValidationError as e:
            result, status = _error(e.status, e.message, rid), e.status
        except ApiError as e:
            result, status = _error(e.status, e.message, rid), e.status
        except ControlDowngrade as e:  # the engine refused to record a downgraded run
            result, status = _error(403, str(e), rid), 403
        except ValueError as e:  # e.g. a risk model applied to another surface
            result, status = _error(400, str(e), rid), 400
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


class BoundedServer(ThreadingHTTPServer):
    """A thread per connection, at most ``max_connections`` at once: past the cap a new
    connection is closed at once instead of holding a thread."""

    daemon_threads = True
    max_connections = 64

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self._slots = threading.BoundedSemaphore(self.max_connections)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(
    app: SentinelApp,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    insecure_demo: bool = False,
) -> ThreadingHTTPServer:
    """Bind the API. A non-loopback address needs an API key or ``insecure_demo``
    (``check_bind``); the check runs before the socket is opened."""
    check_bind(host, insecure_demo=insecure_demo)
    handler = type(
        "BoundHandler",
        (SentinelHandler,),
        {
            "app": app,
            "router": build_routes(app),
            "limiter": RateLimiter(int(os.environ.get("SENTINEL_RATE_LIMIT", "600"))),
            "insecure_demo": insecure_demo and not is_loopback(host),
            "loopback_bind": is_loopback(host),
        },
    )
    server_cls = type(
        "SentinelServer",
        (BoundedServer,),
        {
            "address_family": socket.AF_INET6 if ":" in host else socket.AF_INET,
            "max_connections": int(os.environ.get("SENTINEL_MAX_CONNECTIONS", "64")),
        },
    )
    return server_cls((host, port), handler)


def server_config(app: SentinelApp, host: str, port: int, *, insecure_demo: bool) -> dict[str, Any]:
    """What the server is running with, for the SERVER_START audit event and log line:
    fingerprints of configuration, never a key or a credential."""
    key = api_key()
    info = app.system_info()
    return {
        "version": __version__,
        "host": host,
        "port": port,
        "bind": "loopback" if is_loopback(host) else "network",
        "auth": "api_key" if key else "open",
        # whether a key is set and where from -- never a fingerprint of it (an unsalted hash
        # prefix of a guessable key is a guessing oracle)
        "api_key_source": (
            None if not key else "env" if os.environ.get("SENTINEL_API_KEY") else "file"
        ),
        "insecure_demo": bool(insecure_demo and not is_loopback(host)),
        "mode": info.get("mode"),
        "provider": info.get("provider"),
        "store": Path(app.store.path).name if app.store.path != ":memory:" else ":memory:",
        "require_signed_facts": app.runtime.require_signed_facts,
        "signed_policy": app.runtime.policies.signed,
        "trust": app.config_fingerprint()["trust"],
        "reviewers": app.config_fingerprint()["reviewers"],
        "rate_limit_per_min": int(os.environ.get("SENTINEL_RATE_LIMIT", "600")),
        "pid": os.getpid(),
    }


def serve(
    app: SentinelApp,
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    insecure_demo: bool = False,
) -> None:
    httpd = make_server(app, host, port, insecure_demo=insecure_demo)
    cfg = server_config(app, host, port, insecure_demo=insecure_demo)
    # the configuration a server ran with is part of the record: chained, then logged
    app.runtime.audit.append(
        actor="sentinel", workflow="system", action="SERVER_START", kind="system", detail=cfg
    )
    _log.warning("server start", extra={"detail": cfg})
    print(
        f"Sentinel v{__version__} API + console on http://{host}:{port}  mode={cfg['mode']}  "
        f"auth={cfg['auth']}  bind={cfg['bind']}  db={cfg['store']}"
    )
    if cfg["insecure_demo"]:
        _log.error(
            "INSECURE DEMO: serving without authentication on a network address",
            extra={"detail": {"host": host, "port": port}},
        )
        print(
            "WARNING: --insecure-demo: the API is reachable from the network WITHOUT "
            "authentication. Anyone who can reach it can request evaluations, read every "
            "decision and record case actions with a demo credential. Use only for a "
            "throwaway demo.",
            file=sys.stderr,
        )
    if hasattr(signal, "SIGHUP") and threading.current_thread() is threading.main_thread():
        # A deliberate reload of the trust store and reviewer registry (audited). The
        # handler only sets an event: a signal handler can be re-entered, and reloading in
        # it could deadlock on its own lock. A reloader thread does the work and never
        # lets a failure take the server down.
        wake = threading.Event()

        def reloader() -> None:
            while True:
                wake.wait()
                wake.clear()
                try:
                    app.reload_config("sighup")
                except Exception as e:  # noqa: BLE001 -- keep serving the old configuration
                    _log.error(
                        "configuration reload crashed",
                        extra={"detail": {"error": type(e).__name__}},
                    )

        threading.Thread(target=reloader, name="sentinel-reload", daemon=True).start()
        signal.signal(signal.SIGHUP, lambda *_: wake.set())
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
