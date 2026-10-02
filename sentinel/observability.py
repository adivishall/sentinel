"""Structured JSON logging with correlation ids.

Every line carries trace_id / request_id / decision_id where known, plus the
workflow, entity, risk, policy, capability and action fields the mandate asks
for -- and never raw untrusted text. Off by default (WARNING); set
SENTINEL_LOG=INFO to see per-decision lines."""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

trace_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("trace_id", default=None)
request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id", default=None)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "trace_id": trace_id.get(),
            "request_id": request_id.get(),
        }
        detail = getattr(record, "detail", None)
        if isinstance(detail, dict):
            payload.update(detail)
        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(_JsonFormatter())
        logger.addHandler(h)
        logger.setLevel(os.getenv("SENTINEL_LOG", "WARNING").upper())
        logger.propagate = False
    return logger


def new_trace() -> str:
    t = uuid.uuid4().hex[:16]
    trace_id.set(t)
    return t


def log_decision(logger: logging.Logger, decision: Any, *, risk_version: str | None = None) -> None:
    """One structured line per recorded decision: ids, versions, digests, provenance, who
    and what -- never prose, keys or credentials."""
    logger.info(
        "decision",
        extra={
            "detail": {
                "decision_id": decision.decision_id,
                "case_id": decision.case_id,
                "workflow": decision.workflow.value,
                "entity_id": decision.subject_id,
                "entity_type": decision.subject_type,
                "risk_score": decision.risk_score,
                "risk_level": decision.risk_level.value,
                "policy_version": f"{decision.policy.policy_id}@v{decision.policy.version}",
                "policy_hash": decision.policy.policy_hash,
                "policy_digest": decision.policy.policy_digest or None,
                "policy_release": decision.policy.release_status or None,
                "risk_version": risk_version,
                "facts_provenance": (
                    decision.provenance.status.value if decision.provenance is not None else None
                ),
                "actor": decision.authorization.actor.value,
                "authoritative": decision.authoritative,
                "policy_outcome": decision.policy.outcome.value,
                "capability": (
                    decision.requested_capability.value if decision.requested_capability else None
                ),
                "executed_capability": (
                    decision.executed_capability.value if decision.executed_capability else None
                ),
                "action": decision.final_action.value,
                "security_event": decision.security_event_id,
                "security_severity": decision.security_severity.value,
                "evidence_verdict": decision.evidence_verdict.value,
                "ai_recommendation": (
                    decision.ai_recommendation.recommended_action
                    if decision.ai_recommendation
                    else None
                ),
                "input_hash": decision.input_hash,
                "timestamp": decision.created_at,
            }
        },
    )


class Metrics:
    """Lightweight in-process counters (exposed by GET /v1/system)."""

    def __init__(self) -> None:
        self.counters: Counter[str] = Counter()
        self.latency_ms: dict[str, list[float]] = {}

    def inc(self, key: str, n: int = 1) -> None:
        self.counters[key] += n

    def observe(self, key: str, ms: float) -> None:
        self.latency_ms.setdefault(key, []).append(ms)
        if len(self.latency_ms[key]) > 5000:
            del self.latency_ms[key][:-5000]

    def snapshot(self) -> dict[str, Any]:
        out: dict[str, Any] = {"counters": dict(self.counters), "latency": {}}
        for k, v in self.latency_ms.items():
            s = sorted(v)
            n = len(s)
            out["latency"][k] = {
                "n": n,
                "p50_ms": round(s[n // 2], 3),
                "p95_ms": round(s[min(n - 1, int(n * 0.95))], 3),
                "p99_ms": round(s[min(n - 1, int(n * 0.99))], 3),
            }
        return out


METRICS = Metrics()
