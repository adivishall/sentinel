"""SQLite store: entity tables plus decision / evidence / audit / case tables.

All SQL lives here. Domain objects go in and come out; business logic never
sees a cursor. Nested objects are stored as JSON alongside the columns that
need indexing, which keeps the schema honest without an ORM."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from sentinel.audit.chain import UNREADABLE as _UNREADABLE
from sentinel.audit.chain import AuditIntegrityError
from sentinel.audit.chain import _decode as _decode_audit
from sentinel.domain.cases import Case, CaseEvent, HumanDecision
from sentinel.domain.decisions import Decision
from sentinel.domain.entities import (
    Account,
    Customer,
    Device,
    Dispute,
    KYBApplication,
    LoginSession,
    Merchant,
    PaymentInstrument,
    Transaction,
)
from sentinel.domain.enums import CasePriority, CaseStatus, FactKind, Workflow
from sentinel.domain.risk import RiskAssessment
from sentinel.domain.security import SecurityEvent
from sentinel.domain.serialization import to_dict

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS customers (customer_id TEXT PRIMARY KEY, name TEXT, home_country TEXT, segment TEXT, created_at TEXT, risk_level TEXT);
CREATE TABLE IF NOT EXISTS accounts (account_id TEXT PRIMARY KEY, customer_id TEXT, opened_at TEXT, status TEXT, payout_instrument_id TEXT, mfa_enabled INTEGER, status_since TEXT);
CREATE TABLE IF NOT EXISTS merchants (merchant_id TEXT PRIMARY KEY, name TEXT, mcc TEXT, mcc_risk TEXT, country TEXT, owner_id TEXT, domain TEXT, registered_at TEXT, registration_status TEXT, prior_flags INTEGER);
CREATE TABLE IF NOT EXISTS devices (device_id TEXT PRIMARY KEY, fingerprint TEXT, first_seen TEXT, platform TEXT);
CREATE TABLE IF NOT EXISTS account_devices (account_id TEXT, device_id TEXT, PRIMARY KEY (account_id, device_id));
CREATE TABLE IF NOT EXISTS payment_instruments (instrument_id TEXT PRIMARY KEY, account_id TEXT, kind TEXT, last4 TEXT, added_at TEXT, country TEXT, external_ref TEXT);
CREATE INDEX IF NOT EXISTS ix_instr_ref ON payment_instruments(external_ref);
CREATE TABLE IF NOT EXISTS transactions (transaction_id TEXT PRIMARY KEY, account_id TEXT, merchant_id TEXT, instrument_id TEXT, device_id TEXT, amount INTEGER, currency TEXT, timestamp TEXT, country TEXT, channel TEXT, auth_strength TEXT, delivery_status TEXT, counterparty_account_id TEXT, label TEXT, status TEXT DEFAULT 'settled');
CREATE INDEX IF NOT EXISTS ix_txn_account ON transactions(account_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_txn_merchant ON transactions(merchant_id);
CREATE INDEX IF NOT EXISTS ix_txn_ts ON transactions(timestamp);
CREATE TABLE IF NOT EXISTS disputes (dispute_id TEXT PRIMARY KEY, transaction_id TEXT, account_id TEXT, amount INTEGER, submitted_at TEXT, claim_type_declared TEXT, label TEXT, narrative TEXT, document TEXT, refund_state TEXT DEFAULT 'none', merchant_response TEXT DEFAULT 'none');
CREATE TABLE IF NOT EXISTS kyb_applications (application_id TEXT PRIMARY KEY, merchant_id TEXT, submitted_at TEXT, registration_status TEXT, domain_age_days INTEGER, business_age_days INTEGER, prior_flags INTEGER, mcc_risk TEXT, label TEXT, application TEXT, document TEXT);
CREATE TABLE IF NOT EXISTS login_sessions (session_id TEXT PRIMARY KEY, account_id TEXT, device_id TEXT, ip TEXT, country TEXT, started_at TEXT, mfa_passed INTEGER, events TEXT);
CREATE TABLE IF NOT EXISTS scenarios (scenario TEXT, label TEXT, entity_ids TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS risk_assessments (assessment_id TEXT PRIMARY KEY, entity_type TEXT, entity_id TEXT, score INTEGER, level TEXT, model_version TEXT, computed_at TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS ix_risk_entity ON risk_assessments(entity_type, entity_id);
CREATE TABLE IF NOT EXISTS risk_factors (assessment_id TEXT, code TEXT, points INTEGER, label TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS evidence (evidence_id TEXT, decision_id TEXT, kind TEXT, source TEXT, trust TEXT, field TEXT, value TEXT, status TEXT, content_hash TEXT, PRIMARY KEY (decision_id, evidence_id));
CREATE TABLE IF NOT EXISTS security_events (event_id TEXT PRIMARY KEY, agent TEXT, workflow TEXT, severity TEXT, threat_classes TEXT, requested_capability TEXT, ai_recommendation TEXT, final_action TEXT, decision_id TEXT, created_at TEXT, payload TEXT);
CREATE TABLE IF NOT EXISTS decisions (decision_id TEXT PRIMARY KEY, workflow TEXT, subject_type TEXT, subject_id TEXT, amount INTEGER, final_action TEXT, risk_score INTEGER, risk_level TEXT, evidence_verdict TEXT, security_severity TEXT, policy_id TEXT, policy_version INTEGER, policy_outcome TEXT, authorization TEXT, executed_capability TEXT, case_id TEXT, audit_event_id TEXT, created_at TEXT, payload TEXT, snapshot TEXT);
CREATE INDEX IF NOT EXISTS ix_dec_subject ON decisions(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS ix_dec_created ON decisions(created_at);
CREATE TABLE IF NOT EXISTS policy_decisions (decision_id TEXT PRIMARY KEY, policy_id TEXT, version INTEGER, outcome TEXT, matched_rules TEXT, context_hash TEXT);
CREATE TABLE IF NOT EXISTS ai_recommendations (decision_id TEXT PRIMARY KEY, agent TEXT, recommended_action TEXT, requested_capability TEXT, amount INTEGER, provider TEXT, model TEXT, latency_ms REAL, raw_hash TEXT);
CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, case_type TEXT, status TEXT, priority TEXT, title TEXT, created_at TEXT, updated_at TEXT, opened_by_rule TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS ix_cases_status ON cases(status, created_at);
CREATE TABLE IF NOT EXISTS audit_events (sequence INTEGER PRIMARY KEY, event_id TEXT UNIQUE, decision_id TEXT, previous_hash TEXT, event_hash TEXT, timestamp TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS ix_audit_decision ON audit_events(decision_id, sequence);
CREATE TABLE IF NOT EXISTS replays (replay_id TEXT PRIMARY KEY, decision_id TEXT, changed INTEGER, created_at TEXT, payload TEXT);
CREATE TABLE IF NOT EXISTS policy_versions (policy_id TEXT, version INTEGER, workflow TEXT, payload TEXT, PRIMARY KEY (policy_id, version));
CREATE TABLE IF NOT EXISTS fact_envelopes (record_key TEXT PRIMARY KEY, subject TEXT, kind TEXT, issuer TEXT, sequence INTEGER, envelope TEXT);
CREATE TABLE IF NOT EXISTS executions (key TEXT PRIMARY KEY, holder TEXT);
CREATE TABLE IF NOT EXISTS fact_sequences (issuer TEXT, subject TEXT, sequence INTEGER, envelope_digest TEXT, PRIMARY KEY (issuer, subject));
"""


def _j(obj: object) -> str:
    return json.dumps(to_dict(obj), sort_keys=True, default=str)


# where each kind of record is kept (code constants, never caller input)
_RECORD_TABLES: dict[FactKind, tuple[str, str]] = {
    FactKind.DISPUTE_LEDGER: ("disputes", "dispute_id"),
    FactKind.KYB_RECORD: ("kyb_applications", "application_id"),
    FactKind.TRANSACTION: ("transactions", "transaction_id"),
    FactKind.LOGIN_SESSION: ("login_sessions", "session_id"),
}


class SentinelStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(accounts)")}
            if "status_since" not in cols:  # a store created before 2.2.0
                self._conn.execute("ALTER TABLE accounts ADD COLUMN status_since TEXT")
            self._conn.commit()

    # ---- generic ------------------------------------------------------------------
    def _exec(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _many(self, sql: str, rows: list[tuple[Any, ...]]) -> None:
        with self._lock:
            self._conn.executemany(sql, rows)
            self._conn.commit()

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def _one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))

    def get_meta(self, key: str) -> str | None:
        r = self._one("SELECT value FROM meta WHERE key = ?", (key,))
        return str(r["value"]) if r else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- dataset load ---------------------------------------------------------------
    def load_dataset(self, ds: Any) -> None:
        self._many(
            "INSERT OR REPLACE INTO customers VALUES (?,?,?,?,?,?)",
            [
                (c.customer_id, c.name, c.home_country, c.segment, c.created_at, c.risk_level.value)
                for c in ds.customers
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO accounts VALUES (?,?,?,?,?,?,?)",
            [
                (
                    a.account_id,
                    a.customer_id,
                    a.opened_at,
                    a.status,
                    a.payout_instrument_id,
                    int(a.mfa_enabled),
                    a.status_since,
                )
                for a in ds.accounts
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO merchants VALUES (?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    m.merchant_id,
                    m.name,
                    m.mcc,
                    m.mcc_risk,
                    m.country,
                    m.owner_id,
                    m.domain,
                    m.registered_at,
                    m.registration_status,
                    m.prior_flags,
                )
                for m in ds.merchants
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO devices VALUES (?,?,?,?)",
            [(d.device_id, d.fingerprint, d.first_seen, d.platform) for d in ds.devices],
        )
        self._many(
            "INSERT OR REPLACE INTO account_devices VALUES (?,?)",
            [(a, d) for a, devs in ds.account_devices.items() for d in devs],
        )
        self._many(
            "INSERT OR REPLACE INTO payment_instruments VALUES (?,?,?,?,?,?,?)",
            [
                (
                    i.instrument_id,
                    i.account_id,
                    i.kind,
                    i.last4,
                    i.added_at,
                    i.country,
                    i.external_ref,
                )
                for i in ds.instruments
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    t.transaction_id,
                    t.account_id,
                    t.merchant_id,
                    t.instrument_id,
                    t.device_id,
                    t.amount,
                    t.currency,
                    t.timestamp,
                    t.country,
                    t.channel,
                    t.auth_strength,
                    t.delivery_status,
                    t.counterparty_account_id,
                    t.label,
                    t.status,
                )
                for t in ds.transactions
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO disputes VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    d.dispute_id,
                    d.transaction_id,
                    d.account_id,
                    d.amount,
                    d.submitted_at,
                    d.claim_type_declared,
                    d.label,
                    ds.narratives.get(d.dispute_id, {}).get("narrative"),
                    ds.narratives.get(d.dispute_id, {}).get("document"),
                    d.refund_state,
                    d.merchant_response,
                )
                for d in ds.disputes
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO kyb_applications VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    k.application_id,
                    k.merchant_id,
                    k.submitted_at,
                    k.registration_status,
                    k.domain_age_days,
                    k.business_age_days,
                    k.prior_flags,
                    k.mcc_risk,
                    k.label,
                    ds.narratives.get(k.application_id, {}).get("application"),
                    ds.narratives.get(k.application_id, {}).get("document"),
                )
                for k in ds.kyb_applications
            ],
        )
        self._many(
            "INSERT OR REPLACE INTO login_sessions VALUES (?,?,?,?,?,?,?,?)",
            [
                (
                    s.session_id,
                    s.account_id,
                    s.device_id,
                    s.ip,
                    s.country,
                    s.started_at,
                    int(s.mfa_passed),
                    json.dumps(list(s.events)),
                )
                for s in ds.sessions
            ],
        )
        self._exec("DELETE FROM scenarios")
        self._many(
            "INSERT INTO scenarios VALUES (?,?,?,?)",
            [
                (s.scenario, s.label, json.dumps(list(s.entity_ids)), s.description)
                for s in ds.scenarios
            ],
        )
        self.set_meta("dataset_seed", str(ds.seed))
        self.set_meta("as_of", ds.as_of)
        self.set_meta("profile", getattr(ds, "profile", "balanced"))

    # ---- entity reads -----------------------------------------------------------------
    def customer(self, cid: str) -> Customer | None:
        r = self._one("SELECT * FROM customers WHERE customer_id = ?", (cid,))
        return (
            Customer(r["customer_id"], r["name"], r["home_country"], r["segment"], r["created_at"])
            if r
            else None
        )

    def account(self, aid: str) -> Account | None:
        r = self._one("SELECT * FROM accounts WHERE account_id = ?", (aid,))
        return (
            Account(
                r["account_id"],
                r["customer_id"],
                r["opened_at"],
                r["status"],
                r["payout_instrument_id"],
                bool(r["mfa_enabled"]),
                r["status_since"],
            )
            if r
            else None
        )

    def accounts(self) -> list[Account]:
        return [
            Account(
                r["account_id"],
                r["customer_id"],
                r["opened_at"],
                r["status"],
                r["payout_instrument_id"],
                bool(r["mfa_enabled"]),
                r["status_since"],
            )
            for r in self._rows("SELECT * FROM accounts")
        ]

    def merchant(self, mid: str) -> Merchant | None:
        r = self._one("SELECT * FROM merchants WHERE merchant_id = ?", (mid,))
        return self._merchant(r) if r else None

    @staticmethod
    def _merchant(r: sqlite3.Row) -> Merchant:
        return Merchant(
            r["merchant_id"],
            r["name"],
            r["mcc"],
            r["mcc_risk"],
            r["country"],
            r["owner_id"],
            r["domain"],
            r["registered_at"],
            r["registration_status"],
            r["prior_flags"],
        )

    def merchants(self) -> list[Merchant]:
        return [
            self._merchant(r) for r in self._rows("SELECT * FROM merchants ORDER BY merchant_id")
        ]

    def device(self, did: str) -> Device | None:
        r = self._one("SELECT * FROM devices WHERE device_id = ?", (did,))
        return (
            Device(r["device_id"], r["fingerprint"], r["first_seen"], r["platform"]) if r else None
        )

    def devices(self) -> list[Device]:
        return [
            Device(r["device_id"], r["fingerprint"], r["first_seen"], r["platform"])
            for r in self._rows("SELECT * FROM devices")
        ]

    def account_devices(self, aid: str) -> list[str]:
        return [
            str(r["device_id"])
            for r in self._rows(
                "SELECT device_id FROM account_devices WHERE account_id = ?", (aid,)
            )
        ]

    def all_account_devices(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for r in self._rows("SELECT account_id, device_id FROM account_devices"):
            out.setdefault(str(r["account_id"]), []).append(str(r["device_id"]))
        return out

    @staticmethod
    def _instrument(r: sqlite3.Row) -> PaymentInstrument:
        return PaymentInstrument(
            r["instrument_id"],
            r["account_id"],
            r["kind"],
            r["last4"],
            r["added_at"],
            r["country"],
            r["external_ref"],
        )

    def instrument(self, iid: str) -> PaymentInstrument | None:
        r = self._one("SELECT * FROM payment_instruments WHERE instrument_id = ?", (iid,))
        return self._instrument(r) if r else None

    def instruments(self) -> list[PaymentInstrument]:
        return [self._instrument(r) for r in self._rows("SELECT * FROM payment_instruments")]

    def instruments_for(self, account_id: str) -> list[PaymentInstrument]:
        return [
            self._instrument(r)
            for r in self._rows(
                "SELECT * FROM payment_instruments WHERE account_id = ? ORDER BY added_at",
                (account_id,),
            )
        ]

    @staticmethod
    def _txn(r: sqlite3.Row) -> Transaction:
        return Transaction(
            r["transaction_id"],
            r["account_id"],
            r["merchant_id"],
            r["instrument_id"],
            r["device_id"],
            r["amount"],
            r["currency"],
            r["timestamp"],
            r["country"],
            r["channel"],
            r["auth_strength"],
            r["delivery_status"],
            r["counterparty_account_id"],
            r["label"],
            r["status"] or "settled",
        )

    def held_id(self, kind: FactKind, rid: str) -> str | None:
        """The stored record id equal to ``rid`` ignoring ASCII case, if the store holds
        one: ``tx-000123`` names ``TX-000123`` and is refused as a new subject."""
        table, column = _RECORD_TABLES[kind]
        r = self._one(f"SELECT {column} FROM {table} WHERE {column} = ? COLLATE NOCASE", (rid,))
        return str(r[0]) if r else None

    def transaction(self, tid: str) -> Transaction | None:
        r = self._one("SELECT * FROM transactions WHERE transaction_id = ?", (tid,))
        return self._txn(r) if r else None

    def transactions(
        self,
        *,
        account_id: str | None = None,
        merchant_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order: str = "DESC",
    ) -> list[Transaction]:
        where, params = [], []
        if account_id:
            where.append("account_id = ?")
            params.append(account_id)
        if merchant_id:
            where.append("merchant_id = ?")
            params.append(merchant_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        o = "DESC" if order.upper() == "DESC" else "ASC"
        return [
            self._txn(r)
            for r in self._rows(
                f"SELECT * FROM transactions {w} ORDER BY timestamp {o} LIMIT ? OFFSET ?",
                (*params, limit, offset),
            )
        ]

    def all_transactions(self) -> list[Transaction]:
        return [self._txn(r) for r in self._rows("SELECT * FROM transactions ORDER BY timestamp")]

    def transactions_before(self, account_id: str, ts: str, limit: int = 500) -> list[Transaction]:
        return [
            self._txn(r)
            for r in self._rows(
                "SELECT * FROM transactions WHERE account_id = ? AND timestamp < ? ORDER BY timestamp DESC LIMIT ?",
                (account_id, ts, limit),
            )
        ][::-1]

    def inbound_transfers(self, account_id: str) -> list[Transaction]:
        return [
            self._txn(r)
            for r in self._rows(
                "SELECT * FROM transactions WHERE counterparty_account_id = ? ORDER BY timestamp",
                (account_id,),
            )
        ]

    def count(self, table: str) -> int:
        r = self._one(f"SELECT COUNT(*) AS n FROM {table}")  # table names are internal constants
        return int(r["n"]) if r else 0

    @staticmethod
    def _dispute(r: sqlite3.Row) -> Dispute:
        return Dispute(
            r["dispute_id"],
            r["transaction_id"],
            r["account_id"],
            r["amount"],
            r["submitted_at"],
            r["claim_type_declared"],
            r["label"],
            r["refund_state"] or "none",
            r["merchant_response"] or "none",
        )

    def dispute(self, did: str) -> tuple[Dispute, dict[str, str]] | None:
        r = self._one("SELECT * FROM disputes WHERE dispute_id = ?", (did,))
        if not r:
            return None
        texts = {k: r[k] for k in ("narrative", "document") if r[k]}
        return self._dispute(r), texts

    def disputes(self, *, account_id: str | None = None, limit: int = 100) -> list[Dispute]:
        if account_id:
            return [
                self._dispute(r)
                for r in self._rows(
                    "SELECT * FROM disputes WHERE account_id = ? ORDER BY submitted_at DESC LIMIT ?",
                    (account_id, limit),
                )
            ]
        return [
            self._dispute(r)
            for r in self._rows(
                "SELECT * FROM disputes ORDER BY submitted_at DESC LIMIT ?", (limit,)
            )
        ]

    def all_disputes(self) -> list[Dispute]:
        return [self._dispute(r) for r in self._rows("SELECT * FROM disputes")]

    def kyb_application(self, app_id: str) -> tuple[KYBApplication, dict[str, str]] | None:
        r = self._one("SELECT * FROM kyb_applications WHERE application_id = ?", (app_id,))
        if not r:
            return None
        return KYBApplication(
            r["application_id"],
            r["merchant_id"],
            r["submitted_at"],
            r["registration_status"],
            r["domain_age_days"],
            r["business_age_days"],
            r["prior_flags"],
            r["mcc_risk"],
            r["label"],
        ), {k: r[k] for k in ("application", "document") if r[k]}

    def kyb_applications(self, limit: int = 100) -> list[KYBApplication]:
        return [
            KYBApplication(
                r["application_id"],
                r["merchant_id"],
                r["submitted_at"],
                r["registration_status"],
                r["domain_age_days"],
                r["business_age_days"],
                r["prior_flags"],
                r["mcc_risk"],
                r["label"],
            )
            for r in self._rows(
                "SELECT * FROM kyb_applications ORDER BY submitted_at DESC LIMIT ?", (limit,)
            )
        ]

    @staticmethod
    def _session(r: sqlite3.Row) -> LoginSession:
        return LoginSession(
            r["session_id"],
            r["account_id"],
            r["device_id"],
            r["ip"],
            r["country"],
            r["started_at"],
            bool(r["mfa_passed"]),
            tuple(json.loads(r["events"] or "[]")),
        )

    def session(self, sid: str) -> LoginSession | None:
        r = self._one("SELECT * FROM login_sessions WHERE session_id = ?", (sid,))
        return self._session(r) if r else None

    def sessions(self, *, account_id: str | None = None, limit: int = 100) -> list[LoginSession]:
        if account_id:
            return [
                self._session(r)
                for r in self._rows(
                    "SELECT * FROM login_sessions WHERE account_id = ? ORDER BY started_at DESC LIMIT ?",
                    (account_id, limit),
                )
            ]
        return [
            self._session(r)
            for r in self._rows(
                "SELECT * FROM login_sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            )
        ]

    def scenarios(self) -> list[dict[str, Any]]:
        return [
            {
                "scenario": r["scenario"],
                "label": r["label"],
                "entity_ids": json.loads(r["entity_ids"]),
                "description": r["description"],
            }
            for r in self._rows("SELECT * FROM scenarios")
        ]

    # ---- decisions & friends -----------------------------------------------------------
    def save_risk_assessment(self, ra: RiskAssessment) -> None:
        self._exec(
            "INSERT OR REPLACE INTO risk_assessments VALUES (?,?,?,?,?,?,?,?)",
            (
                ra.assessment_id,
                ra.entity_type,
                ra.entity_id,
                ra.score,
                ra.level.value,
                ra.model_version,
                ra.computed_at,
                _j(ra),
            ),
        )
        self._many(
            "INSERT INTO risk_factors VALUES (?,?,?,?,?)",
            [(ra.assessment_id, f.code, f.points, f.label, f.detail) for f in ra.factors],
        )

    def risk_assessment(self, aid: str) -> dict[str, Any] | None:
        r = self._one("SELECT payload FROM risk_assessments WHERE assessment_id = ?", (aid,))
        return json.loads(r["payload"]) if r else None

    def save_security_event(self, ev: SecurityEvent) -> None:
        self._exec(
            "INSERT OR REPLACE INTO security_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                ev.event_id,
                ev.agent,
                ev.workflow,
                ev.severity.value,
                json.dumps([t.value for t in ev.threat_classes]),
                ev.requested_capability.value if ev.requested_capability else None,
                ev.ai_recommendation,
                ev.final_action,
                ev.decision_id,
                ev.created_at,
                _j(ev),
            ),
        )

    def security_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return [
            json.loads(r["payload"])
            for r in self._rows(
                "SELECT payload FROM security_events ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        ]

    def security_event(self, eid: str) -> dict[str, Any] | None:
        r = self._one("SELECT payload FROM security_events WHERE event_id = ?", (eid,))
        return json.loads(r["payload"]) if r else None

    def security_events_for_decision(self, did: str) -> list[dict[str, Any]]:
        return [
            json.loads(r["payload"])
            for r in self._rows(
                "SELECT payload FROM security_events WHERE decision_id = ? ORDER BY created_at",
                (did,),
            )
        ]

    def risk_evolution(self, account_id: str, limit: int = 60) -> list[dict[str, Any]]:
        """Risk over time for an account: every stored transaction decision on the
        account's transactions plus the account-level investigations, ordered by the
        event time the decision was about (the transaction time, or the decision time
        for investigations)."""
        rows = self._rows(
            "SELECT d.decision_id, d.subject_type, d.subject_id, d.risk_score, d.risk_level, "
            "d.final_action, d.created_at, t.timestamp AS event_time, t.amount AS amount "
            "FROM decisions d JOIN transactions t ON t.transaction_id = d.subject_id "
            "WHERE d.workflow = 'transaction' AND t.account_id = ? "
            "UNION ALL "
            "SELECT decision_id, subject_type, subject_id, risk_score, risk_level, final_action, "
            "created_at, created_at AS event_time, amount FROM decisions "
            "WHERE workflow = 'investigation' AND subject_id = ? "
            "ORDER BY event_time DESC LIMIT ?",
            (account_id, account_id, limit),
        )
        return [dict(r) for r in rows][::-1]

    def save_decision(
        self, d: Decision, snapshot: dict[str, Any], evidence: list[dict[str, Any]]
    ) -> None:
        self._exec(
            "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                d.decision_id,
                d.workflow.value,
                d.subject_type,
                d.subject_id,
                d.amount,
                d.final_action.value,
                d.risk_score,
                d.risk_level.value,
                d.evidence_verdict.value,
                d.security_severity.value,
                d.policy.policy_id,
                d.policy.version,
                d.policy.outcome.value,
                d.authorization.status.value,
                d.executed_capability.value if d.executed_capability else None,
                d.case_id,
                d.audit_event_id,
                d.created_at,
                _j(d),
                json.dumps(snapshot, sort_keys=True, default=str),
            ),
        )
        self._exec(
            "INSERT OR REPLACE INTO policy_decisions VALUES (?,?,?,?,?,?)",
            (
                d.decision_id,
                d.policy.policy_id,
                d.policy.version,
                d.policy.outcome.value,
                json.dumps(list(d.policy.matched_rules)),
                d.policy.context_hash,
            ),
        )
        if d.ai_recommendation:
            a = d.ai_recommendation
            self._exec(
                "INSERT OR REPLACE INTO ai_recommendations VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    d.decision_id,
                    a.agent,
                    a.recommended_action,
                    a.requested_capability.value if a.requested_capability else None,
                    a.amount,
                    a.provider,
                    a.model,
                    a.latency_ms,
                    a.raw_hash,
                ),
            )
        self._many(
            "INSERT OR REPLACE INTO evidence VALUES (?,?,?,?,?,?,?,?,?)",
            [
                (
                    e["evidence_id"],
                    d.decision_id,
                    e["kind"],
                    e["source"],
                    e["trust"],
                    e["field"],
                    json.dumps(e["value"]),
                    e["status"],
                    e.get("content_hash", ""),
                )
                for e in evidence
            ],
        )

    def decision(self, did: str) -> dict[str, Any] | None:
        r = self._one("SELECT payload FROM decisions WHERE decision_id = ?", (did,))
        return json.loads(r["payload"]) if r else None

    def decision_snapshot(self, did: str) -> dict[str, Any] | None:
        r = self._one("SELECT snapshot FROM decisions WHERE decision_id = ?", (did,))
        return json.loads(r["snapshot"]) if r else None

    def decisions(
        self, *, workflow: str | None = None, subject_id: str | None = None, limit: int = 100
    ) -> list[dict[str, Any]]:
        where, params = [], []
        if workflow:
            where.append("workflow = ?")
            params.append(workflow)
        if subject_id:
            where.append("subject_id = ?")
            params.append(subject_id)
        w = ("WHERE " + " AND ".join(where)) if where else ""
        return [
            json.loads(r["payload"])
            for r in self._rows(
                f"SELECT payload FROM decisions {w} ORDER BY created_at DESC LIMIT ?",
                (*params, limit),
            )
        ]

    def evidence_for(self, did: str) -> list[dict[str, Any]]:
        return [
            {**dict(r), "value": json.loads(r["value"])}
            for r in self._rows("SELECT * FROM evidence WHERE decision_id = ?", (did,))
        ]

    def save_replay(
        self,
        replay_id: str,
        decision_id: str,
        changed: bool,
        created_at: str,
        payload: dict[str, Any],
    ) -> None:
        self._exec(
            "INSERT OR REPLACE INTO replays VALUES (?,?,?,?,?)",
            (replay_id, decision_id, int(changed), created_at, json.dumps(payload, default=str)),
        )

    def replays(self, limit: int = 50) -> list[dict[str, Any]]:
        return [
            json.loads(r["payload"])
            for r in self._rows(
                "SELECT payload FROM replays ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        ]

    def replay(self, rid: str) -> dict[str, Any] | None:
        r = self._one("SELECT payload FROM replays WHERE replay_id = ?", (rid,))
        return json.loads(r["payload"]) if r else None

    def save_policy_version(
        self, policy_id: str, version: int, workflow: str, payload: dict[str, Any]
    ) -> None:
        self._exec(
            "INSERT OR REPLACE INTO policy_versions VALUES (?,?,?,?)",
            (policy_id, version, workflow, json.dumps(payload)),
        )

    # ---- signed fact envelopes (sentinel.trust) ---------------------------------------
    def save_fact_envelopes(self, envelopes: list[tuple[str, dict[str, Any]]]) -> None:
        """Keep one statement per record (``record_key``: ``dispute:<id>``,
        ``application:<id>``, ...). Stored as received: verification happens every time one
        is used, so a row edited here fails verification rather than changing a decision."""
        self._many(
            "INSERT OR REPLACE INTO fact_envelopes VALUES (?,?,?,?,?,?)",
            [
                (
                    key,
                    str(e["subject"]),
                    str(e["kind"]),
                    str(e["issuer"]),
                    int(e["sequence"]),
                    json.dumps(e),
                )
                for key, e in envelopes
            ],
        )

    def fact_envelope(self, record_key: str) -> dict[str, Any] | None:
        r = self._one("SELECT envelope FROM fact_envelopes WHERE record_key = ?", (record_key,))
        return json.loads(r["envelope"]) if r else None

    def fact_sequence(self, issuer: str, subject: str) -> tuple[int, str] | None:
        r = self._one(
            "SELECT sequence, envelope_digest FROM fact_sequences WHERE issuer = ? AND subject = ?",
            (issuer, subject),
        )
        return (int(r["sequence"]), str(r["envelope_digest"])) if r else None

    def fact_sequence_from_audit(self, issuer: str, subject: str) -> tuple[int, str] | None:
        """The highest statement a recorded decision acted on, read from the audit chain:
        every decision event names the statement it used (``detail.facts``). A DB writer
        who deletes ``fact_sequences`` rows must also rewrite the chain to roll back."""
        r = self._one(
            "SELECT json_extract(p, '$.detail.facts.sequence') AS seq, "
            "json_extract(p, '$.detail.facts.envelope_digest') AS dig FROM "
            "(SELECT CASE WHEN json_valid(payload) THEN payload ELSE '{}' END AS p "
            "FROM audit_events) "
            "WHERE json_extract(p, '$.detail.facts.status') = 'VERIFIED_EXTERNAL' "
            "AND json_extract(p, '$.detail.facts.source') = ? "
            "AND json_extract(p, '$.detail.facts.subject') = ? "
            "ORDER BY seq DESC LIMIT 1",
            (issuer, subject),
        )
        return (int(r["seq"]), str(r["dig"])) if r and r["seq"] is not None else None

    def policy_activation_floor(self) -> dict[str, int]:
        """The highest policy activation each policy's decisions were made under, read from
        the tamper-evident audit chain: an older activation is a rollback."""
        # an unreadable record is the chain verifier's to report, not a reason to crash here
        rows = self._rows(
            "SELECT json_extract(p, '$.policy_id') AS pid, "
            "MAX(json_extract(p, '$.detail.policy_release.activation_sequence')) AS seq FROM "
            "(SELECT CASE WHEN json_valid(payload) THEN payload ELSE '{}' END AS p "
            "FROM audit_events) WHERE json_extract(p, "
            "'$.detail.policy_release.activation_sequence') IS NOT NULL GROUP BY pid"
        )
        return {str(r["pid"]): int(r["seq"]) for r in rows if r["pid"] is not None}

    def advance_fact_sequence(
        self, issuer: str, subject: str, sequence: int, envelope_digest: str
    ) -> None:
        """Record that a statement was acted on; the high-water mark only moves forward."""
        self._exec(
            "INSERT INTO fact_sequences VALUES (?,?,?,?) ON CONFLICT(issuer, subject) DO UPDATE "
            "SET sequence = excluded.sequence, envelope_digest = excluded.envelope_digest "
            "WHERE excluded.sequence > fact_sequences.sequence",
            (issuer, subject, sequence, envelope_digest),
        )

    def policy_payload(self, policy_id: str, version: int) -> dict[str, Any] | None:
        r = self._one(
            "SELECT payload FROM policy_versions WHERE policy_id = ? AND version = ?",
            (policy_id, version),
        )
        return json.loads(r["payload"]) if r else None

    def to_dataset(self) -> Any:
        """Rebuild an in-memory Dataset (for the graph / entity engine)."""
        from sentinel.data.generator import Dataset, ScenarioTag

        ds = Dataset(
            seed=int(self.get_meta("dataset_seed") or 0),
            as_of=self.get_meta("as_of") or "",
            profile=self.get_meta("profile") or "balanced",
        )
        ds.customers = [
            Customer(r["customer_id"], r["name"], r["home_country"], r["segment"], r["created_at"])
            for r in self._rows("SELECT * FROM customers")
        ]
        ds.accounts = self.accounts()
        ds.merchants = self.merchants()
        ds.devices = self.devices()
        ds.instruments = self.instruments()
        ds.transactions = self.all_transactions()
        ds.disputes = self.all_disputes()
        ds.kyb_applications = self.kyb_applications(limit=1_000_000)
        ds.sessions = self.sessions(limit=1_000_000)
        ds.account_devices = self.all_account_devices()
        ds.scenarios = [
            ScenarioTag(s["scenario"], s["label"], tuple(s["entity_ids"]), s["description"])
            for s in self.scenarios()
        ]
        for r in self._rows("SELECT dispute_id, narrative, document FROM disputes"):
            ds.narratives[r["dispute_id"]] = {k: r[k] for k in ("narrative", "document") if r[k]}
        for r in self._rows("SELECT application_id, application, document FROM kyb_applications"):
            ds.narratives[r["application_id"]] = {
                k: r[k] for k in ("application", "document") if r[k]
            }
        return ds

    # ---- aggregate stats for the dashboard ------------------------------------------------
    def stats(self) -> dict[str, Any]:
        def count(sql: str, *p: Any) -> int:
            r = self._one(sql, p)
            return int(r[0]) if r else 0

        def grouped(sql: str) -> dict[str, int]:
            return {str(r[0]): int(r[1]) for r in self._rows(sql)}

        return {
            "transactions": count("SELECT COUNT(*) FROM transactions"),
            "transactions_analyzed": count(
                "SELECT COUNT(*) FROM decisions WHERE workflow = 'transaction'"
            ),
            "high_risk_transactions": count(
                "SELECT COUNT(*) FROM decisions WHERE workflow = 'transaction' AND risk_level IN ('HIGH','CRITICAL')"
            ),
            "blocked_capabilities": count(
                "SELECT COUNT(*) FROM decisions WHERE final_action IN ('BLOCK','DENY') AND policy_outcome = 'BLOCK'"
            ),
            "cases_requiring_review": count(
                "SELECT COUNT(*) FROM cases WHERE status IN ('OPEN','TRIAGE','INVESTIGATING','WAITING_HUMAN','ESCALATED')"
            ),
            "open_investigations": count(
                "SELECT COUNT(*) FROM cases WHERE case_type = 'investigation' AND status != 'RESOLVED'"
            ),
            "ai_security_events": count("SELECT COUNT(*) FROM security_events"),
            "dispute_exposure": count(
                "SELECT COALESCE(SUM(amount),0) FROM decisions WHERE workflow = 'dispute' AND final_action IN ('REQUIRE_HUMAN_REVIEW','TEMPORARY_HOLD')"
            ),
            "refunds_prevented": count(
                "SELECT COALESCE(SUM(d.amount),0) FROM decisions d JOIN ai_recommendations a ON a.decision_id = d.decision_id "
                "WHERE d.workflow = 'dispute' AND d.final_action IN ('DENY','BLOCK') AND a.requested_capability IS NOT NULL"
            ),
            "ai_overruled": count(
                "SELECT COUNT(*) FROM decisions d JOIN ai_recommendations a ON a.decision_id = d.decision_id "
                "WHERE a.requested_capability IS NOT NULL AND d.final_action != 'ALLOW'"
            ),
            "merchants_high_risk": count(
                "SELECT COUNT(*) FROM risk_assessments WHERE entity_type = 'merchant' AND level IN ('HIGH','CRITICAL')"
            ),
            "decisions": count("SELECT COUNT(*) FROM decisions"),
            "audit_events": count("SELECT COUNT(*) FROM audit_events"),
            "risk_distribution": grouped(
                "SELECT risk_level, COUNT(*) FROM decisions WHERE workflow = 'transaction' GROUP BY risk_level"
            ),
            "decision_outcomes": grouped(
                "SELECT final_action, COUNT(*) FROM decisions GROUP BY final_action"
            ),
            "policy_actions": grouped(
                "SELECT policy_outcome, COUNT(*) FROM decisions GROUP BY policy_outcome"
            ),
            "security_severity": grouped(
                "SELECT severity, COUNT(*) FROM security_events GROUP BY severity"
            ),
            "case_funnel": grouped("SELECT status, COUNT(*) FROM cases GROUP BY status"),
            "workflow_counts": grouped(
                "SELECT workflow, COUNT(*) FROM decisions GROUP BY workflow"
            ),
        }

    def attack_classes(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self._rows("SELECT threat_classes FROM security_events"):
            for c in json.loads(r["threat_classes"] or "[]"):
                out[c] = out.get(c, 0) + 1
        return out

    def risk_over_time(self, buckets: int = 30) -> list[dict[str, Any]]:
        """Average transaction risk per day of the *transaction* (not of the decision:
        a batch run scores months of history in seconds)."""
        rows = self._rows(
            "SELECT substr(t.timestamp, 1, 10) AS h, AVG(d.risk_score) AS avg_score, COUNT(*) AS n, SUM(CASE WHEN d.risk_level IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS high FROM decisions d JOIN transactions t ON t.transaction_id = d.subject_id WHERE d.workflow = 'transaction' GROUP BY h ORDER BY h DESC LIMIT ?",
            (buckets,),
        )
        return [
            {
                "bucket": r["h"],
                "avg_score": round(float(r["avg_score"] or 0), 1),
                "n": int(r["n"]),
                "high": int(r["high"]),
            }
            for r in rows
        ][::-1]


# ---- repository adapters ---------------------------------------------------------------
class SqliteAuditBackend:
    def __init__(self, store: SentinelStore) -> None:
        self.store = store

    def append(self, record: dict[str, object]) -> None:
        try:
            self.store._exec(
                "INSERT INTO audit_events VALUES (?,?,?,?,?,?,?)",
                (
                    record["sequence"],
                    record["event_id"],
                    record.get("decision_id"),
                    record["previous_hash"],
                    record["event_hash"],
                    record["timestamp"],
                    json.dumps(record, sort_keys=True, default=str),
                ),
            )
        except sqlite3.IntegrityError as e:
            raise AuditIntegrityError(
                f"audit chain is inconsistent: sequence {record['sequence']} already exists in the "
                "store (a record was deleted or inserted underneath the chain); refusing to append "
                "-- run `sentinel audit verify`"
            ) from e

    _COLS = "sequence, event_id, decision_id, event_hash, payload"

    @staticmethod
    def _checked(r: Any) -> dict[str, object]:
        """The hashed payload, cross-checked against the index columns a lookup used:
        a side column edited to redirect a lookup is tampering that verify() (which
        reads payloads only) would not see."""
        rec = _decode_audit(r["payload"])
        if _UNREADABLE in rec:
            return rec
        if (
            rec.get("sequence") != r["sequence"]
            or rec.get("event_id") != r["event_id"]
            or rec.get("decision_id") != r["decision_id"]
            or rec.get("event_hash") != r["event_hash"]
        ):
            raise AuditIntegrityError(
                f"audit index columns for sequence {r['sequence']} do not match the hashed "
                "record (index tampered); run `sentinel audit verify`"
            )
        return rec

    def read_all(self) -> list[dict[str, object]]:
        return [
            _decode_audit(r["payload"])
            for r in self.store._rows("SELECT payload FROM audit_events ORDER BY sequence")
        ]

    def count(self) -> int:
        return self.store.count("audit_events")

    def at(self, sequence: int) -> dict[str, object] | None:
        r = self.store._one(
            f"SELECT {self._COLS} FROM audit_events WHERE sequence = ?", (sequence,)
        )
        return self._checked(r) if r else None

    def tail(self, n: int) -> list[dict[str, object]]:
        rows = self.store._rows(
            f"SELECT {self._COLS} FROM audit_events ORDER BY sequence DESC LIMIT ?", (max(0, n),)
        )
        return [self._checked(r) for r in rows][::-1]

    def find(
        self, event_id: str | None = None, decision_id: str | None = None
    ) -> dict[str, object] | None:
        if event_id is not None:
            r = self.store._one(
                f"SELECT {self._COLS} FROM audit_events WHERE event_id = ?", (event_id,)
            )
            if r:
                return self._checked(r)
        if decision_id is not None:
            r = self.store._one(
                f"SELECT {self._COLS} FROM audit_events WHERE decision_id = ? ORDER BY sequence LIMIT 1",
                (decision_id,),
            )
            if r:
                return self._checked(r)
        return None


# the amount of a stored case whose amount was never recorded: larger than any real limit
UNBOUNDED_AMOUNT = 2**53 - 1


class SqliteCaseRepository:
    def __init__(self, store: SentinelStore) -> None:
        self.store = store

    def save(self, case: Case) -> None:
        self.store._exec(
            "INSERT OR REPLACE INTO cases VALUES (?,?,?,?,?,?,?,?,?)",
            (
                case.case_id,
                case.case_type.value,
                case.status.value,
                case.priority.value,
                case.title,
                case.created_at,
                case.updated_at,
                case.opened_by_rule,
                _j(case),
            ),
        )

    def _amount(self, p: dict[str, Any]) -> int:
        """A case's amount. A case stored before amounts were recorded takes its decision's;
        one with a capability and no amount anywhere is treated as unbounded, so no finite
        authority limit covers it (fail closed, not open)."""
        if "amount" in p:
            return int(p["amount"])
        if p.get("decision_ids"):
            r = self.store._one(
                "SELECT amount FROM decisions WHERE decision_id = ?", (p["decision_ids"][0],)
            )
            if r is not None and r["amount"] is not None:
                return int(r["amount"])
        return UNBOUNDED_AMOUNT if p.get("capability") else 0

    def _from(self, payload: dict[str, Any]) -> Case:
        p = payload
        return Case(
            p["case_id"],
            Workflow(p["case_type"]),
            CaseStatus(p["status"]),
            CasePriority(p["priority"]),
            p["title"],
            tuple(p["entities"]),
            tuple(p["decision_ids"]),
            tuple(p["risk_assessment_ids"]),
            tuple(p["evidence_ids"]),
            tuple(p["security_event_ids"]),
            tuple(p["ai_recommendations"]),
            tuple(p["policy_decisions"]),
            tuple(HumanDecision(**h) for h in p["human_decisions"]),
            tuple(CaseEvent(**e) for e in p["events"]),
            p["created_at"],
            p["updated_at"],
            p.get("opened_by_rule", ""),
            p.get("resolution"),
            tuple(p.get("audit_event_ids", [])),
            p.get("required_authorization", "HUMAN_REVIEWER"),
            p.get("capability"),
            p.get("policy_outcome"),
            p.get("evidence_verdict"),
            p.get("facts_provenance"),
            p.get("subject_id"),
            self._amount(p),
            # never below the capability registry's count (sentinel.cases.service)
            int(p.get("approvals_required", 1)),
        )

    def get(self, case_id: str) -> Case | None:
        r = self.store._one("SELECT payload FROM cases WHERE case_id = ?", (case_id,))
        return self._from(json.loads(r["payload"])) if r else None

    def list(self, *, status: CaseStatus | None = None, limit: int = 100) -> list[Case]:
        if status is not None:
            rows = self.store._rows(
                "SELECT payload FROM cases WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit),
            )
        else:
            rows = self.store._rows(
                "SELECT payload FROM cases ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        return [self._from(json.loads(r["payload"])) for r in rows]


class SqliteSequences:
    """The anti-rollback high-water marks (``sentinel.trust.facts.SequenceLedger``), kept in
    the store so they survive a restart."""

    def __init__(self, store: SentinelStore) -> None:
        self._store = store

    def last(self, issuer: str, subject: str) -> tuple[int, str] | None:
        """The higher of the table and the audit chain: the table is a fast index anyone
        with DB write can delete; the chain is tamper-evident (``sentinel.audit``)."""
        marks = [
            m
            for m in (
                self._store.fact_sequence(issuer, subject),
                self._store.fact_sequence_from_audit(issuer, subject),
            )
            if m is not None
        ]
        return max(marks, key=lambda m: m[0]) if marks else None

    def advance(self, issuer: str, subject: str, sequence: int, envelope_digest: str) -> None:
        self._store.advance_fact_sequence(issuer, subject, sequence, envelope_digest)


class SqliteExecutions:
    """One execution per subject and capability (``workflows.ExecutionLedger``), in the
    store so a restart does not forget what already paid. Claiming is a single
    INSERT OR IGNORE under the store's lock: of two concurrent requests, one wins."""

    def __init__(self, store: SentinelStore) -> None:
        self._store = store

    def holder(self, key: str) -> str | None:
        r = self._store._one("SELECT holder FROM executions WHERE key = ?", (key,))
        return str(r["holder"]) if r else None

    def claim(self, key: str, by: str) -> str | None:
        with self._store._lock:
            cur = self._store._conn.execute(
                "INSERT OR IGNORE INTO executions VALUES (?, ?)", (key, by)
            )
            self._store._conn.commit()
            if cur.rowcount == 1:
                return None
        return self.holder(key)
