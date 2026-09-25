"""The application layer: one engine, three surfaces (CLI, API, UI).

``SentinelApp`` owns the store, the runtime (policies, gateway, cases, audit,
event bus, provider) and the entity graph / risk engine built over the loaded
dataset. Every surface calls these methods; none of them re-implements a
decision."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sentinel.audit.chain import AuditChain, ChainVerification
from sentinel.cases.service import CaseService
from sentinel.data.generator import Dataset, generate
from sentinel.data.store import SentinelStore, SqliteAuditBackend, SqliteCaseRepository
from sentinel.decision.session import DisputeSession
from sentinel.decision.snapshot import snapshot
from sentinel.decision.workflows import (
    DEFAULT_OPTIONS,
    AccountSecurityRequest,
    AISecurityRequest,
    AISecurityResult,
    DecisionBundle,
    DisputeRequest,
    InvestigationRequest,
    KYBRequest,
    RunOptions,
    Runtime,
    TransactionRequest,
    run_account_security,
    run_ai_security,
    run_dispute,
    run_investigation,
    run_kyb,
    run_transaction,
)
from sentinel.domain.cases import Case
from sentinel.domain.entities import LoginSession, Transaction
from sentinel.domain.enums import CaseStatus, TrustClass
from sentinel.domain.risk import EntityRiskProfile
from sentinel.domain.serialization import to_dict
from sentinel.observability import METRICS, get_logger, log_decision
from sentinel.policy.loader import DEFAULT_REGISTRY
from sentinel.presets import ATTACKS, SCENARIOS
from sentinel.replay.engine import ReplayEngine, ReplayOverrides, ReplayResult
from sentinel.risk import account_security, monitoring, scoring
from sentinel.risk import transaction as txn_risk
from sentinel.risk.behavioral import BehavioralBaseline, parse_ts
from sentinel.risk.entity import EntityRiskEngine
from sentinel.risk.graph import EntityGraph, Node
from sentinel.security.gateway import Conversation
from sentinel.security.provenance import UntrustedContent

_log = get_logger("sentinel.app")


@dataclass
class _World:
    dataset: Dataset
    graph: EntityGraph
    engine: EntityRiskEngine
    index: dict[str, dict[str, Any]] = field(default_factory=dict)


class SentinelApp:
    def __init__(
        self, store: SentinelStore | None = None, *, persist: bool = True, provider: Any = None
    ) -> None:
        self.store = store or SentinelStore(":memory:")
        self.runtime = Runtime(
            policies=DEFAULT_REGISTRY,
            cases=CaseService(SqliteCaseRepository(self.store)),
            audit=AuditChain(SqliteAuditBackend(self.store)),
            provider=provider,
            persist=persist,
        )
        self.replay_engine = ReplayEngine(self.runtime.policies)
        self._world: _World | None = None
        for p in self.runtime.policies.all():
            self.store.save_policy_version(p.policy_id, p.version, p.workflow.value, p.to_dict())

    # ---- construction ---------------------------------------------------------------------
    @classmethod
    def open(cls, path: str, **kw: Any) -> SentinelApp:
        return cls(SentinelStore(path), **kw)

    @classmethod
    def demo(
        cls,
        seed: int = 42,
        customers: int = 200,
        merchants: int = 40,
        transactions: int = 5000,
        **kw: Any,
    ) -> SentinelApp:
        app = cls(**kw)
        app.load_dataset(generate(seed, customers, merchants, transactions))
        return app

    def load_dataset(self, ds: Dataset) -> dict[str, object]:
        self.store.load_dataset(ds)
        self._world = None
        return ds.summary()

    def generate_dataset(
        self,
        seed: int,
        customers: int,
        merchants: int,
        transactions: int,
        *,
        profile: str = "balanced",
    ) -> dict[str, object]:
        return self.load_dataset(
            generate(seed, customers, merchants, transactions, profile=profile)
        )

    @property
    def world(self) -> _World:
        if self._world is None:
            ds = self.store.to_dataset()
            g = ds.graph()
            idx = ds.by_id()
            eng = EntityRiskEngine(
                g,
                idx["customer"],
                idx["account"],
                idx["merchant"],
                idx["device"],
                idx["transaction"],
                idx["dispute"],
                ds.as_of or datetime.utcnow().isoformat(),
            )
            self._world = _World(ds, g, eng, idx)
        return self._world

    # ---- persistence of a bundle ------------------------------------------------------------
    def _persist(self, b: DecisionBundle) -> DecisionBundle:
        if not self.runtime.persist:
            return b
        if b.risk is not None:
            self.store.save_risk_assessment(b.risk)
        if b.security_event is not None:
            self.store.save_security_event(b.security_event)
        snap = snapshot(b.inputs) if b.inputs is not None else {}
        self.store.save_decision(b.decision, snap, [to_dict(e) for e in b.reconciliation.evidence])
        log_decision(_log, b.decision)
        METRICS.inc(f"decisions.{b.decision.workflow.value}")
        METRICS.inc(f"actions.{b.decision.final_action.value}")
        return b

    # ---- contexts from trusted records --------------------------------------------------------
    def transaction_context(self, t: Transaction) -> txn_risk.TransactionContext:
        w = self.world
        prior = self.store.transactions_before(t.account_id, t.timestamp)
        ts = parse_ts(t.timestamp)
        # Point-in-time: only disputes that existed when this transaction happened may
        # enter its baseline. A dispute filed later is information from the future.
        disputes = [
            d
            for d in self.store.disputes(account_id=t.account_id, limit=1000)
            if parse_ts(d.submitted_at) < ts
        ]
        baseline = BehavioralBaseline.from_history(t.account_id, prior, disputes)
        recent = tuple(x for x in prior if parse_ts(x.timestamp) >= ts - timedelta(hours=24))
        at = t.timestamp
        # A device is "known" on the account once it has been registered or used for at
        # least 24 hours before this transaction (as of the graph at that moment).
        known = frozenset(
            d
            for d in w.graph.devices_for_account(t.account_id, as_of=at)
            if (first := w.graph.device_first_used(t.account_id, d)) is None
            or (ts - parse_ts(first)).total_seconds() >= 24 * 3600
        )
        mprof = w.engine.merchant_risk(t.merchant_id, as_of=at)
        linked, who = w.engine.linked_entity_risk(t.account_id, t.device_id, as_of=at)
        last = prior[-1] if prior else None
        # Trusted sessions in the 24 hours before the transaction (authentication service).
        sessions = tuple(
            s
            for s in self.store.sessions(account_id=t.account_id, limit=500)
            if s.started_at <= at and parse_ts(s.started_at) >= ts - timedelta(hours=24)
        )
        acc = self.store.account(t.account_id)
        payout_shared = 0
        if acc and acc.payout_instrument_id:
            payout = self.store.instrument(acc.payout_instrument_id)
            if payout and payout.added_at <= at:
                payout_shared = len(w.graph.accounts_sharing_instrument(payout.identity, as_of=at))
        return txn_risk.TransactionContext(
            baseline=baseline,
            account=self.store.account(t.account_id),
            merchant=self.store.merchant(t.merchant_id),
            instrument=self.store.instrument(t.instrument_id),
            recent=recent,
            known_devices=known,
            merchant_risk_score=mprof.score,
            linked_entity_risk=linked,
            linked_entity_ids=who,
            last_country=last.country if last else None,
            last_country_ts=last.timestamp if last else None,
            device_shared_accounts=len(w.graph.accounts_sharing_device(t.device_id, as_of=at)),
            device_first_used=w.graph.device_first_used(t.account_id, t.device_id),
            recent_sessions=sessions,
            payout_shared_accounts=payout_shared,
        )

    def account_security_context(self, s: LoginSession) -> account_security.AccountSecurityContext:
        prior = [
            x
            for x in self.store.sessions(account_id=s.account_id, limit=500)
            if x.started_at < s.started_at
        ]
        known_dev = frozenset(self.store.account_devices(s.account_id)) | frozenset(
            x.device_id for x in prior
        )
        known_c = frozenset(x.country for x in prior)
        last = max(prior, key=lambda x: x.started_at) if prior else None
        hours = (
            (parse_ts(s.started_at) - parse_ts(last.started_at)).total_seconds() / 3600
            if last
            else None
        )
        recent = [
            x
            for x in prior
            if parse_ts(x.started_at) >= parse_ts(s.started_at) - timedelta(hours=1)
        ]
        acc = self.store.account(s.account_id)
        return account_security.AccountSecurityContext(
            known_dev,
            known_c,
            last.country if last else None,
            hours,
            len(recent),
            max(1, len(known_dev)),
            bool(acc and acc.status == "frozen"),
        )

    def monitoring_context(
        self, account_id: str, as_of: str | None = None
    ) -> monitoring.MonitoringContext:
        w = self.world
        at = as_of or w.dataset.as_of
        # Point-in-time: nothing after ``at`` is visible to the monitor.
        txns = tuple(
            t
            for t in self.store.transactions(account_id=account_id, limit=100_000, order="ASC")
            if t.timestamp <= at
        )
        base_hist = [t for t in txns if parse_ts(t.timestamp) < parse_ts(at) - timedelta(days=30)]
        linked = tuple(sorted(w.graph.linked_accounts(account_id, as_of=at)))
        linked_risk = max((w.engine.account_risk(a, as_of=at).score for a in linked), default=0)
        for dev in w.graph.devices_for_account(account_id, as_of=at):
            linked_risk = max(linked_risk, w.engine.device_risk(dev, as_of=at).score)
        shared = max(
            (
                len(w.graph.accounts_sharing_device(d, as_of=at))
                for d in w.graph.devices_for_account(account_id, as_of=at)
            ),
            default=0,
        )
        return monitoring.MonitoringContext(
            account_id,
            txns,
            BehavioralBaseline.from_history(account_id, base_hist),
            w.index["merchant"],
            w.graph,
            at,
            inbound=tuple(x for x in self.store.inbound_transfers(account_id) if x.timestamp <= at),
            linked_accounts=linked,
            linked_risk=linked_risk,
            shared_device_accounts=shared,
        )

    # ---- workflow entry points --------------------------------------------------------------------
    def evaluate_transaction(
        self,
        transaction: Transaction | str,
        *,
        untrusted: tuple[UntrustedContent, ...] = (),
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        t0 = time.perf_counter()
        t = self.store.transaction(transaction) if isinstance(transaction, str) else transaction
        if t is None:
            raise KeyError(f"unknown transaction {transaction}")
        ctx = self.transaction_context(t)
        acc = self.store.account(t.account_id)
        mprof = self.world.engine.merchant_risk(t.merchant_id, as_of=t.timestamp)
        b = run_transaction(
            self.runtime,
            TransactionRequest(
                t, ctx, acc.status if acc else "unknown", mprof.level.value, untrusted
            ),
            options,
        )
        METRICS.observe("evaluate_transaction", (time.perf_counter() - t0) * 1000)
        return self._persist(b)

    def evaluate_dispute(
        self,
        narrative: str,
        ledger: dict[str, object] | None = None,
        *,
        dispute_id: str | None = None,
        documents: tuple[str, ...] = (),
        source: str = "cardholder",
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        t0 = time.perf_counter()
        account_id = None
        account_risk = 0
        if dispute_id and ledger is None:
            found = self.store.dispute(dispute_id)
            if found is None:
                raise KeyError(f"unknown dispute {dispute_id}")
            d, texts = found
            t = self.store.transaction(d.transaction_id)
            submitted = parse_ts(d.submitted_at)
            prior_90d = [
                x
                for x in self.store.disputes(account_id=d.account_id, limit=1000)
                if x.dispute_id != d.dispute_id
                and parse_ts(x.submitted_at) < submitted
                and (submitted - parse_ts(x.submitted_at)).days <= 90
            ]
            acc = self.store.account(d.account_id)
            cust = self.store.customer(acc.customer_id) if acc else None
            tenure = max(0, (submitted - parse_ts(cust.created_at)).days) if cust else 0
            ledger = {
                "amount": d.amount,
                "merchant": t.merchant_id if t else "unknown",
                "delivery_status": t.delivery_status if t else "unknown",
                "prior_disputes_90d": len(prior_90d),
                "policy_auto_limit": 50_000,
                "cardholder_present": True,
                "refund_state": d.refund_state,
                "transaction_status": t.status if t else "settled",
                "merchant_response": d.merchant_response,
                "auth_strength": t.auth_strength if t else "unknown",
                "customer_tenure_days": tenure,
            }
            narrative = narrative or texts.get("narrative", "")
            if not documents and texts.get("document"):
                documents = (texts["document"],)
            account_id = d.account_id
            account_risk = self.world.engine.account_risk(d.account_id, as_of=d.submitted_at).score
        docs = tuple(
            UntrustedContent(x, TrustClass.DOCUMENT_CONTROLLED, "uploaded_document", "document")
            for x in documents
        )
        b = run_dispute(
            self.runtime,
            DisputeRequest(
                UntrustedContent(narrative, TrustClass.USER_CONTROLLED, source),
                ledger or {},
                dispute_id or "",
                docs,
                None,
                account_id,
                account_risk,
            ),
            options,
        )
        METRICS.observe("evaluate_dispute", (time.perf_counter() - t0) * 1000)
        return self._persist(b)

    def evaluate_dispute_conversation(
        self,
        turns: tuple[str, ...],
        ledger: dict[str, object],
        *,
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        s = DisputeSession(self.runtime, ledger, options=options)
        b = None
        for t in turns:
            b = s.add(t)
        assert b is not None
        return self._persist(b)

    def evaluate_merchant(
        self,
        application: str,
        records: dict[str, object] | None = None,
        *,
        application_id: str | None = None,
        merchant_id: str = "",
        documents: tuple[str, ...] = (),
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        if application_id and records is None:
            found = self.store.kyb_application(application_id)
            if found is None:
                raise KeyError(f"unknown application {application_id}")
            k, texts = found
            records = {
                "registration_status": k.registration_status,
                "domain_age_days": k.domain_age_days,
                "business_age_days": k.business_age_days,
                "prior_flags": k.prior_flags,
                "mcc_risk": k.mcc_risk,
            }
            application = application or texts.get("application", "")
            if not documents and texts.get("document"):
                documents = (texts["document"],)
            merchant_id = merchant_id or k.merchant_id
        docs = tuple(
            UntrustedContent(x, TrustClass.DOCUMENT_CONTROLLED, "uploaded_document", "document")
            for x in documents
        )
        b = run_kyb(
            self.runtime,
            KYBRequest(
                UntrustedContent(application, TrustClass.MERCHANT_CONTROLLED, "application"),
                records or {},
                merchant_id,
                docs,
            ),
            options,
        )
        return self._persist(b)

    def evaluate_account(
        self,
        session: LoginSession | str,
        *,
        message: str | None = None,
        requested_capability: Any = None,
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        s = self.store.session(session) if isinstance(session, str) else session
        if s is None:
            raise KeyError(f"unknown session {session}")
        ctx = self.account_security_context(s)
        msg = (
            UntrustedContent(message, TrustClass.USER_CONTROLLED, "customer_message")
            if message
            else None
        )
        b = run_account_security(
            self.runtime, AccountSecurityRequest(s, ctx, msg, requested_capability), options
        )
        return self._persist(b)

    def evaluate_investigation(
        self,
        account_id: str,
        *,
        case_notes: tuple[str, ...] = (),
        as_of: str | None = None,
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        ctx = self.monitoring_context(account_id, as_of)
        notes = tuple(UntrustedContent(n, TrustClass.UNKNOWN, "case_notes") for n in case_notes)
        b = run_investigation(self.runtime, InvestigationRequest(ctx, notes), options)
        return self._persist(b)

    def evaluate_ai_security(
        self,
        contents: tuple[UntrustedContent, ...],
        *,
        agent_key: str = "dispute",
        run_agent: bool = True,
        conversation: Conversation | None = None,
    ) -> AISecurityResult:
        r = run_ai_security(
            self.runtime, AISecurityRequest(contents, agent_key, run_agent, conversation)
        )
        if r.event is not None and self.runtime.persist:
            self.store.save_security_event(r.event)
        return r

    # ---- attack simulator + flagship scenarios ----------------------------------------------------
    def simulate_attack(
        self,
        kind: str,
        *,
        narrative: str | None = None,
        document: str | None = None,
        options: RunOptions = DEFAULT_OPTIONS,
        compare: bool = False,
    ) -> dict[str, Any]:
        """Run an attack preset through the real engine. With ``compare`` the same
        input is run twice -- against the *simulated naive agent with no controls*
        and against full Sentinel -- and both storyboards are returned, labelled."""
        p = ATTACKS[kind]

        def _run(opts: RunOptions) -> tuple[DecisionBundle, str]:
            if p.turns and narrative is None:
                b = self.evaluate_dispute_conversation(p.turns, p.ledger, options=opts)
                return b, "\n".join(f"Turn {i + 1}: {t}" for i, t in enumerate(p.turns))
            docs = (document,) if document else ((p.document,) if p.document else ())
            b = self.evaluate_dispute(
                narrative if narrative is not None else p.narrative,
                dict(p.ledger),
                documents=docs,
                options=opts,
            )
            return b, narrative if narrative is not None else p.narrative

        b, shown = _run(options)
        sb = self.storyboard(
            b,
            preset=p.key,
            shown_input=shown,
            shown_document=document or p.document,
            target_workflow=p.workflow,
            target_capability=p.target_capability,
            attack_class=p.threat_class,
        )
        if not compare:
            return sb
        unguarded, _ = _run(RunOptions(controls=frozenset(), hardened=options.hardened))
        usb = self.storyboard(
            unguarded,
            preset=p.key,
            shown_input=shown,
            shown_document=document or p.document,
            target_workflow=p.workflow,
            target_capability=p.target_capability,
            attack_class=p.threat_class,
        )
        return {
            "preset": p.key,
            "attack_class": p.threat_class,
            "target_workflow": p.workflow,
            "target_capability": p.target_capability,
            "without_sentinel": {
                "label": "WITHOUT SENTINEL -- simulated naive agent, no controls; its tool call executes",
                "caveat": "The victim is the deterministic offline simulator, not a real LLM; this path shows what the architecture prevents, not a measured model failure rate.",
                **usb,
            },
            "with_sentinel": {
                "label": "WITH SENTINEL -- full controls; the agent only recommends",
                **sb,
            },
            "summary": {
                "agent_recommendation": sb["ai"]["recommended_action"] if sb.get("ai") else None,
                "without_sentinel_executed": usb["decision"]["executed_capability"],
                "with_sentinel_final_action": sb["decision"]["final_action"],
                "with_sentinel_executed": sb["decision"]["executed_capability"],
                "blocked_layer": sb["blocked_layer"],
                "blocked_by": sb["decision"]["blocked_by"],
            },
        }

    def storyboard(
        self,
        b: DecisionBundle,
        *,
        preset: str | None = None,
        shown_input: str = "",
        shown_document: str | None = None,
        target_workflow: str = "dispute",
        target_capability: str | None = None,
        attack_class: str | None = None,
    ) -> dict[str, Any]:
        d = b.decision
        first_block = d.blocked_by[0] if d.blocked_by else None
        return {
            "preset": preset,
            "attack_class": attack_class,
            "target_workflow": target_workflow,
            "target_capability": target_capability,
            "controls": list(d.controls),
            "blocked_layer": first_block,
            "attacker_input": shown_input,
            "attacker_document": shown_document,
            "ledger": {k: v for k, v in (b.inputs.facts if b.inputs else {}).items()},
            "stages": [
                {
                    "stage": "untrusted_input",
                    "title": "Untrusted input",
                    "value": (
                        (
                            "USER_CONTROLLED + DOCUMENT_CONTROLLED"
                            if shown_document
                            else "USER_CONTROLLED"
                        )
                        + f" · hash {d.input_hash}"
                    ),
                    "status": "info",
                },
                {
                    "stage": "ai_security_gateway",
                    "title": "AI Security Gateway",
                    "value": f"{b.security.severity.value} · {', '.join(t.value for t in b.security.threat_classes) or 'no findings'}",
                    "status": "alert" if b.security.flagged else "ok",
                },
                {
                    "stage": "ai_recommendation",
                    "title": "LLM recommendation",
                    "value": (
                        f"{b.ai.recommended_action.upper()} (MODEL_GENERATED)" if b.ai else "n/a"
                    ),
                    "status": "alert" if (b.ai and b.ai.requested_capability) else "ok",
                },
                {
                    "stage": "trusted_evidence",
                    "title": "Trusted evidence",
                    "value": f"{b.reconciliation.verdict.value} — {b.reconciliation.explanation}",
                    "status": "ok" if b.reconciliation.supports_claim else "alert",
                },
                {
                    "stage": "policy",
                    "title": f"Policy {d.policy.policy_id}@v{d.policy.version}",
                    "value": f"{d.policy.outcome.value} · {', '.join(d.policy.matched_rules) or 'no rules matched'}",
                    "status": "ok" if d.policy.outcome.value == "ALLOW" else "alert",
                },
                {
                    "stage": "authorization",
                    "title": "Capability authorization",
                    "value": f"{(d.requested_capability.value if d.requested_capability else 'none')} → {d.authorization.status.value}",
                    "status": "ok" if d.authorization.status.value == "GRANTED" else "alert",
                },
                {
                    "stage": "final",
                    "title": "Final Sentinel decision",
                    "value": d.final_action.value,
                    "status": "ok" if d.final_action.value == "ALLOW" else "alert",
                },
                {
                    "stage": "case",
                    "title": "Case",
                    "value": b.case.case_id if b.case else "no case",
                    "status": "info",
                },
                {
                    "stage": "audit",
                    "title": "Audit",
                    "value": (
                        f"event #{b.audit_event.sequence} {b.audit_event.event_hash[:16]}…"
                        if b.audit_event
                        else "not persisted"
                    ),
                    "status": "info",
                },
            ],
            "headline": (
                "The AI was persuaded. The financial system was not."
                if (b.ai and b.ai.requested_capability and not d.executed)
                else (
                    f"{d.executed} executed on a claim the trusted records do not support."
                    if (d.executed and not b.reconciliation.supports_claim)
                    else ("Legitimate request approved." if d.executed else "Held for a human.")
                )
            ),
            "decision": to_dict(d),
            "security": to_dict(b.security),
            "reconciliation": to_dict(b.reconciliation),
            "risk": to_dict(b.risk) if b.risk else None,
            "ai": to_dict(b.ai) if b.ai else None,
            "case": to_dict(b.case) if b.case else None,
            "audit_event": b.audit_event.to_dict() if b.audit_event else None,
        }

    def run_scenario(self, key: str, *, options: RunOptions = DEFAULT_OPTIONS) -> dict[str, Any]:
        p = SCENARIOS[key]
        tags = [s for s in self.store.scenarios() if s["scenario"] == key]
        results: list[dict[str, Any]] = []
        if key == "normal_purchase":
            for t in self.store.transactions(limit=3, order="DESC"):
                if t.label == "legit":
                    results.append(
                        self._scenario_item(self.evaluate_transaction(t, options=options))
                    )
        elif p.workflow == "transaction":
            for tag in tags[:3]:
                for eid in tag["entity_ids"]:
                    if eid.startswith("TX-"):
                        results.append(
                            self._scenario_item(self.evaluate_transaction(eid, options=options))
                        )
        elif p.workflow == "dispute":
            for tag in tags[:1]:
                for did in [e for e in tag["entity_ids"] if e.startswith("DSP-")][:4]:
                    results.append(
                        self._scenario_item(
                            self.evaluate_dispute("", dispute_id=did, options=options)
                        )
                    )
        elif p.workflow == "merchant":
            for tag in tags[:2]:
                mid = tag["entity_ids"][0]
                prof = self.world.engine.merchant_risk(mid)
                results.append(
                    {"subject": f"merchant:{mid}", "risk": to_dict(prof), "final_action": None}
                )
        elif p.workflow == "investigation":
            for tag in tags[:2]:
                for aid in [e for e in tag["entity_ids"] if e.startswith("ACC-")][:3]:
                    results.append(
                        self._scenario_item(self.evaluate_investigation(aid, options=options))
                    )
        return {"scenario": to_dict(p), "results": results, "tags": tags[:3]}

    def _scenario_item(self, b: DecisionBundle) -> dict[str, Any]:
        d = b.decision
        return {
            "subject": f"{d.subject_type}:{d.subject_id}",
            "final_action": d.final_action.value,
            "risk_score": d.risk_score,
            "risk_level": d.risk_level.value,
            "evidence_verdict": d.evidence_verdict.value,
            "security_severity": d.security_severity.value,
            "ai_recommendation": b.ai.recommended_action if b.ai else None,
            "policy_outcome": d.policy.outcome.value,
            "case_id": d.case_id,
            "decision_id": d.decision_id,
            "factors": [f"{f.points:+d} {f.label}" for f in (b.risk.factors if b.risk else ())],
        }

    # ---- batch analysis (populates the dashboard from real computation) -------------------------------
    def analyze(
        self,
        *,
        transactions: int = 300,
        disputes: int = 60,
        applications: int = 30,
        sessions: int = 60,
        accounts: int = 20,
        skip_agent: bool = False,
    ) -> dict[str, int]:
        opts = RunOptions(skip_agent=skip_agent)
        n = {
            "transactions": 0,
            "disputes": 0,
            "applications": 0,
            "sessions": 0,
            "investigations": 0,
        }
        for t in self.store.transactions(limit=transactions, order="DESC"):
            self.evaluate_transaction(t, options=opts)
            n["transactions"] += 1
        for d in self.store.disputes(limit=disputes):
            self.evaluate_dispute("", dispute_id=d.dispute_id, options=opts)
            n["disputes"] += 1
        for k in self.store.kyb_applications(limit=applications):
            self.evaluate_merchant("", application_id=k.application_id, options=opts)
            n["applications"] += 1
        for s in self.store.sessions(limit=sessions):
            self.evaluate_account(s, options=opts)
            n["sessions"] += 1
        flagged = {
            e
            for s in self.store.scenarios()
            if s["scenario"] in ("graph_linked_fraud", "structuring_like", "dormant_activation")
            for e in s["entity_ids"]
            if e.startswith("ACC-")
        }
        for aid in list(flagged)[:accounts]:
            self.evaluate_investigation(aid, options=opts)
            n["investigations"] += 1
        for m in self.store.merchants():
            prof = self.world.engine.merchant_risk(m.merchant_id)
            from sentinel.domain.risk import RiskAssessment

            self.store.save_risk_assessment(
                RiskAssessment(
                    f"RISK-M-{m.merchant_id}",
                    "merchant",
                    m.merchant_id,
                    prof.score,
                    prof.level,
                    prof.factors,
                    "n/a",
                    prof.model_version,
                    {},
                    self.world.dataset.as_of,
                )
            )
        return n

    # ---- reads -------------------------------------------------------------------------------------------
    def overview(self) -> dict[str, Any]:
        st = self.store.stats()
        st["attack_classes"] = self.store.attack_classes()
        st["risk_over_time"] = self.store.risk_over_time()
        st["audit_chain"] = to_dict(self.verify_audit())
        st["dataset"] = {
            "seed": self.store.get_meta("dataset_seed"),
            "as_of": self.store.get_meta("as_of"),
            "customers": self.store.count("customers"),
            "merchants": self.store.count("merchants"),
            "accounts": self.store.count("accounts"),
        }
        return st

    def entity_risk(
        self, entity_type: str, entity_id: str, as_of: str | None = None
    ) -> dict[str, Any]:
        """An entity's profile as of ``as_of`` (default: the dataset's now)."""
        if entity_type == "transaction":
            t = self.store.transaction(entity_id)
            if t is None:
                raise KeyError(entity_id)
            ra = txn_risk.assess_transaction(t, self.transaction_context(t))
            return to_dict(ra)
        prof: EntityRiskProfile = self.world.engine.profile(entity_type, entity_id, as_of)
        return to_dict(prof)

    def graph_for(self, entity_type: str, entity_id: str, depth: int = 2) -> dict[str, Any]:
        return self.world.graph.to_dict(Node(entity_type, entity_id), depth)

    def timeline(self, account_id: str, around: str, days: int = 7) -> list[dict[str, Any]]:
        """Trusted account activity around a moment: transactions, sessions and disputes
        within +/- ``days``, in time order, each tagged with its kind and what the
        risk engine could see at that moment (point-in-time)."""
        centre = parse_ts(around)
        lo, hi = centre - timedelta(days=days), centre + timedelta(days=days)
        items: list[dict[str, Any]] = []
        for t in self.store.transactions(account_id=account_id, limit=100_000, order="ASC"):
            ts = parse_ts(t.timestamp)
            if lo <= ts <= hi:
                items.append(
                    {
                        "at": t.timestamp,
                        "kind": "transaction",
                        "id": t.transaction_id,
                        "summary": f"₹{t.amount:,} at {t.merchant_id} · {t.channel} · {t.country} · {t.auth_strength} · device {t.device_id}",
                        "amount": t.amount,
                        "label": t.label,
                        "future": ts > centre,
                    }
                )
        for s in self.store.sessions(account_id=account_id, limit=500):
            ts = parse_ts(s.started_at)
            if lo <= ts <= hi:
                items.append(
                    {
                        "at": s.started_at,
                        "kind": "session",
                        "id": s.session_id,
                        "summary": f"login from {s.country} on {s.device_id} · mfa {'passed' if s.mfa_passed else 'FAILED'}"
                        + (f" · events: {', '.join(s.events)}" if s.events else ""),
                        "future": ts > centre,
                    }
                )
        for d in self.store.disputes(account_id=account_id, limit=500):
            ts = parse_ts(d.submitted_at)
            if lo <= ts <= hi:
                items.append(
                    {
                        "at": d.submitted_at,
                        "kind": "dispute",
                        "id": d.dispute_id,
                        "summary": f"dispute on {d.transaction_id} · claims {d.claim_type_declared} · ₹{d.amount:,} · refund {d.refund_state} · merchant {d.merchant_response}",
                        "future": ts > centre,
                    }
                )
        items.sort(key=lambda x: x["at"])
        return items

    def transaction_view(self, transaction_id: str) -> dict[str, Any]:
        t = self.store.transaction(transaction_id)
        if t is None:
            raise KeyError(transaction_id)
        ctx = self.transaction_context(t)
        w = self.world
        decisions = self.store.decisions(subject_id=transaction_id, limit=5)
        latest = decisions[0] if decisions else None
        return {
            "transaction": to_dict(t),
            "customer": (
                to_dict(self.store.customer(ctx.account.customer_id)) if ctx.account else None
            ),
            "account": to_dict(ctx.account) if ctx.account else None,
            "merchant": to_dict(ctx.merchant) if ctx.merchant else None,
            "device": to_dict(self.store.device(t.device_id)),
            "baseline": ctx.baseline.to_dict(),
            "risk": to_dict(txn_risk.assess_transaction(t, ctx)),
            "entity_risk": {  # as of the transaction, i.e. what the decision path saw
                "account": to_dict(w.engine.account_risk(t.account_id, as_of=t.timestamp)),
                "merchant": to_dict(w.engine.merchant_risk(t.merchant_id, as_of=t.timestamp)),
                "device": to_dict(w.engine.device_risk(t.device_id, as_of=t.timestamp)),
            },
            "graph": w.graph.to_dict(Node("transaction", transaction_id), 2),
            "decision": latest,
            "evidence": self.store.evidence_for(latest["decision_id"]) if latest else [],
            "audit_event": self.audit_event(latest["decision_id"]) if latest else None,
            "security_events": (
                self.store.security_events_for_decision(latest["decision_id"]) if latest else []
            ),
            "timeline": self.timeline(t.account_id, t.timestamp),
            "decisions": decisions,
        }

    def cases(self, status: str | None = None, limit: int = 100) -> list[Case]:
        return self.runtime.cases.list(status=CaseStatus(status) if status else None, limit=limit)

    def case(self, case_id: str) -> Case | None:
        return self.runtime.cases.get(case_id)

    def review_packet(self, case_id: str) -> dict[str, Any] | None:
        """Everything a human reviewer needs, in one object, with the AI recommendation
        explicitly separated from the trusted evidence and the deterministic decision."""
        c = self.runtime.cases.get(case_id)
        if c is None:
            return None
        decisions = [d for d in (self.store.decision(x) for x in c.decision_ids) if d]
        latest = decisions[-1] if decisions else None
        evidence = self.store.evidence_for(latest["decision_id"]) if latest else []
        risk = (
            self.store.risk_assessment(latest["risk_assessment_id"])
            if latest and latest.get("risk_assessment_id")
            else None
        )
        audit = [self.audit_event(x) for x in c.audit_event_ids]
        events = [self.store.security_event(x) for x in c.security_event_ids]
        return {
            "case": to_dict(c),
            "why_this_case_exists": {
                "rule": c.opened_by_rule,
                "reason": latest["reason"] if latest else "",
                "human_review_reason": latest["human_review"]["reason"] if latest else "",
                "final_action": latest["final_action"] if latest else None,
            },
            "risk": {
                "score": latest["risk_score"] if latest else None,
                "level": latest["risk_level"] if latest else None,
                "factors": (risk or {}).get("factors", []),
                "components": (risk or {}).get("components", {}),
                "model_version": (risk or {}).get("model_version"),
            },
            "trusted_evidence": [e for e in evidence if e["status"] == "VERIFIED"],
            "untrusted_claims": [e for e in evidence if e["status"] != "VERIFIED"],
            "contradictions": latest["contradiction_count"] if latest else 0,
            "ai_recommendation": (
                {
                    "note": "MODEL_GENERATED -- recorded for context, NOT a decision and NOT evidence",
                    **(latest["ai_recommendation"] or {}),
                }
                if latest and latest.get("ai_recommendation")
                else None
            ),
            "policy": latest["policy"] if latest else None,
            "capability": {
                "requested": latest["requested_capability"] if latest else None,
                "authorization": latest["authorization"] if latest else None,
                "executed": latest["executed_capability"] if latest else None,
            },
            "security_events": [e for e in events if e],
            "human_decisions": [to_dict(h) for h in c.human_decisions],
            "timeline": [to_dict(e) for e in c.events],
            "audit_history": [a for a in audit if a],
            "decisions": decisions,
            "principle": "AI recommendation != final decision. Only a human can resolve this case.",
        }

    def audit_event(self, event_or_decision_id: str) -> dict[str, Any] | None:
        ev = self.runtime.audit.get(event_or_decision_id)
        return ev.to_dict() if ev else None

    def verify_audit(self) -> ChainVerification:
        return self.runtime.audit.verify()

    def replay(self, decision_id: str, overrides: ReplayOverrides) -> ReplayResult:
        original = self.store.decision(decision_id)
        snap = self.store.decision_snapshot(decision_id)
        if original is None or snap is None:
            raise KeyError(f"unknown decision {decision_id}")
        from sentinel.decision.composer import compose
        from sentinel.decision.snapshot import restore

        base = compose(
            restore(snap, self.runtime.policies)
        )  # canonical re-derivation of the original
        r = self.replay_engine.replay(base, snap, overrides, recorded=original)
        if self.runtime.persist:
            payload = {
                "replay_id": r.replay_id,
                "decision_id": r.decision_id,
                "overrides": r.overrides,
                "original": r.original,
                "replayed": r.replayed,
                "changed": r.changed,
                "diffs": [to_dict(d) for d in r.diffs],
                "explanation": r.explanation,
                "created_at": r.created_at,
                "policy_drift": r.policy_drift,
                "original_drift": r.original_drift,
            }
            self.store.save_replay(r.replay_id, decision_id, r.changed, r.created_at, payload)
            self.runtime.audit.append(
                actor="sentinel",
                workflow=r.replayed_decision.workflow.value,
                action=f"REPLAY:{r.replayed['final_action']}",
                decision_id=decision_id,
                subject_id=r.replay_id,
                policy_id=r.replayed_decision.policy.policy_id,
                policy_version=r.replayed_decision.policy.version,
                kind="replay",
                detail={
                    "overrides": r.overrides,
                    "changed": r.changed,
                    "policy_drift": r.policy_drift,
                    "original_drift": r.original_drift,
                },
            )
        return r

    def system_info(self) -> dict[str, Any]:
        from sentinel import __version__
        from sentinel.agents.providers import get_provider, mode

        p = self.runtime.provider or get_provider()
        return {
            "name": "sentinel",
            "version": __version__,
            "mode": mode(),
            "provider": p.name,
            "model": p.model,
            "policies": [pp.key for pp in self.runtime.policies.all()],
            "risk_models": sorted(scoring.MODELS),
            "default_transaction_model": scoring.TRANSACTION_DEFAULT.version,
            "audit": to_dict(self.verify_audit()),
            "metrics": METRICS.snapshot(),
            "store": self.store.path,
        }
