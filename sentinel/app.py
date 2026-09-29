"""The application layer: one engine, three surfaces (CLI, API, UI).

``SentinelApp`` owns the store, the runtime (policies, gateway, cases, audit,
provider) and the entity graph / risk engine built over the loaded dataset. Every surface calls these methods; none of them re-implements a
decision."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from sentinel.audit.chain import AuditChain, ChainVerification
from sentinel.cases.service import CaseService
from sentinel.data.generator import Dataset, generate
from sentinel.data.store import (
    SentinelStore,
    SqliteAuditBackend,
    SqliteCaseRepository,
    SqliteSequences,
)
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
    session_record,
    transaction_record,
)
from sentinel.domain.cases import Case
from sentinel.domain.entities import Dispute, KYBApplication, LoginSession, Transaction
from sentinel.domain.enums import CaseStatus, FactKind, FactsSource, TrustClass
from sentinel.domain.ids import content_hash, new_id
from sentinel.domain.risk import EntityRiskProfile
from sentinel.domain.serialization import to_dict
from sentinel.observability import METRICS, get_logger, log_decision
from sentinel.policy.loader import DEFAULT_REGISTRY, PolicyIntegrityError
from sentinel.presets import ATTACKS, SCENARIOS
from sentinel.replay.engine import ReplayEngine, ReplayOverrides, ReplayResult
from sentinel.risk import account_security, monitoring, scoring
from sentinel.risk import transaction as txn_risk
from sentinel.risk.behavioral import BehavioralBaseline, parse_ts
from sentinel.risk.entity import EntityRiskEngine
from sentinel.risk.graph import EntityGraph, Node
from sentinel.security.gateway import Conversation
from sentinel.security.provenance import UntrustedContent
from sentinel.trust.facts import verify_fact
from sentinel.trust.issuer import Issuer
from sentinel.trust.keys import TrustStore

_log = get_logger("sentinel.app")

DEMO_ISSUER = "synthetic-ledger"
DEMO_ISSUER_LABEL = (
    "ephemeral demo issuer: stands in for the institution's systems of record signing their "
    "records; its key is generated in this process and never written anywhere"
)


def configured_trust() -> TrustStore:
    """The operator's trust store (``SENTINEL_TRUST_STORE``), or an empty one."""
    path = os.environ.get("SENTINEL_TRUST_STORE")
    return TrustStore.load(path) if path else TrustStore.empty()


def _named(envelope: dict[str, Any] | None, kind: FactKind) -> str | None:
    """The record id a caller-carried statement names (for the stored-record check)."""
    subject = envelope.get("subject") if isinstance(envelope, dict) else None
    prefix = kind.subject_prefix + ":"
    if isinstance(subject, str) and subject.startswith(prefix):
        return subject[len(prefix) :] or None
    return None


def _transaction_from_record(rec: dict[str, Any]) -> Transaction:
    """A transaction as its issuer stated it (an envelope payload)."""
    need = ("transaction_id", "account_id", "merchant_id", "instrument_id", "device_id")
    try:
        t = Transaction(
            **{k: str(rec[k]) for k in need},
            amount=rec["amount"],  # validated by the workflow (a positive integer)
            currency=str(rec.get("currency", "INR")),
            timestamp=str(rec["timestamp"]),
            country=str(rec["country"]),
            channel=str(rec.get("channel", "ecommerce")),
            auth_strength=str(rec.get("auth_strength", "none")),
            delivery_status=str(rec.get("delivery_status", "unknown")),
            counterparty_account_id=(
                str(rec["counterparty_account_id"]) if rec.get("counterparty_account_id") else None
            ),
            label="unknown",
            status=str(rec.get("status", "settled")),
        )
    except (KeyError, TypeError) as e:
        raise ValueError(f"the envelope carries no usable transaction record: {e}") from None
    return t


def _session_from_record(rec: dict[str, Any]) -> LoginSession:
    try:
        events = rec.get("events", [])
        if not isinstance(events, list) or not all(isinstance(e, str) for e in events):
            raise TypeError("events must be a list of strings")
        if not isinstance(rec.get("mfa_passed", True), bool):
            raise TypeError("mfa_passed must be a boolean")
        return LoginSession(
            str(rec["session_id"]),
            str(rec["account_id"]),
            str(rec["device_id"]),
            str(rec.get("ip", "")),
            str(rec["country"]),
            str(rec["started_at"]),
            bool(rec.get("mfa_passed", True)),
            tuple(events),
        )
    except (KeyError, TypeError) as e:
        raise ValueError(f"the envelope carries no usable session record: {e}") from None


@dataclass
class _World:
    dataset: Dataset
    graph: EntityGraph
    engine: EntityRiskEngine
    index: dict[str, dict[str, Any]] = field(default_factory=dict)


class SentinelApp:
    def __init__(
        self,
        store: SentinelStore | None = None,
        *,
        persist: bool = True,
        provider: Any = None,
        trust: TrustStore | None = None,
        issuer: Issuer | None = None,
        require_signed_facts: bool | None = None,
    ) -> None:
        """``trust``: the operator's trust store (default: ``SENTINEL_TRUST_STORE``, else
        empty -- nothing can be VERIFIED_EXTERNAL). ``issuer``: a signer for this app's own
        dataset and fixtures (the demo's ephemeral issuer); its key is added to the trust
        store, and nothing reachable from the API can use it. ``require_signed_facts``
        (default: on when this app signs its own records, or ``SENTINEL_REQUIRE_SIGNED_FACTS``)
        makes a record-store read without its signed statement INVALID."""
        self.store = store or SentinelStore(":memory:")
        self.issuer = issuer
        trust = trust if trust is not None else configured_trust()
        if issuer is not None:
            trust = trust.with_key(issuer.key)
        sequences = SqliteSequences(self.store)
        if require_signed_facts is None:
            require_signed_facts = issuer is not None or os.environ.get(
                "SENTINEL_REQUIRE_SIGNED_FACTS", ""
            ) in ("1", "true", "yes")
        self.runtime = Runtime(
            policies=DEFAULT_REGISTRY,
            cases=CaseService(SqliteCaseRepository(self.store)),
            audit=AuditChain(SqliteAuditBackend(self.store)),
            provider=provider,
            persist=persist,
            trust=trust,
            sequences=sequences,
            require_signed_facts=require_signed_facts,
        )
        # What-if runs (reduced controls, a historical policy or risk model) use the same
        # policies, gateway and provider but never persist: no audit event, no case, no
        # stored decision (sentinel.decision.authority).
        self.what_if_runtime = Runtime(
            policies=self.runtime.policies,
            gateway=self.runtime.gateway,
            provider=provider,
            persist=False,
            trust=trust,
            sequences=sequences,  # read for rollback checks; a what-if never advances it
            require_signed_facts=require_signed_facts,
        )
        self.replay_engine = ReplayEngine(self.runtime.policies)
        self._world: _World | None = None
        for p in self.runtime.policies.all():
            stored = self.store.policy_payload(p.policy_id, p.version)
            if stored is None:
                self.store.save_policy_version(
                    p.policy_id, p.version, p.workflow.value, p.to_dict()
                )
            elif content_hash(stored) != p.content_hash:
                # This store recorded decisions under this version with other content: the
                # version was edited in place. Refuse to run rather than mix the two.
                raise PolicyIntegrityError(
                    f"{p.key}: the store holds different content for this version "
                    f"(hash {content_hash(stored)}, loaded {p.content_hash}); a changed "
                    "policy needs a new version"
                )

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
        *,
        sign: bool = True,
        **kw: Any,
    ) -> SentinelApp:
        """A synthetic dataset in memory. With ``sign`` (the default) an ephemeral demo
        issuer signs every record, so decisions by record id are VERIFIED_EXTERNAL and
        tampering with a stored row is detected."""
        if sign and "issuer" not in kw:
            kw["issuer"] = Issuer.ephemeral(DEMO_ISSUER, label=DEMO_ISSUER_LABEL)
        app = cls(**kw)
        app.load_dataset(generate(seed, customers, merchants, transactions))
        return app

    def load_dataset(self, ds: Dataset) -> dict[str, object]:
        self.store.load_dataset(ds)
        self._world = None
        if self.issuer is not None:
            self._sign_records()
        return ds.summary()

    # ---- the records as their issuers state them ---------------------------------------------
    def _duplicate_on_record(self, t: Transaction) -> bool:
        """Does the ledger hold a second identical charge: same account, merchant and
        amount within 48 hours?"""
        ts = parse_ts(t.timestamp)
        return any(
            x.transaction_id != t.transaction_id
            and x.amount == t.amount
            and abs(parse_ts(x.timestamp) - ts) <= timedelta(hours=48)
            for x in self.store.transactions(
                account_id=t.account_id, merchant_id=t.merchant_id, limit=1000
            )
        )

    def _dispute_ledger(self, d: Dispute) -> dict[str, object]:
        """The ledger facts for a stored dispute. A field the store does not hold is
        ``None`` (unknown) -- never an assumed constant: a claim that depends on it is held
        for a human, not decided on a guess."""
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
        return {
            "amount": d.amount,
            "merchant": t.merchant_id if t else "unknown",
            "delivery_status": t.delivery_status if t else "unknown",
            "prior_disputes_90d": len(prior_90d),
            "duplicate_confirmed": self._duplicate_on_record(t) if t else None,
            "cancellation_confirmed": None,  # the store keeps no cancellation record
            "cardholder_present": None,  # nor a card-present record (auth strength is not proof)
            "refund_state": d.refund_state,
            "transaction_status": t.status if t else "unknown",
            "merchant_response": d.merchant_response,
            "auth_strength": t.auth_strength if t else "unknown",
            "customer_tenure_days": tenure,
        }

    @staticmethod
    def _kyb_record(k: KYBApplication) -> dict[str, object]:
        """The acquirer's record for one application. It names the application, so a
        statement about one of a merchant's applications cannot stand in for another."""
        return {
            "application_id": k.application_id,
            "registration_status": k.registration_status,
            "domain_age_days": k.domain_age_days,
            "business_age_days": k.business_age_days,
            "prior_flags": k.prior_flags,
            "mcc_risk": k.mcc_risk,
        }

    def _sign_records(self) -> None:
        """The demo issuer signs every stored record. A merchant's applications are
        sequenced in submission order, so acting on a newer acquirer record makes an older
        one SUPERSEDED."""
        iss = self.issuer
        assert iss is not None
        env: list[tuple[str, dict[str, Any]]] = []
        for d in self.store.all_disputes():
            e = iss.sign(FactKind.DISPUTE_LEDGER, d.dispute_id, self._dispute_ledger(d))
            env.append((e["subject"], e))
        per_merchant: dict[str, int] = {}
        apps = self.store.kyb_applications(limit=1_000_000)
        for k in sorted(apps, key=lambda a: (a.submitted_at, a.application_id)):
            seq = per_merchant[k.merchant_id] = per_merchant.get(k.merchant_id, 0) + 1
            e = iss.sign(FactKind.KYB_RECORD, k.merchant_id, self._kyb_record(k), sequence=seq)
            env.append((f"application:{k.application_id}", e))
        for t in self.store.all_transactions():
            e = iss.sign(FactKind.TRANSACTION, t.transaction_id, transaction_record(t))
            env.append((e["subject"], e))
        for ss in self.store.sessions(limit=1_000_000):
            e = iss.sign(FactKind.LOGIN_SESSION, ss.session_id, session_record(ss))
            env.append((e["subject"], e))
        self.store.save_fact_envelopes(env)

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
    def _rt(self, options: RunOptions) -> Runtime:
        return self.what_if_runtime if options.what_if else self.runtime

    def _persist(self, b: DecisionBundle) -> DecisionBundle:
        if not self.runtime.persist or not b.decision.authoritative:
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
        # Payout sharing as of T: the bank accounts this account held at T, each looked up by
        # identity. Not the account's CURRENT payout field, which a later change would move.
        payout_shared = max(
            (
                len(w.graph.accounts_sharing_instrument(i.identity, as_of=at))
                for i in self.store.instruments_for(t.account_id)
                if i.kind == "bank_account" and i.added_at <= at
            ),
            default=0,
        )
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
            bool(acc and acc.status_at(s.started_at) == "frozen"),
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
        transaction: Transaction | str | None = None,
        *,
        envelope: dict[str, Any] | None = None,
        untrusted: tuple[UntrustedContent, ...] = (),
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        """By id (or a record identical to the stored one): the record store, TRUSTED_LOCAL,
        or VERIFIED_EXTERNAL when the store holds its issuer's signed statement. With
        ``envelope``: the issuer's statement carried by the caller. Any other transaction
        object is UNTRUSTED."""
        t0 = time.perf_counter()
        if envelope is not None:
            if transaction is not None:
                raise ValueError("pass a transaction or a signed envelope, not both")
            payload = envelope.get("payload") if isinstance(envelope, dict) else None
            if not isinstance(payload, dict):
                raise ValueError("the envelope carries no transaction record")
            t = _transaction_from_record(payload)
            for rid in (t.transaction_id, _named(envelope, FactKind.TRANSACTION)):
                if rid and self.store.transaction(rid) is not None:
                    raise ValueError(f"{rid} is held by the record store; evaluate it by id")
            src = FactsSource.CALLER_SUPPLIED
        else:
            if transaction is None:
                raise ValueError("a transaction, its id or a signed envelope is required")
            found = (
                self.store.transaction(transaction) if isinstance(transaction, str) else transaction
            )
            if found is None:
                raise KeyError(f"unknown transaction {transaction}")
            t = found
            # A transaction read by id (or identical to the stored record) is system-of-record
            # input, checked against its issuer's statement when the store holds one.
            stored = self.store.transaction(t.transaction_id)
            if isinstance(transaction, str) or stored == t:
                src = FactsSource.SYSTEM_OF_RECORD
                envelope = self.store.fact_envelope(FactKind.TRANSACTION.subject(t.transaction_id))
            elif stored is not None:
                raise ValueError(
                    f"{t.transaction_id} is held by the record store; evaluate it by id"
                )
            else:
                src = FactsSource.CALLER_SUPPLIED
        ctx = self.transaction_context(t)
        acc = self.store.account(t.account_id)
        mprof = self.world.engine.merchant_risk(t.merchant_id, as_of=t.timestamp)
        b = run_transaction(
            self._rt(options),
            TransactionRequest(
                t,
                ctx,
                acc.status_at(t.timestamp) if acc else "unknown",
                mprof.level.value,
                untrusted,
                src,
                envelope,
            ),
            options,
        )
        METRICS.observe("evaluate_transaction", (time.perf_counter() - t0) * 1000)
        return self._persist(b)

    def evaluate_dispute(
        self,
        narrative: str = "",
        ledger: dict[str, object] | None = None,
        *,
        dispute_id: str | None = None,
        envelope: dict[str, Any] | None = None,
        documents: tuple[str, ...] = (),
        source: str = "cardholder",
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        """How the facts arrive decides what they can establish (``sentinel.trust``):

        - ``dispute_id`` alone: the record store -- TRUSTED_LOCAL, or VERIFIED_EXTERNAL when
          the store holds the issuer's signed statement (verified again now, and checked
          against the stored row). The stored narrative is the claim.
        - ``envelope``: an issuer's signed statement carried by the caller, trusted only if
          it verifies and only for the dispute it names.
        - ``ledger``: facts in the request, unsigned -- UNTRUSTED. They can make an outcome
          stricter, never looser."""
        t0 = time.perf_counter()
        if ledger is not None and envelope is not None:
            raise ValueError("pass a ledger or a signed envelope, not both")
        named = dispute_id or _named(envelope, FactKind.DISPUTE_LEDGER)
        if (ledger is not None or envelope is not None) and named and self.store.dispute(named):
            # a stored dispute is evaluated as stored: its recorded submission, its account's
            # context and its statement checked against the stored row -- never re-pointed
            raise ValueError(f"{named} is held by the record store; evaluate it by id")
        account_id = None
        account_risk = 0
        facts_source = FactsSource.CALLER_SUPPLIED
        if dispute_id and ledger is None and envelope is None:
            found = self.store.dispute(dispute_id)
            if found is None:
                raise KeyError(f"unknown dispute {dispute_id}")
            d, texts = found
            stored = (
                texts.get("narrative", ""),
                (texts["document"],) if texts.get("document") else (),
            )
            if (narrative and narrative != stored[0]) or (documents and documents != stored[1]):
                # The claim selector of a stored dispute is its stored text; new text is a
                # new submission, not a way to re-point an existing one.
                raise ValueError(
                    f"{dispute_id} is evaluated on its recorded submission; new text is a new dispute"
                )
            narrative, documents = stored
            ledger = self._dispute_ledger(d)
            envelope = self.store.fact_envelope(FactKind.DISPUTE_LEDGER.subject(dispute_id))
            facts_source = FactsSource.SYSTEM_OF_RECORD
            account_id = d.account_id
            account_risk = self.world.engine.account_risk(d.account_id, as_of=d.submitted_at).score
        b = self._dispute(
            narrative,
            ledger or {},
            dispute_id or "",
            envelope,
            facts_source,
            documents,
            source,
            account_id,
            account_risk,
            options,
        )
        METRICS.observe("evaluate_dispute", (time.perf_counter() - t0) * 1000)
        return self._persist(b)

    def _dispute(
        self,
        narrative: str,
        ledger: dict[str, object],
        dispute_id: str,
        envelope: dict[str, Any] | None,
        facts_source: FactsSource,
        documents: tuple[str, ...],
        source: str,
        account_id: str | None,
        account_risk: int,
        options: RunOptions,
    ) -> DecisionBundle:
        docs = tuple(
            UntrustedContent(x, TrustClass.DOCUMENT_CONTROLLED, "uploaded_document", "document")
            for x in documents
        )
        return run_dispute(
            self._rt(options),
            DisputeRequest(
                UntrustedContent(narrative, TrustClass.USER_CONTROLLED, source),
                ledger,
                dispute_id,
                docs,
                None,
                account_id,
                account_risk,
                facts_source,
                envelope,
            ),
            options,
        )

    def evaluate_dispute_conversation(
        self,
        turns: tuple[str, ...],
        ledger: dict[str, object] | None = None,
        *,
        envelope: dict[str, Any] | None = None,
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        """A multi-turn dispute: one conversation, one decision. Facts as for
        ``evaluate_dispute``: a signed ``envelope``, or an unsigned ``ledger`` (UNTRUSTED)."""
        if (ledger is None) == (envelope is None):
            raise ValueError("pass exactly one of a ledger or a signed envelope")
        return self._persist(
            self._conversation(turns, ledger or {}, envelope, FactsSource.CALLER_SUPPLIED, options)
        )

    def _conversation(
        self,
        turns: tuple[str, ...],
        ledger: dict[str, object],
        envelope: dict[str, Any] | None,
        facts_source: FactsSource,
        options: RunOptions,
        *,
        dispute_id: str | None = None,
    ) -> DecisionBundle:
        subject = envelope.get("subject") if isinstance(envelope, dict) else None
        if dispute_id is None and isinstance(subject, str) and subject.startswith("dispute:"):
            dispute_id = subject.split(":", 1)[1]  # the dispute the statement is about
        s = DisputeSession(
            self._rt(options),
            ledger,
            dispute_id=dispute_id or new_id("DSP"),
            options=options,
            facts_source=facts_source,
            envelope=envelope,
        )
        for t in turns:
            s.append(t)
        return s.decide()  # one conversation, one decision

    def evaluate_merchant(
        self,
        application: str,
        records: dict[str, object] | None = None,
        *,
        application_id: str | None = None,
        merchant_id: str = "",
        envelope: dict[str, Any] | None = None,
        documents: tuple[str, ...] = (),
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        """As for disputes: ``application_id`` reads the record store (and its issuer's
        signed statement, when held); ``envelope`` is a signed acquirer record carried by
        the caller; ``records`` are unsigned request facts (UNTRUSTED)."""
        if records is not None and envelope is not None:
            raise ValueError("pass records or a signed envelope, not both")
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        app_named = payload.get("application_id") if isinstance(payload, dict) else None
        if isinstance(app_named, str) and self.store.kyb_application(app_named) is not None:
            raise ValueError(f"{app_named} is held by the record store; evaluate it by id")
        facts_source = FactsSource.CALLER_SUPPLIED
        if application_id and records is None and envelope is None:
            facts_source = FactsSource.SYSTEM_OF_RECORD
            found = self.store.kyb_application(application_id)
            if found is None:
                raise KeyError(f"unknown application {application_id}")
            k, texts = found
            stored = (
                texts.get("application", ""),
                (texts["document"],) if texts.get("document") else (),
            )
            if (application and application != stored[0]) or (documents and documents != stored[1]):
                raise ValueError(
                    f"{application_id} is evaluated on its recorded application; new text is a "
                    "new application"
                )
            if merchant_id and merchant_id != k.merchant_id:
                raise ValueError(f"{application_id} belongs to {k.merchant_id}, not {merchant_id}")
            application, documents = stored
            records = self._kyb_record(k)
            merchant_id = k.merchant_id
            envelope = self.store.fact_envelope(f"application:{application_id}")
        docs = tuple(
            UntrustedContent(x, TrustClass.DOCUMENT_CONTROLLED, "uploaded_document", "document")
            for x in documents
        )
        b = run_kyb(
            self._rt(options),
            KYBRequest(
                UntrustedContent(application, TrustClass.MERCHANT_CONTROLLED, "application"),
                records or {},
                merchant_id,
                docs,
                facts_source,
                envelope,
            ),
            options,
        )
        return self._persist(b)

    def evaluate_account(
        self,
        session: LoginSession | str | None = None,
        *,
        envelope: dict[str, Any] | None = None,
        message: str | None = None,
        requested_capability: Any = None,
        options: RunOptions = DEFAULT_OPTIONS,
    ) -> DecisionBundle:
        """Facts as for transactions: by id (store, with its signed statement when held), a
        signed ``envelope`` carried by the caller, or an unsigned session object."""
        if envelope is not None:
            if session is not None:
                raise ValueError("pass a session or a signed envelope, not both")
            payload = envelope.get("payload") if isinstance(envelope, dict) else None
            if not isinstance(payload, dict):
                raise ValueError("the envelope carries no session record")
            s = _session_from_record(payload)
            for rid in (s.session_id, _named(envelope, FactKind.LOGIN_SESSION)):
                if rid and self.store.session(rid) is not None:
                    raise ValueError(f"{rid} is held by the record store; evaluate it by id")
            src = FactsSource.CALLER_SUPPLIED
        else:
            if session is None:
                raise ValueError("a session, its id or a signed envelope is required")
            found = self.store.session(session) if isinstance(session, str) else session
            if found is None:
                raise KeyError(f"unknown session {session}")
            s = found
            stored_session = self.store.session(s.session_id)
            if isinstance(session, str) or stored_session == s:
                src = FactsSource.SYSTEM_OF_RECORD
                envelope = self.store.fact_envelope(FactKind.LOGIN_SESSION.subject(s.session_id))
            elif stored_session is not None:
                raise ValueError(f"{s.session_id} is held by the record store; evaluate it by id")
            else:
                src = FactsSource.CALLER_SUPPLIED
        ctx = self.account_security_context(s)
        msg = (
            UntrustedContent(message, TrustClass.USER_CONTROLLED, "customer_message")
            if message
            else None
        )
        b = run_account_security(
            self._rt(options),
            AccountSecurityRequest(s, ctx, msg, requested_capability, src, envelope),
            options,
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
        backtest = as_of is not None and as_of != self.world.dataset.as_of
        rt = self.what_if_runtime if backtest else self._rt(options)
        b = run_investigation(
            rt, InvestigationRequest(ctx, notes, FactsSource.SYSTEM_OF_RECORD), options
        )
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
            # The preset's ledger stands for the institution's record of the disputed
            # payment: the demo issuer signs it, exactly as it signs the dataset.
            dispute_id = new_id("DSP")
            env = (
                self.issuer.sign(FactKind.DISPUTE_LEDGER, dispute_id, dict(p.ledger))
                if self.issuer is not None
                else None
            )
            if p.turns and narrative is None:
                b = self._persist(
                    self._conversation(
                        p.turns,
                        {} if env is not None else dict(p.ledger),
                        env,
                        FactsSource.DEMO_FIXTURE,
                        opts,
                        dispute_id=dispute_id,
                    )
                )
                return b, "\n".join(f"Turn {i + 1}: {t}" for i, t in enumerate(p.turns))
            docs = (document,) if document else ((p.document,) if p.document else ())
            b = self._persist(
                self._dispute(
                    narrative if narrative is not None else p.narrative,
                    {} if env is not None else dict(p.ledger),
                    dispute_id,
                    env,
                    FactsSource.DEMO_FIXTURE,
                    docs,
                    "cardholder",
                    None,
                    0,
                    opts,
                )
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
        on = set(d.controls)  # a control that is off is shown as such, not as a verdict
        cap = d.requested_capability.value if d.requested_capability else "none"
        executed = d.executed_capability.value if d.executed_capability else None
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
                    "value": f"{b.security.severity.value} · {', '.join(t.value for t in b.security.threat_classes) or 'no findings'}"
                    + ("" if "detection" in on else " -- computed, not enforced (control off)"),
                    "status": (
                        ("alert" if b.security.flagged else "ok") if "detection" in on else "off"
                    ),
                },
                {
                    "stage": "ai_recommendation",
                    "title": "AI recommendation",
                    "value": (
                        f"{b.ai.recommended_action.upper()} (MODEL_GENERATED, {b.ai.provider})"
                        if b.ai
                        else "n/a"
                    ),
                    "status": "alert" if (b.ai and b.ai.requested_capability) else "ok",
                },
                {
                    "stage": "trusted_evidence",
                    "title": "Trusted evidence",
                    "value": (
                        f"{b.reconciliation.verdict.value} — {b.reconciliation.explanation}"
                        if "adjudication" in on
                        else "NOT CONSULTED -- the agent's tool call is taken at its word "
                        f"(the records say {b.reconciliation.verdict.value})"
                    ),
                    "status": (
                        ("ok" if b.reconciliation.supports_claim else "alert")
                        if "adjudication" in on
                        else "off"
                    ),
                },
                {
                    "stage": "policy",
                    "title": f"Policy {d.policy.policy_id}@v{d.policy.version}",
                    "value": (
                        f"{d.policy.outcome.value} · {', '.join(d.policy.matched_rules) or 'no rules matched'}"
                        if "policy" in on
                        else "NOT EVALUATED -- control off"
                    ),
                    "status": (
                        ("ok" if d.policy.outcome.value == "ALLOW" else "alert")
                        if "policy" in on
                        else "off"
                    ),
                },
                {
                    "stage": "authorization",
                    "title": "Capability authorization",
                    "value": (
                        f"{cap} → {d.authorization.status.value}"
                        if "authorization" in on
                        else f"NOT CONSULTED -- {cap} runs because the agent asked"
                    ),
                    "status": (
                        ("ok" if d.authorization.status.value == "GRANTED" else "alert")
                        if "authorization" in on
                        else "off"
                    ),
                },
                {
                    "stage": "final",
                    "title": "Final Sentinel decision" if on else "Outcome (no controls)",
                    "value": f"{d.final_action.value} · "
                    + (f"EXECUTED {executed}" if executed else "nothing executed"),
                    "status": (
                        "ok"
                        if d.final_action.value == "ALLOW"
                        and (not executed or b.reconciliation.supports_claim)
                        else "alert"
                    ),
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
                        else "not recorded (a what-if run)"
                    ),
                    "status": "info",
                },
            ],
            "headline": (
                "The AI was persuaded. The financial system was not."
                if (b.ai and b.ai.requested_capability and not d.executed)
                else (
                    f"{d.executed_capability.value if d.executed_capability else 'capability'} "
                    "executed on a claim the trusted records do not support."
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
        for aid in sorted(flagged)[:accounts]:  # sorted: set order varies per process
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

    # ---- list / catalog payloads shared by the API routes and the static snapshot ----------
    def transaction_list(
        self,
        *,
        account_id: str | None = None,
        merchant_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Transactions with a summary of the latest decision on each."""
        rows = self.store.transactions(
            account_id=account_id, merchant_id=merchant_id, limit=limit, offset=offset
        )
        latest = {
            d["subject_id"]: d for d in self.store.decisions(workflow="transaction", limit=2000)
        }
        out = []
        for t in rows:
            d = latest.get(t.transaction_id)
            out.append(
                {
                    **to_dict(t),
                    "decision": (
                        {
                            k: d.get(k)
                            for k in (
                                "decision_id",
                                "final_action",
                                "risk_score",
                                "risk_level",
                                "case_id",
                            )
                        }
                        if d
                        else None
                    ),
                }
            )
        return {"transactions": out, "total": self.store.count("transactions")}

    def merchant_list(self, limit: int = 50) -> dict[str, Any]:
        return {
            "merchants": [
                {**to_dict(m), "risk": to_dict(self.world.engine.merchant_risk(m.merchant_id))}
                for m in self.store.merchants()[:limit]
            ]
        }

    def account_list(self, limit: int = 50) -> dict[str, Any]:
        return {
            "accounts": [
                {**to_dict(a), "risk": to_dict(self.world.engine.account_risk(a.account_id))}
                for a in self.store.accounts()[:limit]
            ]
        }

    def attack_catalog(self) -> dict[str, Any]:
        return {"attacks": [to_dict(a) for a in ATTACKS.values()]}

    def scenario_catalog(self) -> dict[str, Any]:
        return {
            "scenarios": [to_dict(s) for s in SCENARIOS.values()],
            "tags": self.store.scenarios(),
        }

    def cases(self, status: str | None = None, limit: int = 100) -> list[Case]:
        return self.runtime.cases.list(status=CaseStatus(status) if status else None, limit=limit)

    def case(self, case_id: str) -> Case | None:
        return self.runtime.cases.get(case_id)

    def case_view(self, case_id: str) -> dict[str, Any] | None:
        """A case with the decisions and security events it links to; None if unknown."""
        c = self.runtime.cases.get(case_id)
        if c is None:
            return None
        return {
            "case": to_dict(c),
            "decisions": [d for d in (self.store.decision(x) for x in c.decision_ids) if d],
            "security_events": [
                e for e in (self.store.security_event(x) for x in c.security_event_ids) if e
            ],
        }

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
            "provenance": (latest or {}).get("provenance"),
            "facts_source": {
                "source": (latest or {}).get("facts_source", FactsSource.CALLER_SUPPLIED.value),
                "meaning": FactsSource(
                    (latest or {}).get("facts_source", FactsSource.CALLER_SUPPLIED.value)
                ).describe,
            },
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
            # whether each review level may approve: the registry's answer for a human actor
            "approval": {
                role: dict(
                    zip(("allowed", "reason"), self.runtime.cases.approval(c, role), strict=True)
                )
                for role in ("HUMAN_REVIEWER", "SENIOR_REVIEWER")
            },
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
        ev = self.runtime.audit.get(decision_id)
        r = self.replay_engine.replay(
            base,
            snap,
            overrides,
            recorded=original,
            audit=ev.to_dict() if ev else None,
            verify=True,
        )
        r = replace(
            r, facts=self._reverify_facts(snap, ev.to_dict() if ev else None, r.record_verified)
        )
        if self.runtime.persist:
            payload = r.to_dict()
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
                    "record_verified": r.record_verified,
                    "facts_signature_now": r.facts.get("signature_now"),
                },
            )
        return r

    def _reverify_facts(
        self, snap: dict[str, Any], audit: dict[str, Any] | None, record_verified: bool
    ) -> dict[str, Any]:
        """The decision's fact provenance as its audit event recorded it, and whether the
        statement's signature still holds today (key, revocation, expiry). This is a
        signature check only: it does not repeat the stored-row comparison or the rollback
        state the decision was made with. Withheld when the stored snapshot disagrees with
        the audit event."""
        recorded = ((audit or {}).get("detail") or {}).get("facts") or snap.get("provenance")
        if not recorded:
            return {}
        out: dict[str, Any] = {
            "recorded": recorded["status"],
            "source": recorded["source"],
            "payload_digest": recorded["payload_digest"],
        }
        if not record_verified:
            return {
                **out,
                "signature_now": None,
                "reason": "withheld: the stored snapshot disagrees with its audit event",
            }
        env = snap.get("fact_envelope")
        if env is None:
            return {**out, "signature_now": None, "reason": "unsigned facts: no signature to check"}
        v = verify_fact(
            env,
            trust=self.runtime.trust,
            now=self.runtime.clock(),
            kind=FactKind(recorded["kind"]),
            subject=recorded["subject"],
        )
        return {
            **out,
            "signature_now": v.provenance.status.value,
            "reason": v.provenance.reason,
            "same_payload": v.provenance.payload_digest == recorded["payload_digest"],
        }

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
            "facts_sources": {f.value: f.describe for f in FactsSource},
            "trust": {
                "origin": self.runtime.trust.origin,
                "keys": self.runtime.trust.summary(),
                "demo_issuer": self.issuer.key.key_id if self.issuer is not None else None,
            },
            "audit": to_dict(self.verify_audit()),
            "metrics": METRICS.snapshot(),
            "store": self.store.path,
        }
