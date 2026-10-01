"""Workflows: the same pipeline for every financial surface.

    untrusted information -> gateway -> risk -> AI recommendation ->
    trusted-evidence reconciliation -> policy -> authorization ->
    human review -> action -> case -> audit

Every ``run_*`` builds typed ``DecisionInputs`` and hands them to the
composer. Nothing here decides; it assembles trusted inputs, records the
model's opinion, and persists the outcome. API, CLI, UI and evaluation all
call these functions -- there is no second pipeline.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol

from sentinel import __version__
from sentinel.agents.base import Agent
from sentinel.agents.catalog import SPECS
from sentinel.agents.providers import LLMProvider
from sentinel.audit.chain import AuditChain, AuditEvent
from sentinel.cases.service import CaseService
from sentinel.decision import composer
from sentinel.decision.authority import ControlDowngrade, require_authoritative
from sentinel.decision.composer import DecisionInputs, compose
from sentinel.decision.snapshot import snapshot, snapshot_hash
from sentinel.domain.cases import Case
from sentinel.domain.decisions import AIRecommendation, Decision
from sentinel.domain.entities import LoginSession, Transaction
from sentinel.domain.enums import (
    Capability,
    EvidenceKind,
    EvidenceVerdict,
    FactKind,
    FactsSource,
    ProvenanceStatus,
    Severity,
    TrustClass,
    Workflow,
)
from sentinel.domain.evidence import Claim, Evidence, Reconciliation
from sentinel.domain.ids import content_hash, new_id, now_iso
from sentinel.domain.provenance import FactProvenance
from sentinel.domain.risk import RiskAssessment
from sentinel.domain.security import SecurityAssessment, SecurityEvent
from sentinel.evidence.reconcile import reconcile_dispute, reconcile_kyb, reconcile_records_only
from sentinel.policy.loader import DEFAULT_REGISTRY, PolicyRegistry
from sentinel.risk import (
    account_security,
    monitoring,
    scoring,
)
from sentinel.risk import (
    dispute as dispute_risk,
)
from sentinel.risk import (
    transaction as txn_risk,
)
from sentinel.risk.scoring import RiskModel
from sentinel.security.capabilities import execution_key
from sentinel.security.gateway import GATEWAY, AISecurityGateway, Conversation
from sentinel.security.normalize import InvalidSubmission, validate
from sentinel.security.provenance import UntrustedContent, wrap_many
from sentinel.security.trust_boundary import MAX_AMOUNT, DisputeFacts, KYBFacts, UntrustedText
from sentinel.trust import local, record_digest, untrusted
from sentinel.trust.facts import MemorySequences, SequenceLedger, verify_fact
from sentinel.trust.issuer import utc_now
from sentinel.trust.keys import TrustStore

PROVENANCE = "provenance"  # wrap untrusted spans in the agent prompt
FULL: frozenset[str] = composer.FULL | {PROVENANCE}
NONE: frozenset[str] = frozenset()


class ExecutionLedger(Protocol):
    """Which decision (or human approval) executed each capability on each subject."""

    def holder(self, key: str) -> str | None: ...

    def claim(self, key: str, by: str) -> str | None:
        """Claim ``key`` for ``by``; None when claimed now, else the existing holder."""
        ...


class MemoryExecutions:
    def __init__(self) -> None:
        self._held: dict[str, str] = {}
        self._lock = threading.Lock()

    def holder(self, key: str) -> str | None:
        return self._held.get(key)

    def claim(self, key: str, by: str) -> str | None:
        with self._lock:
            if key in self._held:
                return self._held[key]
            self._held[key] = by
            return None


@dataclass
class Runtime:
    """Shared services. One per process (or per test)."""

    policies: PolicyRegistry = field(default_factory=lambda: DEFAULT_REGISTRY)
    gateway: AISecurityGateway = field(default_factory=lambda: GATEWAY)
    cases: CaseService = field(default_factory=CaseService)
    audit: AuditChain = field(default_factory=AuditChain)
    provider: LLMProvider | None = None
    persist: bool = True  # write audit events and open cases
    # Which issuers' signed facts are trusted (operator configuration), the highest
    # statement already acted on per subject (anti-rollback), and the verification clock.
    trust: TrustStore = field(default_factory=TrustStore.empty)
    sequences: SequenceLedger = field(default_factory=MemorySequences)
    clock: Callable[[], datetime] = utc_now
    # Deployment configuration, not data: every record-store read must come with its
    # issuer's signed statement. Without it, deleting a statement from the store would
    # silently downgrade a tampered record to TRUSTED_LOCAL instead of exposing it.
    require_signed_facts: bool = False
    # One execution per subject and capability (idempotency): a re-evaluation of a record
    # that already paid, onboarded or authorised is denied, not executed again.
    executions: ExecutionLedger = field(default_factory=lambda: MemoryExecutions())

    def __post_init__(self) -> None:
        # a recording runtime chains every human case action into its own audit chain, and
        # a human approval claims the same execution a decision would
        if self.persist and self.cases.audit is None:
            self.cases.audit = self.audit
        if self.persist and self.cases.executions is None:
            self.cases.executions = self.executions

    def agent(self, key: str) -> Agent:
        return Agent(SPECS[key], self.provider)


@dataclass(frozen=True)
class RunOptions:
    """How to run one evaluation. ``controls``, ``policy_version`` and ``risk_model`` are
    what-if switches (``sentinel.decision.authority``): any of them makes the run a
    what-if that is never recorded as a decision. ``hardened`` and ``skip_agent`` only
    change the model call and are allowed on the authoritative path (with no model
    call there is no model output to check; nothing else changes)."""

    controls: frozenset[str] = FULL
    policy_version: int | None = None
    risk_model: RiskModel | None = None
    hardened: bool = False
    session_id: str | None = None
    skip_agent: bool = False  # evaluate without calling any model
    # an attack-simulator run: its facts are demo fixtures signed on request, so however it
    # is decided it is a simulation -- never recorded, never executed
    simulation: bool = False

    @property
    def what_if(self) -> bool:
        return (
            self.controls != FULL
            or self.policy_version is not None
            or self.risk_model is not None
            or self.simulation
        )


DEFAULT_OPTIONS = RunOptions()


@dataclass(frozen=True)
class DecisionBundle:
    decision: Decision
    security: SecurityAssessment
    reconciliation: Reconciliation
    risk: RiskAssessment | None
    ai: AIRecommendation | None
    security_event: SecurityEvent | None
    case: Case | None
    audit_event: AuditEvent | None
    policy_context_hash: str
    inputs: DecisionInputs | None = None


# ---- helpers ------------------------------------------------------------------------
def _inspect_all(
    rt: Runtime, contents: tuple[UntrustedContent, ...], conversation: Conversation | None
) -> SecurityAssessment:
    parts = [rt.gateway.inspect(c) for c in contents]
    if conversation is not None and len(conversation.turns) > 1:
        parts.append(rt.gateway.inspect_conversation(conversation))
    return rt.gateway.merge(*parts)


def _prompt(
    contents: tuple[UntrustedContent, ...], trusted_block: str, controls: frozenset[str]
) -> str:
    if PROVENANCE in controls:
        return (trusted_block + "\n\n" if trusted_block else "") + wrap_many(list(contents))
    return (trusted_block + "\n\n" if trusted_block else "") + "\n\n".join(c.text for c in contents)


def _run_agent(rt: Runtime, key: str, prompt: str, opts: RunOptions) -> AIRecommendation | None:
    if opts.skip_agent:
        return None
    agent = rt.agent(f"{key}_hardened" if opts.hardened and f"{key}_hardened" in SPECS else key)
    return agent.recommend(prompt)


def _admit(rt: Runtime, opts: RunOptions) -> None:
    """A recording runtime refuses what-if options before anything runs. ``_finish`` also
    checks the composed inputs; this catches what the inputs cannot show -- a run without
    prompt provenance, or a custom risk model that reuses the active model's version name."""
    if rt.persist and opts.what_if:
        raise ControlDowngrade(
            "refusing a what-if run on a recording runtime (reduced controls, a named policy "
            "version or a supplied risk model); use the what-if runtime or replay"
        )


def _id_from_subject(kind: FactKind, subject: str) -> str | None:
    prefix = kind.subject_prefix + ":"
    rid = subject[len(prefix) :] if subject.startswith(prefix) else ""
    return rid if rid and rid != "?" else None


# What a signed statement of each kind must state. An issuer that leaves a field out has
# not said it; a default filled in here would be Sentinel's assumption presented as the
# issuer's word (a missing refund_state read as "none" can pay a second refund).
STATEMENT_FIELDS: dict[FactKind, frozenset[str]] = {
    FactKind.DISPUTE_LEDGER: frozenset(
        {
            "amount",
            "delivery_status",
            "prior_disputes_90d",
            "duplicate_confirmed",
            "cancellation_confirmed",
            "cardholder_present",
            "refund_state",
            "transaction_status",
            "merchant_response",
            "auth_strength",
            "customer_tenure_days",
        }
    ),
    FactKind.KYB_RECORD: frozenset(
        {"registration_status", "domain_age_days", "business_age_days", "prior_flags", "mcc_risk"}
    ),
    FactKind.TRANSACTION: frozenset(
        {
            "transaction_id",
            "account_id",
            "merchant_id",
            "instrument_id",
            "device_id",
            "amount",
            "currency",
            "timestamp",
            "country",
            "channel",
            "auth_strength",
            "delivery_status",
            "counterparty_account_id",
            "status",
        }
    ),
    FactKind.LOGIN_SESSION: frozenset(
        {
            "session_id",
            "account_id",
            "device_id",
            "ip",
            "country",
            "started_at",
            "mfa_passed",
            "events",
        }
    ),
}


def _resolve_facts(
    rt: Runtime,
    kind: FactKind,
    record_id: str,
    record: Mapping[str, object],
    source: FactsSource,
    envelope: Mapping[str, object] | None,
    *,
    new_prefix: str,
    uses_record: bool = False,
) -> tuple[FactProvenance, dict[str, object], str]:
    """Establish the facts a decision may use, and how far they can be trusted.

    - an envelope is verified against the runtime's trust store (``sentinel.trust``);
      only one that verifies, states every field its kind requires, and (for a record
      read from the store) matches the stored row yields VERIFIED_EXTERNAL, and then its
      payload -- the issuer's statement, not a stored copy -- is what the decision uses.
      A statement that does not verify is never decided on: the decision falls back to
      the request's own record (empty for a bare envelope), which fails safe.
    - a record read by id from the record store is TRUSTED_LOCAL (INVALID when the
      deployment requires signed records and none is held);
    - anything else (a request body, a demo fixture nobody signed) is UNTRUSTED.

    ``uses_record``: the workflow decides on ``record`` itself (a transaction or session
    builds its risk context from it), so the provenance names that record's digest.
    Returns the provenance, the facts to use and the record id (taken from the envelope's
    subject when the request named none)."""
    if envelope is not None:
        v = verify_fact(
            envelope,
            trust=rt.trust,
            now=rt.clock(),
            kind=kind,
            subject=kind.subject(record_id) if record_id else None,
            sequences=rt.sequences,
        )
        prov = v.provenance
        rid = record_id or _id_from_subject(kind, prov.subject) or new_id(new_prefix)
        if v.verified:
            assert v.payload is not None
            missing = sorted(STATEMENT_FIELDS[kind] - set(v.payload))
            if missing:
                prov = replace(
                    prov,
                    status=ProvenanceStatus.INVALID,
                    reason=f"the signed statement omits {missing}; an unstated field is not "
                    "the issuer's word",
                )
            elif source is FactsSource.SYSTEM_OF_RECORD and record:
                diff = sorted(
                    k
                    for k in set(v.payload) | set(record)
                    if v.payload.get(k, _MISSING) != record.get(k, _MISSING)
                )
                if diff:
                    prov = replace(
                        prov,
                        status=ProvenanceStatus.INVALID,
                        reason=f"the stored record differs from the signed statement on {diff}",
                    )
        verified = prov.status is ProvenanceStatus.VERIFIED_EXTERNAL
        facts = dict(v.payload) if verified and v.payload is not None else dict(record)
        used = record if uses_record else facts
        return replace(prov, payload_digest=record_digest(used)), facts, rid
    rid = record_id or new_id(new_prefix)
    if source is FactsSource.SYSTEM_OF_RECORD:
        prov = local(kind, rid, record)
        if rt.require_signed_facts:
            prov = replace(
                prov,
                status=ProvenanceStatus.INVALID,
                reason="the record store holds no signed statement for this record, and "
                "this deployment requires one (a deleted statement is a tamper signal)",
            )
        return prov, dict(record), rid
    return untrusted(kind, rid, record), dict(record), rid


_MISSING = object()


def _record_evidence(
    evidence_id: str,
    source: str,
    field_name: str,
    value: str | int | bool,
    prov: FactProvenance,
    *,
    kind: EvidenceKind = EvidenceKind.LEDGER_FACT,
    note: str = "",
) -> Evidence:
    """A record field as evidence, carrying the trust its provenance earned: a verified or
    stored record is a VERIFIED fact; an unverified one is only a claim about the records."""
    trust = prov.evidence_trust
    if trust.is_trusted:
        return Evidence.fact(
            evidence_id, source, field_name, value, kind=kind, trust=trust, note=note
        )
    return Evidence.claim(
        evidence_id,
        source,
        field_name,
        value,
        kind=kind,
        trust=trust,
        note=(note + "; " if note else "") + f"unverified record ({prov.status.value})",
    )


def _finish(
    rt: Runtime,
    inputs: DecisionInputs,
    *,
    entities: tuple[str, ...],
    reconciliation: Reconciliation,
    risk: RiskAssessment | None,
    ai: AIRecommendation | None,
    agent_name: str,
) -> DecisionBundle:
    if rt.persist:
        # Structural: nothing is audited, cased or stored as authoritative unless it ran
        # with every control, the active policy and the active risk model.
        require_authoritative(inputs, rt.policies)
    if rt.persist and inputs.candidate_capability is not None:
        key = execution_key(
            inputs.workflow.value, inputs.subject_id, inputs.candidate_capability.value
        )
        inputs = replace(inputs, prior_execution=rt.executions.holder(key))
    decision = compose(inputs)
    if rt.persist and decision.executed_capability is not None:
        key = execution_key(
            decision.workflow.value, decision.subject_id, decision.executed_capability.value
        )
        prior = rt.executions.claim(key, decision.decision_id)
        if prior is not None:  # claimed concurrently since the check above
            inputs = replace(inputs, prior_execution=prior)  # what the snapshot records
            decision = compose(inputs)
    if rt.persist:
        decision = replace(decision, authoritative=True)
    sec = inputs.security
    security_event: SecurityEvent | None = None
    if sec.severity.rank >= Severity.MEDIUM.rank or sec.capability_escalation:
        security_event = SecurityEvent(
            event_id=new_id("SEC"),
            agent=agent_name,
            workflow=inputs.workflow.value,
            severity=sec.severity,
            threat_classes=sec.threat_classes,
            findings=sec.findings,
            source_trust=sec.source_trust,
            content_hash=sec.content_hash,
            requested_capability=ai.requested_capability if ai else None,
            ai_recommendation=ai.recommended_action if ai else None,
            evidence_verdict=reconciliation.verdict.value,
            policy_id=f"{decision.policy.policy_id}@v{decision.policy.version}",
            final_action=decision.final_action.value,
            blocked_by=decision.blocked_by,
            decision_id=decision.decision_id,
            created_at=now_iso(),
        )
        decision = replace(decision, security_event_id=security_event.event_id)

    case: Case | None = None
    audit_event: AuditEvent | None = None
    if rt.persist:
        case = rt.cases.open_for_decision(decision, entities=entities)
        if case is not None:
            decision = replace(
                decision,
                case_id=case.case_id,
                human_review=replace(decision.human_review, case_id=case.case_id),
            )
        audit_event = rt.audit.append(
            actor="sentinel",
            workflow=decision.workflow.value,
            action=decision.final_action.value,
            decision_id=decision.decision_id,
            subject_id=decision.subject_id,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level.value,
            policy_id=decision.policy.policy_id,
            policy_version=decision.policy.version,
            capability=(
                decision.requested_capability.value if decision.requested_capability else None
            ),
            evidence_ids=decision.evidence_ids,
            security_severity=decision.security_severity.value,
            input_hash=decision.input_hash,
            case_id=decision.case_id,
            detail={
                "evidence_verdict": decision.evidence_verdict.value,
                "ai_recommendation": ai.recommended_action if ai else None,
                "ai_requested_capability": (
                    ai.requested_capability.value if ai and ai.requested_capability else None
                ),
                "executed_capability": (
                    decision.executed_capability.value if decision.executed_capability else None
                ),
                "blocked_by": list(decision.blocked_by),
                "authorization": decision.authorization.status.value,
                "controls": list(decision.controls),
                "security_event_id": decision.security_event_id,
                "risk_model": risk.model_version if risk is not None else None,
                "facts_source": str(inputs.facts_source),
                "facts": inputs.provenance.audit_detail() if inputs.provenance else None,
                "policy_release": {
                    "digest": decision.policy.policy_digest,
                    "status": decision.policy.release_status,
                    "signer": decision.policy.release_signer,
                    "key_id": decision.policy.release_key_id,
                    "activation_sequence": decision.policy.activation_sequence,
                },
                # replay verifies the stored input snapshot against this
                "snapshot_hash": snapshot_hash(snapshot(inputs)),
                "engine_version": __version__,
            },
        )
        decision = replace(decision, audit_event_id=audit_event.event_id)
        if case is not None:
            rt.cases.link_audit(case.case_id, audit_event.event_id)
        prov = inputs.provenance
        if (
            prov is not None
            and prov.status is ProvenanceStatus.VERIFIED_EXTERNAL
            and prov.sequence is not None
            and prov.envelope_digest is not None
        ):
            # acted on: an older statement about this subject is now SUPERSEDED
            rt.sequences.advance(prov.source, prov.subject, prov.sequence, prov.envelope_digest)
    return DecisionBundle(
        decision,
        sec,
        reconciliation,
        risk,
        ai,
        security_event,
        case,
        audit_event,
        decision.policy.context_hash,
        inputs,
    )


def _provider_meta(rt: Runtime, ai: AIRecommendation | None) -> tuple[str, str]:
    if ai is not None:
        return ai.provider, ai.model
    p = rt.provider
    if p is not None:
        return p.name, p.model
    from sentinel.agents.providers import get_provider

    p = get_provider()
    return p.name, p.model


def _fail_safe(
    rt: Runtime,
    workflow: Workflow,
    subject_type: str,
    subject_id: str,
    amount: int,
    capability: Capability | None,
    policy_id: str,
    error: str,
    opts: RunOptions,
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED,
    provenance: FactProvenance | None = None,
) -> DecisionBundle:
    """Unusable untrusted input never silently approves -- it goes to a human. An amount
    outside what a record may state is recorded as 0: it was never a usable amount."""
    if isinstance(amount, bool) or not isinstance(amount, int) or not 0 <= amount <= MAX_AMOUNT:
        amount = 0
    from sentinel.domain.enums import EvidenceVerdict
    from sentinel.domain.evidence import EvidenceSet

    rec = Reconciliation(
        None, EvidenceVerdict.INSUFFICIENT, EvidenceSet(), (), f"invalid submission: {error}"
    )
    sec = SecurityAssessment(Severity.NONE, 0.0, (), (), TrustClass.UNKNOWN, "", False, None, False)
    policy = rt.policies.get(policy_id, opts.policy_version)
    provider, model = _provider_meta(rt, None)
    inputs = DecisionInputs(
        workflow,
        subject_type,
        subject_id,
        amount,
        capability,
        {},
        rec,
        sec,
        policy,
        None,
        None,
        controls=opts.controls & composer.FULL,
        input_hash="",
        session_id=opts.session_id,
        provider=provider,
        model=model,
        claim_type="invalid",
        facts_source=facts_source,
        provenance=provenance,
    )
    return _finish(
        rt, inputs, entities=(), reconciliation=rec, risk=None, ai=None, agent_name="n/a"
    )


# =====================================================================================
# Dispute
# =====================================================================================
@dataclass(frozen=True)
class DisputeRequest:
    narrative: UntrustedContent
    ledger: Mapping[str, object]  # trusted ledger facts
    dispute_id: str = ""
    documents: tuple[UntrustedContent, ...] = ()
    conversation: Conversation | None = None
    account_id: str | None = None
    account_risk_score: int = 0
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED
    envelope: Mapping[str, object] | None = None  # a signed dispute_ledger statement


def run_dispute(
    rt: Runtime, req: DisputeRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    _admit(rt, opts)
    prov, ledger, dispute_id = _resolve_facts(
        rt,
        FactKind.DISPUTE_LEDGER,
        req.dispute_id,
        req.ledger,
        req.facts_source,
        req.envelope,
        new_prefix="DSP",
    )
    facts = DisputeFacts.from_ledger(ledger)
    try:
        bad = DisputeFacts.problems(ledger)
        if bad:  # an unusable trusted record is never coerced into a decision
            raise InvalidSubmission("ledger record malformed: " + "; ".join(bad))
        validate(req.narrative.text)
        for d in req.documents:
            validate(d.text)
    except InvalidSubmission as e:
        return _fail_safe(
            rt,
            Workflow.DISPUTE,
            "dispute",
            dispute_id,
            facts.amount,
            Capability.APPROVE_REFUND,
            "dispute-refund",
            str(e),
            opts,
            facts_source=req.facts_source,
            provenance=prov,
        )

    contents = (req.narrative,) + req.documents
    security = _inspect_all(rt, contents, req.conversation)
    if composer.DETECTION not in opts.controls:
        pass  # the composer ignores it; still recorded for explainability

    # The agent (the victim) sees the provenance-wrapped untrusted content.
    prompt = _prompt(contents, "", opts.controls)
    ai = _run_agent(rt, "dispute", prompt, opts)
    if ai is not None:
        security = rt.gateway.merge(
            security,
            rt.gateway.inspect_model_output(ai, tool_surface=SPECS["dispute"].tool_surface),
        )

    # Trusted-evidence reconciliation: prose contributes only a ClaimType.
    claim = UntrustedText(req.narrative.text, req.narrative.source, req.narrative.trust).claim()
    extra: list[Claim] = [UntrustedText(d.text, d.source, d.trust).claim() for d in req.documents]
    rec = reconcile_dispute(
        claim,
        facts,
        extra_claims=tuple(c for c in extra if c.claim_type.value != "unspecified"),
        provenance=prov,
    )

    risk = dispute_risk.assess_dispute(
        dispute_id,
        facts,
        contradicted=bool(rec.contradictions),
        account_risk_score=req.account_risk_score,
        security_flagged=security.flagged,
        model=scoring.model_for("dispute", opts.risk_model),
    )
    provider, model = _provider_meta(rt, ai)
    inputs = DecisionInputs(
        workflow=Workflow.DISPUTE,
        subject_type="dispute",
        subject_id=dispute_id,
        amount=facts.amount,
        candidate_capability=Capability.APPROVE_REFUND,
        facts={**facts.as_policy_facts(), "account_risk_score": req.account_risk_score},
        reconciliation=rec,
        security=security,
        policy=rt.policies.get("dispute-refund", opts.policy_version),
        risk=risk,
        ai=ai,
        controls=opts.controls & composer.FULL,
        input_hash=content_hash([c.text for c in contents]),
        session_id=opts.session_id,
        provider=provider,
        model=model,
        claim_type=claim.claim_type.value,
        facts_source=req.facts_source,
        provenance=prov,
        fact_envelope=dict(req.envelope) if req.envelope is not None else None,
    )
    entities = (f"account:{req.account_id}",) if req.account_id else ()
    return _finish(
        rt,
        inputs,
        entities=entities,
        reconciliation=rec,
        risk=risk,
        ai=ai,
        agent_name=SPECS["dispute"].name,
    )


# =====================================================================================
# Transaction
# =====================================================================================
@dataclass(frozen=True)
class TransactionRequest:
    transaction: Transaction
    context: txn_risk.TransactionContext
    account_status: str = "active"
    merchant_risk_level: str = "LOW"
    untrusted: tuple[UntrustedContent, ...] = ()  # merchant descriptor, customer note, ...
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED
    envelope: Mapping[str, object] | None = None  # a signed transaction statement


def transaction_record(t: Transaction) -> dict[str, object]:
    """The transaction as its issuer (the payment switch) states it. The evaluation
    label is ground truth for scoring the engine, not a fact the switch attests."""
    return {
        "transaction_id": t.transaction_id,
        "account_id": t.account_id,
        "merchant_id": t.merchant_id,
        "instrument_id": t.instrument_id,
        "device_id": t.device_id,
        "amount": t.amount,
        "currency": t.currency,
        "timestamp": t.timestamp,
        "country": t.country,
        "channel": t.channel,
        "auth_strength": t.auth_strength,
        "delivery_status": t.delivery_status,
        "counterparty_account_id": t.counterparty_account_id,
        "status": t.status,
    }


def run_transaction(
    rt: Runtime, req: TransactionRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    _admit(rt, opts)
    t = req.transaction
    prov, _, _ = _resolve_facts(
        rt,
        FactKind.TRANSACTION,
        t.transaction_id,
        transaction_record(t),
        req.facts_source,
        req.envelope,
        new_prefix="TX",
        uses_record=True,
    )
    if (
        isinstance(t.amount, bool)
        or not isinstance(t.amount, int)
        or not 0 < t.amount <= MAX_AMOUNT
    ):
        # a caller-supplied record with a zero, negative or non-integer amount is not a
        # payment to authorise; it goes to a human, never through the limit checks
        return _fail_safe(
            rt,
            Workflow.TRANSACTION,
            "transaction",
            t.transaction_id,
            0,
            Capability.APPROVE_TRANSACTION,
            "transaction-authorization",
            f"transaction amount {t.amount!r} is not a positive integer up to {MAX_AMOUNT:,}",
            opts,
            req.facts_source,
            prov,
        )
    risk = txn_risk.assess_transaction(
        t, req.context, scoring.model_for("transaction", opts.risk_model)
    )
    security = (
        _inspect_all(rt, req.untrusted, None)
        if req.untrusted
        else SecurityAssessment(
            Severity.NONE,
            0.0,
            (),
            (),
            TrustClass.UNKNOWN,
            content_hash(t.transaction_id),
            False,
            None,
            False,
        )
    )
    trusted_block = (
        '{"transaction": '
        + f'{{"id": "{t.transaction_id}", "amount": {t.amount}, "currency": "{t.currency}", '
        f'"merchant_id": "{t.merchant_id}", "country": "{t.country}", "auth": "{t.auth_strength}", '
        f'"risk_score": {risk.score}, "risk_level": "{risk.level.value}"}}}}'
    )
    ai = _run_agent(rt, "transaction", _prompt(req.untrusted, trusted_block, opts.controls), opts)
    if ai is not None:
        security = rt.gateway.merge(
            security,
            rt.gateway.inspect_model_output(ai, tool_surface=SPECS["transaction"].tool_surface),
        )
    pairs: tuple[tuple[str, str | int | bool], ...] = (
        ("transaction_id", t.transaction_id),
        ("amount", t.amount),
        ("merchant_id", t.merchant_id),
        ("device_id", t.device_id),
        ("country", t.country),
        ("auth_strength", t.auth_strength),
        ("account_status", req.account_status),
    )
    fact_ev = tuple(
        _record_evidence(f"EV-TXN-{i:03d}", "payment_switch", k, v, prov)
        for i, (k, v) in enumerate(pairs, start=1)
    ) + tuple(
        _record_evidence(
            f"EV-RISK-{i:03d}",
            "risk_engine",
            f.code,
            f.points,
            prov,
            kind=EvidenceKind.RISK_SIGNAL,
            note=f.label,
        )
        for i, f in enumerate(risk.factors, start=1)
    )
    rec = reconcile_records_only(
        fact_ev, why="payment-switch record and risk signals", provenance=prov
    )
    provider, model_name = _provider_meta(rt, ai)
    inputs = DecisionInputs(
        workflow=Workflow.TRANSACTION,
        subject_type="transaction",
        subject_id=t.transaction_id,
        amount=t.amount,
        candidate_capability=Capability.APPROVE_TRANSACTION,
        facts={
            "account_status": req.account_status,
            "merchant_risk_level": req.merchant_risk_level,
            "merchant_risk_score": req.context.merchant_risk_score,
            "account_risk_score": req.context.linked_entity_risk,
        },
        reconciliation=rec,
        security=security,
        policy=rt.policies.get("transaction-authorization", opts.policy_version),
        risk=risk,
        ai=ai,
        controls=opts.controls & composer.FULL,
        input_hash=content_hash([c.text for c in req.untrusted] or [t.transaction_id]),
        session_id=opts.session_id,
        provider=provider,
        model=model_name,
        facts_source=req.facts_source,
        provenance=prov,
        fact_envelope=dict(req.envelope) if req.envelope is not None else None,
    )
    entities = (f"account:{t.account_id}", f"merchant:{t.merchant_id}", f"device:{t.device_id}")
    return _finish(
        rt,
        inputs,
        entities=entities,
        reconciliation=rec,
        risk=risk,
        ai=ai,
        agent_name=SPECS["transaction"].name,
    )


# =====================================================================================
# Merchant onboarding (KYB)
# =====================================================================================
@dataclass(frozen=True)
class KYBRequest:
    application: UntrustedContent
    records: Mapping[str, object]
    merchant_id: str = ""
    documents: tuple[UntrustedContent, ...] = ()
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED
    envelope: Mapping[str, object] | None = None  # a signed kyb_record statement


def run_kyb(rt: Runtime, req: KYBRequest, opts: RunOptions = DEFAULT_OPTIONS) -> DecisionBundle:
    _admit(rt, opts)
    if opts.risk_model is not None:
        raise ValueError(
            f"risk model {opts.risk_model.version} does not apply to merchant onboarding "
            "(scored by the entity engine, which has no selectable version)"
        )
    prov, records, merchant_id = _resolve_facts(
        rt,
        FactKind.KYB_RECORD,
        req.merchant_id,
        req.records,
        req.facts_source,
        req.envelope,
        new_prefix="MER",
    )
    facts = KYBFacts.from_records(records)
    try:
        bad = KYBFacts.problems(records)
        if bad:
            raise InvalidSubmission("acquirer record malformed: " + "; ".join(bad))
        validate(req.application.text)
        for d in req.documents:
            validate(d.text)
    except InvalidSubmission as e:
        return _fail_safe(
            rt,
            Workflow.MERCHANT_ONBOARDING,
            "merchant",
            merchant_id,
            0,
            Capability.APPROVE_MERCHANT,
            "merchant-onboarding",
            str(e),
            opts,
            facts_source=req.facts_source,
            provenance=prov,
        )
    contents = (req.application,) + req.documents
    security = _inspect_all(rt, contents, None)
    ai = _run_agent(rt, "kyb", _prompt(contents, "", opts.controls), opts)
    if ai is not None:
        security = rt.gateway.merge(
            security, rt.gateway.inspect_model_output(ai, tool_surface=SPECS["kyb"].tool_surface)
        )
    claim = UntrustedText(
        req.application.text, req.application.source, req.application.trust
    ).claim()
    rec = reconcile_kyb(facts, application_claim=claim, provenance=prov)
    provider, model = _provider_meta(rt, ai)
    inputs = DecisionInputs(
        workflow=Workflow.MERCHANT_ONBOARDING,
        subject_type="merchant",
        subject_id=merchant_id,
        amount=0,
        candidate_capability=Capability.APPROVE_MERCHANT,
        facts={
            "registration_status": facts.registration_status,
            "prior_flags": facts.prior_flags,
            "mcc_risk": facts.mcc_risk,
            "domain_age_days": facts.domain_age_days,
            "business_age_days": facts.business_age_days,
        },
        reconciliation=rec,
        security=security,
        policy=rt.policies.get("merchant-onboarding", opts.policy_version),
        risk=None,
        ai=ai,
        controls=opts.controls & composer.FULL,
        input_hash=content_hash([c.text for c in contents]),
        session_id=opts.session_id,
        provider=provider,
        model=model,
        facts_source=req.facts_source,
        provenance=prov,
        fact_envelope=dict(req.envelope) if req.envelope is not None else None,
    )
    return _finish(
        rt, inputs, entities=(), reconciliation=rec, risk=None, ai=ai, agent_name=SPECS["kyb"].name
    )


# =====================================================================================
# Account security
# =====================================================================================
@dataclass(frozen=True)
class AccountSecurityRequest:
    session: LoginSession
    context: account_security.AccountSecurityContext
    message: UntrustedContent | None = None  # what the customer / agent said
    requested_capability: Capability | None = None  # e.g. CHANGE_PAYOUT, UNFREEZE_ACCOUNT
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED
    envelope: Mapping[str, object] | None = None  # a signed login_session statement


def session_record(s: LoginSession) -> dict[str, object]:
    """The login session as the authentication service states it."""
    return {
        "session_id": s.session_id,
        "account_id": s.account_id,
        "device_id": s.device_id,
        "ip": s.ip,
        "country": s.country,
        "started_at": s.started_at,
        "mfa_passed": s.mfa_passed,
        "events": list(s.events),
    }


# The session event that evidences each capability an account-security decision may
# execute (``capabilities.WORKFLOW_CAPABILITIES``).
SESSION_EVIDENCE: dict[Capability, str] = {
    Capability.CHANGE_PAYOUT: "payout_change",
    Capability.FREEZE_ACCOUNT: "freeze_request",
    Capability.UNFREEZE_ACCOUNT: "unfreeze_request",
    Capability.RELEASE_FUNDS: "release_request",
}


def run_account_security(
    rt: Runtime, req: AccountSecurityRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    _admit(rt, opts)
    s = req.session
    prov, _, _ = _resolve_facts(
        rt,
        FactKind.LOGIN_SESSION,
        s.session_id,
        session_record(s),
        req.facts_source,
        req.envelope,
        new_prefix="SES",
        uses_record=True,
    )
    risk = account_security.assess_login(
        s, req.context, scoring.model_for("login", opts.risk_model)
    )
    untrusted = (req.message,) if req.message else ()
    security = (
        _inspect_all(rt, untrusted, None)
        if untrusted
        else SecurityAssessment(
            Severity.NONE,
            0.0,
            (),
            (),
            TrustClass.UNKNOWN,
            content_hash(s.session_id),
            False,
            None,
            False,
        )
    )
    trusted_block = f'{{"session": {{"id": "{s.session_id}", "country": "{s.country}", "device": "{s.device_id}", "events": {list(s.events)!r}, "risk_score": {risk.score}}}}}'
    ai = _run_agent(rt, "account", _prompt(untrusted, trusted_block, opts.controls), opts)
    if ai is not None:
        security = rt.gateway.merge(
            security,
            rt.gateway.inspect_model_output(ai, tool_surface=SPECS["account"].tool_surface),
        )
    spairs: tuple[tuple[str, str | bool], ...] = (
        ("session_id", s.session_id),
        ("device_id", s.device_id),
        ("country", s.country),
        ("mfa_passed", s.mfa_passed),
        ("events", ",".join(s.events)),
    )
    fact_ev = tuple(
        _record_evidence(
            f"EV-SESS-{i:03d}", "auth_service", k, v, prov, kind=EvidenceKind.SESSION_RECORD
        )
        for i, (k, v) in enumerate(spairs, start=1)
    )
    rec = reconcile_records_only(
        fact_ev, why="session record from the authentication service", provenance=prov
    )
    cap = req.requested_capability
    if cap is None:
        cap = Capability.CHANGE_PAYOUT if "payout_change" in s.events else None
    # A requested capability is a claim about what the session asked for; the session
    # record is the evidence. A request the authentication service did not record (a
    # caller asking to FREEZE_ACCOUNT a stored session that never asked) is held for a
    # human -- it never executes on the caller's word.
    evidence_event = SESSION_EVIDENCE.get(cap) if cap is not None else None
    if cap is not None and evidence_event not in s.events:
        rec = replace(
            rec,
            verdict=EvidenceVerdict.INSUFFICIENT,
            explanation=(
                f"{cap.value} was requested, but the session record shows no "
                f"{evidence_event or 'event that requests it'}; held for a human"
            ),
        )
    provider, model = _provider_meta(rt, ai)
    feats = risk.features
    inputs = DecisionInputs(
        workflow=Workflow.ACCOUNT_SECURITY,
        subject_type="login",
        subject_id=s.session_id,
        amount=0,
        candidate_capability=cap,
        facts={
            "new_device": bool(feats.get("new_device")),
            "new_country": bool(feats.get("new_country")),
            "impossible_travel": bool(feats.get("impossible_travel")),
            "payout_change": bool(feats.get("payout_change")),
            "mfa_change": bool(feats.get("mfa_change")),
            "mfa_passed": bool(feats.get("mfa_passed", True)),
            "account_status": "frozen" if req.context.account_frozen else "active",
        },
        reconciliation=rec,
        security=security,
        policy=rt.policies.get("account-security", opts.policy_version),
        risk=risk,
        ai=ai,
        controls=opts.controls & composer.FULL,
        input_hash=content_hash([c.text for c in untrusted] or [s.session_id]),
        session_id=opts.session_id,
        provider=provider,
        model=model,
        facts_source=req.facts_source,
        provenance=prov,
        fact_envelope=dict(req.envelope) if req.envelope is not None else None,
    )
    return _finish(
        rt,
        inputs,
        entities=(f"account:{s.account_id}", f"device:{s.device_id}"),
        reconciliation=rec,
        risk=risk,
        ai=ai,
        agent_name=SPECS["account"].name,
    )


# =====================================================================================
# Investigation (transaction monitoring)
# =====================================================================================
@dataclass(frozen=True)
class InvestigationRequest:
    context: monitoring.MonitoringContext
    case_notes: tuple[UntrustedContent, ...] = ()
    facts_source: FactsSource = FactsSource.CALLER_SUPPLIED


def run_investigation(
    rt: Runtime, req: InvestigationRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    _admit(rt, opts)
    risk = monitoring.assess_account_activity(
        req.context, scoring.model_for("account", opts.risk_model)
    )
    security = (
        _inspect_all(rt, req.case_notes, None)
        if req.case_notes
        else SecurityAssessment(
            Severity.NONE,
            0.0,
            (),
            (),
            TrustClass.UNKNOWN,
            content_hash(req.context.account_id),
            False,
            None,
            False,
        )
    )
    trusted_block = (
        '{"indicators": ' + repr([f.code for f in risk.factors]) + f', "risk_score": {risk.score}}}'
    )
    ai = _run_agent(rt, "aml", _prompt(req.case_notes, trusted_block, opts.controls), opts)
    if ai is not None:
        security = rt.gateway.merge(
            security, rt.gateway.inspect_model_output(ai, tool_surface=SPECS["aml"].tool_surface)
        )
    fact_ev = tuple(
        Evidence.fact(
            f"EV-MON-{i:03d}",
            "monitoring_engine",
            f.code,
            f.points,
            kind=EvidenceKind.RISK_SIGNAL,
            note=f.detail,
        )
        for i, f in enumerate(risk.factors, start=1)
    )
    rec = reconcile_records_only(
        fact_ev, why="structured monitoring indicators are computed from trusted records"
    )
    provider, model = _provider_meta(rt, ai)
    inputs = DecisionInputs(
        workflow=Workflow.INVESTIGATION,
        subject_type="account",
        subject_id=req.context.account_id,
        amount=0,
        candidate_capability=None,
        facts={"monitoring_patterns": [f.code for f in risk.factors]},
        reconciliation=rec,
        security=security,
        policy=rt.policies.get("investigation", opts.policy_version),
        risk=risk,
        ai=ai,
        controls=opts.controls & composer.FULL,
        input_hash=content_hash([c.text for c in req.case_notes] or [req.context.account_id]),
        session_id=opts.session_id,
        provider=provider,
        model=model,
        facts_source=req.facts_source,
    )
    return _finish(
        rt,
        inputs,
        entities=(f"account:{req.context.account_id}",),
        reconciliation=rec,
        risk=risk,
        ai=ai,
        agent_name=SPECS["aml"].name,
    )


# =====================================================================================
# AI security only (no financial decision)
# =====================================================================================
@dataclass(frozen=True)
class AISecurityRequest:
    contents: tuple[UntrustedContent, ...]
    agent_key: str = "dispute"
    run_agent: bool = True
    conversation: Conversation | None = None


@dataclass(frozen=True)
class AISecurityResult:
    assessment: SecurityAssessment
    ai: AIRecommendation | None
    event: SecurityEvent | None
    audit_event: AuditEvent | None


def run_ai_security(
    rt: Runtime, req: AISecurityRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> AISecurityResult:
    for c in req.contents:
        validate(c.text)
    sec = _inspect_all(rt, req.contents, req.conversation)
    ai = None
    if req.run_agent and not opts.skip_agent:
        ai = rt.agent(req.agent_key).recommend(_prompt(req.contents, "", opts.controls))
        sec = rt.gateway.merge(
            sec, rt.gateway.inspect_model_output(ai, tool_surface=SPECS[req.agent_key].tool_surface)
        )
    event: SecurityEvent | None = None
    audit_event: AuditEvent | None = None
    if sec.severity.rank >= Severity.MEDIUM.rank or sec.capability_escalation:
        event = SecurityEvent(
            new_id("SEC"),
            SPECS[req.agent_key].name,
            Workflow.AI_SECURITY.value,
            sec.severity,
            sec.threat_classes,
            sec.findings,
            sec.source_trust,
            sec.content_hash,
            ai.requested_capability if ai else None,
            ai.recommended_action if ai else None,
            None,
            None,
            None,
            (),
            None,
            now_iso(),
        )
        if rt.persist:
            audit_event = rt.audit.append(
                actor="sentinel",
                workflow=Workflow.AI_SECURITY.value,
                action="SECURITY_EVENT",
                subject_id=event.event_id,
                security_severity=sec.severity.value,
                input_hash=sec.content_hash,
                kind="security",
                detail={"classes": [t.value for t in sec.threat_classes], "agent": req.agent_key},
            )
    return AISecurityResult(sec, ai, event, audit_event)
