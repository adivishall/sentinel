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

from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from sentinel.agents.base import Agent
from sentinel.agents.catalog import SPECS
from sentinel.agents.providers import LLMProvider
from sentinel.audit.chain import AuditChain, AuditEvent
from sentinel.cases.service import CaseService
from sentinel.decision import composer
from sentinel.decision.composer import DecisionInputs, compose
from sentinel.domain.cases import Case
from sentinel.domain.decisions import AIRecommendation, Decision
from sentinel.domain.entities import LoginSession, Transaction
from sentinel.domain.enums import (
    Capability,
    EvidenceKind,
    Severity,
    ThreatClass,
    TrustClass,
    Workflow,
)
from sentinel.domain.events import (
    AUDIT_RECORDED,
    CASE_CREATED,
    DECISION_FINALIZED,
    HUMAN_REVIEW_REQUESTED,
    POLICY_EVALUATED,
    SECURITY_THREAT_DETECTED,
    TRANSACTION_RISK_ASSESSED,
    EventBus,
)
from sentinel.domain.evidence import Claim, Evidence, Reconciliation
from sentinel.domain.ids import content_hash, new_id, now_iso
from sentinel.domain.risk import RiskAssessment
from sentinel.domain.security import SecurityAssessment, SecurityEvent
from sentinel.evidence.reconcile import reconcile_dispute, reconcile_kyb, reconcile_records_only
from sentinel.policy.loader import DEFAULT_REGISTRY, PolicyRegistry
from sentinel.risk import (
    account_security,
    monitoring,
)
from sentinel.risk import (
    dispute as dispute_risk,
)
from sentinel.risk import (
    transaction as txn_risk,
)
from sentinel.risk.scoring import RiskModel
from sentinel.security.gateway import GATEWAY, AISecurityGateway, Conversation
from sentinel.security.normalize import InvalidSubmission, validate
from sentinel.security.provenance import UntrustedContent, wrap_many
from sentinel.security.trust_boundary import DisputeFacts, KYBFacts, UntrustedText

PROVENANCE = "provenance"  # wrap untrusted spans in the agent prompt
FULL: frozenset[str] = composer.FULL | {PROVENANCE}
NONE: frozenset[str] = frozenset()


@dataclass
class Runtime:
    """Shared services. One per process (or per test)."""

    policies: PolicyRegistry = field(default_factory=lambda: DEFAULT_REGISTRY)
    gateway: AISecurityGateway = field(default_factory=lambda: GATEWAY)
    cases: CaseService = field(default_factory=CaseService)
    audit: AuditChain = field(default_factory=AuditChain)
    bus: EventBus = field(default_factory=EventBus)
    provider: LLMProvider | None = None
    persist: bool = True  # write audit events and open cases
    security_events: list[SecurityEvent] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)

    def agent(self, key: str) -> Agent:
        return Agent(SPECS[key], self.provider)


@dataclass(frozen=True)
class RunOptions:
    controls: frozenset[str] = FULL
    policy_version: int | None = None
    risk_model: RiskModel | None = None
    hardened: bool = False
    session_id: str | None = None
    skip_agent: bool = False  # evaluate without calling any model


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
    decision = compose(inputs)
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
        if rt.persist:
            rt.security_events.append(security_event)
        rt.bus.emit(
            SECURITY_THREAT_DETECTED,
            decision.subject_id,
            severity=sec.severity.value,
            classes=[t.value for t in sec.threat_classes],
        )
    if risk is not None:
        rt.bus.emit(
            (
                TRANSACTION_RISK_ASSESSED
                if inputs.workflow is Workflow.TRANSACTION
                else "RiskAssessed"
            ),
            decision.subject_id,
            score=risk.score,
            level=risk.level.value,
        )
    rt.bus.emit(
        POLICY_EVALUATED,
        decision.subject_id,
        policy=decision.policy.policy_id,
        version=decision.policy.version,
        outcome=decision.policy.outcome.value,
    )

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
            rt.bus.emit(
                CASE_CREATED, case.case_id, rule=case.opened_by_rule, priority=case.priority.value
            )
            if decision.human_review.required:
                rt.bus.emit(HUMAN_REVIEW_REQUESTED, case.case_id, decision_id=decision.decision_id)
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
            },
        )
        decision = replace(decision, audit_event_id=audit_event.event_id)
        if case is not None:
            rt.cases.link_audit(case.case_id, audit_event.event_id)
        rt.decisions.append(decision)
        rt.bus.emit(
            AUDIT_RECORDED,
            decision.decision_id,
            event_id=audit_event.event_id,
            sequence=audit_event.sequence,
        )
    rt.bus.emit(
        DECISION_FINALIZED,
        decision.decision_id,
        action=decision.final_action.value,
        workflow=decision.workflow.value,
    )
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
) -> DecisionBundle:
    """Unusable untrusted input never silently approves -- it goes to a human."""
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


def run_dispute(
    rt: Runtime, req: DisputeRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    facts = DisputeFacts.from_ledger(req.ledger)
    dispute_id = req.dispute_id or new_id("DSP")
    try:
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
        claim, facts, extra_claims=tuple(c for c in extra if c.claim_type.value != "unspecified")
    )

    risk = dispute_risk.assess_dispute(
        dispute_id,
        facts,
        contradicted=bool(rec.contradictions),
        account_risk_score=req.account_risk_score,
        security_flagged=security.flagged,
    )
    provider, model = _provider_meta(rt, ai)
    inputs = DecisionInputs(
        workflow=Workflow.DISPUTE,
        subject_type="dispute",
        subject_id=dispute_id,
        amount=facts.amount,
        candidate_capability=Capability.APPROVE_REFUND,
        facts={
            "policy_auto_limit": facts.policy_auto_limit,
            "prior_disputes_90d": facts.prior_disputes_90d,
            "delivery_status": facts.delivery_status,
            "account_risk_score": req.account_risk_score,
        },
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


def run_transaction(
    rt: Runtime, req: TransactionRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    t = req.transaction
    model = opts.risk_model
    risk = (
        txn_risk.assess_transaction(t, req.context, model)
        if model
        else txn_risk.assess_transaction(t, req.context)
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
        Evidence.fact(f"EV-TXN-{i:03d}", "payment_switch", k, v)
        for i, (k, v) in enumerate(pairs, start=1)
    ) + tuple(
        Evidence.fact(f"EV-RISK-{i:03d}", "risk_engine", f.code, f.points, note=f.label)
        for i, f in enumerate(risk.factors, start=1)
    )
    rec = reconcile_records_only(fact_ev, why="payment-switch record and risk signals are trusted")
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


def run_kyb(rt: Runtime, req: KYBRequest, opts: RunOptions = DEFAULT_OPTIONS) -> DecisionBundle:
    facts = KYBFacts.from_records(req.records)
    merchant_id = req.merchant_id or new_id("MER")
    try:
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
    rec = reconcile_kyb(facts, application_claim=claim)
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


def run_account_security(
    rt: Runtime, req: AccountSecurityRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    s = req.session
    risk = account_security.assess_login(
        s, req.context, opts.risk_model or account_security.scoring.ACCOUNT_SECURITY_V1
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
        Evidence.fact(f"EV-SESS-{i:03d}", "auth_service", k, v, kind=EvidenceKind.SESSION_RECORD)
        for i, (k, v) in enumerate(spairs, start=1)
    )
    rec = reconcile_records_only(
        fact_ev, why="session record from the authentication service is trusted"
    )
    cap = req.requested_capability
    if cap is None:
        cap = Capability.CHANGE_PAYOUT if "payout_change" in s.events else None
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


def run_investigation(
    rt: Runtime, req: InvestigationRequest, opts: RunOptions = DEFAULT_OPTIONS
) -> DecisionBundle:
    risk = monitoring.assess_account_activity(
        req.context, opts.risk_model or monitoring.scoring.MONITORING_V1
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
        Evidence.fact(f"EV-MON-{i:03d}", "monitoring_engine", f.code, f.points, note=f.detail)
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
        extra_context={
            "requested_capability": (
                ai.requested_capability.value if (ai and ai.requested_capability) else "NONE"
            )
        },
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
            rt.security_events.append(event)
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
        rt.bus.emit(SECURITY_THREAT_DETECTED, event.event_id, severity=sec.severity.value)
    return AISecurityResult(sec, ai, event, audit_event)


def threat_classes_of(sec: SecurityAssessment) -> tuple[ThreatClass, ...]:
    return sec.threat_classes
