"""The AI Security Gateway.

Generalises the original four-layer firewall's L1 (provenance) and L2
(detection) into one component that inspects **every** kind of untrusted
content that can reach an agent or come out of one:

    user text  ·  merchant documents  ·  transaction descriptors  ·  case notes
    email-like content  ·  multi-turn transcripts  ·  model outputs  ·  tool requests

It produces a ``SecurityAssessment`` (severity, findings, threat classes) that
downstream policy consumes as a *trusted signal about untrusted content*. The
gateway never decides the financial outcome; it informs it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.domain.decisions import AIRecommendation
from sentinel.domain.enums import Capability, Severity, ThreatClass, TrustClass
from sentinel.domain.ids import content_hash
from sentinel.domain.security import SecurityAssessment, SecurityFinding
from sentinel.security import injection
from sentinel.security.capabilities import is_consequential
from sentinel.security.normalize import normalize_report
from sentinel.security.provenance import UntrustedContent

_DOCUMENT_TRUST = (TrustClass.DOCUMENT_CONTROLLED,)
_THIRD_PARTY_TRUST = (TrustClass.MERCHANT_CONTROLLED, TrustClass.UNKNOWN)


@dataclass(frozen=True)
class Conversation:
    """Multi-turn untrusted transcript. The gateway inspects the *cumulative*
    transcript so a payload split across turns is still visible."""

    turns: tuple[UntrustedContent, ...] = field(default_factory=tuple)

    def add(self, content: UntrustedContent) -> Conversation:
        return Conversation(self.turns + (content,))

    def transcript(self) -> UntrustedContent:
        text = "\n".join(f"Turn {i + 1}: {t.text}" for i, t in enumerate(self.turns))
        trust = self.turns[-1].trust if self.turns else TrustClass.USER_CONTROLLED
        return UntrustedContent(text, trust, "conversation", "transcript")


def _severity(score: float, escalation: bool, consequential_requested: bool) -> Severity:
    if escalation:
        return Severity.CRITICAL
    if score >= 0.85:
        return Severity.CRITICAL if consequential_requested else Severity.HIGH
    if score >= injection.THRESHOLD:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.NONE


class AISecurityGateway:
    """Stateless inspector. One instance can be shared by every workflow."""

    def inspect(
        self,
        content: UntrustedContent,
        *,
        turns: int = 1,
        per_turn_texts: tuple[str, ...] = (),
    ) -> SecurityAssessment:
        report = normalize_report(content.text)
        peak, hits = injection.scan(report.text)
        findings: list[SecurityFinding] = [
            SecurityFinding(h.threat_class, h.signal, h.weight, content_hash(h.span), len(h.span))
            for h in hits
        ]
        classes: list[ThreatClass] = [h.threat_class for h in hits]

        # Provenance-aware reclassification: the same directive is document-borne
        # when it arrives in an upload and indirect when it arrives via a third party.
        if hits and content.trust in _DOCUMENT_TRUST:
            classes.append(ThreatClass.DOCUMENT_BORNE)
        if hits and content.trust in _THIRD_PARTY_TRUST:
            classes.append(ThreatClass.INDIRECT_INJECTION)
            findings.append(
                SecurityFinding(
                    ThreatClass.INDIRECT_INJECTION,
                    "third_party_directive",
                    peak,
                    content_hash(content.source),
                    0,
                    f"instruction-like content from {content.source}",
                )
            )

        # Unicode obfuscation: folding was needed AND it revealed a signal, or a lot of it.
        if report.changed and (hits or report.obfuscation_count >= 3):
            w = 0.7 if hits else 0.3
            peak = max(peak, w)
            classes.append(ThreatClass.UNICODE_OBFUSCATION)
            findings.append(
                SecurityFinding(
                    ThreatClass.UNICODE_OBFUSCATION,
                    "normalisation_folded",
                    w,
                    content_hash(content.text),
                    report.obfuscation_count,
                    f"{report.obfuscation_count} obfuscating code points folded",
                )
            )

        # Multi-turn: the transcript trips a signal that no single turn does, or
        # the text leans on prior turns ('as agreed above').
        if turns > 1:
            split = (
                hits
                and per_turn_texts
                and not any(
                    injection.scan(normalize_report(t).text)[0] >= injection.THRESHOLD
                    for t in per_turn_texts
                )
            )
            poisoned = any(h.threat_class is ThreatClass.CONTEXT_POISONING for h in hits)
            if split or poisoned:
                w = 0.75
                peak = max(peak, w)
                classes.append(ThreatClass.MULTI_TURN_ESCALATION)
                findings.append(
                    SecurityFinding(
                        ThreatClass.MULTI_TURN_ESCALATION,
                        "split_payload" if split else "prior_turn_leverage",
                        w,
                        content_hash(content.text),
                        turns,
                    )
                )

        consequential = any(
            h.threat_class is ThreatClass.CAPABILITY_ESCALATION for h in hits
        ) or any(h.signal == "imperative_financial_action" for h in hits)
        sev = _severity(peak, False, consequential)
        return SecurityAssessment(
            severity=sev,
            score=round(peak, 2),
            findings=tuple(findings),
            threat_classes=tuple(dict.fromkeys(classes)),
            source_trust=content.trust,
            content_hash=content.sha256(),
            normalized_changed=report.changed,
        )

    def inspect_conversation(self, convo: Conversation) -> SecurityAssessment:
        return self.inspect(
            convo.transcript(),
            turns=len(convo.turns),
            per_turn_texts=tuple(t.text for t in convo.turns),
        )

    def inspect_model_output(
        self,
        recommendation: AIRecommendation,
        *,
        tool_surface: frozenset[Capability],
    ) -> SecurityAssessment:
        """Model output is untrusted too. Structural check: did the model request
        a capability outside the surface its agent is permitted to *request*?
        (Even in-surface requests are only recommendations downstream.)"""
        cap = recommendation.requested_capability
        # An escalation is a request for a CONSEQUENTIAL capability outside the surface.
        # A read, a bare recommendation, or an unknown tool name that the interpreter
        # mapped to RECOMMEND_ACTION is not an attack -- it is just not authoritative.
        escalation = cap is not None and cap not in tool_surface and is_consequential(cap)
        findings: tuple[SecurityFinding, ...] = ()
        classes: tuple[ThreatClass, ...] = ()
        if escalation and cap is not None:
            findings = (
                SecurityFinding(
                    ThreatClass.CAPABILITY_ESCALATION,
                    "off_surface_capability",
                    1.0,
                    content_hash(cap.value),
                    0,
                    f"{recommendation.agent} requested {cap.value}; surface is "
                    f"{', '.join(sorted(c.value for c in tool_surface)) or 'read-only'}",
                ),
            )
            classes = (ThreatClass.CAPABILITY_ESCALATION,)
        return SecurityAssessment(
            severity=_severity(1.0 if escalation else 0.0, escalation, is_consequential(cap)),
            score=1.0 if escalation else 0.0,
            findings=findings,
            threat_classes=classes,
            source_trust=TrustClass.MODEL_GENERATED,
            content_hash=recommendation.raw_hash or content_hash(recommendation.rationale),
            requested_capability=cap,
            capability_escalation=escalation,
        )

    @staticmethod
    def merge(*parts: SecurityAssessment) -> SecurityAssessment:
        parts = tuple(p for p in parts if p is not None)
        if not parts:
            raise ValueError("nothing to merge")
        worst = max(parts, key=lambda p: (p.severity.rank, p.score))
        findings = tuple(f for p in parts for f in p.findings)
        classes = tuple(dict.fromkeys(c for p in parts for c in p.threat_classes))
        return SecurityAssessment(
            severity=worst.severity,
            score=max(p.score for p in parts),
            findings=findings,
            threat_classes=classes,
            source_trust=worst.source_trust,
            content_hash=content_hash([p.content_hash for p in parts]),
            normalized_changed=any(p.normalized_changed for p in parts),
            requested_capability=next(
                (p.requested_capability for p in parts if p.requested_capability), None
            ),
            capability_escalation=any(p.capability_escalation for p in parts),
        )


GATEWAY = AISecurityGateway()
