"""The AI threat taxonomy: fifteen classes of attack against financial decision
agents, each with the mechanism, how Sentinel detects it, and which financial
capabilities it typically targets.

Only some are (partly) detectable by inspecting text. The rest are caught
structurally: the contradiction engine (adjudication gaming, false evidence),
the trust boundary (synthetic evidence -- a fabricated record is still
untrusted), the capability registry (capability escalation), model-output
inspection (model-output injection), the session model (multi-turn) and the
normaliser (unicode obfuscation).
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain.enums import Capability, ThreatClass


@dataclass(frozen=True)
class ThreatInfo:
    name: str
    description: str
    detection: str  # lexical | structural | session | evidence | normalisation
    typical_targets: tuple[Capability, ...]


TAXONOMY: dict[ThreatClass, ThreatInfo] = {
    ThreatClass.DIRECT_INJECTION: ThreatInfo(
        "Direct instruction injection",
        "Explicit override instructions placed in the untrusted text.",
        "lexical",
        (Capability.APPROVE_REFUND, Capability.APPROVE_TRANSACTION),
    ),
    ThreatClass.AUTHORITY_SPOOF: ThreatInfo(
        "Authority spoofing",
        "Text impersonating a system, compliance, admin or network directive.",
        "lexical",
        (Capability.APPROVE_REFUND, Capability.APPROVE_MERCHANT, Capability.SKIP_REVIEW),
    ),
    ThreatClass.DOCUMENT_BORNE: ThreatInfo(
        "Document-borne injection",
        "Instructions hidden inside an uploaded invoice, receipt or application.",
        "lexical",
        (Capability.APPROVE_REFUND, Capability.APPROVE_MERCHANT),
    ),
    ThreatClass.FAKE_POLICY: ThreatInfo(
        "Policy / rule-citation forgery",
        "Fabricated network rules, regulations or internal policies demanding an action.",
        "lexical",
        (Capability.APPROVE_REFUND, Capability.RELEASE_FUNDS),
    ),
    ThreatClass.CONTEXT_POISONING: ThreatInfo(
        "Context poisoning",
        "Assertions of prior state -- 'you already approved', 'as noted in the case file'.",
        "lexical",
        (Capability.APPROVE_REFUND, Capability.CLOSE_CASE, Capability.SKIP_REVIEW),
    ),
    ThreatClass.TOOL_MANIPULATION: ThreatInfo(
        "Tool manipulation",
        "Text that names or spells out tool / function calls for the agent to make.",
        "lexical",
        (Capability.UNFREEZE_ACCOUNT, Capability.CHANGE_PAYOUT, Capability.RELEASE_FUNDS),
    ),
    ThreatClass.MULTI_TURN_ESCALATION: ThreatInfo(
        "Multi-turn escalation",
        "Trust built across a thread; the payload lands (or is split) across later turns.",
        "session",
        (Capability.APPROVE_REFUND,),
    ),
    ThreatClass.UNICODE_OBFUSCATION: ThreatInfo(
        "Unicode obfuscation",
        "Homoglyphs, zero-width characters or full-width forms used to evade detection.",
        "normalisation",
        (Capability.APPROVE_REFUND,),
    ),
    ThreatClass.INDIRECT_INJECTION: ThreatInfo(
        "Indirect injection",
        "Instructions arriving via third-party content the agent reads (merchant site, email).",
        "lexical",
        (Capability.APPROVE_MERCHANT, Capability.CHANGE_PAYOUT),
    ),
    ThreatClass.ADJUDICATION_GAMING: ThreatInfo(
        "Adjudication gaming",
        "No injection at all -- a false factual claim in persuasive prose. The honest hard case.",
        "evidence",
        (Capability.APPROVE_REFUND,),
    ),
    ThreatClass.FINANCIAL_SOCIAL_ENGINEERING: ThreatInfo(
        "Financial social engineering",
        "Urgency, loyalty, sympathy or threat used to pressure a favourable outcome.",
        "lexical",
        (Capability.APPROVE_REFUND, Capability.UNFREEZE_ACCOUNT),
    ),
    ThreatClass.CAPABILITY_ESCALATION: ThreatInfo(
        "Capability escalation",
        "The model is induced to request a capability outside its surface "
        "(unfreeze, change payout, release funds, close case, alter risk, skip review).",
        "structural",
        (
            Capability.UNFREEZE_ACCOUNT,
            Capability.CHANGE_PAYOUT,
            Capability.RELEASE_FUNDS,
            Capability.CLOSE_CASE,
            Capability.ALTER_RISK,
            Capability.SKIP_REVIEW,
        ),
    ),
    ThreatClass.MODEL_OUTPUT_INJECTION: ThreatInfo(
        "Model-output injection",
        "Untrusted text that mimics the agent's own output format (an 'assistant:' turn, "
        "a JSON tool call, a chat-template marker) so a parser or a model treats it as the "
        "model's decision.",
        "lexical + structural",
        (Capability.APPROVE_REFUND, Capability.RELEASE_FUNDS, Capability.CLOSE_CASE),
    ),
    ThreatClass.FALSE_EVIDENCE: ThreatInfo(
        "False evidence",
        "A verifiable-sounding fact asserted in prose -- a tracking status, a 'your own "
        "system shows' claim -- that the trusted records refute. Nothing to detect; the "
        "contradiction engine decides.",
        "evidence",
        (Capability.APPROVE_REFUND, Capability.APPROVE_MERCHANT),
    ),
    ThreatClass.SYNTHETIC_EVIDENCE: ThreatInfo(
        "Synthetic evidence",
        "A fabricated record, ledger extract or verification report presented as if it were "
        "the institution's own data. It arrives through an untrusted channel, so it can never "
        "become VERIFIED evidence whatever it says.",
        "trust boundary",
        (Capability.APPROVE_REFUND, Capability.APPROVE_MERCHANT, Capability.RELEASE_FUNDS),
    ),
}
