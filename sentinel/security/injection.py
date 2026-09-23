"""Lexical injection detection over *normalised* untrusted spans.

A transparent, auditable signal set: every finding names its signal, its threat
class and (as a hash) the span that fired, so a block is always explainable.
This is defence-in-depth, not the backstop -- the security case does not
depend on it (see the ablation and ``docs/EVALUATION.md``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.domain.enums import ThreatClass


@dataclass(frozen=True)
class Signal:
    name: str
    threat_class: ThreatClass
    weight: float
    pattern: re.Pattern[str]


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I | re.S)


_TOOLS = (
    r"approve_refund|approve_merchant|release_funds|change_payout|unfreeze_account|"
    r"freeze_account|close_case|skip_review|alter_risk|set_risk|mark_resolved|approve_transaction"
)

SIGNALS: tuple[Signal, ...] = (
    Signal(
        "instruction_override",
        ThreatClass.DIRECT_INJECTION,
        0.9,
        _rx(
            r"(ignore|disregard|override|forget|bypass).{0,40}"
            r"(previous|prior|above|earlier|your|the|all).{0,20}"
            r"(instruction|prompt|rule|system|guideline|checklist|check|guidance|policy)"
        ),
    ),
    Signal(
        "imperative_financial_action",
        ThreatClass.DIRECT_INJECTION,
        0.8,
        _rx(
            r"(issue|process|approve|grant|authorli?[sz]e|release|refund|reimburse|push through)"
            r".{0,30}(the )?(full |immediate |complete )?(refund|reimbursement|amount|₹|rs\b|funds)"
        ),
    ),
    Signal(
        "authority_spoof",
        ThreatClass.AUTHORITY_SPOOF,
        0.85,
        _rx(
            r"system (note|message|override|instruction|prompt)"
            r"|compliance (has |team |desk )?(pre[- ]?)?approv"
            r"|as (an? |the )?(admin|administrator|supervisor|manager|auditor|mastercard|risk manager|fraud desk)"
            r"|priority[- ]?override|internal use only|supervisor override|override code"
            r"|(fraud|risk|compliance) (ops|desk|team)('s)? (note|standing note|directive)"
        ),
    ),
    Signal(
        "fake_policy_citation",
        ThreatClass.FAKE_POLICY,
        0.7,
        _rx(
            r"per (\w+ ){0,3}rule \d|regulation [\w/-]+ (requires|mandates)"
            r"|section \d+(\.\d+)*.{0,20}(requires|mandates|refund|obliges)"
            r"|clause \d+\(?\w?\)?.{0,30}(obliges|requires|mandates)"
            r"|(charter|policy|rulebook) (says|obliges|requires|mandates)"
        ),
    ),
    Signal(
        "role_play_escape",
        ThreatClass.DIRECT_INJECTION,
        0.6,
        _rx(r"you are now|from now on you|pretend (you|to)|new persona|developer mode"),
    ),
    Signal(
        "hidden_channel",
        ThreatClass.DOCUMENT_BORNE,
        0.65,
        _rx(
            r"</?(system|assistant|instruction|admin)>|\[/?(inst|system)\]|```system|<\|.*?\|>"
            r"|<<.{0,40}(directive|instruction).{0,40}>>"
        ),
    ),
    Signal(
        "document_directive",
        ThreatClass.DOCUMENT_BORNE,
        0.7,
        _rx(
            r"(note|instruction|directive|message) to (the )?(reviewer|agent|processor|processing agent|assistant)"
            r"|processor directive|reviewer sign[- ]?off attached|automated note.{0,30}(verification passed|approve)"
            r"|(agent|assistant|reviewer) (must|should|is to) (issue|approve|onboard|release|mark)"
        ),
    ),
    Signal(
        "context_poisoning",
        ThreatClass.CONTEXT_POISONING,
        0.7,
        _rx(
            r"(you|the (bank|team|system)) (already|previously|earlier) (agreed|approved|confirmed|decided|cleared)"
            r"|as (agreed|confirmed|discussed|decided) (above|earlier|before|in (our|the) (thread|chat|previous))"
            r"|(case|dispute|ticket) (was|is|has been) (already )?(resolved|closed|approved|settled)"
            r"|as noted in (the|your) (case|file|notes|records)"
            r"|you (already )?made the decision"
        ),
    ),
    Signal(
        "tool_manipulation",
        ThreatClass.TOOL_MANIPULATION,
        0.8,
        _rx(
            rf"(call|invoke|run|execute|use)\s+(the\s+)?(tool\s+)?({_TOOLS})"
            rf"|({_TOOLS})\s*\("
            rf"|[\"']tool[\"']\s*:\s*[\"']({_TOOLS})"
            r"|the correct action here is (approve|release|unfreeze|change)"
        ),
    ),
    Signal(
        "capability_request",
        ThreatClass.CAPABILITY_ESCALATION,
        0.75,
        _rx(
            r"(unfreeze|un-freeze|lift the (freeze|hold|block)|reactivate) (the |my |this )?(account|card)"
            r"|(change|update|switch|redirect) (the |my |our )?(payout|settlement|bank) (account|destination|details)"
            r"|release (the |all |remaining |held )?(funds|money|balance|payout)"
            r"|(close|resolve|mark) (the |this )?(case|investigation|alert) (as )?(resolved|closed|cleared)?"
            r"|(lower|reduce|set|override|reset) (the |this |my )?risk (score|level|rating)"
            r"|(skip|bypass|waive) (the |any |manual )?(review|escalation|verification|approval|checks?)"
        ),
    ),
    Signal(
        "social_engineering_pressure",
        ThreatClass.FINANCIAL_SOCIAL_ENGINEERING,
        0.4,
        _rx(
            r"(loyal|banked (with|here)|customer for \d+ years|since \d{4})"
            r".{0,120}(today|immediately|right now|at once|without (delay|checks))"
            r"|(legal action|ombudsman|consumer court|social media|twitter|press)"
            r".{0,60}(unless|if you (don't|do not)|otherwise)"
        ),
    ),
)

THRESHOLD = 0.6


@dataclass(frozen=True)
class Hit:
    signal: str
    threat_class: ThreatClass
    weight: float
    span: str


def scan(normalized_text: str) -> tuple[float, tuple[Hit, ...]]:
    """Score normalised text. Returns (peak weight, hits). The raw matched span
    is returned for in-memory explainability only; persisted forms hash it."""
    hits: list[Hit] = []
    peak = 0.0
    for sig in SIGNALS:
        m = sig.pattern.search(normalized_text)
        if m:
            hits.append(Hit(sig.name, sig.threat_class, sig.weight, m.group(0)[:120].strip()))
            peak = max(peak, sig.weight)
    return peak, tuple(hits)


def is_injection(normalized_text: str) -> tuple[bool, float, tuple[Hit, ...]]:
    peak, hits = scan(normalized_text)
    return peak >= THRESHOLD, peak, hits
