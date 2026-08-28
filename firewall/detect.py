"""Layer 2 -- Injection detection on untrusted spans.

Scores an untrusted span for instruction-like / authority-spoofing content.
LIVE mode can use an LLM classifier; here we ship a transparent, auditable
lexical+structural detector so the repo is fully reproducible and every block
is explainable (we can point at the exact trigger). Returns (score, hits)."""
from __future__ import annotations
import re

SIGNALS = [
    ("instruction_override", 0.9,
     re.compile(r"(ignore|disregard|override|forget).{0,40}"
                r"(previous|prior|above|earlier|your|the).{0,20}"
                r"(instruction|prompt|rule|system|guideline)", re.I | re.S)),
    ("imperative_refund", 0.8,
     re.compile(r"(issue|process|approve|grant|authorli?ze|release|refund)"
                r".{0,30}(the )?(full |immediate |complete )?(refund|amount|₹|rs)", re.I | re.S)),
    ("authority_spoof", 0.85,
     re.compile(r"system (note|message|override|instruction|prompt)"
                r"|compliance (has )?(pre[- ]?)?approv"
                r"|as (an? )?(admin|administrator|supervisor|manager|auditor|mastercard)"
                r"|priority[- ]?override|internal use only", re.I | re.S)),
    ("fake_rule_citation", 0.7,
     re.compile(r"per (network |mastercard )?rule \d|regulation \w+ (requires|mandates)"
                r"|section \d+\.\d+.{0,20}(requires|mandates|refund)", re.I | re.S)),
    ("role_play_escape", 0.6,
     re.compile(r"you are now|from now on you|pretend (you|to)|new persona|developer mode", re.I)),
    ("hidden_channel", 0.65,
     re.compile(r"</?(system|assistant|instruction|admin)>|\[/?(inst|system)\]"
                r"|```system|<\|.*?\|>", re.I)),
]

def score(untrusted_text: str) -> tuple[float, list[dict]]:
    hits = []
    peak = 0.0
    for name, weight, rx in SIGNALS:
        m = rx.search(untrusted_text)
        if m:
            hits.append({"signal": name, "weight": weight,
                         "span": m.group(0)[:120].strip()})
            peak = max(peak, weight)
    return peak, hits

THRESHOLD = 0.6
def is_injection(untrusted_text: str) -> tuple[bool, float, list[dict]]:
    s, hits = score(untrusted_text)
    return s >= THRESHOLD, s, hits
