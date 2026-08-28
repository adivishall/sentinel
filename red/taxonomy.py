"""Attack taxonomy -- six classes of GenAI attack against back-office LLM
pipelines. This is the conceptual contribution: a structured map of how
attacker-controlled text, arriving through legitimate channels, subverts a
financial decision agent."""

CLASSES = {
    "direct_injection": {
        "name": "Direct instruction injection",
        "desc": "Explicit override instructions placed in the submission text.",
    },
    "authority_spoof": {
        "name": "Authority spoofing",
        "desc": "Text impersonating a system/compliance/admin directive.",
    },
    "document_borne": {
        "name": "Document-borne injection",
        "desc": "Instructions hidden inside an uploaded document the agent reads.",
    },
    "fake_rule": {
        "name": "Policy / rule-citation forgery",
        "desc": "Fabricated network rules or regulations demanding a refund.",
    },
    "multiturn": {
        "name": "Multi-turn escalation",
        "desc": "Trust built across a thread; the payload lands in a later turn.",
    },
    "adjudication_gaming": {
        "name": "Adjudication gaming",
        "desc": "No injection at all -- a narrative engineered to exploit the "
                "model's decision heuristics. The honest hard case.",
    },
}
ORDER = list(CLASSES)
