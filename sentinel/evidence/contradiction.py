"""Contradiction engine: a claim and a verified fact about the same field
that cannot both be true.

    USER CLAIM      delivery_status = NEVER_RECEIVED   (USER_CONTROLLED)
    TRUSTED RECORD  delivery_status = DELIVERED        (TRUSTED_INTERNAL)
    RESULT          CONTRADICTION -> claim unsupported

Compatibility is data: for each field, which claimed values are consistent
with which recorded values. Anything not listed as compatible is a
contradiction; a field with no table falls back to strict equality."""

from __future__ import annotations

from sentinel.domain.evidence import Contradiction, Evidence, EvidenceSet

# field -> {claimed_value: set(recorded values that are consistent with it)}
COMPATIBILITY: dict[str, dict[object, frozenset[object]]] = {
    "delivery_status": {
        "never_received": frozenset({"not_delivered", "returned", "lost", "in_transit"}),
        "in_transit": frozenset({"in_transit", "not_delivered"}),
        "delivered": frozenset({"delivered"}),
    },
    # "not confirmed" is an absence of confirmation, not a contradiction
    "duplicate_confirmed": {True: frozenset({True, False}), False: frozenset({False, True})},
    "cancellation_confirmed": {True: frozenset({True, False}), False: frozenset({False, True})},
    "cardholder_present": {False: frozenset({False}), True: frozenset({True, False})},
    "registration_status": {"verified": frozenset({"verified"})},
}


def is_consistent(field: str, claimed: object, recorded: object) -> bool:
    table = COMPATIBILITY.get(field)
    if table is None:
        return claimed == recorded
    allowed = table.get(claimed)
    if allowed is None:
        return claimed == recorded
    return recorded in allowed


def find_contradictions(evidence: EvidenceSet) -> tuple[Contradiction, ...]:
    """Every (claim, verified fact) pair on the same field that is inconsistent."""
    facts: dict[str, Evidence] = {}
    for e in evidence.verified():
        facts.setdefault(e.field, e)
    out: list[Contradiction] = []
    for c in evidence.claims():
        f = facts.get(c.field)
        if f is None:
            continue
        if not is_consistent(c.field, c.value, f.value):
            out.append(
                Contradiction(
                    claim_evidence_id=c.evidence_id,
                    fact_evidence_id=f.evidence_id,
                    field=c.field,
                    claimed=c.value,
                    recorded=f.value,
                    impact="claim unsupported",
                )
            )
    return tuple(out)
