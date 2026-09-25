"""The claim classifier: a deterministic, explainable reading of *what* an
untrusted party asserts, with an explicit confidence and an explicit abstain.

The classifier is the only thing derived from prose, and it is only ever a
selector for which trusted fact to check. It is deliberately not a model:

- every decision is a weighted pattern family per claim type, a negation
  guard and a hedge detector, all inspectable;
- an unrecognised phrasing does not pick a type by accident -- it **abstains**,
  and the reconciliation engine turns an abstain into INSUFFICIENT, i.e. a
  human review, never an automatic approval or an automatic denial;
- a recognised *non-claim* ("it arrived but I don't like it", "just checking
  my statement") is not an abstain: it is UNSUPPORTED, and denied;
- two strong, incompatible claims in one message ("charged twice" and "never
  arrived") abstain as *conflicting*, because the ledger cannot be asked one
  question.

``docs/EVALUATION.md`` §L reports the classifier on a labelled benchmark
(``sentinel eval run --suite claims``) that shares an author with these
patterns; its numbers describe the patterns on that benchmark, nothing more.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.domain.enums import ClaimType

STRONG = 0.9
WEAK = 0.6
CLAIM_THRESHOLD = 0.6  # below this the classifier abstains
HEDGE_FACTOR = 0.6  # "might", "not sure", "maybe" scale the score down
CONFLICT_MARGIN = 0.15  # two different types both strong and this close -> conflicting


def _rx(p: str) -> re.Pattern[str]:
    return re.compile(p, re.I | re.S)


@dataclass(frozen=True)
class Signal:
    name: str
    claim: ClaimType | None  # None = a non-claim signal
    weight: float
    pattern: re.Pattern[str]


# Weighted pattern families. Strong = an unambiguous statement of the claim;
# weak = suggestive wording that needs no counter-evidence to be believed at
# lower confidence. Order does not matter (max weight per type wins).
SIGNALS: tuple[Signal, ...] = (
    # ---- non-receipt --------------------------------------------------------------
    Signal(
        "never_arrived",
        ClaimType.NON_RECEIPT,
        STRONG,
        _rx(
            r"never (arrived|received|delivered|reached|came|turned up|showed up|got here|got to me)"
            r"|not delivered|non[- ]?receipt|item (was )?never (sent|shipped)"
        ),
    ),
    Signal(
        "has_not_arrived",
        ClaimType.NON_RECEIPT,
        STRONG,
        _rx(
            r"(has ?n'?t|have ?n'?t|had ?n'?t|did ?n'?t|has not|have not|still (has|had) not|not)"
            r"\W{0,3}(\w+\W+){0,3}(arriv|reach|deliver|come|came|turn(ed)? up|show(ed)? up|receiv)"
        ),
    ),
    Signal(
        "missing_parcel",
        ClaimType.NON_RECEIPT,
        WEAK,
        _rx(
            r"\b(missing|lost) (parcel|package|order|item|delivery)"
            r"|no sign of (the |my )?(parcel|package|order|delivery)"
            r"|where is my (parcel|package|order)"
            r"|nothing (has )?(arrived|turned up|came)"
        ),
    ),
    # ---- in transit ---------------------------------------------------------------
    Signal(
        "in_transit",
        ClaimType.IN_TRANSIT,
        STRONG,
        _rx(
            r"\bin transit\b|still (on the way|on its way|coming|shipping)|not yet arrived|hasn'?t arrived yet"
        ),
    ),
    Signal(
        "running_late",
        ClaimType.IN_TRANSIT,
        WEAK,
        _rx(r"(order|parcel|package|delivery) (is|might be|may be|seems) (late|delayed|overdue)"),
    ),
    # ---- duplicate ----------------------------------------------------------------
    Signal(
        "charged_twice",
        ClaimType.DUPLICATE,
        STRONG,
        _rx(
            r"\bduplicate\b|charged (me )?twice|billed (me )?(\w+ ){0,3}(twice|two times|double)"
            r"|(two|2|double|multiple) (\w+ ){0,3}(charges|debits|entries|transactions|deductions)"
            r"|charged (\w+ ){0,3}(twice|two times|multiple times|more than once)"
            r"|(taken|debited|deducted) (\w+ ){0,3}(twice|two times)"
        ),
    ),
    Signal(
        "same_amount_repeated",
        ClaimType.DUPLICATE,
        WEAK,
        _rx(
            r"same (charge|amount|purchase|payment) (appears|shows|listed|is there) (\w+ ){0,3}(again|twice|two)|paid twice"
        ),
    ),
    # ---- cancellation -------------------------------------------------------------
    Signal(
        "cancelled",
        ClaimType.CANCELLATION,
        STRONG,
        _rx(
            r"cancel(l)?(ed|ation)?\W+(\w+\W+){0,5}(order|booking|purchase|subscription|payment|reservation|plan|membership|it)"
            r"|(order|booking|purchase|subscription|reservation|membership)\W+(\w+\W+){0,5}cancel"
            r"|call(ed)? (it |the \w+ |my \w+ )?off"
            r"|withdrew (the |my )?(order|booking|purchase)"
        ),
    ),
    Signal(
        "cancel_word",
        ClaimType.CANCELLATION,
        WEAK,
        _rx(r"\bcancel(l)?(ed|ation|ing)?\b|\bunsubscribed\b|\bended (the|my) (subscription|plan)"),
    ),
    # ---- unauthorised -------------------------------------------------------------
    Signal(
        "unauthorised",
        ClaimType.UNAUTHORIZED,
        STRONG,
        _rx(
            r"\b(this|that|it|these|those|my)( \w+){0,2} (is|was|are|were) (clearly |definitely |plain |a )?fraud(ulent)?\b"
            r"|fraudulent (charge|transaction|payment|purchase|use|activity)|fraud on my (card|account)"
            r"|victim of (card )?fraud|report(ing|ed)? (it |this |these )?(as )?fraud"
            r"|didn'?t (make|authori[sz]e|do|place)|unauthori[sz]ed|don'?t recogni[sz]e"
            r"|not mine|\bnot me\b|(card|phone) (was )?with me|never (made|authori[sz]ed|placed)|never left my (wallet|possession|hands)"
            r"|someone (else )?(used|has used|is using) my (card|account)|(stolen|cloned|skimmed) card|wasn'?t me"
            r"|i (did ?n'?t|never|have never) (bought|ordered|purchased|shopped)"
        ),
    ),
    Signal(
        "not_recognised",
        ClaimType.UNAUTHORIZED,
        WEAK,
        _rx(
            r"(don'?t|do not|can'?t) (remember|recall) (making|this|that|the)|unfamiliar (charge|transaction|merchant)|strange (charge|transaction)"
        ),
    ),
    # ---- non-claims: recognised statements that assert no refundable event -------------
    Signal(
        "receipt_confirmed",
        None,
        STRONG,
        _rx(
            r"(it|item|order|parcel|package|product|goods|delivery) (has |have )?(arrived|came|turned up|was delivered|got here|reached me)"
            r"|i (have )?(received|got) (it|the (order|parcel|package|item|product|goods))"
            r"|^\W*received (it|the|my)|\breceived the (order|parcel|package|item|product|goods)"
        ),
    ),
    Signal(
        "preference_only",
        None,
        STRONG,
        _rx(
            r"(don'?t|didn'?t|do not|did not) (love|like|want|need) (it|the (colou?r|size|fit|style|product|item))"
            r"|changed my mind|wrong (colou?r|size)|not what i expected|doesn'?t suit me"
        ),
    ),
    Signal(
        "no_issue",
        None,
        STRONG,
        _rx(
            r"no (issues?|problems?|complaints?)|(just|only) (checking|confirming|asking|wondering)"
            r"|thanks for (the|your) help|how do i|what is the status|can you (check|confirm) (the )?(status|whether)"
        ),
    ),
)

HEDGES = _rx(
    r"\b(might|maybe|perhaps|possibly|not sure|unsure|i think|i guess|i believe|could be|may have)\b"
)
NEGATED_RECEIPT = _rx(
    r"(never|not|hasn'?t|haven'?t|didn'?t) (\w+ ){0,2}(arrived|received|delivered|came|got here)"
)
# "I have not received the refund" is about money owed, not goods: it is not a
# non-receipt claim about the order, and there is no trusted field for it -> abstain.
REFUND_NOT_RECEIVED = _rx(
    r"(not|never|hasn'?t|haven'?t|didn'?t|yet to) (\w+ ){0,3}(received|receive|got|seen|see) "
    r"(the |my |a |any )?(refund|money|credit|reversal|reimbursement|amount back)"
)


@dataclass(frozen=True)
class ClaimClassification:
    """What the classifier read, and how sure it is. ``kind`` is one of
    ``claim`` (a claim type with confidence >= threshold), ``non_claim`` (a
    recognised statement that asserts no refundable event) or ``abstain``
    (unrecognised, hedged below threshold, or conflicting)."""

    claim_type: ClaimType
    kind: str
    confidence: float
    signals: tuple[str, ...]
    reason: str

    @property
    def abstained(self) -> bool:
        return self.kind == "abstain"


def classify(text: str) -> ClaimClassification:
    t = text.lower()
    fired: list[Signal] = [s for s in SIGNALS if s.pattern.search(t)]
    hedged = bool(HEDGES.search(t))
    scores: dict[ClaimType, float] = {}
    non_claim: list[str] = []
    for s in fired:
        if s.claim is None:
            non_claim.append(s.name)
        else:
            scores[s.claim] = max(scores.get(s.claim, 0.0), s.weight)
    # "receipt confirmed" is a non-claim only when the message does not also deny receipt
    if "receipt_confirmed" in non_claim and NEGATED_RECEIPT.search(t):
        non_claim.remove("receipt_confirmed")
    if ClaimType.NON_RECEIPT in scores and REFUND_NOT_RECEIVED.search(t):
        del scores[ClaimType.NON_RECEIPT]
        non_claim = [n for n in non_claim if n != "receipt_confirmed"]
    # non-receipt vs in-transit: "never arrived; tracking says in transit" is a non-receipt
    # claim, but "hasn't arrived yet, still shipping" expects the parcel and is in transit
    if ClaimType.NON_RECEIPT in scores and ClaimType.IN_TRANSIT in scores:
        fired_names = {s.name for s in fired}
        definite = fired_names & {"never_arrived", "missing_parcel"}
        if definite or scores[ClaimType.IN_TRANSIT] < STRONG:
            del scores[ClaimType.IN_TRANSIT]
        else:
            del scores[ClaimType.NON_RECEIPT]
    names = tuple(s.name for s in fired)
    if not scores:
        # a hedged or questioning message that only trips non-claim wording ("not sure
        # if it has arrived yet?") is a status question, not a confirmed non-claim
        if non_claim and not hedged:
            return ClaimClassification(
                ClaimType.UNSPECIFIED, "non_claim", STRONG, names, "recognised non-claim"
            )
        return ClaimClassification(
            ClaimType.UNSPECIFIED, "abstain", 0.0, names, "no recognisable claim"
        )
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0].value))
    top, top_score = ranked[0]
    if len(ranked) > 1:
        second, second_score = ranked[1]
        if second_score >= STRONG and top_score - second_score < CONFLICT_MARGIN:
            return ClaimClassification(
                ClaimType.UNSPECIFIED,
                "abstain",
                0.0,
                names,
                f"conflicting claims ({top.value} and {second.value})",
            )
    confidence = top_score * (HEDGE_FACTOR if hedged else 1.0)
    # a strong claim next to a recognised non-claim signal is a mixed message
    if non_claim and top_score < STRONG:
        confidence *= HEDGE_FACTOR
    confidence = round(confidence, 2)
    if confidence < CLAIM_THRESHOLD:
        return ClaimClassification(
            ClaimType.UNSPECIFIED,
            "abstain",
            confidence,
            names,
            f"{top.value} suggested but hedged or weak (confidence {confidence:.2f})",
        )
    return ClaimClassification(top, "claim", confidence, names, f"{top.value} at {confidence:.2f}")
