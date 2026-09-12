# Design decisions

Short architecture-decision records. Each states the decision, why, and the
trade-off — the kind of thing an interviewer will probe.

## D1 — The authoritative decision is never computed from attacker prose

**Decision.** L3 decides using only structured facts extracted from the bank's own
records; the narrative contributes at most a coarse `ClaimType`.
**Why.** Even a perfect injection detector misses *adjudication gaming* — a false
claim with no injection. If the decision reads the prose, prose can move it.
**Trade-off.** We can only adjudicate claims we can map to a verified fact; an
unrecognised claim degrades to `escalate`/`deny` (fail-safe), which can be a false
positive on unusual legitimate phrasing. The held-out set exists to catch these.

## D2 — Make the trust boundary a *type*, not a comment

**Decision.** `UntrustedText` (opaque) vs `TrustedFacts` (`DisputeFacts`/`KYBFacts`),
with `TrustedFacts.supports(ClaimType)` as the only evidence check.
**Why.** Comments rot; types are checked. mypy now rejects passing a narrative
where evidence is expected, and a test proves the narrative never reaches the
adjudicator input. This is the single strongest guard against silently
reintroducing the vulnerability.
**Trade-off.** A little more ceremony than passing dicts around.

## D3 — Detection (L2) is defence-in-depth, not the backstop

**Decision.** Ship a transparent lexical detector, but do not let the security
case depend on it.
**Why.** Lexical detection is explainable (it names the trigger) but evadable. The
ablation shows detection-only still leaks 6.7%; L3 is what closes it. Honest
engineering puts the load on the layer that can carry it.
**Trade-off.** L2's held-out recall is low (~25%); we accept that and say so.

## D4 — Offline is a deterministic *simulation* of the failure mode

**Decision.** Offline, the "agent" is a rule-based instruction-follower, not an
LLM. Its gullibility is deliberately **not** keyed to the detector's patterns.
**Why.** Reproducibility with no key/network, and a fair test: the win must come
from L3 checking facts, not from a detector matching its own words.
**Trade-off.** It is not proof a specific production LLM fails identically —
`make live` runs the identical firewall behind real Claude to narrow that gap.

## D5 — One canonical `Decision` object

**Decision.** A single serialisable `Decision` drives CLI output, the API
response, the audit trail and test assertions.
**Why.** Parallel representations drift. One `to_dict()` means the console, the
JSON API and an auditor all see the same shape.
**Trade-off.** The object carries fields not every consumer needs.

## D6 — Audit stores hashes, not prose; opt-in persistence

**Decision.** Each decision can emit an append-only JSONL audit event that stores a
**hash** of the raw submission, never the text. Persistence is opt-in
(`persist_audit`) so the 1,560-decision benchmark isn't slowed.
**Why.** Reconstructability without hoarding sensitive customer text; performance.
**Trade-off.** You cannot read the original submission back from the audit log (by
design).

## D7 — Zero-dependency stdlib API instead of a framework

**Decision.** `http.server`, not FastAPI/Flask.
**Why.** The offline core has zero runtime deps; keeping the API dep-free means
`git clone && python3 sentinel_api.py` works with nothing installed, and the
container stays tiny.
**Trade-off.** No batteries (async, schema UI). `evaluate()` is a pure function so
swapping in a framework later is trivial.

## D8 — Evaluate the whole transcript for multi-turn

**Decision.** A `Session` re-evaluates the full conversation on each turn.
**Why.** Multi-turn escalation hides the payload in earlier turns or splits it;
inspecting only the latest message is blind to that.
**Trade-off.** Cost grows with transcript length; fine at these sizes, would need
windowing at scale.

## D9 — Held-out set is authored by hand, kept disjoint, never fed back

**Decision.** A separate, independently worded corpus (`red/heldout.py`); a test
asserts it is disjoint from the dev corpus; its examples never become detector
rules.
**Why.** It is the only honest defence against "you pattern-matched your own test
set." When it found a false-positive bug, we fixed the *general* behaviour, not
the specific strings.
**Trade-off.** It is still hand-authored and small; real attacker text is more
varied.

## D10 — Repository named `sentinel`

**Decision.** Renamed from `TheScouts` to `sentinel` so the product name is
consistent everywhere (repo, Pages URL, badges, clone command).
**Why.** A recruiter clicking a "Live Demo" badge that 404s is worse than any
missing feature.
