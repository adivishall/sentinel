# Design decisions

Short architecture-decision records: the decision, why, and the trade-off.

## D1 — The authoritative decision is never computed from attacker prose or model output

**Decision.** `compose()` builds a `_TrustedView` with no field for the model's
recommendation and no prose; final action, policy outcome and authorization
are computed from it. Untrusted text contributes at most a `ClaimType`
selector and a *security signal that can only tighten*.
**Why.** Even a perfect injection detector misses adjudication gaming (a lie
with no injection) and a model can simply be wrong. If the decision reads
prose or opinion, prose or opinion can move it.
**Trade-off.** We can only adjudicate claims we can map to a verified fact; an
unrecognised claim degrades to a human review, which is a false positive on
unusual legitimate phrasing. The held-out set exists to find those.

## D2 — Trust is a type, and only two classes can authorize

**Decision.** Seven `TrustClass` values; `is_trusted` is true for exactly
`TRUSTED_INTERNAL` and `VERIFIED_EXTERNAL`. `Evidence`, `UntrustedContent`,
`Claim` and `AIRecommendation` enforce it in their constructors.
**Why.** Comments rot; constructors don't. A `MODEL_GENERATED` value cannot
become `VERIFIED` evidence by any code path.
**Trade-off.** A little ceremony around construction.

## D3 — Model output is untrusted, full stop

**Decision.** The agent's tool call is *interpreted* into an
`AIRecommendation` (trust `MODEL_GENERATED`) and recorded as claim-status
evidence; it is never executed. The gateway inspects it for off-surface
capability requests.
**Why.** "Our" AI reads hostile input; its output is the attacker's output
one hop later.
**Trade-off.** The model cannot short-cut anything, even when it is right;
the ablation quantifies what that costs (nothing on this corpus).

## D4 — Capabilities are a registry with actors, not a limit table

**Decision.** Each capability declares risk, reversibility, monetary impact,
required authorization, allowed actors and a human-review threshold.
`AI_AGENT` is allowed on no consequential capability; `SKIP_REVIEW` on none.
**Why.** "Who may make this happen" is a security property; an amount
threshold alone cannot express "a model may never unfreeze an account".
**Trade-off.** Values are demo policy, not industry standards, and are
labelled as such.

## D5 — Policy is versioned, schema-validated, fail-closed data

**Decision.** JSON policies validated against a field catalog; all rules
evaluated, most severe wins, all matches explained. Every field a rule reads
must be one the composer always provides or be declared in
`required_fields`; a context missing any referenced field raises (→ fail-safe
human review). Every policy carries a content hash; decisions and snapshots
pin it.
**Why.** Deterministic, testable, replayable, diff-able; misconfiguration is
caught at load time rather than at 3 a.m. v2.0.0 treated an absent field as
"condition does not hold", which let a missing input silently disable a
BLOCK rule -- the classic fail-open. A version number alone cannot prove a
replay ran the same policy; a hash can.
**Trade-off.** Expressiveness is limited to AND-ed conditions over declared
fields. That is a feature.

## D6 — Risk is a versioned weight table over a stored feature snapshot

**Decision.** Deterministic rules, capped 0–100, factor-level explanation,
feature snapshot stored with each decision.
**Why.** Explainability and replay: re-score under `txn-1.1` without touching
source systems. No ML claim is made.
**Trade-off.** A rule model is coarser than a trained one; the financial
evaluation reports exactly how coarse, per scenario and per level.

## D7 — Entity risk is computed in a fixed order

**Decision.** device → merchant → account → customer; a transaction's
linked-entity risk reads precomputed profiles.
**Why.** Avoids circular definitions and keeps every score explainable.
**Trade-off.** No iterative graph propagation; the graph is one hop of
signal, which is what the scenarios need.

## D8 — SQLite, an in-process event bus, a dict-backed graph

**Decision.** No Kafka, Redis, Neo4j, microservices.
**Why.** A portfolio system should be runnable from a clean checkout in one
command and every architectural choice should be explainable. The
abstractions (repository protocol, `EventBus`, `EntityGraph`) are the seams
where real infrastructure would attach.
**Trade-off.** Not horizontally scalable as-is; `docs/INTERVIEW.md` covers
what changes.

## D9 — Hash-chained audit that stores hashes, not prose

**Decision.** `hash_n = SHA256(event_n ‖ hash_(n-1))`; defensive redaction of
any raw-text field; `sentinel audit verify` names the first bad record.
**Why.** Tamper evidence and privacy at once.
**Trade-off.** The original submission cannot be read back from the audit
log (by design); the dataset stores narratives where a real system would.

## D10 — Cases are opened by deterministic rules; only humans resolve them

**Decision.** Five opening rules over the decision; a guarded status
lifecycle; `record_human_decision` is the only path to RESOLVED.
**Why.** "The model closed its own case" is a real failure mode; the
investigation corpus includes it as an attack.
**Trade-off.** More cases than a tuned production queue would open.

## D11 — Offline is a deterministic simulation of the naive agent

**Decision.** `OfflineProvider` models the documented failure mode (obeys
in-context instructions, believes stated reasons, calls any tool it knows);
its gullibility is not keyed to the detector.
**Why.** Reproducible, key-free evaluation; a fair test where the win must
come from evidence and policy, not from a detector matching its own words.
**Trade-off.** Not proof about a specific production LLM. `sentinel eval run
--suite models` runs the identical suite live when a key is present and
records `not_run` otherwise; nothing is fabricated.

## D13 — Ablation controls are a lab feature, not an API option

**Decision.** `options.controls` / `unguarded` are refused (403) on the
authoritative evaluate routes unless the operator sets
`SENTINEL_ALLOW_UNGUARDED=1`; the attack simulator and replay accept them and
record the control set on the decision and the audit event.
**Why.** "The protected path is always FULL" was true in the composer and
false at the API boundary: any caller could switch controls off per request
and record an `APPROVE_REFUND` execution.
**Trade-off.** The console's unguarded toggle only works through the
simulator, which is where it belongs.

## D14 — The detection-only ablation holds exactly what it flags

**Decision.** With policy off, a detected finding (severity ≥ MEDIUM, the
same threshold `detection_recall` counts) holds the request for a human.
**Why.** v2.0.0 held only HIGH+, so the "detection only" configuration
leaked 35 attacks it had flagged and reported 45.8% attack success. With a
consistent definition it leaks exactly the two classes with nothing to
detect: 16.7%. Reporting the higher number would have flattered Sentinel's
marginal contribution.
**Trade-off.** None; the honest number is smaller.

## D12 — One engine, three surfaces, a static snapshot for hosting

**Decision.** CLI, API and console call `SentinelApp`; the console contains
no scoring or policy logic (asserted by a test). GitHub Pages serves a
snapshot the engine computed.
**Why.** The v1 console re-implemented the firewall in JavaScript -- a second
decision engine that could drift. Never again.
**Trade-off.** The static demo is read-only; custom attacks need `make ui`.
