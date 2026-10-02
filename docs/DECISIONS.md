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

## D8 — SQLite, synchronous workflows, a dict-backed graph

**Decision.** No Kafka, Redis, Neo4j, microservices.
**Why.** A portfolio system should be runnable from a clean checkout in one
command and every architectural choice should be explainable. The
abstractions (repository protocol, audit backend protocol, `EntityGraph`,
`LLMProvider`) are the seams where real infrastructure would attach. An
in-process `EventBus` existed until 2.2.0; nothing subscribed to it, so it was
removed rather than kept as decoration -- the audit chain is the durable record
of every decision.
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

## D12 — One engine, three surfaces, a static snapshot for hosting

**Decision.** CLI, API and console call `SentinelApp`; the console contains
no scoring or policy logic (asserted by a test). GitHub Pages serves a
snapshot the engine computed.
**Why.** The v1 console re-implemented the firewall in JavaScript -- a second
decision engine that could drift. Never again.
**Trade-off.** The static demo is read-only; custom attacks need `make ui`.

## D13 — Ablation controls are a lab feature, not an API option

*Superseded by D25: there is no longer a lab switch; what-if runs are never
recorded, whatever the surface.*

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

## D15 — Every feature is computed as of the decision, and the graph knows time

**Decision.** Behavioural baselines read only earlier transactions and
earlier disputes; entity profiles take `as_of`, are cached per
`(entity, as_of)` and read only records at or before it; every graph edge
carries a timestamp and every query takes `as_of`; device knowledge is "used
on this account at least 24 h before"; the monitoring cycle finder accepts
only hops inside `cycle_window_days`. The invariant *data available after T
never influences a decision made at T* is a documented, benchmarked property
(`results/temporal.json`).
**Why.** The v2.0.1 review found the baseline counting disputes filed after
the transaction; a wider audit found profiles reading the whole dataset, a
cycle finder unbounded in time, and a generator that registered the
attacker's device as known. Each leak either flattered precision or depressed
recall; none was visible without an explicit as-of.
**Trade-off.** Profiles are computed per time and cached per time, so a
replay across many timestamps does more work than a single dataset-date
profile would.

## D16 — `txn-2.0` adds features, not threshold tuning

**Decision.** The default transaction model adds short-window velocity,
inter-arrival timing, the trusted account-security events of the previous
24 h and payout-instrument sharing; existing point values were not moved to
improve a number, and `txn-1.0` / `txn-1.1` remain loadable for replay.
**Why.** The burst and takeover scenarios were being missed for identifiable
reasons (no signal until the ninth transaction; a device the generator had
wrongly registered), and the honest fix is a feature that exists in the
records, not a lower threshold. Recall that improves because a leak was
removed or a real signal was added is reported; recall that would improve by
tuning is not pursued.
**Trade-off.** Burst recall at the transaction level remains partial by
construction (the first transactions of a burst cannot carry a short-window
signal); the account-level monitor is where a burst is meant to be caught,
and the evaluation reports both.

## D17 — The audit trail is a tamper-evident application audit chain with exportable checkpoints

**Decision.** Keep the SHA-256 link and the redaction; add indexed lookups on
every backend (never on the verification path) and a `Checkpoint`
(length + head hash, HMAC-signed with `SENTINEL_AUDIT_KEY`) meant to be stored
outside the store. Call it a tamper-evident application audit chain; never a
blockchain or an immutable ledger.
**Why.** A consistent rewrite from genesis was the documented residual risk;
an external anchor closes it without inventing consensus. Honest terminology
is part of the security claim.
**Trade-off.** The operator must keep the checkpoint and the key somewhere
the storage attacker cannot reach; the platform cannot do that for them.

## D18 — "Consequential" includes human-reserved capabilities, and every surface is attacked

**Decision.** A capability counts as consequential when it is irreversible,
moves money, *or* requires a human reviewer (closing a case, overriding a risk
score). Attack success on the transaction, account-security and
investigation surfaces is measured against a text-free baseline of the same
request, and the temporal suite is part of `make eval`.
**Why.** An agent closing a fraud case has no direct monetary effect and is
exactly the failure the registry exists to prevent; excluding it would have
under-counted escalation. The dispute corpus alone could not show that
descriptors, login messages and case notes are on the protected path.
**Trade-off.** More attacks and more structural 0% rows; the honest content
stays in the empirical columns and the docs say so.

## D19 — The KYB benchmark is balanced and reports its false positives twice

**Decision.** Balanced categories (legitimate, suspicious, fraudulent,
ambiguous, incomplete, malicious document on bad and on clean records,
high-risk but legitimate) with records-only ground truth, and two
false-positive rates: on benign input, and on any input including clean
merchants held because their upload was hostile.
**Why.** The v2 KYB set had ten attacks on bad records and reported 0% false
positives, which measured nothing. A clean merchant with an injected upload is
held for a human by design; that is a cost and it is published.
**Trade-off.** The headline any-input false-positive rate is not zero and is
not tuned to be.

## D20 — The authoritative path never runs an older policy or another risk model on request

*Superseded by D25, which moved the rule from the API / CLI edge into the
engine and removed `SENTINEL_ALLOW_UNGUARDED`.*

**Decision.** `options.policy_version` and `options.risk_model` are refused
(403 / exit 2) on the evaluate routes and commands unless the operator sets
`SENTINEL_ALLOW_UNGUARDED=1`; replay and the attack simulator keep them.
**Why.** The final review showed `dispute-refund@v1` has no double-refund
rule, so a caller could pin it and pay a second refund on an already-refunded
ledger, and pinning `txn-1.0` turned flagged fraud into executed approvals. A
what-if is not an authorization.
**Trade-off.** A legitimate "evaluate under the previous policy" question now
goes through replay, which is where it is recorded as a what-if.

## D21 — A case is resolved only by a recorded human decision

**Decision.** `CaseService.transition` refuses `RESOLVED`; the only path is
`record_human_decision`, which writes a `HumanDecision`.
**Why.** D10 claimed this and the code did not honour it: a plain status
transition through the API could close a case with no human verdict.
**Trade-off.** None.

## D22 — The claim classifier abstains, and an abstain is a human review

**Decision.** The claim classifier is a deterministic scorer over weighted
pattern families with a negation guard, a hedge detector and a conflict rule;
it reports a confidence and the signals that fired. An unreadable message
abstains and reconciles to INSUFFICIENT (held for a human); a recognised
non-claim stays UNSUPPORTED (denied); two incompatible claims abstain. The
invariant is restated accordingly: on an unsupporting ledger nothing executes
and nothing rises above a human review; on a supporting ledger nothing
exceeds the plain claim's outcome.
**Why.** The old classifier denied every phrasing it did not recognise, which
the docs described as "fails safe to a human" -- it did not. Auto-denying a
legitimate customer for wording is the wrong failure; a human with the review
packet is the designed safeguard, and a vague attacker still gets no
execution. The benchmark that reports the classifier shares its author and is
labelled a regression floor.
**Trade-off.** A vague attacker reaches a human reviewer rather than an
automatic deny; the packet keeps the ledger facts first and the model output
marked untrusted.

## D23 — Replay diffs the stored decision, not a re-derivation

*Extended by D27: the stored decision is itself checked against the audit
chain.*

**Decision.** The "before" side of a replay is the decision as stored; engine
drift is the disagreement between the stored record and its re-derivation
across final action, policy outcome, matched rules, risk score,
authorization, executed capability and verdict.
**Why.** The final review found the diff was taken against a fresh
recomputation, so a silently changed engine moved both sides at once.
**Trade-off.** A deliberate engine change reports drift on every earlier
decision until they are re-baselined -- which is the point.

## D24 — The synthetic world must carry the same signals as fraud

**Decision.** Legitimate accounts burst, travel, switch phones, fail MFA and
change credentials at realistic rates; fraud timestamps and gaps vary;
records that were impossible (purchases before a merchant existed, disputes
after the dataset end, POS deliveries) are gone. Recall that falls as a
result is published as it is.
**Why.** A realism review found that several labels were recoverable from a
single field (second-level timestamps, a fixed gap, an unregistered device
that only attackers ever used). A rule engine evaluated against such a
generator measures the generator, not the rules.
**Trade-off.** Transaction-level burst recall dropped and account-level
recall rose; the per-signal table shows how often every factor fires on
legitimate traffic now.

## D25 — Evaluation authority is enforced in the engine, not at the edge

**Decision.** An evaluation is *authoritative* (recorded, audited, able to
open a case and to execute) only when its inputs carry every control, the
active policy version (content hash included) and the active risk model of
its surface. `_finish` checks the inputs a decision was composed from and
raises `ControlDowngrade` before anything is written; `SentinelApp` sends
what-if options to a runtime that never persists. The evaluate routes refuse
every what-if switch with 403, the authoritative CLI commands do not have the
flags, unknown option keys are a 400, and the lab switch is gone.
**Why.** The earlier fix (D20) refused the switches at the API and CLI only.
The engine would still record a downgraded run, the attack simulator's
no-controls side and scenario what-ifs were stored and audited next to real
decisions, and a new surface would have had to remember the rule. A rule a
caller cannot reach is only as good as every caller; a rule in `_finish` is
structural.
**Trade-off.** The simulator's WITHOUT side no longer appears in the audit
log or the decision list; it is returned to the caller, labelled, and that is
all.

## D26 — Policy documents are strict and typed, and shipped versions are pinned

**Decision.** Unknown keys, a missing `default_outcome` and a value a field
can never take are load errors; every value a rule reads is type-checked at
evaluation (a mistyped value fails safe to a human); `sentinel/policy/policies/MANIFEST.json`
pins the SHA-256 of every shipped version, and a store that recorded a version
with other content refuses to open.
**Why.** An adversarial pass found each of these failing open: a string amount
switched a BLOCK rule off, an absent default meant ALLOW, a typo'd capability
made a gate that could never fire, and "policy versions are labels" meant v3
could be edited in place.
**Trade-off.** Adding a policy version is a two-step change (`sentinel policy
pin`). The manifest guards against accidental edits, not against someone who
can change both files.

## D27 — Replay's recorded side comes from the audit chain

**Decision.** Each decision's audit event records the SHA-256 of its input
snapshot, the risk model and the engine version; replay verifies the stored
snapshot against it and takes the recorded fields from the event, reporting
every disagreement (`record_verified`, `record_issues`).
**Why.** The decisions table and the snapshot are not tamper-evident; editing
both consistently would replay as "no change".
**Trade-off.** Decisions recorded before 2.2.0 carry no snapshot hash and
replay as unverified -- correctly.

## D28 — A case's approval level comes from the capability registry

**Decision.** When a case opens it records who may approve it
(`HUMAN_REVIEWER`, `SENIOR_REVIEWER` or `NOBODY`) from the registry; approving
needs that declared level, denying needs any human; reserved system and model
names cannot record a human decision; RESOLVED is not in the status table.
**Why.** A RELEASE_FUNDS case could be approved by any reviewer name, and the
state machine relied on a special case to keep RESOLVED unreachable.
**Trade-off.** The level is declared, not authenticated: without an identity
system the control is a structure waiting for one (`docs/LIMITATIONS.md`).

## D29 — Current-state fields are read as of the decision

**Decision.** `Account.status_since` / `status_at(t)`; payout sharing is read
from the bank accounts held at the decision time, not the account's current
payout field.
**Why.** The extended temporal benchmark showed a freeze or a payout change
after T1 changing T1's decisions (24/24 on a probe).
**Trade-off.** A status with no recorded start (legacy data) is still read as
current state; `docs/LIMITATIONS.md` says so.

## D30 — Classifier changes are measured on a set written before them

**Decision.** A held-out set of uncommon legitimate phrasings was written and
labelled before the classifier was run on it; its first-run score (7/21) is
published next to the post-change score (17/21), and the change was made
against a separate development set.
**Why.** "Improve the classifier" against the same phrasings it is scored on
measures the author, not the classifier.
**Trade-off.** The author had seen the held-out misses, so the post-change
number is optimistic; the remaining misses were deliberately left unfitted.

## D31 — A fact's trust is computed from its provenance, and a signature is the only proof

**Decision.** Every decision carries a `FactProvenance` for its primary record, computed by
the workflow (`_resolve_facts`) and never taken from a request field:

- `VERIFIED_EXTERNAL` when an issuer's Ed25519-signed fact envelope verifies against the
  operator's trust store;
- `TRUSTED_LOCAL` for a record read by id from the store;
- `UNTRUSTED` for request-body facts;
- `EXPIRED`, `SUPERSEDED`, `REVOKED` or `INVALID` for a statement that does not verify.

Evidence takes its trust class from this status. What an unverified record would support
is `INSUFFICIENT`.
**Why.** The 2.3 trust audit found that trust was an assertion made by a code path. A
ClassVar labelled caller JSON `VERIFIED_EXTERNAL`, and a body ledger executed a refund
authoritatively. "The decision is based on trusted evidence" meant nothing until something
an attacker cannot produce stood behind "trusted". A signature from a key in a trust store
the operator controls is that thing. A request body, a label and a stored row are not.
**Trade-off.**

- `cryptography` (pyca) becomes the one runtime dependency. The standard library has no
  public-key signatures, and implementing Ed25519 would be inventing cryptography, which
  is worse than a dependency.
- Body facts no longer execute anything. The demos sign their fixtures with an ephemeral
  in-process issuer, labelled as such.
- A signature proves who stated a record, not that the record is true, and the risk
  context around the record is still read from the store (`TRUSTED_LOCAL` at best).
- The attack simulator no longer records anything. Its preset ledger is signed on
  request, so a simulator decision proves nothing about a real payment. While D25
  recorded the simulator's WITH side, every legitimate-control run executed a refund on
  a dispute that does not exist (found by the review of #12). Both sides are now
  what-ifs. The demo's "a case opens and the event is chained" is shown by the evaluate
  routes, not the simulator.

## D32 — Policy states the provenance it needs; the registry holds a floor no policy can lower

**Decision.**
- **Policy field.** Every policy context carries `facts_provenance`. The v4 / v3 / v2
  policies state their requirements declaratively:
  - a failed or revoked signature → BLOCK;
  - unverified facts → human review;
  - a refund above ₹25,000, a payment above ₹100,000, or any merchant onboarding on an
    unsigned stored record → human review.
- **Registry floor.** The capability registry gives every consequential capability a
  `min_fact_provenance` (`TRUSTED_LOCAL`) that `authorize()` enforces under every policy
  version. Facts whose verification failed, or with no recorded provenance, are denied
  for every actor. For the system, facts below the floor are held for a human.
- **Vocabularies.** Record-field vocabularies are one source (`sentinel.domain.vocab`) for
  record validation and for the engine, which fails closed on an out-of-vocabulary
  context value.
- **Session evidence.** A requested account capability must be evidenced by the session
  record.

- **Idempotent execution.** One capability executes once per (workflow, subject,
  capability). The system claims the key when it executes and a human approval claims
  it when a case resolves; a repeat is `DENY` "already executed", recorded in the
  snapshot as `prior_execution` and restored by replay.
- **A decisive BLOCK outranks a context error.** The engine fails closed on a missing,
  mistyped or out-of-vocabulary field, as before -- unless a BLOCK rule whose own fields
  are present and valid matches. Then the policy's BLOCK stands (with a `[fail-closed]`
  explanation). A statement that failed verification is therefore `DENY`, not a review
  nobody may approve.
- **Every vocabulary value is named.** A test fails when an active policy reads a
  closed-vocabulary field and a value of it is neither named by a rule nor explicitly
  accepted with a reason.

**Why.** The trust audit found three authoritative bypasses through structured fields:
- `FREEZE_ACCOUNT` requested on stored sessions executed (17 of 20);
- `refund_state: "REFUNDED"` made every rule on the field false, so the BLOCK became an
  ALLOW and a double refund executed;
- a backdated transaction slipped past an account freeze.

The adversarial review of the branch then found `closed` and `unknown` -- in the
vocabularies, named by no rule, allowed -- and a failed signature parked as a dead case.
Naming every value and letting a decisive BLOCK stand close both without putting policy
logic in code. Provenance also needed to reach a place where it decides; the floor keeps
an old or misconfigured policy from undoing it.

**Trade-off.**
- The tiers are Sentinel's demo values.
- A deployment without signing issuers sends more to human review. That is the honest
  cost of not being able to prove where facts came from.
- A legitimate customer "freeze my card" request also goes to a human until the
  authentication service records it.
- The decisive-BLOCK rule means a context error is not always a review: when the policy
  can already say BLOCK, it does. A review is still the answer to every other error.
