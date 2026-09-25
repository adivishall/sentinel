# Interview guide

The strongest sentence in the project:

> **The model can recommend the action. Sentinel decides whether the action is allowed to happen.**

Below: the questions a serious interviewer asks, and the answers the code
backs up. Every claim points at a module or a test.

## Architecture

**Why a modular monolith?**
Because the security property is a *global* one -- "no untrusted information
reaches the authoritative decision" -- and it is far easier to prove and test
in one process with one engine than across services. The seams where real
infrastructure would attach are explicit: the repository protocol
(`data/store.py`), the `EventBus` (`domain/events.py`), the `EntityGraph`
(`risk/graph.py`), the `LLMProvider` protocol. Nothing else would need to
change to swap them. Fake microservices would have added failure modes
without adding a single security guarantee.

**Why typed trust boundaries?**
Comments and prompts rot; constructors don't. `Evidence` refuses to be
VERIFIED from an untrusted source, `UntrustedContent` refuses a trusted
class, `AIRecommendation` is always `MODEL_GENERATED`. mypy checks the
signatures and `tests/test_trust_boundary.py` proves prose never reaches the
policy context or the audit log.

**Why deterministic policy?**
A financial control must be explainable, versioned, diff-able and replayable.
A deterministic engine over declared fields gives you all four; a model
"deciding" gives you none. All rules are evaluated and the most severe wins,
so the explanation is complete regardless of rule order. It is fail-closed:
every field a rule reads must be present, so a missing input can never
silently switch a BLOCK rule off (v2.0.0 had that fail-open bug; the review
found it and the fix is a validation rule plus an evaluation error).

**How do you know a replay ran the same policy?**
A version number is a label; a file edit can reuse it. Every decision and
snapshot pins the policy's *content hash*. Replay compares the hash the
decision was made under with the hash the registry serves now and flags
`policy_drift`; it also re-derives the original from its snapshot and flags
`original_drift` if the engine no longer reproduces the recorded outcome.

**Why SQLite?**
The core is standard-library only and runs from a clean checkout; SQLite gives
real tables, indexes, transactions and a file you can inspect. All SQL lives
in one module behind repository adapters. Postgres is a driver change, not a
redesign.

**Why not microservices?**
See above. Also: at the scale where they matter, the split that makes sense is
by *trust*, not by feature -- an ingestion tier that only produces typed
`UntrustedContent`, and a decision tier that never receives raw text.

**Where would this scale?**
Risk feature extraction is O(baseline size) per transaction and reads only
the account's recent history -- that is a per-account partition key. Policy
evaluation is microseconds. The gateway is regex-linear. The audit chain is
the only serialised structure; at scale you shard chains per tenant and
anchor heads periodically. The graph would move to an adjacency store with the
same query surface (`accounts_sharing_device`, `linked_accounts`, cycles).

## Security

**What attacks does Sentinel defend against?**
<!-- gen:interview-classes -->
15 classes (`security/threats.py`): direct injection, authority spoof, document borne, fake policy, context poisoning, tool manipulation, multi turn escalation, unicode obfuscation, indirect injection, adjudication gaming, financial social engineering, capability escalation, model output injection, false evidence, synthetic evidence. Each has a development corpus, a held-out variant and, for the non-dispute surfaces, a transaction / account-security / investigation variant.
<!-- /gen:interview-classes -->
The full taxonomy with detection kind and typical targets is rendered in
`docs/SECURITY_MODEL.md`.

**Why is prompt-injection detection insufficient?**
Because the hardest attack contains no injection: a false claim in ordinary
prose. The ablation shows `detection_only` leaks exactly those classes at
100% and the hardened-prompt baseline fails 100% on them. Only checking the
claim against the ledger closes them.

**What is adjudication gaming?**
Writing a narrative engineered to exploit the decision maker's heuristics
(loyalty, sympathy, urgency) while lying about a verifiable fact. Sentinel
defeats it structurally: the narrative yields a claim *type*, the ledger
yields the fact, the contradiction engine records the mismatch.

**What if the detector misses the attack?**
Nothing changes for the outcome. Detection informs severity (which can only
tighten); it is not on the authorization path. Held-out detection recall is
reported honestly and is well below 100%; guarded attack success is still 0%
-- and it is 0% *by construction*: an attack on an unsupporting ledger cannot
execute under the design, so that number is a regression check, not a
detection result. The honest empirical numbers are the false-positive rate on
deserved claims and the claim classifier's held-out coverage.

**Isn't "0% attack success" then vacuous?**
On its own, yes, and the docs say so. What makes it meaningful is the
contrast, and the honest shape of the property on ledgers that *do* support
the claim:
<!-- gen:interview-numbers -->
The same inputs against the unguarded simulated agent execute 90.0% of the
time, a hardened prompt still leaks 23.3%, and a detection-only system leaks
20.0% (exactly the classes with no injection to detect: adjudication_gaming, financial_social_engineering, false_evidence).
On supporting ledgers, 0.0% of attack texts exceed the ledger-supported
ceiling and 0.0% execute without support, while 62.4% do change the
outcome relative to a neutral message (they select the claim) and 9.4% are
approved -- deserved refunds, whatever the prose around them.
<!-- /gen:interview-numbers -->
The claim is not "we detect attacks"; it is "detection is not what stops
them". And the three kinds of number are kept apart: a structural guarantee
(the 0% rows), a synthetic evaluation (the simulator's rates, detection
recall, false positives) and a live-model evaluation (not run; recorded as
such).

**What can untrusted text actually change?**
It selects the claim type -- which trusted fact gets checked. On a ledger
that supports the claim, "my order never arrived" is approved and "following
up, thanks" is not; on a ledger that does not, nothing is. The integrity
suite measures exactly that (the numbers above). Saying "text can only
tighten" would be wrong; saying "text cannot produce an outcome the records
do not support" is right.

**What if the LLM itself is compromised?**
Its output is `MODEL_GENERATED`, so: it can recommend anything, it can request
any tool; the registry does not allow `AI_AGENT` on any consequential
capability, the composer only ever executes the *workflow's* candidate
capability under evidence + policy + authorization, and an off-surface request
is a CRITICAL security event that blocks the request and opens a P1 case.
Invariants 2 and 6 and the integrity suite (`model_influence_protected = 0`)
pin this.

**Why are model outputs untrusted?**
Because the model read the attacker's text. Trust does not launder through a
model call.

**What happens when evidence conflicts?**
`Reconciliation` distinguishes SUPPORTED, UNSUPPORTED (no confirmation),
CONTRADICTED (the record says the opposite) and INSUFFICIENT (cannot be
verified yet). Only SUPPORTED can execute; INSUFFICIENT fails safe to a human;
the rest deny. Contradictions are recorded as first-class objects and shown in
the UI and the case.

**What about the audit log?**
A tamper-evident application audit chain -- deliberately not called a
blockchain or an immutable ledger. Modification, deletion, insertion and
reordering are detected and the first bad record is named; a consistent
rewrite from genesis is caught against an exported, HMAC-signed checkpoint
that the operator stores elsewhere. It stores hashes of untrusted content,
never prose, and even detector spans are hashed. Lookups by event or
decision id are indexed; verification deliberately is not
(`docs/AUDIT_MODEL.md`).

## Finance

**How does transaction risk work?**
Features are extracted from trusted records only (`risk/transaction.py`), all
as of the transaction: amount deviation from the account baseline (z-score,
or ratio on thin baselines), 1-hour velocity plus short-window velocity and
inter-arrival timing (`txn-2.0`), device novelty and sharing, geography and
impossible travel, the trusted account-security events of the previous 24 h
(a payout change or a failed second factor before a purchase), payout
instruments shared across accounts, merchant profile, account and instrument
age, authentication strength, point-in-time chargeback history, time of day,
merchant novelty, repeat-merchant bursts, linked-entity risk. A versioned
point table maps them to a capped 0–100 score with named factors and a
component breakdown; every factor, condition and value is in
`docs/RISK_ENGINE.md`. The values are Sentinel heuristics, not industry
standards. The score is a *recommendation*; policy decides.

**How are behavioural baselines constructed?**
Descriptive statistics over the account's prior transactions
(`risk/behavioral.py`): mean/stddev/median amount, daily count, common
countries/devices/merchants/instruments (share ≥ 10%), usual hours (≥ 5%),
chargeback rate. Deterministic synthetic history; no ML claim.

**How are merchant/account relationships used?**
The `EntityGraph` answers "what accounts shared this device / instrument *as
of this time*", "what merchants does this owner control", "is there a
transfer cycle whose every hop falls inside this window". Every edge carries a
timestamp, so a relationship does not exist at every point in time merely
because it exists somewhere in the dataset. Those answers feed device
profiles (shared device), merchant profiles (owner linked to a flagged
merchant), account profiles (high-risk device), transaction risk
(linked-entity risk, young account on a shared device, shared payout
instrument) and monitoring (circular transfers, rings). Each graph feature is
consumed downstream; none exists for decoration.

**How does a high-value transaction get handled?**
Scenario G: valid evidence, home device and country, LOW/MEDIUM risk -- and
the amount exceeds the auto-approval limit, so policy says
REQUIRE_HUMAN_REVIEW and the registry's human-review threshold agrees. A case
opens with priority by amount. Sentinel is not a blocker; it knows the
difference between suspicious and merely large.

**How would this integrate with a payment processor?**
The transaction workflow takes a `Transaction` plus a context built from
trusted records. An authorisation host would call
`POST /v1/transactions/evaluate` (or the library) synchronously with the
switch record; ALLOW/STEP_UP map to the auth response, REQUIRE_HUMAN_REVIEW
to a hold queue, BLOCK/DENY to a decline. The context builder is the
integration point: replace the SQLite reads with the real history service.

**How would real sanctions/AML providers be integrated?**
As `VERIFIED_EXTERNAL` evidence and additional monitoring indicators. The
current layer is explicitly a labelled simulation and claims no compliance.

## Systems

**How does the audit chain work?**
`audit/chain.py`: each event's hash covers its canonical JSON body plus the
previous hash; sequence numbers are contiguous from 0; verification recomputes
from genesis and names the first bad record. Backends: memory, JSONL, SQLite,
each with an indexed `find` for the console and API and a full read for
verification. `sentinel audit checkpoint` exports the length and head hash,
HMAC-signed when `SENTINEL_AUDIT_KEY` is set; `audit verify --checkpoint`
proves the stored prefix still hashes to that head.

**How does replay work?**
Every decision stores a `DecisionInputs` snapshot. `ReplayEngine` restores it,
applies overrides (policy version, rule threshold, risk model version, model
recommendation, controls), re-runs the pure composer and compares the result
with the **originally stored** decision field by field (`decision_diff`). It
reports `policy_drift` when the policy version named in the snapshot no
longer has the content the decision was made under, and `engine_drift` when
re-deriving the original no longer reproduces the recorded outcome. For
identical input, facts, configuration, policy and engine the result
reproduces exactly. The replay itself is audited.

**How do policy versions work?**
Files `policy-id.vN.json` with `effective_from`; the registry serves the
latest by default and any version on request; decisions record the version
and the content hash they used; replay can pin another. `dispute-refund` is
at v3, which reads richer ledger facts (already refunded, reversed,
merchant-contested, strongly authenticated "unauthorised" claims). A linter
reports rules that can never fire before a version is activated.

**How do you maintain determinism?**
No randomness on the decision path; ids are the only non-deterministic
values and are excluded from replay comparison; timestamps are ISO strings;
the generator is seeded; the offline provider is a pure function of its input.

**What happens under load?**
Measured (`results/performance.json`): the end-to-end dispute pipeline is
sub-millisecond p99 offline; a live LLM call dominates by three orders of
magnitude. The API is a threaded stdlib server with a body cap and a per-client
rate limit -- fine for a demo, not a production edge.

## ML / AI

**Are the financial numbers real?**
<!-- gen:interview-financial -->
They characterise a hand-weighted rule model on a synthetic generator. The
point values were tuned while looking at seed 42, so the suite also runs two
seeds they never saw and reports the range (transaction precision
91.5%–95.6%, recall 76.8%–79.6%). Transaction-level recall is 79.6%
on the development seed and every miss is a burst transaction whose
short-window signals had not yet formed; the account-level monitor catches
66.7% of the burst accounts. Account-level recall is 80.0% at
0.0% FPR. A review found the per-transaction baseline counting
disputes filed *after* the transaction; fixing that leak (and then every other
aggregation) is why there is now a temporal-leakage benchmark, at 0.0%.
<!-- /gen:interview-financial -->

**Why not simply train a fraud model?**
You should, eventually -- as *one more trusted signal*. It does not replace
the architecture: a trained score is still a recommendation, evidence still
decides support, policy still decides who may execute. Sentinel makes the
place for it explicit (`RiskAssessment.model_version`).

**Why not use an LLM for everything?**
Because an LLM reading hostile input cannot be the authority over an
irreversible capability. It is excellent at summarising, classifying and
proposing; the platform keeps it there.

**Where is ML appropriate?**
Claim classification (today lexical), risk scoring (today rules), anomaly
detection over baselines, case summarisation. All are recommendation-tier.

**Where must deterministic controls remain?**
Evidence verification, policy evaluation, capability authorization, human
review routing, audit.

## Eight claims and their evidence

The claims an interviewer will push on, what backs each one, and the caveat
that must travel with it. Numbers live in `docs/EVALUATION.md` and the
generated blocks; this table points at the evidence.

| Claim | Evidence | Caveat |
|---|---|---|
| Untrusted text and model output cannot produce an outcome the trusted records do not support | `_TrustedView` has no field for either (`decision/composer.py`); integrity suite §H; `test_invariants.py`, `test_model_output_separation.py` | structural; text still selects the claim type, by design |
| No unauthorised consequential capability executed under attack | security, held-out, surfaces and KYB suites; `test_results_regression.py` recomputes the 0% rows | 0 by construction on unsupporting records; a regression check, not a detection result |
| Deserved refunds are not held | FP rows in §A and §B; the `legit_plus_injection` rows in §H | on hand-authored legitimate phrasings; the classifier is lexical and new phrasings will degrade to a human |
| Detection is not what stops the attacks | ablation §F: detection-only leaks the classes with nothing to detect; adjudication alone closes them | the hardened-prompt and detection-only rows are the simulator's behaviour |
| The unguarded contrast is meaningful | baselines §E and the WITHOUT / WITH simulator | it is the offline simulator, authored alongside the corpus; the live row is `not_run` |
| A decision at T never reads data after T | temporal suite §I; `test_temporal_leakage.py`, `test_entity_pointintime.py`, `test_graph_temporal.py` | a sampled spot check over the generator plus per-feature tests |
| The risk model is explainable and its numbers are honest | `docs/RISK_ENGINE.md` (every factor and value); financial suite §G with held-out seeds and a miss breakdown | rules tuned on one seed, not ML, not industry standards; burst recall is partial at the transaction level by construction |
| The audit trail is tamper-evident and decisions replay | `test_audit_chain.py`, `test_audit_indexing.py`, `test_replay_determinism.py`; `sentinel audit verify --checkpoint` | not a blockchain; a rewrite from genesis is caught only against a checkpoint the operator stores elsewhere |

## Honesty

**Which parts are simulated?**
The dataset, the fraud scenarios, the transaction-monitoring patterns, the
offline agent, the KYB records. Everything is labelled synthetic.

<!-- gen:interview-claims -->
**What claims can you actually prove?**
Structural ones, by test: untrusted text and model output cannot produce an
outcome the trusted records do not support (integrity suite over 170
attacks: 0.0% exceeded the ledger-supported ceiling, 0.0% executed
without support, 0.0% of 360 recommendation replays changed anything, vs
83.5% permissive influence with no controls); zero unauthorised capability
executions across 200 attacks on four surfaces and 24 hostile KYB applications --
which is 0 by construction and is kept as a regression check; 0.0% temporal
leakage; audit tampering is detected. Empirical ones, on synthetic data:
0.0% false positives on deserved refunds, 0.0% on unseen legitimate wording,
26.3% of clean-but-hostile KYB applications held for a human, and the financial
figures with their held-out-seed range. Nothing about a live model: the live
row is `not_run`. See `docs/EVALUATION.md`, which separates the three kinds.
<!-- /gen:interview-claims -->

**What remains unimplemented for production?**
Real record integrations, binary document parsing, a trained risk model,
real sanctions/AML providers, per-tenant auth and roles, a production edge
(reverse proxy, TLS, WSGI/ASGI), key management, PII handling beyond hashing,
retention policies, and a live-model evaluation on the operator's own key.
