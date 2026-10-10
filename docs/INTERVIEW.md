# Interview guide

The strongest sentence in the project:

> **The model can recommend the action. Sentinel decides whether the action is allowed to happen.**

Below: the pitch, then the questions a serious interviewer asks, with the
answers the code backs up. Every claim points at a module or a test, and every
important answer is split three ways -- **implemented** (code and a test),
**simulated** (it runs, on synthetic or offline stand-ins) and **not
implemented** (say so before you are asked).

<!-- gen:interview-pitch -->
## The 60-second pitch

"Banks and fintechs are putting AI agents into decision paths -- refunds,
onboarding, account security -- and those agents read attacker-controlled text
through legitimate channels: a dispute narrative, an uploaded invoice. Most
defences look for injected instructions. The harder attack has none: the
customer simply lies about a fact and a persuadable model approves; a hardened
prompt doesn't help against a lie. Sentinel's answer is architectural: the
model may recommend, but the authoritative decision is computed from a view
that has no field for the prose or the model's opinion. The institution's own
records decide whether the claim is supported, versioned fail-closed policy
decides the outcome, a capability registry decides who may execute it, and a
tamper-evident audit chain records why, so every decision replays. On
synthetic corpora against a simulated naive agent, unauthorised execution
goes from 90.0% to 0.0% with 0.0% false positives on deserved refunds -- and I can
show you exactly what that does and doesn't prove."
<!-- /gen:interview-pitch -->

<!-- gen:interview-core -->
## The core questions

Each answer separates what is **IMPLEMENTED** (code and a test), what is
**SIMULATED** (it runs, on synthetic or offline stand-ins) and what is **NOT
IMPLEMENTED** (say it before you are asked).

**1. Why isn't the LLM authoritative?**
It reads the attacker's text, so its output is a function of attacker-controlled
input; a customer who simply lies persuades it, and it cannot be replayed or
audited like a rule. **IMPLEMENTED:** agents recommend (`sentinel/agents/`);
their output is typed `MODEL_GENERATED`, never enters an `EvidenceSet`, and the
composer's `_TrustedView` has no field for it; an off-surface tool call is a
CRITICAL escalation; 360 replays with a different recommendation changed no
outcome (60 main-corpus attacks × 6 recommendations). **SIMULATED:** every "persuaded agent" number
is the offline simulator. Live-model result: `not_run` (no live number is quoted anywhere in this repository).

**2. Why isn't prompt hardening enough?**
Hardening teaches a model to refuse *instructions*; a false claim contains
none. **SIMULATED:** against the offline agent a hardened prompt still leaks
23.3% of the main corpus, and fails 100% on the false-claim classes
(ablation, `docs/EVALUATION.md` §E-F). **IMPLEMENTED:** the protection that works
is not in the prompt -- the records are checked. **NOT IMPLEMENTED:** the same
comparison on a live model.

**3. What is adjudication gaming?**
A narrative engineered to exploit the decision maker's heuristics (loyalty,
urgency, sympathy) while lying about a verifiable fact, with no injected
instruction at all. **IMPLEMENTED:** a threat class with its own corpus rows; the
gateway detects 0.0% of it and guarded attack success is still
0.0%, because the narrative only yields a claim type and the ledger yields the
fact (`make attack-compare` then `--scenario adjudication_gaming`).
**SIMULATED:** the phrasings are hand-authored.

**4. Why does point-in-time data matter?**
A decision scored with data from its own future looks better than it was, in
evaluation and in replay. **IMPLEMENTED:** every feature is as-of; graph edges are
timestamped; account status counts from `status_since`; payout sharing reads the
bank accounts held at T; a benchmark re-scores 3,648 checks against
9 kinds of later record: **0 observed leaks across the tested synthetic
benchmark** -- and its 2.2.0 extension first found two current-state reads, now
fixed. **NOT IMPLEMENTED:** a fully event-sourced history; merchant registration,
flags and MCC tier are static attributes. Zero observed is evidence for a
tested invariant, not a proof.

**5. Why is the claim classifier not the security foundation?**
It only chooses *which* trusted field is checked. **IMPLEMENTED:** deterministic
pattern families with a confidence; an abstain goes to a human
(INSUFFICIENT), a recognised non-claim is UNSUPPORTED; whatever it reads,
nothing executes unless the selected field supports the claim. A misreading
is a cost (a human review), not a breach. **SIMULATED:** its benchmark shares its
author; on 21 held-out unusual phrasings it read 7 on the first, blind run and
17 after the patterns were extended by someone who had seen the misses --
partially informed, not a clean benchmark. It is defence in depth.

**6. What does the audit chain protect?**
**IMPLEMENTED:** tamper-evidence for every decision, every human case action
(manual case, status change, decision) and every replay: modification,
deletion, insertion, reordering and unreadable records are an AUDIT INTEGRITY
ERROR naming the first bad record (exit 2); a consistent rewrite of the whole
chain is caught only against a checkpoint stored elsewhere, HMAC-signed with a
shared key. It stores hashes of untrusted text, never the text. **NOT
IMPLEMENTED:** proof that an event is true (a compromised writer writes false
events honestly), availability, immutability, key management. It is a
tamper-evident application audit chain -- not a blockchain, not an immutable ledger.

**7. Why is replay useful?**
**IMPLEMENTED:** any recorded decision re-runs from its stored inputs under another
policy version, rule threshold, risk model or recommendation, with a
field-level diff, the versions on each side, policy drift and engine drift;
the recorded side is checked against its audit event, so a rewritten record
cannot replay as unchanged. It answers "what would v1 have done?" (the console
example: a v3 denial of a second refund that v1 would have paid), "did the
engine change?" and "does this record match what was audited?". **NOT
IMPLEMENTED:** bulk backtesting over a history, scheduled drift monitoring.

**8. What can Sentinel actually guarantee?**
**IMPLEMENTED, structural and tested:** no consequential capability executes
unless the trusted records support it, the active policy allows it and the
registry authorizes the actor -- attacker text and model output cannot change
that; a workflow executes only the capabilities it owns; no evaluation with a
weakened control, a historical policy or a historical risk model is recorded;
only a human decision resolves a case, checked against the registry; tampering
with a recorded event is detected; a recorded decision replays
deterministically. **NOT guaranteed:** that the records are true, who the
reviewer is, that detection catches everything, that the risk model is
accurate, temporal correctness beyond the tested record kinds.

**9. What happens if detection misses the attack?**
Nothing changes for execution. **IMPLEMENTED:** three classes
(adjudication_gaming, financial_social_engineering, false_evidence) have nothing to detect -- the gateway scores 0% on them --
and their guarded attack success is still 0.0%; the ablation shows detection alone
leaks exactly those classes. **SIMULATED:** the corpus and the gateway share an author.

**10. What is the trust boundary?**
**IMPLEMENTED:** trust is a type (`TrustClass`); `UntrustedContent` refuses a
trusted class and its source is a sanitised label; `DisputeFacts` / `KYBFacts`
are built from records only, and a malformed record goes to a human; every
decision names where its facts came from (`facts_source`). **SIMULATED:** the
"system of record" is a synthetic SQLite store; the ad-hoc API forms accept
caller-supplied facts, labelled `caller_supplied` or `demo_fixture`. **NOT
IMPLEMENTED:** real systems of record; caller authentication beyond one optional
bearer token.

**11. How would caller-supplied facts be replaced?**
**IMPLEMENTED:** every workflow already has an id form (`dispute_id`,
`transaction_id`, `application_id`, `session_id`, `account_id`) that reads the
facts from the record store and labels the decision `system_of_record`; the
context builders in `sentinel/app.py` are the single seam. **SIMULATED:** the
store is synthetic. **NOT IMPLEMENTED:** production would take identifiers only on
the authoritative API (the fact-carrying forms move to a sandbox), have the
context builders read the ledger, payment switch and KYB provider through
authenticated service calls with freshness checks, and record per fact the
source system and record version.

**12. How would reviewer authentication work?**
**IMPLEMENTED:**
- A reviewer registry (operator configuration) holds id, role, authority
  limit and an active flag. Its bearer credentials are stored only as SHA-256
  and matched in constant time.
- Every case action resolves who acts from the credential. A body naming a
  reviewer or role is refused.
- Approvals check the capability registry's level, the reviewer's authority
  limit and, where the registry asks, four eyes: two distinct reviewers
  before a case resolves.
- Every human action is chained with the resolved reviewer id and credential
  id.

**NOT IMPLEMENTED:**
- SSO / OIDC: the credential is a bearer token Sentinel issues, not a
  session from the institution's identity provider.
- Credential expiry and rotation schedules, and TLS termination (issue #20).
- Binding a reviewer to the subjects they may not review, such as their own
  account.

**13. Why not just use a fraud model?**
A fraud model answers "does this payment look like fraud?", not "is this
claim true?", "may this tool call execute?" or "who may release these funds?".
**IMPLEMENTED:** a transparent, versioned rule model whose score is one input to
policy, every factor explained. **SIMULATED:** labels come from a seeded generator;
a model trained on them would learn the generator. **NOT IMPLEMENTED:** a trained
model -- it would be one more trusted signal, never the authority.

**14. Why aren't synthetic benchmarks enough?**
The corpus and the gateway share an author; the victim agent is a simulator;
the risk labels are the generator's and the point values were tuned on the
development seed; the classifier's held-out score was partially informed.
Structural rows (0 by construction) are regression checks; empirical rows
describe this corpus and this generator. Enough would be labelled real
disputes and transactions, a red-team corpus written by someone else, and a
live-model run.

**15. What would production require?**
Integration with the systems of record behind an identifier-only API;
authentication, roles and four-eyes approval; signed policy releases and key
management; an event-sourced history; a production edge (TLS, a real server,
per-identity rate limits); PII handling and retention; monitoring; a
live-model evaluation; a trained risk model as an extra signal; and regulatory
review. None of it is claimed.
<!-- /gen:interview-core -->

## Architecture

**Why a modular monolith?**
Because the security property is a *global* one -- "no untrusted information
reaches the authoritative decision" -- and it is far easier to prove and test
in one process with one engine than across services. The seams where real
infrastructure would attach are explicit: the repository protocol
(`data/store.py`), the audit backend protocol (`audit/chain.py`), the `EntityGraph`
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
The core is the standard library plus one dependency (pyca/cryptography, for signatures)
and runs from a clean checkout; SQLite gives
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

**Isn't "0% attack success" then vacuous?**
On its own, yes, and the docs say so. What makes it meaningful is the
contrast, and the honest shape of the property on ledgers that *do* support
the claim:
<!-- gen:interview-numbers -->
The same inputs against the unguarded simulated agent execute 90.0% of the
time, a hardened prompt still leaks 23.3%, and a detection-only system leaks
20.0% (exactly the classes with no injection to detect: adjudication_gaming, financial_social_engineering, false_evidence).
On supporting ledgers, 0.0% of attack texts exceed the ledger-supported
ceiling and 0.0% execute without support, while 44.1% do change the
outcome relative to a neutral message (they select the claim) and 8.2% are
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

**What happens when evidence conflicts?**
`Reconciliation` distinguishes SUPPORTED, UNSUPPORTED (no confirmation),
CONTRADICTED (the record says the opposite) and INSUFFICIENT (cannot be
verified yet). Only SUPPORTED can execute; INSUFFICIENT fails safe to a human;
the rest deny. Contradictions are recorded as first-class objects and shown in
the UI and the case.

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
with the **originally recorded** decision field by field (`decision_diff`).
The recorded side is anchored to the tamper-evident chain: the decision's
audit event carries the SHA-256 of its input snapshot and the key outcome
fields, so a database row and snapshot edited consistently cannot replay as
"no change" -- the replay says the record disagrees with its audit event. It
reports `policy_drift` when the policy version named in the snapshot no
longer has the content the decision was made under, `engine_drift` when
re-deriving the original no longer reproduces the recorded outcome, and the
policy, risk-model and engine version on each side. For identical input,
facts, configuration, policy and engine the result reproduces exactly. A
replay is a what-if: audited as a replay, never recorded as a decision.

**How do policy versions work?**
Files `policy-id.vN.json` with `effective_from`, pinned by SHA-256 in
`MANIFEST.json` (an edited, unpinned or deleted version fails closed). The
authoritative path always uses the **active** version; historical versions
are loadable only for replay and what-if runs; decisions record the version
and the content hash they used. `dispute-refund` is
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
77.3%–87.8%, recall 65.4%–67.2%). Transaction-level recall is 67.2%
on the development seed and the misses are burst transactions; a burst's
first transactions carry no short-window signal, and the account-level monitor
catches 100.0% of the burst accounts. Legitimate accounts burst, travel
and switch phones too, so the signals are not free. Account-level recall is 90.0% at
0.7% FPR. A review found the per-transaction baseline counting
disputes filed *after* the transaction; fixing that leak (and then every other
aggregation) is why there is a temporal-leakage benchmark; extending it in 2.2.0 found two
more current-state reads (account status, payout destination), now fixed: 0 observed
leaks in 3,648 checks -- evidence for the invariant, not a proof.
<!-- /gen:interview-financial -->

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
outcome the trusted records do not support (integrity suite, 170 attacks = main
150 + held-out 20: 0.0% exceeded the ledger-supported ceiling, 0.0%
executed without support, 0.0% of 360 recommendation replays changed
anything, vs 83.5% permissive influence with no controls); zero unauthorised
capability executions across the main (150), held-out (20) and other-surface (30)
corpora and 24 hostile KYB applications -- 0 by construction, kept as a regression
check; a workflow executes only its own capabilities; audit tampering is
detected. Empirical ones, on synthetic data: 0.0% false positives on the 10
deserved refunds of the main corpus and 0.0% on the 4 of the held-out corpus;
26.3% of records-approve KYB applications not approved because of a hostile
upload; the financial figures with their held-out-seed range; 0 observed
temporal leaks in 3,648 checks (a tested invariant, not a proof). Nothing about
a live model: the live row is `not_run`. `docs/EVALUATION.md` separates the
three kinds.
<!-- /gen:interview-claims -->

**Why is the classifier deterministic rather than an LLM?**
Because the classifier's output selects which trusted fact is checked, and a
model reading hostile text would be one more thing the attacker can steer. A
weighted pattern classifier with a negation guard, a hedge detector and a
conflict rule is inspectable, replayable and cheap; it reports a confidence
and abstains when it cannot read a claim, and an abstain is a human review,
not a denial and not an approval. Its benchmark shares its author and is
labelled a regression floor, not a generalisation claim; an LLM classifier
would be a recommendation-tier upgrade that keeps the same abstain semantics.

**How do you stop a caller from choosing a weaker policy or model?**
Structurally, not at the edge. An evaluation is authoritative only if the
inputs it was composed from carry every control, the active policy version
and the active risk model of its surface; `_finish` checks that before
anything is audited or stored and refuses otherwise. What-if runs (the
simulator, scenario runs, replay) go to a runtime that never persists. The
API returns 403 and the CLI has no flag, but those are conveniences: the
release review found the first version of this fix lived only in the API and
CLI, while the engine would still have recorded a downgraded run.

**What did the release reviews actually find?**
Real defects, each now pinned by a test. The release-candidate review: a
caller-selected policy version that paid a second refund; a caller-selected
risk model that approved flagged fraud; a case resolvable without a human;
replay trusting an editable record; a malformed audit record crashing
verification; a string amount that switched a BLOCK rule off; a policy file
with no default meaning ALLOW; an unparseable ledger amount coerced to 0; two
temporal leaks through current-state fields; `make eval` itself failing; a
classifier pattern that read "never made it to my house" as fraud. The final
consequential-capability trace (`tests/test_release_trace.py`): the account
route executed any capability a caller named, including APPROVE_REFUND on a
login; a multi-turn dispute executed and audited the refund once per turn;
human case decisions were not audited; a human could approve a case the
registry forbids (policy BLOCK, contradicted records); `"false"` read as True
in a ledger flag; a negative transaction amount was authorised; and model
prose, replay overrides and a content `source` label reached places only
bounded identifiers should.

## Questions where the honest answer is "not implemented"

- **Can it learn from reviewer decisions?** No. Human decisions are recorded
  and audited; nothing feeds them back into the classifier, the risk model or
  the policies.
- **Does it run against a real LLM in the evaluation?** Not here. The
  provider comparison exists (`eval run --suite models --provider anthropic`)
  and stores model, date, per-attack outcomes, latency and tokens, but the
  live row is `not_run` in this repository.
- **Is there user identity on the API?** No. One optional bearer token, no
  roles. Only a human decision resolves a case, reserved system / model names
  are refused, the registry's review level and its answer for a human actor
  are checked, an escalated case needs a senior, and every human action is
  chained into the audit log -- but the reviewer's name and level are declared
  by the caller.
- **Does it parse PDFs or images?** No. Uploads are untrusted text.
- **Does it scale horizontally?** Not as built. One process, one SQLite
  file, an in-memory graph; the seams where real infrastructure would attach
  are named, not implemented.
- **Is the monitoring layer AML-compliant?** No. It is a synthetic
  investigation simulation with structured indicators and no filing
  capability.
- **Can the classifier read a claim it has never seen?** Not reliably. On a
  held-out set of uncommon legitimate wording written before it was run, it
  read 7 of 21 at first and 17 of 21 after the patterns were extended (by an
  author who had seen the misses). A miss abstains and the case goes to a
  human; the 100% on ordinary paraphrases is on phrasings by the same author.
