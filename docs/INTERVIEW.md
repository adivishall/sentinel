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
that has no field for the prose or the model's opinion. Issuer-signed records
decide whether the claim is supported, a signed and activated policy decides
the outcome, a capability registry and authenticated reviewers decide who may
execute it, and a tamper-evident audit chain with anchored checkpoints records
why, so every decision replays. On
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
bank accounts held at T; a benchmark re-scores 9,443 checks against
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

**6. What does the audit chain protect, and what can an external checkpoint prove?**
**IMPLEMENTED:** tamper-evidence for every decision, human case action, server
start, configuration reload and replay: modification, deletion, insertion,
reordering and unreadable records are an AUDIT INTEGRITY ERROR naming the
first bad record. On its own the chain proves only self-consistency -- someone
who can rewrite the store and recompute SHA-256 rewrites a suffix and it still
verifies. A checkpoint signed with Ed25519 by an `audit-checkpoint` key (the
verifier holds only the public key) and kept in an append-only anchor fixes
the prefix it covers: a decision is `anchored` (unchanged since the
checkpoint), `not_anchored` (after the latest one -- a rewrite cannot be
excluded, and the report says so) or `anchor_mismatch`. **NOT IMPLEMENTED:**
an anchor nobody can delete from (WORM storage, a transparency log); proof that
an event is *true*; availability. A tamper-evident application audit chain --
not a blockchain, not an immutable ledger.

**7. What can replay prove?**
**IMPLEMENTED:** any recorded decision re-runs from its stored inputs under
another policy version, rule threshold, risk model or recommendation, with a
field-level diff and a named `drift`: policy content, risk-model configuration
(a digest of weights and thresholds), engine, record vs audit event, policy
release artifact, audit anchor, fact signature (re-verified now: a key revoked
since shows). The recorded side is read from the audit event, and the original
is never changed (INV-REPLAY-1). It proves what another rule *would* have done
and whether the record still matches what was audited. A **backtest**
(`sentinel replay backtest --policy-version N`) is the same replay over the
recorded history: which decisions would change, which would *newly execute* a
consequential capability (the loosening list, which `--fail-on-loosening`
turns into a CI gate on policy changes), which cannot be replayed and why; one
`backtest` audit event, nothing recorded changed (INV-BACKTEST-1).
**NOT IMPLEMENTED:** scheduled drift monitoring.

**8. What can Sentinel actually guarantee?**
**IMPLEMENTED, structural and tested** (`docs/INVARIANTS.md`): no consequential
capability executes unless verified or trusted facts support it, a signed and
activated policy allows it and the registry authorises the actor; attacker
text, model output and caller-chosen fields cannot change that (the adaptive
red team, a regression check of the design: 0 bypasses in 5,749 queries and
25 structured attempts; text never reaches the facts that decide); unsigned or failed
facts never execute; a modified policy cannot decide; a reviewer cannot declare
their own authority and four eyes needs two identities; no what-if is recorded
as authoritative; a recorded decision replays; tampering is detected, and a
consistent rewrite is detected where an anchored checkpoint covers it. **NOT
guaranteed:** that a signed fact is true, that a signed policy is right, that
detection catches everything, that the risk model is accurate.

**9. What happens if detection misses the attack?**
Nothing changes for execution. **IMPLEMENTED:** three classes
(adjudication_gaming, financial_social_engineering, false_evidence) have nothing to detect -- the gateway scores 0% on them --
and their guarded attack success is still 0.0%; the ablation shows detection alone
leaks exactly those classes. **SIMULATED:** the corpus and the gateway share an author.

**10. How are facts trusted, and what does a signature prove?**
**IMPLEMENTED:** every decision carries the provenance of its primary record,
computed by the workflow and never taken from a request: `VERIFIED_EXTERNAL`
(an issuer's Ed25519 statement over canonical JSON, verified against an
operator trust store -- key purpose and scope, validity window, revocation,
expiry, anti-rollback, and bound to this record), `TRUSTED_LOCAL` (read by id
from the store), `UNTRUSTED` (request body), or `INVALID` / `REVOKED` /
`EXPIRED` / `SUPERSEDED`. Policy states the level it needs, and the
capability registry holds a floor no policy can lower: failed facts are
denied, unverified ones go to a human. A signature proves **who stated the
record and that it was not changed since** -- not that the record is true.
**SIMULATED:** the issuer is an ephemeral demo key over a synthetic store.

**11. What is the trust boundary, and how would real systems plug in?**
**IMPLEMENTED:** trust is a type (`TrustClass`); untrusted text yields at most a
claim type; facts arrive through three interfaces -- `RecordProvider`,
`FactProvider`, `RiskContextProvider` (`sentinel/data/providers.py`) -- and no
decision, risk, evidence or policy module reads storage (a test asserts it).
Stored records are evaluated by id on every route; caller-named ids follow one
grammar. **SIMULATED:** the only provider is a synthetic SQLite store. **NOT
IMPLEMENTED:** adapters for a real ledger, payment switch or KYB provider.

**12. How does four-eyes approval work?**
**IMPLEMENTED:** who acts is resolved from a credential in an operator
registry (stored as SHA-256, matched in constant time), never from the
request. The capability registry decides how many distinct reviewers a case
needs (payout changes, fund releases and risk overrides always two; refunds
from ₹100,000, payments from ₹500,000); one identity cannot supply both however
many requests it sends; a deny resolves; an escalation -- by decision or by
status change -- hands the case to a senior and restarts the count; a
deactivated reviewer's pending approval stops counting; each approval also
checks the reviewer's authority limit; a policy BLOCK is final for everyone.
Every action is chained with reviewer id, role and credential id, never the
credential. **NOT IMPLEMENTED:** SSO/OIDC; conflict-of-interest binding.

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

**15. What happens if the risk model or the policy is wrong?**
A wrong risk model mis-scores: its score is one input to policy, never the
authority, so a missed fraud signal still has to clear evidence, policy and
authorisation, and a false alarm goes to a human rather than denying outright.
Every assessment pins its model's configuration digest, and replay shows what
another model version would have done. A wrong policy is signed and activated
by someone accountable (the release names the key); replay under the old
version shows what changed, and rolling back is a new, higher activation of
the old version -- removing the newest one is refused. Neither is caught
automatically: drift monitoring is not implemented.

**16. What is still simulated?**
The agent (an offline deterministic simulator; every live-model row is NOT
RUN without a key), the records (a seeded synthetic world), the issuers (an
ephemeral demo key), the evaluation corpora (hand-authored, sharing an author
with the detector), and the fraud labels (the generator's). The checks are
real: the policy, capability, provenance, release, reviewer and audit code
runs exactly as it would, and the tests exercise it.

**17. What would production require?**
Adapters for the systems of record behind the provider interfaces; issuers
signing real statements; SSO for reviewers; a policy release pipeline with
multi-party sign-off; an anchor nobody can delete from; the event envelope of
D37; a production edge (TLS proxy, a real server); PII handling and retention;
monitoring and drift alerts; a live-model evaluation on the operator's key; a
trained risk model as an extra signal; regulatory review. None of it is
claimed.
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
verification. `sentinel audit checkpoint --sign-key` signs the length and the
head (recomputed from genesis) with an Ed25519 `audit-checkpoint` key, links it
to the previous checkpoint and publishes it to an append-only anchor; `audit
verify --anchor` proves the stored prefix still hashes to each signed head and
reports what is not yet anchored. The legacy HMAC checkpoint remains.

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
leaks in 9,443 checks -- evidence for the invariant, not a proof.
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
temporal leaks in 9,443 checks (a tested invariant, not a proof). Nothing about
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

The 2.3 trust work ran an independent adversarial review on every pull
request, and each one found real defects, now pinned by tests: the multi-turn
conversation route re-pointed a stored dispute and executed its refund; the
attack simulator recorded executed refunds on fabricated disputes; a junior
reviewer could undo an escalation and approve alone; a release was not bound
to its document (a replay override kept a VERIFIED stamp); DNS rebinding
defeated the browser checks and two SIGHUPs deadlocked the server; one corrupt
record at checkpoint time disabled anchoring for good, and the scheduled
checkpoint job broke the running server; a benchmark row reported a 0% false
positive rate over zero measured controls. The review of the red team found the
release's one real bypass, by hand rather than by the search: `^...$` with
`match()` accepts a final newline, so a dispute the system had already refunded
could be named again as `"DSP-000002\n"` with a body ledger, and a human
approval of that case refunded it a second time. Every grammar is now a full
match, and the red team now tries that spelling. The same review showed the
red team's evasion numbers counted seeds the detector already missed; they are
now measured against an unmutated baseline.

## Questions where the honest answer is "not implemented"

- **Can it learn from reviewer decisions?** No. Human decisions are recorded
  and audited; nothing feeds them back into the classifier, the risk model or
  the policies.
- **Does it run against a real LLM in the evaluation?** Not here. The
  provider comparison exists (`eval run --suite models --provider anthropic`)
  and stores model, date, per-attack outcomes, latency and tokens, but the
  live row is `not_run` in this repository.
- **Is there user identity on the API?** Partly. Reviewers are authenticated
  from a registry credential (role, authority limit, four eyes); API callers
  share one API key. There is no SSO / OIDC and no per-caller identity for the
  evaluate routes.
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
  author who had seen the misses). A set frozen and committed before its first
  run (2026-10-01, partially informed, never to be tuned against) scores
  24/40: every miss abstained to a human, none misread. The 100% on ordinary
  paraphrases is on phrasings by the same author.
