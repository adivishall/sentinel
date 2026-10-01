# Changelog

All notable changes to Sentinel. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

## [2.3.0] — unreleased (on the pull-request stack; not yet merged to main)

A trust audit asked why Sentinel should trust the facts it decides on. The answer was
that nothing proved any of them: trust labels came from code paths, and request-body
facts executed authoritative refunds, merchant onboardings, payments and account
freezes. The 2.3 work makes the facts' provenance the thing that decides how far they
can be trusted (roadmap issues #11–#20).

### Security — fact provenance (#11)
- **Signed fact envelopes** (`sentinel/trust/`). An issuer signs a record as a
  `sentinel.fact/1` envelope. Ed25519 comes via pyca/cryptography, the one new runtime
  dependency, and the signature is domain-separated and computed over canonical JSON.
  Verification checks, in a fixed fail-closed order:
  - shape, and the payload's signed digest;
  - kind and subject binding;
  - the signer against the operator's trust store (key id = key fingerprint, one
    purpose per key, scopes);
  - the signature;
  - revocation, and the key's validity window (rotation);
  - clock skew, maximum lifetime and expiry;
  - anti-rollback sequences (an older statement is `SUPERSEDED`; the same sequence
    with other content is equivocation).
- **Every decision carries a provenance status for its primary record**, computed by the
  workflow and never taken from a request: `VERIFIED_EXTERNAL`, `TRUSTED_LOCAL`,
  `UNTRUSTED`, `EXPIRED`, `SUPERSEDED`, `REVOKED` or `INVALID`. Evidence takes its trust
  class from it, so a record Sentinel could not establish is a claim
  (`UNVERIFIED_RECORD`), never a VERIFIED fact. What such a record would support is
  `INSUFFICIENT`: human review, never execution.
- **Request-body facts no longer execute.** An API or CLI `ledger` / `records` /
  `transaction` / `session` is `UNTRUSTED`. `facts_envelope` carries an issuer's signed
  statement instead. The Python API no longer takes a `facts_source` argument, which had
  let a caller label fabricated facts `system_of_record`.
- **The record store is checked against its statements.** A stored row that differs
  from its signed statement is `INVALID`. With `require_signed_facts` (on for the
  in-memory demo; `SENTINEL_REQUIRE_SIGNED_FACTS`), deleting a statement cannot
  downgrade a tampered row to `TRUSTED_LOCAL`.
- **System-of-record ledgers no longer assert constants.** The store holds no
  card-present or cancellation record, so those flags are unknown and the claims that
  depend on them are held for a human. Before, every unauthorized claim was
  "contradicted" by a hard-coded `True`. A duplicate is read from the ledger (a second
  identical charge within 48 hours). `policy_auto_limit` is a policy parameter and is
  no longer read from a ledger.
- **A stored dispute or application is judged on its recorded submission.** New text
  sent with a record id is refused.
- **Duplicate JSON keys are refused in every API request body.**
- The audit event of every decision records the fact provenance: status, issuer, key,
  envelope digest, payload digest and sequence. Replay verifies the recorded statement
  again and reports a key revoked since.
- `sentinel trust keygen | sign | verify | list | revoke | ingest`, a `--trust-store`
  option and `SENTINEL_TRUST_STORE`.
- **Adversarial review of the first draft.** Nothing reached `VERIFIED_EXTERNAL` without
  an issuer key, and unverified facts never executed. The review found these weaknesses,
  all fixed with regression tests:
  - a stored dispute's own statement sent in the body skipped the recorded-submission
    binding and the account's risk; stored records are now evaluated by id only;
  - a database writer could delete the anti-rollback marks and act on an older
    statement; the marks are now also derived from the audit chain;
  - one application's KYB statement could stand in for another's; statements now name
    their application;
  - a statement that failed verification was still decided on, and an oversized integer
    caused a 500 with an orphan audit event; it now fails safe, and numbers are bounded;
  - transaction and session audits could name a payload other than the record used;
  - an incomplete signed statement was completed with permissive defaults; it is now
    `INVALID`;
  - replay's re-verification could read as more than a signature check; it is now
    `signature_now`, withheld when the snapshot disagrees with its audit event;
  - a 4,300-digit JSON integer dropped the connection.

  The review of #12 found two more on this branch, both fixed with regression tests:
  - **the conversation route re-pointed a stored dispute.** A caller sent a stored
    dispute's own signed statement with new text; the refund executed, with the
    account's risk dropped, where the dispute by id went to review (seeds 2, 3 and 8).
    The route now refuses it, as the dispute route does;
  - **the attack simulator minted executed refunds.** It signed its preset ledger on
    request and recorded the WITH side as authoritative, so every legitimate-control run
    executed a refund on a dispute that does not exist. Every simulator run is now a
    what-if: never recorded, never executed.

  Scope correction: the `facts_source` argument is gone from the *public* `SentinelApp`
  methods. The internal `run_*` workflow layer trusts its caller's transport label, as
  it always did.

### Security — provenance-aware policy and the structured-channel bypasses (#12)
- **Policy.** `facts_provenance` is a policy context field on every decision. New
  versions `dispute-refund@v4`, `transaction-authorization@v3`, `merchant-onboarding@v2`
  and `account-security@v2` state what each outcome requires:
  - a failed or revoked signature → BLOCK;
  - unverified facts → human review;
  - high-value money movement (refund > ₹25,000, payment > ₹100,000) or any onboarding on
    an unsigned stored record → human review.
- **Registry floor.** `CapabilitySpec.min_fact_provenance` is `TRUSTED_LOCAL` for every
  consequential capability, and `authorize()` enforces it under every policy version.
  Failed or missing provenance is denied for every actor; for the system, facts below the
  floor go to a human. Nobody approves a case whose facts failed verification; a human
  may establish unverified ones.
- **Fixed: a caller-chosen `FREEZE_ACCOUNT` executed on stored sessions** (17 of 20 in the
  audit). A requested account capability must be evidenced by the session record
  (`payout_change`, `freeze_request`, ...); otherwise INSUFFICIENT, human review.
- **Fixed: an out-of-vocabulary value disabled a BLOCK rule.** `refund_state: "REFUNDED"`
  paid a second refund. Record fields are validated against one set of vocabularies
  (`sentinel.domain.vocab`), and the policy engine fails closed on any context value
  outside a field's vocabulary. An unknown account's status, which no rule named, now
  fails safe as well.
- **Fixed: caller-controlled time.** `Account.status_at` compared ISO strings, so
  `"2026-08-15 10:00:00"` sorted before a freeze that started that day; it now compares
  instants. An unsigned caller transaction or session is assessed as of the system's
  time, so backdating past a freeze changes nothing.
- **Execution is idempotent.** A consequential capability executes once per workflow,
  subject and capability (an execution ledger: `executions` table, in memory for a bare
  runtime). The system claims the key when it executes; a human approval claims it when a
  case resolves; a repeat evaluation is `DENY` "already executed". The snapshot records
  `prior_execution`; replay restores it.
- **Adversarial review of this branch** (the registry floor, SESSION_EVIDENCE, the
  execution ledger under concurrency and what-if isolation held). Found and fixed, each
  with a regression test:
  - the conversation route re-pointed a stored dispute, and the attack simulator
    recorded executed refunds on fabricated disputes (fixed on #11, 12325a5);
  - `closed` accounts and `unknown` merchant categories were in the vocabularies but
    named by no rule, so they were allowed: `block-closed-account` and
    `review-unknown-mcc`, and a test that every vocabulary value an active policy reads
    is named by a rule or explicitly accepted with a reason;
  - a list- or dict-valued vocabulary field was a 500 (unhashable) on three routes;
  - replay re-derived ALLOW for a decision that was DENY "already executed", because
    `prior_execution` was not restored and the lost race was snapshotted without it;
  - a signed statement that failed verification went to a fail-safe review nobody could
    approve (a dead case). The engine now lets a decisive BLOCK outrank a context error:
    `block-failed-fact-provenance` fires although the facts cannot be evaluated → DENY,
    no case;
  - `tx-000123`, `TX‑000123` (U+2011) and `ＴＸ-000123` were new subjects for a stored
    payment, one execution key each. Caller-named ids are in one grammar, and an
    ASCII-case variant of a stored id is refused like the stored id.
  The four policy versions on this branch (unreleased) were edited in place and re-pinned;
  `NONE` provenance is now named by their review rule.

### Security — reviewer identity, authority limits, four eyes (#13)
- **Fixed: a caller could self-declare `SENIOR_REVIEWER`**, and one caller escalated and
  then approved the same case. The reserved-name list let `claude` and `ѕentinel` (Cyrillic)
  through, and any caller could write `sentinel`-attributed case events.
- **Reviewer registry** (`sentinel/cases/identity.py`, `SENTINEL_REVIEWERS`):
  - id, role, authority limit, active flag, and one bearer credential stored only as its
    SHA-256, matched in constant time;
  - every case action resolves who acts from `X-Reviewer-Token` (CLI:
    `SENTINEL_REVIEWER_TOKEN`), and a body naming a reviewer or role is a 400;
  - `sentinel reviewers add | list | deactivate`.
- **Authority limits and four eyes.** Approvals check the reviewer's limit against the case
  amount. `dual_approval_at` in the capability registry requires two distinct reviewers:
  always for payout changes, fund releases and risk overrides, and above a threshold for
  refunds and payments. A deny resolves, and an escalation restarts the count.
- **Execution.** A human approval claims the same once-per-subject key a decision does.
- **Audit.** Human-action events record the resolved reviewer id, role, credential id and
  limit, never the credential.
- **Console.** The case-review form takes a reviewer credential (kept for the tab only), and
  the in-memory demo prints two demo credentials at start.
- **Adversarial review of this branch.** Identity came only from the credential, tokens
  never leaked (responses, audit, logs, 1,410 malformed requests → no 500), and one
  identity could not approve a four-eyes case. Found and fixed, each with a regression
  test:
  - a HUMAN_REVIEWER undid an escalation (ESCALATED → INVESTIGATING by transition) and
    approved alone; an escalated case is moved on and decided only by a senior, and stays
    handed up;
  - escalating by status transition did not restart the four-eyes count;
  - a case stored before amounts were recorded loaded with amount 0 and one approval, so a
    1,000-limit reviewer resolved a 900,000 refund alone; a missing amount is read from
    the decision, else unbounded, and a case needs never fewer approvals than the registry
    asks;
  - a deactivated reviewer's earlier approval still counted;
  - `claude`, `gpt-4o`, `sentinel-bot`, `ai-reviewer` were accepted as reviewer ids;
    `credential_id` and `name` were untyped and unchecked;
  - case routes ignored unknown body fields (`Role`, `by`) rather than refusing them, and a
    duplicated `X-Reviewer-Token` header picked the first.
  Documented, not changed: account-security cases carry no amount, so authority limits do
  not bound them (role and four eyes do).

### Security — signed policy releases (#14)
- A policy version decides only if a `policy-release` key the operator trusts signed its
  exact content (`sentinel.policy-release/1`, Ed25519 over the full SHA-256 of the
  document) and a signed activation in effect names it (`sentinel.policy-activation/1`:
  explicit, sequenced, never before the document's own `effective_from`). A higher version
  number activates nothing.
- The trust root is `SENTINEL_POLICY_TRUST` or the shipped `sentinel/trust/policy_root.json`
  (a public key), never the policy directory: an edited policy with a recomputed manifest,
  an unsigned new version, a forged or edited activation, an unknown, wrong-purpose,
  wrong-scope or revoked signer, a relabelled version, an early activation and two
  activations with one sequence are each refused, named. An activation older than one a
  store's decisions were made under (read from the audit chain) is a rollback and refused.
- Every decision records the policy digest, release status, signer, key id and activation
  sequence (decision, audit event, snapshot). The authority gate refuses to record a
  decision under an unverified release, and replay reports the recorded release beside the
  artifact it ran.
- `sentinel policy sign | activate | verify`; `SENTINEL_REQUIRE_SIGNED_POLICY` (default on).
- **Adversarial review of this branch.** Every edit-and-repin, unsigned version, forged
  activation, relabel, revoked or wrong-purpose signer was refused. Found and fixed, each
  with a regression test (`tests/test_policy_release.py::test_r*`):
  - a release was not bound to its document: a replay rule override, or an in-process
    edit, kept a VERIFIED stamp. A policy whose content differs from its release now
    carries `INVALID`; the authority gate requires a verified, activated release of
    exactly the document that ran; replay reports the artifact's own digest;
  - the digest was not canonical for non-JSON values (a YAML date stringified like a
    string): policy values must be JSON values, duplicate keys and non-integer versions
    are refused, and signed policies are JSON only;
  - an unreadable trust root left the shared registry usable but empty; it now stays
    unusable and the start is refused;
  - rollback was caught only for policies with a recorded decision: activations in effect
    are now chained at every start (`POLICY_ACTIVATIONS`);
  - one store's history set a floor on the process-wide registry and locked out every
    other app; the check is per app, and "no trustworthy active policy" is a 503;
  - `policy activate` took its next sequence from unverified book entries;
  - an `effective_from` the verifier could not read silently skipped the effective-date
    floor; it is refused.

### Security — secure-by-default deployment (#20)
- **Loopback by default** (`serve`, `make_server`, `make api`). A network bind with no API
  key is refused before a socket opens (CLI exit 2); a key shorter than 16 characters does
  not count. `--insecure-demo` (`SENTINEL_INSECURE_DEMO=1`) is the only way to serve the
  network unauthenticated: logged at ERROR, audited, marked on every response, bannered in
  the console. The Docker image therefore refuses to start without a key or the flag;
  `make docker-run` publishes the demo on 127.0.0.1 only.
- `SENTINEL_API_KEY_FILE` (a mounted secret); the key is compared over SHA-256 digests in
  constant time; the console asks for it once and keeps it for the tab.
- **Browser requests:** POSTs must be `application/json` (415) and same-origin (403 for a
  foreign `Origin`, `Origin: null` or `Sec-Fetch-Site: cross-site`), so a page elsewhere
  cannot drive the loopback default. Security headers on every response and a CSP on the
  console; negative `Content-Length` is a 400; a 30-second socket timeout.
- **The record of how the server ran:** a `SERVER_START` audit event (bind, auth mode, key
  fingerprint prefix, insecure-demo, signed facts and policy settings, trust-store and
  reviewer-registry fingerprints). SIGHUP reloads the trust store and reviewer registry
  deliberately: audited (`CONFIG_RELOAD`, with what changed), and a file that fails to
  load keeps the running configuration (`CONFIG_RELOAD_FAILED`).
- `/version` no longer names the provider and model unauthenticated; `/v1/system` names
  the store's file, not its path. The in-memory demo's reviewer credentials are minted
  only on loopback or under `--insecure-demo`.
- `docs/DEPLOYMENT.md` is a runbook: TLS termination, the three key purposes (facts,
  policy release, audit checkpoint) and why none lives on the Sentinel host, issuer and
  policy-release keys, reviewer credentials, reload, rotation and revocation.
- **Adversarial review of this branch.** Bind parsing failed closed for every odd address,
  no GET wrote anything, traversal and symlinks were refused, and no secret reached a
  response, log or audit event. Found and fixed, each with a regression test:
  - **DNS rebinding** defeated the Origin check (a rebound page is same-origin with
    itself): a loopback server now answers only loopback names or `SENTINEL_ALLOWED_HOSTS`
    (421 otherwise);
  - **two SIGHUPs** 0.2 ms apart deadlocked the server, and a reload raising anything but
    ValueError/OSError killed it: the handler only wakes a reloader thread, which catches
    everything and audits `CONFIG_RELOAD_FAILED`;
  - rotating the key file did nothing until a restart; a whitespace key passed the bind
    check; `SERVER_START` carried an unsalted key-hash prefix (a guessing oracle);
  - `snapshot.json` was served without the key; a malformed `Origin` dropped the
    connection; a TLS proxy rewriting `Host` had its console POSTs refused; the console
    prompted for the API key on a blank reviewer credential; `::1` could not be bound;
    trust-store paths reached `/v1/system` and reload failures.
  Documented, not changed: a client trickling bytes is the proxy's to cut off; concurrent
  connections are now capped (`SENTINEL_MAX_CONNECTIONS`).

### Adaptive red team (#15; supersedes #4)
- `sentinel eval run --suite redteam` (`sentinel/evaluation/redteam.py`): a seeded,
  black-box attacker that *searches*. Per corpus seed it mutates the text with 13
  operators -- paraphrase, synonyms, reordering, authority spoofing, homoglyphs,
  zero-width, bidi, spacing, multi-turn splitting, document style, indirect requests,
  ambiguous wording, compositions -- reads only what the API returns, and hill-climbs on
  executed, policy ALLOW and detector rating. Two objectives: contradicted claims, and
  over-limit refunds the ledger *supports* (the text must push past mandatory review).
  A structured campaign attacks facts (unsigned, altered, forged, expired, replayed,
  mis-addressed envelopes; re-pointed and case-variant stored ids), caller-chosen
  capabilities, backdated time, what-if switches and reviewer identity through the API.
- Four numbers, never combined: detection-only evasion **22.4% / 25.8%** of 5,760 queries
  (the lexical detector is beatable, as expected); capability/policy evasion **0**;
  trusted-fact manipulation **0** of 16 structured attempts; authoritative bypasses **0**.
  A bypass would be listed attack by attack, and the tests fail on it.
- Found and fixed: the dispute route dropped a `dispute_id` sent with body facts, so the
  stored-record check never ran there (a new, `UNTRUSTED` dispute was evaluated; no
  bypass). It is now checked like every other route.

### Live provider and model benchmark (#19, #16)
- **The current Claude API** (`anthropic==1.11.0`, verified on PyPI; the old 0.40.0 pin
  predated typed `output_config`). Requests send `max_tokens` sized for thinking as well as
  the reply (agents ask for 4,096; current models may think on any request),
  `output_config.effort`, no sampling parameters and no thinking budget. Every completion records requested and served model, SDK version,
  request id, stop reason (and a refusal's category), latency, tokens including cache
  tokens, and the settings sent.
- **Only `end_turn` is parsed.** A truncated reply (even one that looks like complete
  JSON), a refusal (with or without `stop_details`), an empty reply or an unexpected stop
  is a labelled fail-safe: the agent's fallback tool, never "deny", never a consequential
  capability. A refusal is not a verdict.
- **One benchmark row per exact configuration** (provider, requested model, effort,
  `max_tokens`), measured against the same prompts, corpus, policy and risk models,
  identified by digest. A row that ran records served models, SDK version, ASR, FP,
  latency p50/p95, stop-reason counts, refusals, truncations, parse failures, tokens and,
  only from a dated list price, cost. One failed call is one error row. Configurations that
  did not run stay **NOT RUN** with the reason; there is no score across rows. In this
  repository: the offline simulator ran; `claude-opus-5-5/effort-low` and
  `claude-sonnet-5-5/effort-low` are NOT RUN (no key). `scripts/live_check.py` records
  `results/live_check.json` -- `not_run` here.
- **Adversarial review of this branch.** Every non-`end_turn` ending (19 kinds, 6 agent
  specs) fell back safely; no fallback is a denial or consequential; the request shape is
  right for both configured models; offline numbers are unchanged. Fixed, with tests: a
  row with no controls measured reported FP 0% (rates over nothing are now `None`, a row
  with failed cases is `partial`, and §K shows attacks / controls / errors); the
  "no live number" wording was fixed text (it now follows the live rows); provenance did
  not cover the rendered prompt, every agent-spec field or the code version (it does);
  `SENTINEL_MODEL` + `SENTINEL_EFFORT` could skip the operator's configuration; stop
  reasons counted calls of failed cases; error rows dropped their spend.

### Security — asymmetric, anchored audit checkpoints (#17)
- `sentinel.audit-checkpoint/1`: the chain's head (recomputed from genesis), length, chain
  id, checkpoint sequence and the previous checkpoint's digest, signed with Ed25519 by a key
  whose only purpose is `audit-checkpoint` (a facts or policy-release key is refused). The
  verifier holds the public key, so verifying cannot forge; the HMAC checkpoint could.
- **Anchors** (`sentinel.audit.anchor`): an exclusive-create directory (one file per
  checkpoint, never overwritten) and an append-only JSONL file; `Anchor` is the interface
  for a WORM store or a transparency log (none integrated). Checkpoints link to each other,
  and each publication is recorded in the chain (`CHECKPOINT_PUBLISHED`): a dropped or
  substituted checkpoint is visible, and so is a deleted one unless the same party can also
  rewrite the chain's unanchored tail (only WORM or an external log rules that out).
- `anchored` | `not_anchored` | `anchor_mismatch` for the chain (`audit verify --anchor`,
  `/v1/audit/verify`) and for each decision (replay; a mismatch makes `record_verified`
  false). INV-AUDIT-2 is tested in both directions: a consistent rewrite before an anchored
  checkpoint is a mismatch; one after it is reported as `not_anchored`, never as anchored.
- **Adversarial review of this branch.** Rewrites before a checkpoint, from genesis, with
  relinked hashes, swapped, inserted, symlinked or edited anchor entries were all detected.
  Found and fixed, each with a regression test:
  - **one corrupted record at checkpoint time disabled anchoring for good**: a checkpoint
    with a null head was signed and written before the job crashed, and every later
    rewrite then looked like the honest state. No checkpoint is signed over a chain that
    does not verify or disagrees with its anchor, and the anchor refuses malformed
    statements;
  - **the scheduled checkpoint job broke the running server**: its `CHECKPOINT_PUBLISHED`
    record, appended from another process, made every later decision a 500. The chain
    adopts records another writer appended when they link to its head;
  - `--require-anchored` was inverted (an honest chain always exited 3; removing the
    publication record made it pass): the publication record is required and not counted
    as a gap, and an integrity failure is exit 2 whatever the flags;
  - revoking a checkpoint key was a permanent mismatch: its checkpoints now retire with a
    note, and a current key re-anchors;
  - `/v1/system` re-read and re-verified the whole chain twice per call (2.4 s at 100k
    events): it names the anchor only; `/v1/audit/verify` checks it;
  - `--json` omitted the anchoring; `--anchor` was ignored with `--file`; a non-UTF-8 byte in
    a JSONL anchor was a 400; anchor errors named paths; a relabelled sequence could claim
    coverage; a checkpoint issued in the future was accepted.
- `sentinel audit checkpoint --sign-key --signer --anchor`, `audit verify --anchor
  [--require-anchored]`, `trust keygen --purpose audit-checkpoint`, `SENTINEL_AUDIT_ANCHOR`.

### Decision lineage, risk-model provenance, the system-of-record boundary
- **`GET /v1/decisions/{id}/lineage`** (`SentinelApp.decision_lineage`): one view of a
  recorded decision -- what and when, fact provenance and payload digest, evidence,
  risk (model version and digest), the AI recommendation (recorded, never
  authoritative), the policy release (digest, signer, key, activation), the capability
  authorization, the humans who acted on its case, the outcome, and the audit event
  with its anchoring status.
- **A risk assessment pins its model's configuration digest** (`RiskModel.digest`,
  `RiskAssessment.model_digest`), recorded in the snapshot and the audit event. Replay
  reports a model whose name and version are unchanged but whose weights or thresholds
  are not (`risk_model_drift`).
- **Replay names its drift**: `drift` lists every way the replay differs from the
  decision as recorded (`policy_content`, `risk_model_configuration`, `engine`,
  `record_vs_audit`, `policy_release_artifact`, `audit_anchor`, `fact_signature`), and
  `drift_class` is `none`, `override` (only the replay's own overrides changed the
  outcome), the one named drift, or `multiple`.
- **`sentinel/data/providers.py`**: `RecordProvider`, `FactProvider` and
  `RiskContextProvider`, the three interfaces between the decision logic and a system of
  record. The shipped SQLite store over synthetic data is the only implementation;
  `tests/test_providers_boundary.py` checks that the store satisfies all three and that
  the decision, risk, evidence, policy and security packages never import it.

### Console
- The decision view shows the policy release (version, signer, key, activation) and the
  fact provenance; replay shows ORIGINAL vs RECOMPUTED with the drift and the anchoring
  status; the audit view reports anchoring; the system view lists the trust roots
  (policy releases, fact trust store, audit anchor) -- public keys only; the
  evaluation view adds the model benchmark, the red team and the frozen
  claims set. The console still renders only what the engine returns.

### CI
- CI verifies the shipped policy releases (`sentinel policy verify`), runs the red-team
  suite, and signs and verifies an anchored audit checkpoint with a throwaway key.

### Evaluation
- The corpora's ledgers and acquirer records are signed by an ephemeral evaluation
  issuer and verified in every case, so the suites measure text and model influence on
  verified facts. The integrity suite adds F: the same claim-supporting ledgers sent
  unsigned (expected 0 executions). The benchmark adds `fact_verify`, and the e2e
  pipeline now includes verification.
- **Temporal benchmark**: four seeds (42, 7, 11, 23), 497 stratified transactions, nine
  kinds, 9,443 decisions compared at four future offsets -- 0 leaks (95% upper bound
  0.03% per decision). A tested property over synthetic worlds, not a proof.
- **A frozen claims set** (`evaluation/attacks/claims_frozen.json`, 40 phrasings),
  written and committed before the classifier first ran on it, and never to be tuned
  against. Labelled *partially informed*: its author maintains the classifier. First
  run: 24/40; 14 of 28 claims missed, every one abstained to a human, 0 misread as
  another claim type, 0 of 12 controls read as a claim.

### Docs
- Corrected: the audit chain does **not** detect a consistent rewrite of the events
  after the last checkpoint by someone who can recompute it (THREAT_MODEL, LIMITATIONS).
  Before, the docs said it did.

## [2.2.0] — 2026-09-27

A release-candidate review of 2.1.0 as if the system protected real money,
done in two passes: every consequential capability traced from input to
action, every downgrade vector sought at every layer, the evaluation
methodology audited, the synthetic world made less trivially separable, the
claim classifier measured on a held-out set, and the code pruned. No point
value or threshold was moved to improve a number; several metrics fell
because the data or the evaluation became more honest.

### Security
- **Evaluation authority is structural** (`sentinel/decision/authority.py`).
  `options.policy_version=1` paid a second refund on an already-refunded
  ledger and `options.risk_model=txn-1.0` turned flagged fraud into executed
  approvals. The first fix refused them at the API / CLI edge; the engine
  still recorded downgraded runs, and the simulator's no-controls side and
  scenario what-ifs were stored and audited next to real decisions. Now
  `_finish` refuses to record any run whose inputs lack a control or name a
  non-active policy version or risk model; what-if runs go to a runtime that
  never persists; every decision carries `authoritative`. The evaluate routes
  refuse every what-if switch (incl. investigation `as_of`) with 403, unknown
  option keys with 400; the authoritative CLI commands no longer have the
  flags; `SENTINEL_ALLOW_UNGUARDED` is gone. Risk models are bound to their
  surface (a transaction model was silently applied to logins).
- **Case lifecycle.** A status transition could resolve a case. RESOLVED is
  now absent from the status table and reachable only through a human
  decision from TRIAGE / INVESTIGATING / WAITING_HUMAN / ESCALATED; reserved
  system / model actor names are refused; approving needs the review level the
  capability registry requires (RELEASE_FUNDS / ALTER_RISK: senior; SKIP_REVIEW:
  nobody); RESOLVED is final.
- **Replay** diffed a fresh re-derivation instead of the stored decision, and
  the stored decision itself was not tamper-evident. The audit event now
  records the input snapshot's SHA-256, the risk model and the engine version;
  replay anchors its recorded side to the event and reports `record_issues`,
  and names policy / risk model / engine versions on each side.
- **Policy engine fail-open paths closed**: a mistyped context value disabled a
  BLOCK rule (now a fail-safe human review); a document without
  `default_outcome` meant ALLOW, unknown keys were ignored and impossible
  capability / enum values were only linted (now load errors); shipped
  versions are pinned in `sentinel/policy/policies/MANIFEST.json` (`sentinel policy pin`) and a
  store that recorded other content for a version refuses to open.
- **Malformed trusted records**: an unparseable or negative ledger amount was
  coerced to 0 / -N and passed the auto-limit, and `"inf"` crashed; dispute
  ledgers and KYB records with such values now go to a human.
- **Audit chain**: unreadable records (malformed JSON, truncated line, missing
  field) are reported with the reason and verification continues past them;
  SQLite lookups cross-check index columns; every backend refuses to append
  onto an inconsistent store; `audit verify` prints AUDIT INTEGRITY ERROR and
  exits 2; `audit verify --file` checks an exported chain.
- **Temporal leaks**: a freeze or a payout change after T1 changed T1's
  decisions (both read the account's current fields). Status is now read as
  of the decision (`Account.status_since` / `status_at`) and payout sharing
  from the bank accounts held at T1.
- `authorize()` denies an unregistered capability or unknown actor instead of
  raising; the API drains an oversized body before answering 413.
- **Facts provenance.** Sentinel adjudicates against its facts; it does not
  verify them, and the ad-hoc API forms let the caller supply them. Every
  decision now carries `facts_source` (`system_of_record` -- read by id from the
  synthetic record store -- or demo / simulation input: `caller_supplied`,
  `demo_fixture`), recorded in its audit event and shown by the API, CLI and
  console. A past `as_of` investigation through the Python API is a backtest on
  the what-if runtime, never recorded.
- A malformed-input battery (~450 requests) found no route returning 500;
  pinned as a regression.

### Added
- **Claim classifier** (`sentinel/security/claims.py`): weighted pattern
  families, negation guard, hedge detector, conflict rule, explicit confidence
  and abstain (an abstain is INSUFFICIENT → human review; a recognised
  non-claim is UNSUPPORTED). Suite `claims`: 117 phrasings in seven
  categories, including a **held-out** set of 21 uncommon legitimate
  phrasings written before the classifier was run on it (first run 7/21, all
  misses abstained, none misread) and the development set the patterns were
  then extended against (held-out now 17/21 -- optimistic, the author had seen
  the misses). Reports classifier-sense false negatives and false positives.
  The review also fixed "never made it to my house" being read as fraud.
- **Temporal benchmark**: two seeds, 192 stratified transactions, nine kinds
  of future record (dispute, device burst, flagged merchant, graph
  relationship, session, account status, payout change, stored risk
  assessment, stored AI-security event) at +1/+7/+30/+90 days; exact counts
  (0 leaks in 3,648 decisions tested) with a one-sided 95% bound.
- **Regression suites** for every finding: `test_evaluation_authority.py`,
  `test_case_lifecycle.py`, `test_replay_integrity.py`,
  `test_policy_adversarial.py`, `test_audit_corruption.py`,
  `test_capability_trace.py`, `test_generator_chronology.py`,
  `test_rc_hardening.py`, `test_claims.py`.
- **Methodology record** on every results file and in every section of
  `docs/EVALUATION.md`; per-signal fire statistics in the financial suite and
  the risk-engine document.
- **Provider comparison**: `eval run --suite models --provider
  offline|anthropic|all --sample N`; the live row stays `not_run` until an
  operator runs it.
- **Console**: data-source lines, the claim reading beside the evidence,
  methodology under every evaluation section, replay versions and record
  check; a six-class trust legend (untrusted, model-generated, trusted,
  derived, policy, human); the facts' source on every decision; replay labels
  ORIGINAL vs RECOMPUTED and offers a one-click example in which
  dispute-refund v1 would have paid a second refund.
- **`make attack-compare`** answers five questions in order: what the
  attacker submitted, what the AI recommended, what the trusted records say,
  what policy said, what was finally allowed.
- **Burst analysis** in the financial suite: recall by position in the burst
  and by whether the velocity rule's input existed at authorisation time --
  the early-burst misses are structural and documented, not tuned away.
- **Consequential-capability trace**, rendered into `docs/SECURITY_MODEL.md`
  and checked against the workflow source; the detection / claim
  classification / trusted adjudication distinction; per-field time semantics
  (tested temporal invariant vs a fully event-sourced history); audit CLI exit
  codes; an evaluation-categories table (kind of evidence, sample, seeds).
- **Live provider verified offline** against a stub SDK (request shape,
  parsing, tokens, the evaluation pipeline); the default model id is now a real
  identifier (`claude-opus-5-5`). No key is present, so the live row stays
  `not_run`.

### Changed
- **Synthetic generator realism**: varied fraud timestamps and gaps;
  legitimate accounts burst, travel, change phones and fail MFA; impossible
  records removed; and, in the second pass, no scenario constants left
  (takeover login gap and size, dormant silence and size, ring timing,
  structuring count, merchant-abuse volume all vary). Transaction recall fell
  from ~80% to 67.2% on the development seed, dormant-activation account
  recall to 50%.
- Informational integrity / surfaces rows moved with the classifier and the
  regenerated world ("text changed a protected outcome" 38.2% → 58.2%,
  tightening only; surfaces "tightened vs baseline" 43.3% → 30.0%); the
  structural rows and every guarded attack-success rate stay 0.0%.
- `make eval` failed after the ablation suite since `0b08279` (the
  methodology record was read as a configuration); fixed.
- Dead code and write-only state removed: the unused `EventBus`, write-only
  `Runtime.decisions` / `security_events` (unbounded in a long-running
  server), offline adjudicator roles, never-produced evidence kinds and a dozen
  unused helpers; one numeric coercion instead of three; the static snapshot
  built from the same builders as the API; `requirements.txt` retired.
- README rewritten for a first-time reader; résumé reduced to three bullets;
  the interview guide answers twelve questions as implemented / simulated /
  not implemented; `submission/` and `social/` are marked historical drafts.
- Version 2.2.0.

### Final release pass (2026-09-27)
An independent source-level trace of every consequential capability through
every entry point, a documentation-versus-code audit, and a console pass for
screenshots. Nine defects were found and fixed, each with a regression test
(`tests/test_release_trace.py`):
- **A workflow executes only the capabilities it owns**
  (`capabilities.WORKFLOW_CAPABILITIES`, enforced in `authorize()`). The
  account route executed any capability a caller named -- APPROVE_REFUND on a
  login session was allowed, executed and audited. The API and CLI refuse an
  off-surface capability with 400.
- **One conversation, one decision.** A multi-turn dispute audited every turn,
  could open a case per turn and "executed" the refund once per turn while
  storing only the last; `DisputeSession.add` is now an interim assessment
  that never records and `decide()` records once.
- **Human case actions are audited** (manual case, status change, human
  decision; notes hashed). Before, a resolution lived only in the mutable
  cases table.
- **A human approval gets the registry's answer** for the reviewer's actor
  kind: a policy BLOCK or contradicted records cannot be approved by anyone; a
  claim the classifier could not read can. An escalated case needs a
  SENIOR_REVIEWER.
- **A recording runtime refuses what-if options up front** (`_admit`): a run
  without prompt provenance, or a custom risk model reusing the active version
  name, had been persisted as authoritative.
- Ledger flags must be booleans (`"false"` read as True); transaction amounts
  must be positive integers; `mfa_passed` must be a boolean.
- A model's tool name is a bounded identifier; replay `rule_values` must name
  real rules with short scalar values; a content `source` / `kind` is a
  sanitised label (it was an unscanned channel into the agent prompt).
- Console: every clickable table rendered its cells as wrapped blocks (a
  `.row` CSS collision); "Replay it under v1" also opened a drawer over its
  own result; the no-controls column showed verdicts no control had enforced;
  "risk over time" bucketed by batch run time. The four main views were
  reworked for a first-time viewer, with shareable URLs, and four screenshots
  of the running console were added (`make screenshots`).
- Documentation: every attack count is scoped (main 150 / held-out 20 /
  surfaces 30 / integrity 170 = main + held-out / 360 replays = 60 main-corpus
  attacks × 6); the temporal result is "0 observed leaks", a tested invariant
  rather than a structural guarantee; the classifier's 17/21 is described as
  partially informed; the burst misses are explained per position; the KYB
  any-input rate names its denominator; stale descriptions (evidence model,
  architecture dependencies, demo script, `.env.example`) corrected.
- Deterministic metrics are unchanged by these fixes (regenerated with
  `make eval`); only timings moved.

## [2.1.0] — 2026-09-25

A full-scale hardening pass over the reviewed 2.0.1 system: temporal
correctness, richer trusted facts, a wider attack surface, honest benchmarks,
a polished console and documentation rendered from the code. No point value
or threshold was moved to improve a number; where a metric changed it is
because a leak was removed, a real signal was added, or the evaluation became
more honest.

### Fixed
- **Temporal leakage, everywhere it was found.** Entity profiles are
  point-in-time (`entity-1.1`: cached per `(entity, as_of)`, reading only
  records at or before it); every graph edge carries a timestamp and every
  query takes `as_of`; device knowledge is "used on this account at least
  24 h before"; the monitoring cycle finder accepts only hops inside
  `cycle_window_days`. A temporal-leakage benchmark (`results/temporal.json`)
  re-scores transactions with records truncated to their timestamp and with
  records added 1, 30 and 90 days later.
- **The generator registered the attacker's device as known**, so
  `new_device` never fired on takeovers; takeover devices are now genuinely
  new at the takeover, with a regression test on both directions. Payout
  instruments are shareable across accounts and events are emitted in time
  order.
- **The investigation workflow's `extra_context` side channel** is gone: the
  trusted view has no such field.
- **Audit lookups** by event or decision id are indexed on every backend;
  verification still reads everything. **Static path containment** on the
  console routes is hardened. **API token comparison** is constant-time.
- **The benchmark evaluated a hand-typed policy context**; it now benchmarks
  the composer's real context (its field count is recorded in the output).
- The `is_new_country … or True` cosmetic bug and the over-frequent
  `new_merchant` signal (now "never used before", not "below a share
  threshold").

### Added
- **`txn-2.0`**: short-window velocity, inter-arrival timing, the trusted
  account-security events of the previous 24 h, and payout-instrument sharing;
  factor groups give every assessment a component breakdown. `txn-1.0` and
  `txn-1.1` remain loadable for replay.
- **Richer dispute facts and `dispute-refund` v3**: refund state, transaction
  status, merchant response, authentication strength and tenure; an
  already-refunded or reversed transaction can never be refunded again; a
  merchant-contested or strongly-authenticated "unauthorised" claim needs a
  human. An explicit adjudication view shows claimed vs recorded.
- **Three more threat classes** (model-output injection, false evidence,
  synthetic evidence) and a corpus expanded to 150 attacks targeting refunds,
  fund release, unfreezes, case closure and risk overrides; a **surfaces
  suite** attacking the transaction, account-security and investigation
  workflows against a text-free baseline; a **balanced KYB benchmark** (47
  applications across eight categories) that reports false positives on
  benign input and on any input.
- **Policy linter** (`sentinel policy lint`, `POST /v1/policies/lint`) with
  exhaustive boundary tests of the shipped policies.
- **Capability security matrix as data** (`sentinel capability list`,
  `GET /v1/capabilities`, `docs/SECURITY_MODEL.md`); "consequential" now
  includes human-reserved capabilities such as `CLOSE_CASE` and `ALTER_RISK`.
- **Audit checkpoints**: `sentinel audit checkpoint` exports the length and
  head hash, HMAC-signed with `SENTINEL_AUDIT_KEY`; `audit verify
  --checkpoint` detects a consistent rewrite from genesis.
- **Replay** compares the recomputed decision with the stored original field
  by field (`decision_diff`) and reports `policy_drift` and `engine_drift`.
- **Human-review packet** (`sentinel case review`, `GET /v1/cases/{id}/review`)
  separating trusted evidence from untrusted claims and marking the model's
  recommendation MODEL_GENERATED.
- **Attack simulator WITHOUT / WITH comparison** (`make attack-compare`,
  `compare: true`), labelled as the offline simulator, not a real-LLM
  experiment.
- **Console**: transaction timeline, risk components, bounded relationship
  graphs, the AI-security incident view with USER INPUT / MODEL OUTPUT /
  TRUSTED EVIDENCE / DETERMINISTIC DECISION kept visually distinct, the
  investigation workflow view, replay with drift chips and the field diff, an
  evaluations dashboard that shows sample sizes, seed ranges and the kind of
  every number, and the capability matrix. The console still contains no
  decision logic and every route it calls is checked against the API.
- **Generator profiles**, structured per-decision logs, and 95 new tests.
- **Documentation rendered from the code**: `docs/SECURITY_MODEL.md`,
  `docs/RISK_ENGINE.md`, `docs/POLICY_ENGINE.md`, `docs/EVIDENCE_MODEL.md`,
  `docs/AUDIT_MODEL.md` join `EVALUATION` and `PERFORMANCE` as generated
  files; every number in the README, résumé, limitations, interview guide,
  threat model and demo script comes from a generated block.

### Changed
- Financial evaluation reports explicit ground truth, stages (screening,
  decisioning, investigation triage), a miss breakdown with the signals
  present on detected and missed transactions, slices by channel / segment /
  merchant tier, and held-out seeds. Removing the leaks and adding the
  `txn-2.0` features moved transaction-level recall and precision; the
  account-level false positives caused by the unbounded cycle finder are
  gone because the finder is bounded, not because it was tuned.
- Every published number is labelled as one of three kinds: structural
  guarantee, synthetic evaluation, live-model evaluation.
- Terminology: the audit trail is a *tamper-evident application audit
  chain*; risk point values are *Sentinel heuristics*, never industry
  standards; transaction monitoring is a *synthetic investigation simulation*.
- Version 2.1.0.

## [2.0.1] — 2026-09-24

A hostile senior-engineer review of the finished 2.0.0 system (fintech
backend, fraud/risk, application security, AI security, recruiter). Only the
critical and high findings are fixed here; the medium and cosmetic ones are
listed in `docs/LIMITATIONS.md`. No weight or threshold was changed to move a
number.

### Fixed
- **Policy engine was fail-open on absent fields.** A rule whose field was
  missing from the context silently did not fire, which could switch a BLOCK
  rule off. Every field a rule reads must now be always-present or declared in
  `required_fields` (validated at load); evaluation raises on any missing
  referenced field and the composer turns that into a fail-safe human review.
  The shipped policies declare their fields.
- **Policy versions were mutable labels.** Every `Policy` carries a content
  hash; decisions and input snapshots pin it; replay reports `policy_drift`
  when the served version no longer matches, and `original_drift` when the
  engine no longer reproduces the recorded outcome. Exposed on the API, CLI
  and audit event.
- **The evaluate routes accepted `unguarded` / `options.controls` from any
  caller.** They now return 403 unless `SENTINEL_ALLOW_UNGUARDED=1`; the attack
  simulator and replay keep the switches. `serve` warns when auth is off on a
  non-loopback bind.
- **Temporal leakage in transaction risk features.** The per-transaction
  baseline counted disputes filed *after* the transaction; it is now
  point-in-time, and `prior_disputes_90d` for stored disputes counts only
  earlier disputes within 90 days. Transaction-level precision moved from
  73.7% to 93.3% (recall unchanged) purely from removing the leak.
- **The detection-only ablation leaked attacks it had flagged.** It held only
  HIGH+ findings while "detected" meant ≥ MEDIUM; it now holds exactly what it
  flags. Its attack success drops from 45.8% to 16.7%, which is the honest
  (smaller) contribution of the other controls.

### Changed
- **The invariant is stated precisely.** "Untrusted text can only tighten a
  decision" was false as written: text selects the claim type, so on a
  supporting ledger a clear claim is approved and a vague one is not. The
  claim now reads "untrusted text and model output cannot produce an outcome
  the trusted records do not support"; the integrity suite measures it on
  supporting ledgers (ledger-supported ceiling, execution without support) and
  labels the unsupporting-ledger rows as structural (0 by construction). The
  property test's escape hatch is gone.
- **The financial suite runs two held-out seeds** (7, 2024) alongside the
  development seed the weights were tuned on, and reports the range.
- Documentation regenerated from `results/` by `scripts/render_docs.py`
  (`make docs`); every headline number says whether it is structural or
  empirical and that the unguarded baseline is the offline simulator's.
- Version 2.0.1.

## [2.0.0] — 2026-09-23

**Sentinel becomes Financial Decision Security Infrastructure.** The v1
four-layer LLM firewall is generalised into a platform where every financial
surface -- transactions, disputes, merchant onboarding, account security,
investigations, AI-agent inputs and outputs -- flows through one pipeline:

```text
untrusted information → AI Security Gateway → risk intelligence → AI recommendation
→ trusted-evidence adjudication → deterministic policy → capability authorization
→ human review → action → case → tamper-evident audit → replay
```

### Added
- **Domain model** (`sentinel/domain`): typed, immutable entities, Evidence
  with a structural claim-vs-verified-fact distinction, RiskAssessment,
  SecurityEvent, the canonical Decision, Case, an in-process typed event bus.
- **Trust / provenance model**: seven `TrustClass` values; only
  `TRUSTED_INTERNAL` and `VERIFIED_EXTERNAL` can authorize; model output is
  `MODEL_GENERATED` and can never become VERIFIED evidence.
- **AI Security Gateway** (`sentinel/security`): 12-class threat taxonomy,
  expanded explainable signal set (context poisoning, tool manipulation,
  capability requests, social pressure, indirect/document reclassification),
  unicode-obfuscation accounting, multi-turn split-payload detection, and
  inspection of model output for off-surface capability requests.
- **Capability registry**: per-capability risk, reversibility, monetary
  impact, allowed actors, required authorization, human-review thresholds;
  `AI_AGENT` allowed on no consequential capability; `SKIP_REVIEW` on none.
- **Policy-as-code** (`sentinel/policy`): versioned JSON policies validated
  against a field catalog; deterministic, order-independent evaluation with
  complete explanations; fail-safe on missing required fields. Ships
  `dispute-refund` v1/v2, `transaction-authorization` v1/v2,
  `merchant-onboarding`, `account-security`, `investigation`.
- **Evidence reconciliation + contradiction engine** (`sentinel/evidence`):
  SUPPORTED / UNSUPPORTED / CONTRADICTED / INSUFFICIENT with first-class
  Contradiction objects.
- **Decision composer** (`sentinel/decision/composer.py`): the one place an
  outcome is computed, from a `_TrustedView` with no model-recommendation
  field; controls toggles for the ablation.
- **Risk engine** (`sentinel/risk`): versioned weight tables, behavioural
  baselines, an entity relationship graph, entity profiles (device → merchant
  → account → customer), transaction risk with 13 signal families, account
  security, and a labelled transaction-monitoring simulation (structuring-like,
  rapid movement, velocity, 24h bursts, geography shifts, exposure, circular
  transfers, dormant activation, shared-device rings, linked-entity risk).
- **Workflows** for disputes, transactions, KYB, account security,
  investigations and AI-security-only evaluation; multi-turn dispute sessions.
- **Cases** with deterministic opening rules, a guarded lifecycle and
  human-only resolution.
- **Tamper-evident audit chain** (`hash_n = SHA256(event_n ‖ hash_n-1)`) with
  memory / JSONL / SQLite backends and `sentinel audit verify`.
- **Deterministic synthetic data generator** with correlated behaviour and
  nine labelled scenarios; **SQLite store** with decision input snapshots.
- **Replay engine**: rerun a decision under another policy version, rule
  threshold, risk model version, model recommendation or control set, with a
  field-level diff and explanation; replays are audited.
- **Application layer** (`sentinel/app.py`), **versioned API** (`/v1/...`),
  **CLI** (`sentinel ...`), and a **console** (`ui/`) that only renders engine
  output, with a static snapshot mode for hosting.
- **Unified evaluation**: security (ASR = unauthorised capability executed,
  detection recall, false positives, escalation), held-out, KYB, baselines,
  8-configuration ablation, multi-level financial risk metrics on labelled
  data, decision-integrity suite, component benchmarks, provider comparison,
  charts; `sentinel eval run --suite full`.
- **Ten security invariants** with property-based tests (Hypothesis), a
  hostile-vector suite, trust-boundary proofs re-pinned against the new
  modules; CI runs lint, types, coverage gate, invariants, evaluation smoke,
  CLI + audit smoke and a Docker build.
- Documentation rewritten: README, ARCHITECTURE, THREAT_MODEL, EVALUATION,
  DECISIONS, INTERVIEW, API, DEPLOYMENT, TESTING, DEMO, LIMITATIONS,
  PERFORMANCE, RESUME.

### Changed
- The v1 `firewall/`, `agents/`, `red/`, `eval/`, `llm.py`, `sentinel_api.py`
  and `console/` are retired; their ideas and their test pins live on in the
  new package and suite. The v1 console's JavaScript re-implementation of the
  firewall is gone: the UI has no decision logic.
- "Attack success" now means an unauthorised consequential capability
  executed, not "the detector flagged the sentence".
- Held-out evaluation surfaced a false positive on a novel cancellation
  phrasing ("called off the booking"); the general pattern was broadened.
- v1 reports archived under `docs/archive/`.

## v1 documentation on main — 2026-09-13 to 2026-09-17 (unversioned)
Three documentation commits pushed to main after 1.0.1, merged into the 2.x
history at 2.2.0:
- The v1 README scoped its headline numbers (a simulated agent, small n,
  Layer 3 carrying the result). The same scoping is in the 2.x documents.
- A v1 interview guide and résumé bullets, superseded by the 2.x
  `docs/INTERVIEW.md` and `docs/RESUME.md`.
- Three v1 console screenshots, kept in `docs/images/`.
- The same change removed `social/` and the `submission/` deck, build script
  and charts. The 2.2.0 merge keeps them as historical hackathon assets.

## [1.0.1] — 2026-09-13
Final-audit patch: audit redaction of matched-trigger snippets; test count
corrections. See `docs/archive/`.

## [1.0.0] — 2026-09-13
The v1 four-layer AI firewall (typed trust boundary, structured adjudication,
capability limits, held-out evaluation, zero-dependency API, interactive
console). See `docs/archive/`.
