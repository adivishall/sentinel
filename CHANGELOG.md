# Changelog

All notable changes to Sentinel. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses
[Semantic Versioning](https://semver.org/).

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

## [1.0.1] — 2026-09-13
Final-audit patch: audit redaction of matched-trigger snippets; test count
corrections. See `docs/archive/`.

## [1.0.0] — 2026-09-13
The v1 four-layer AI firewall (typed trust boundary, structured adjudication,
capability limits, held-out evaluation, zero-dependency API, interactive
console). See `docs/archive/`.
