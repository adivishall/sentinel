# Security model

Rendered by `make docs` from `sentinel/domain/enums.py`,
`sentinel/security/capabilities.py`, `sentinel/security/threats.py`,
`sentinel/security/injection.py` and `sentinel/cases/rules.py`. Nothing in
this file is typed by hand except the prose; the tables are the code.

## The principle

```text
AI may recommend. Trusted evidence, deterministic policy and authorization decide.

AUTHORITATIVE_DECISION = f(TRUSTED_FACTS, VERIFIED_EVIDENCE, RISK_STATE, POLICY, AUTHORIZATION)
AUTHORITATIVE_DECISION ≠ f(ATTACKER_CONTROLLED_TEXT)
AUTHORITATIVE_DECISION ≠ f(MODEL_OUTPUT)
```

Stated precisely: untrusted text and model output cannot produce an outcome
the trusted records do not support. Untrusted text selects *which* trusted
fact is checked (a `ClaimType`); it never exceeds the ledger-supported
ceiling. This is a **structural** property of the composer
(`sentinel/decision/composer.py`: the `_TrustedView` has no field for prose or
for the model's recommendation) and is measured as enforced in
`docs/EVALUATION.md` §H. It is not a claim about any model's robustness.

## Trust classes

| Trust class | Source | May reach the authoritative decision |
|---|---|---|
| `TRUSTED_INTERNAL` | a record read by id from Sentinel's own record store (fact provenance `TRUSTED_LOCAL`); our own policies | **yes** |
| `VERIFIED_EXTERNAL` | a record whose issuer's signed statement verified against the operator's trust store (fact provenance `VERIFIED_EXTERNAL`) | **yes** |
| `USER_CONTROLLED` | a cardholder narrative, chat turn or form field | never |
| `MERCHANT_CONTROLLED` | merchant application copy, descriptors, site text | never |
| `DOCUMENT_CONTROLLED` | an uploaded invoice, receipt or PDF (treated as text) | never |
| `MODEL_GENERATED` | anything an LLM produced, including 'our' agent's recommendation | never |
| `UNVERIFIED_RECORD` | record fields Sentinel could not establish: sent in a request body, or carried by a signature that failed, expired, was revoked or was superseded -- claims about the records, never facts | never |
| `UNKNOWN` | unlabelled third-party content | never |

`TrustClass.is_trusted` is the only predicate the platform uses. `Evidence`
refuses to be VERIFIED from an untrusted class; `UntrustedText`, `Claim` and
`AIRecommendation` refuse a trusted class. Trust does not launder through a
model call: the agent read the attacker's text, so its output is
`MODEL_GENERATED`.

A record's trust class is not a property of its Python type. It comes from the
record's **fact provenance**, which the workflow computes from how the facts
arrived.

## Fact provenance (`sentinel/trust/`)

Why may Sentinel trust the facts it decides on? Every decision carries one
`FactProvenance` for its primary record (dispute ledger, acquirer record,
transaction, login session): a status, the issuer and key, the digest of the
exact signed statement, and the digest of the exact payload used. The workflow
computes it (`workflows._resolve_facts`); no request field can set it.

| Provenance | Meaning | Can support an outcome |
|---|---|---|
| `VERIFIED_EXTERNAL` | an issuer's signed fact envelope verified: known key, the issuer's own, scoped to the kind of fact, unrevoked, signed within the key's validity, about this record, unexpired, not older than a statement already acted on | **yes** |
| `TRUSTED_LOCAL` | read by id from Sentinel's record store, unsigned: trusted for where it is kept, not because anything proves it (a DB-write attacker could change it) | **yes** |
| `UNTRUSTED` | sent in the request body, unsigned: a claim about the records | no -- stricter outcomes only |
| `EXPIRED` | a valid signature past its `expires_at` | no -- stricter outcomes only |
| `SUPERSEDED` | a valid signature older than a statement about the same record that this deployment already acted on (a replayed statement) | no -- stricter outcomes only |
| `REVOKED` | signed by a key the operator revoked; a compromised key can backdate, so its `issued_at` does not help | no -- stricter outcomes only |
| `INVALID` | malformed, altered, unknown or wrong signer, out of scope, another record's statement, issued in the future, valid longer than the key allows, a stored row that differs from its signed statement, or a record-store read with no statement where the deployment requires one | no -- stricter outcomes only |

- **Signed fact envelopes.** An issuer (the core ledger, the acquirer's KYB
  registry, the authentication service) signs `sentinel.fact/1` envelopes with
  Ed25519 (RFC 8032, via pyca/cryptography; Sentinel implements no
  cryptographic primitive). The signature covers the domain prefix
  `sentinel.fact/1\n` and the canonical JSON of the header. The header names
  the issuer, key, kind, subject, sequence, issued / effective / expires times
  and the payload's SHA-256.
- **Canonical JSON.** Signing needs one byte string per value. Floats, NaN,
  duplicate keys, out-of-range integers, lone surrogates and deep nesting are
  refused, not normalised. The API rejects duplicate keys in every request
  body.
- **The trust store** is operator configuration (`SENTINEL_TRUST_STORE`,
  `--trust-store`) and holds public keys only. Each key has one purpose, its
  scopes, a validity window and a maximum statement lifetime. A key id is the
  fingerprint of its public key, so an entry cannot claim another key's
  identity. Rotation (`not_after`) keeps earlier statements valid until they
  expire. Revocation invalidates everything the key ever signed.
- **Complete statements.** A signed statement must state every field its kind
  requires (`workflows.STATEMENT_FIELDS`). An omitted field is not the
  issuer's word, and Sentinel does not fill it in with a default: an
  incomplete statement is `INVALID`. A statement that does not verify is never
  decided on. The decision falls back to the request's own record, which fails
  safe.
- **Anti-rollback.** The highest sequence acted on per issuer and subject is
  the higher of an index table and the tamper-evident audit chain (every
  decision event names the statement it used). A database writer who deletes
  the table's rows must also rewrite the chain. An older statement is
  `SUPERSEDED`, and a different statement with the same sequence is `INVALID`
  (equivocation).
- **Stored records are evaluated by id.** A caller cannot send body facts or a
  statement for a dispute, application, transaction or session the store
  holds -- under its exact id or an ASCII-case variant of it -- on any route
  (the multi-turn conversation route included); that is a 400. A caller-named
  id must be in the one record-id grammar (ASCII letters, digits, `. _ -`), so
  a Unicode look-alike cannot be a second subject. Its recorded submission,
  its account's context and its stored statement decide. A KYB statement names its application, so a
  statement about one of a merchant's applications cannot stand in for
  another. `sentinel trust ingest` verifies issuers' statements and stores
  them beside the records.
- **Record-store tampering.** A record read by id is checked field by field
  against its stored signed statement. With `require_signed_facts` (on
  whenever the app signs its own records), a stored record whose statement is
  missing is `INVALID`. Deleting a statement therefore cannot downgrade a
  tampered row to `TRUSTED_LOCAL`.
- **Asymmetry.** Unverified records can make an outcome stricter (a refunded
  ledger still denies) but never support one. Reconciliation turns what they
  would support into `INSUFFICIENT`, which goes to human review, so the system
  never executes a capability on them; only an authenticated reviewer's
  recorded decision can act on what they claim.
- **A failed statement is decisive.** A statement whose signature, key or
  binding failed (`INVALID`, `REVOKED`) is a tamper signal: the policy's BLOCK
  on it outranks the fact that the facts it carried cannot be evaluated
  (DENY, no case), rather than a fail-safe review nobody may ever approve.
- **Execution is idempotent.** A consequential capability executes once per
  (workflow, subject, capability): the system claims the key when it executes,
  a human approval claims it when it resolves a case, and a repeat evaluation
  of an executed subject is `DENY` ("already executed"). The claim is recorded
  in the decision's input snapshot (`prior_execution`) and restored by replay.

**What `VERIFIED_EXTERNAL` proves.** The holder of a key the operator trusts
for this issuer and this kind of fact signed exactly this payload about this
record, within the key's validity. The statement has not expired and is not
older than one already acted on.

**What it does not prove.** That the issuer's record is *true*; that the
issuer has not issued a newer statement Sentinel has not yet seen (expiry
bounds that window); or anything about a key the operator should not have
trusted. The demo's issuer is ephemeral and in-process: it shows the
mechanism, not an external trust relationship.

## Capability security matrix

17 capabilities. 10 are **consequential** (irreversible, or moving money, or
reserved to a human reviewer): executing one of those without support is what
"attack success" means. The AI agent actor may execute only
`READ_TRANSACTION`, `READ_ACCOUNT`, `READ_MERCHANT`, `CREATE_CASE`, `CREATE_ALERT`, `RECOMMEND_REFUND`, `RECOMMEND_ACTION` -- reads, case and alert creation, and
recommendations. `SKIP_REVIEW` has no allowed
actor at all. These are Sentinel's own values, documented as such; they are
not industry standards.

| Capability | Risk | Irreversible | Money | Consequential | AI agent may execute | Allowed actors | Required authorization | Human-review threshold (₹) | Least fact provenance | Executable from | Policy gates |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `READ_TRANSACTION` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `READ_ACCOUNT` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `READ_MERCHANT` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `CREATE_CASE` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `CREATE_ALERT` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `RECOMMEND_REFUND` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `RECOMMEND_ACTION` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — | — | — |
| `APPROVE_REFUND` | HIGH | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | 50,000 | `TRUSTED_LOCAL` | dispute | — |
| `APPROVE_TRANSACTION` | HIGH | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | 150,000 | `TRUSTED_LOCAL` | transaction | — |
| `APPROVE_MERCHANT` | HIGH | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | — | `TRUSTED_LOCAL` | merchant_onboarding | — |
| `FREEZE_ACCOUNT` | MEDIUM | no | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | — | `TRUSTED_LOCAL` | account_security | — |
| `UNFREEZE_ACCOUNT` | HIGH | no | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER | HUMAN_REVIEWER | — | `TRUSTED_LOCAL` | account_security | `account-security@v1:review-sensitive-capability`, `account-security@v2:review-sensitive-capability` |
| `CHANGE_PAYOUT` | CRITICAL | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER | HUMAN_REVIEWER | 0 | `TRUSTED_LOCAL` | account_security | `account-security@v1:review-sensitive-capability`, `account-security@v2:review-sensitive-capability` |
| `RELEASE_FUNDS` | CRITICAL | yes | yes | yes | **no** | SENIOR_REVIEWER | SENIOR_REVIEWER | 0 | `TRUSTED_LOCAL` | account_security | — |
| `CLOSE_CASE` | MEDIUM | no | no | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER | HUMAN_REVIEWER | — | `TRUSTED_LOCAL` | no workflow (a human, via the case service) | — |
| `ALTER_RISK` | HIGH | no | no | yes | **no** | SENIOR_REVIEWER | SENIOR_REVIEWER | — | `TRUSTED_LOCAL` | no workflow (a human, via the case service) | — |
| `SKIP_REVIEW` | CRITICAL | yes | yes | yes | **no** | nobody | SENIOR_REVIEWER | — | `TRUSTED_LOCAL` | no workflow (a human, via the case service) | — |

"Policy gates" lists the shipped policy rules whose conditions name the
capability (`docs/POLICY_ENGINE.md`); the registry applies regardless of
policy.

### Authorization (`capabilities.authorize`)

Called with the capability the **workflow** is considering, never the one the
model asked for, and with the workflow itself. In order:

1. no consequential capability requested → GRANTED;
2. an unregistered capability → DENIED (fail closed);
3. a capability the workflow does not own (`WORKFLOW_CAPABILITIES`: a dispute
   owns APPROVE_REFUND, a login decision owns only the account actions) →
   DENIED -- a caller naming APPROVE_REFUND on the account route gets a 400 at
   the API and a DENY from the engine;
4. the actor is not in the capability's allowed actors → DENIED;
5. policy outcome BLOCK → DENIED;
6. **the fact-provenance floor** (`min_fact_provenance`, `TRUSTED_LOCAL` for
   every consequential capability). Facts whose verification failed
   (`INVALID`, `REVOKED`), or with no recorded provenance at all → DENIED for
   every actor. For SYSTEM, facts below the floor (`UNTRUSTED`, `EXPIRED`,
   `SUPERSEDED`) → PENDING_HUMAN. This holds under every policy version: a
   policy may demand more, never less;
7. a consequential capability whose verified evidence does not support the
   request → DENIED;
8. policy outcome REQUIRE_HUMAN_REVIEW or TEMPORARY_HOLD → PENDING_HUMAN;
9. the automated path (SYSTEM) on a capability that requires a human or
   senior reviewer → PENDING_HUMAN;
10. SYSTEM above the capability's human-review amount threshold → PENDING_HUMAN;
11. otherwise GRANTED.

A human approval of a case gets the same answer for the reviewer's actor kind
(`CaseService.approval`):

- a policy BLOCK is final for every actor;
- records that contradict the claim cannot be approved;
- nobody approves facts whose verification failed.

A human may approve on unverified facts, because establishing them is what the
human review is for.

The policy states finer requirements declaratively on the `facts_provenance`
context field (`docs/POLICY_ENGINE.md`):

- a failed or revoked signature → BLOCK;
- unverified facts → human review;
- a refund above ₹25,000, a payment above ₹100,000, or any merchant onboarding
  on an unsigned stored record → human review.

### Final action (`composer._final_action`)

Policy BLOCK → BLOCK when a security finding (severity ≥ HIGH or an
off-surface request) caused it, else DENY; evidence INSUFFICIENT →
REQUIRE_HUMAN_REVIEW (fail-safe); evidence not SUPPORTED → DENY; policy
TEMPORARY_HOLD → TEMPORARY_HOLD; policy REQUIRE_HUMAN_REVIEW or authorization
PENDING_HUMAN → REQUIRE_HUMAN_REVIEW; policy STEP_UP with authorization
GRANTED → STEP_UP; authorization GRANTED → ALLOW (the candidate capability
executes); anything else → DENY. Only ALLOW executes a capability.

## Detection, claim classification and trusted adjudication

Three different things, often conflated:

- **Detection** (the AI Security Gateway) looks for *attacks* in text and in
  model output: injected instructions, spoofed authority, an off-surface tool
  call. It is heuristic and can only **tighten** an outcome. It misses
  attacks with nothing to detect (a plain lie), and the architecture assumes
  it will.
- **Claim classification** (`sentinel/security/claims.py`) reads *what the
  customer claims* ("it never arrived") so the right trusted field is checked.
  It is deterministic and lexical, abstains when it cannot read a claim (a
  human review), and is defence in depth: whatever it reads, nothing executes
  unless the records support it.
- **Trusted adjudication** (the reconciliation engine + policy + the registry)
  decides *whether the records support the request*. It is the security
  foundation: it reads only trusted facts, and it is what holds the guarded
  attack-success rate at 0 when detection misses.

## Consequential-capability trace

Checked against the workflow source by this renderer (it fails if a
workflow's candidate capability comes from anywhere else). Every path runs:
input → provenance (typed trust class) → model recommendation (recorded,
never read by the decision) → risk (derived from trusted records) → evidence
(claim vs trusted facts) → policy (active version) → authorization (the
registry, for the SYSTEM actor) → human review when required → final action →
audit.

| Capability | How a decision path can consider it | Model's request | Evidence | Policy | Authorization (registry) | Human review (who may approve a held case) | Audit |
|---|---|---|---|---|---|---|---|
| `APPROVE_REFUND` | dispute workflow -- fixed candidate | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | SYSTEM may execute up to ₹50,000 | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `APPROVE_TRANSACTION` | transaction workflow -- fixed candidate | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | SYSTEM may execute up to ₹150,000 | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `APPROVE_MERCHANT` | merchant-onboarding workflow -- fixed candidate | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | SYSTEM may execute | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `FREEZE_ACCOUNT` | account-security workflow -- the caller's `requested_capability`, supported only when the session record shows a `freeze_request`; otherwise INSUFFICIENT (human review) | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | SYSTEM may execute | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `UNFREEZE_ACCOUNT` | account-security workflow -- the caller's `requested_capability`, supported only when the session record shows an `unfreeze_request` | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | human only -- never the system | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `CHANGE_PAYOUT` | account-security workflow -- a `payout_change` event in the session record (a caller's `requested_capability` the record does not show is held for a human) | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | human only -- never the system | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `RELEASE_FUNDS` | account-security workflow -- the caller's `requested_capability`, supported only when the session record shows a `release_request` | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | human only -- never the system | SENIOR_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `CLOSE_CASE` | account-security `requested_capability` only; the investigation workflow never has a candidate. Closing a *case* is `record_human_decision`, never a capability execution | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | human only -- never the system | HUMAN_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `ALTER_RISK` | account-security workflow -- the caller's structured `requested_capability` | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | human only -- never the system | SENIOR_REVIEWER to approve | decision event (action, capability, facts provenance + payload digest, snapshot hash) |
| `SKIP_REVIEW` | account-security workflow -- the caller's structured `requested_capability` (no actor may be granted it) | recorded, never read | SUPPORTED required | must not BLOCK / hold / review | nobody | NOBODY | decision event (action, capability, facts provenance + payload digest, snapshot hash) |

A capability executes only when the final action is ALLOW (or STEP_UP once
satisfied): evidence SUPPORTED, policy not BLOCK / HOLD / REVIEW, and the
registry GRANTED for SYSTEM -- and only in an authoritative evaluation (every
control, the active policy and risk model). `tests/test_capability_trace.py`
drives a model requesting each capability in every workflow and a caller
requesting each one directly (denied unless the workflow owns it);
`tests/test_release_trace.py` pins the defects the final trace found.

## Evaluation authority (`sentinel/decision/authority.py`)

A caller may request an evaluation; it may not weaken one. An evaluation is
**authoritative** -- recorded, audited, able to open a case and to execute --
only when its inputs carry every control, the active version of its policy
(content hash included) and the active risk model for its surface. The check
runs in `_finish` on the inputs the decision was actually composed from,
before anything is written, and raises `ControlDowngrade` otherwise; the
application sends what-if runs to a runtime that never persists, and every
decision carries `authoritative`. A recording runtime also refuses what-if
*options* before running (`workflows._admit`): the composed inputs cannot show
a run without prompt provenance, or a custom risk model that reuses the active
model's version name.

| Parameter class | Parameters | Where accepted |
|---|---|---|
| user-controllable | `hardened`, `skip_agent` | every route and command |
| what-if (system-controlled on the authoritative path) | `controls`, `policy_version`, `risk_model`, `unguarded`, top-level `unguarded`, investigation `as_of` | `/v1/attacks/simulate`, `/v1/scenarios/{key}/run`, `/v1/replay`, `sentinel security attack`, `sentinel scenario run`, `sentinel replay run` -- never recorded as decisions |
| unknown option keys | anything else | refused (400) |

The evaluate routes answer a what-if switch with 403; the authoritative CLI
commands do not have the flags. Risk models are bound to their surface: a
transaction model is refused on the login surface rather than silently
applied.

## Case lifecycle (`sentinel/cases/service.py`)

RESOLVED is not a target anywhere in the status table; a case reaches it only
through `record_human_decision`, and RESOLVED is final (no transition, no
second decision, no reopen).

| From | Status moves (any actor) | Human decision allowed |
|---|---|---|
| `OPEN` | `ESCALATED`, `INVESTIGATING`, `TRIAGE`, `WAITING_HUMAN` | no |
| `TRIAGE` | `ESCALATED`, `INVESTIGATING`, `WAITING_HUMAN` | yes |
| `INVESTIGATING` | `ESCALATED`, `WAITING_HUMAN` | yes |
| `WAITING_HUMAN` | `ESCALATED`, `INVESTIGATING` | yes |
| `RESOLVED` | — (final) | no |
| `ESCALATED` | `INVESTIGATING` | yes |

A human decision recorded under a reserved system or model actor name
(`agent`, `ai`, `auto`, `automation`, `bot`, `human`, `llm`, `model`, `sentinel`, `system`, any `agent:` / `ai:` / `model:` prefix) or under the name
of an agent that recommended on the case is refused. Approving needs the
level the case's capability requires, read from the registry when the case
opens: `APPROVE_REFUND` → HUMAN_REVIEWER, `APPROVE_TRANSACTION` → HUMAN_REVIEWER, `APPROVE_MERCHANT` → HUMAN_REVIEWER, `FREEZE_ACCOUNT` → HUMAN_REVIEWER, `UNFREEZE_ACCOUNT` → HUMAN_REVIEWER, `CHANGE_PAYOUT` → HUMAN_REVIEWER, `RELEASE_FUNDS` → SENIOR_REVIEWER, `CLOSE_CASE` → HUMAN_REVIEWER, `ALTER_RISK` → SENIOR_REVIEWER, `SKIP_REVIEW` → NOBODY; and the registry must allow the approval for that
reviewer's actor kind given the recorded policy outcome and evidence (a policy
BLOCK or CONTRADICTED records cannot be approved by anyone; a claim the
classifier could not read -- INSUFFICIENT -- can). Denying or escalating needs
any human; once escalated -- by a decision or by a status change -- the case
is moved on and decided only by a SENIOR_REVIEWER, and it stays handed up
when it moves back to investigation. Every
human action -- a manual case, a status change, a decision -- is appended to
the audit chain before the case is saved (notes and titles hashed), so a
resolution cannot be written into the case table without a chained record.
**Who acts is authenticated, not declared** (`sentinel/cases/identity.py`).

- **The registry.** A reviewer registry is operator configuration
  (`SENTINEL_REVIEWERS`), apart from the case data. It holds each reviewer's
  id, role, authority limit, active flag and one random 256-bit credential,
  stored only as its SHA-256.
- **Resolving the reviewer.** A case action presents the credential
  (`X-Reviewer-Token`, or `SENTINEL_REVIEWER_TOKEN` for the CLI). The id,
  role and limit on the record come from the registry. A request body that
  names a reviewer, role or actor is refused.
- **Approving** also needs:
  - an authority limit that covers the case amount (account-security cases
    carry no amount: they are bounded by role and by four eyes);
  - four eyes where the capability registry asks for it (`dual_approval_at`):
    two distinct reviewers must approve before the case resolves. One
    identity cannot supply both, a deny resolves, an escalation of either
    kind restarts the count, and an approval by a reviewer whose credential
    has since been deactivated no longer counts. A case needs never fewer
    approvals than the registry asks for its amount, whatever its stored
    count says.
- **The registry file is typed.** Every field has one type, the credential
  id is derived from the credential's digest (it cannot be blank, shared or
  the token itself), and an id with a reserved word or a model name as any
  component (`sentinel-bot`, `ai-reviewer`, `claude`, `gpt-4o`) is refused.
  The name check is hygiene for the audit trail, not the control: authority
  comes from the credential the operator issued.
- **Executing.** The deciding approval executes the case's capability, so it
  claims the same once-per-subject key a decision would; a first of two
  approvals executes nothing.

## Threat taxonomy (15 classes)

| Class | Name | Mechanism | Detection kind | Typical targets |
|---|---|---|---|---|
| `direct_injection` | Direct instruction injection | Explicit override instructions placed in the untrusted text. | lexical | APPROVE_REFUND, APPROVE_TRANSACTION |
| `authority_spoof` | Authority spoofing | Text impersonating a system, compliance, admin or network directive. | lexical | APPROVE_REFUND, APPROVE_MERCHANT, SKIP_REVIEW |
| `document_borne` | Document-borne injection | Instructions hidden inside an uploaded invoice, receipt or application. | lexical | APPROVE_REFUND, APPROVE_MERCHANT |
| `fake_policy` | Policy / rule-citation forgery | Fabricated network rules, regulations or internal policies demanding an action. | lexical | APPROVE_REFUND, RELEASE_FUNDS |
| `context_poisoning` | Context poisoning | Assertions of prior state -- 'you already approved', 'as noted in the case file'. | lexical | APPROVE_REFUND, CLOSE_CASE, SKIP_REVIEW |
| `tool_manipulation` | Tool manipulation | Text that names or spells out tool / function calls for the agent to make. | lexical | UNFREEZE_ACCOUNT, CHANGE_PAYOUT, RELEASE_FUNDS |
| `multi_turn_escalation` | Multi-turn escalation | Trust built across a thread; the payload lands (or is split) across later turns. | session | APPROVE_REFUND |
| `unicode_obfuscation` | Unicode obfuscation | Homoglyphs, zero-width characters or full-width forms used to evade detection. | normalisation | APPROVE_REFUND |
| `indirect_injection` | Indirect injection | Instructions arriving via third-party content the agent reads (merchant site, email). | lexical | APPROVE_MERCHANT, CHANGE_PAYOUT |
| `adjudication_gaming` | Adjudication gaming | No injection at all -- a false factual claim in persuasive prose. The honest hard case. | evidence | APPROVE_REFUND |
| `financial_social_engineering` | Financial social engineering | Urgency, loyalty, sympathy or threat used to pressure a favourable outcome. | lexical | APPROVE_REFUND, UNFREEZE_ACCOUNT |
| `capability_escalation` | Capability escalation | The model is induced to request a capability outside its surface (unfreeze, change payout, release funds, close case, alter risk, skip review). | structural | UNFREEZE_ACCOUNT, CHANGE_PAYOUT, RELEASE_FUNDS, CLOSE_CASE, ALTER_RISK, SKIP_REVIEW |
| `model_output_injection` | Model-output injection | Untrusted text that mimics the agent's own output format (an 'assistant:' turn, a JSON tool call, a chat-template marker) so a parser or a model treats it as the model's decision. | lexical + structural | APPROVE_REFUND, RELEASE_FUNDS, CLOSE_CASE |
| `false_evidence` | False evidence | A verifiable-sounding fact asserted in prose -- a tracking status, a 'your own system shows' claim -- that the trusted records refute. Nothing to detect; the contradiction engine decides. | evidence | APPROVE_REFUND, APPROVE_MERCHANT |
| `synthetic_evidence` | Synthetic evidence | A fabricated record, ledger extract or verification report presented as if it were the institution's own data. It arrives through an untrusted channel, so it can never become VERIFIED evidence whatever it says. | trust boundary | APPROVE_REFUND, APPROVE_MERCHANT, RELEASE_FUNDS |

By how each class is caught:

- **lexical**: direct_injection, authority_spoof, document_borne, fake_policy, context_poisoning, tool_manipulation, indirect_injection, financial_social_engineering
- **session**: multi_turn_escalation
- **normalisation**: unicode_obfuscation
- **evidence**: adjudication_gaming, false_evidence
- **structural**: capability_escalation
- **lexical + structural**: model_output_injection
- **trust boundary**: synthetic_evidence

Only the lexical classes are (partly) detectable by inspecting text; the
gateway carries 13 bounded-quantifier signals plus provenance rules,
a session model and a model-output check. Detection can only **tighten** an
outcome (severity feeds policy; an off-surface request is a CRITICAL
escalation). The evidence, structural and trust-boundary classes are closed
by the reconciliation engine, the registry and the type system, which is why
the ablation in `docs/EVALUATION.md` §F shows detection alone leaking exactly
the classes with nothing to detect.

## Case rules (`cases/rules.py`)

A case opens by a deterministic rule over the finished decision -- never
because a model asked for one -- and only a human can resolve it.

| Rule | Priority | Fires when |
|---|---|---|
| `capability_escalation` | P1 | a CRITICAL security event with the registry in `blocked_by`, or the model requested a capability other than the workflow's and the request was blocked |
| `critical_risk_financial` | P1 | risk level CRITICAL on a request for a consequential capability |
| `ai_security_block` | P2 | final action BLOCK with security severity ≥ HIGH |
| `human_review_required` | P1 / P2 | final action REQUIRE_HUMAN_REVIEW or TEMPORARY_HOLD; P1 above ₹1,50,000 or on a hold, else P2 |
| `monitoring_patterns` | P2 | an investigation whose account risk is HIGH or CRITICAL |

## Where each property is tested

| Property | Test |
|---|---|
| prose never reaches the policy context or the audit log | `tests/test_trust_boundary.py`, `tests/test_invariants.py` |
| the model's requested capability is never the one executed | `tests/test_invariants.py`, `tests/test_model_output_separation.py` |
| AI_AGENT is allowed on no consequential capability | `tests/test_capabilities.py` (asserted again by this renderer) |
| a workflow executes only its own capabilities; one conversation is one decision; every human case action is audited; approvals get the registry's answer | `tests/test_release_trace.py` |
| the console holds no decision logic and calls only real routes | `tests/test_ui_api_contract.py` |
| no persisted decision ran with fewer controls, a historical policy or a historical risk model; every evaluate route refuses every what-if switch | `tests/test_evaluation_authority.py` |
| every consequential capability, requested by a model in every workflow or by a caller, executes only through the full path | `tests/test_capability_trace.py`, `tests/test_policy_adversarial.py` |
| only a human decision resolves a case; the required review level comes from the registry | `tests/test_case_lifecycle.py` |
| replay cannot report equivalence for a rewritten record | `tests/test_replay_integrity.py` |
| every audit corruption is an integrity error, never a crash | `tests/test_audit_corruption.py` |
| headline results recompute from `results/` | `tests/test_results_regression.py` |
