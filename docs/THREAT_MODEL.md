# Threat model

## What is protected

High-impact financial decisions that an institution increasingly delegates
to automated and AI-assisted systems: refunds, payment authorisation,
merchant onboarding, account security state (freezes, payout destinations),
and investigation outcomes. The asset is **decision integrity**: an outcome
must be a function of trusted evidence, risk state, policy and authorization
-- never of attacker-controlled text or of a model's opinion.

## Adversaries and what they control

| Adversary | Controls | Cannot |
|---|---|---|
| Malicious cardholder / fraudster | dispute narratives, chat turns, forms, "claims" about facts | the ledger, the policy, tool wiring |
| Malicious merchant | applications, uploaded documents, descriptors, site copy | acquirer records |
| API caller / compromised integration | request bodies: record facts, fact envelopes, timestamps, capability fields | a `VERIFIED_EXTERNAL` fact (that takes an issuer's private key); body facts are `UNTRUSTED`: the system never executes on them, only an authenticated reviewer's approval can |
| Third-party content | emails, pages, order-status text the agent reads | anything trusted |
| Compromised / over-permissive AI agent | its own output: recommendations and tool calls | authorization |
| Malicious model output | the same channel as above | evidence status |
| Insider / operator error | policy misconfiguration | the field catalog / validation |
| Storage attacker | records at rest, including the audit chain | a record behind a signed statement (a changed row, or a deleted statement under `require_signed_facts`, is `INVALID`); rolling a record back to an older statement already acted on (the marks are also derived from the audit chain); audit events before the last checkpoint the operator holds outside the store |

## Trust boundary

Every piece of information that enters the decision system carries a
`TrustClass`. Only `TRUSTED_INTERNAL` and `VERIFIED_EXTERNAL` can produce
`VERIFIED` evidence; the type system refuses the rest
(`Evidence.__post_init__`). Model output is `MODEL_GENERATED` -- untrusted --
even though it came from "our" AI.

A record's trust class comes from its **fact provenance**
(`docs/SECURITY_MODEL.md`), not from its type. The provenance is computed from
how the record arrived:

- read from the store: `TRUSTED_LOCAL`;
- an issuer's signed statement that verifies against the operator's trust
  store: `VERIFIED_EXTERNAL`;
- a request body, or a signature that fails, expires, was revoked or was
  superseded: never trusted.

## Threat taxonomy

<!-- gen:threat-taxonomy -->
| Class | Mechanism | Caught by |
|---|---|---|
| `direct_injection` | Explicit override instructions placed in the untrusted text. | lexical |
| `authority_spoof` | Text impersonating a system, compliance, admin or network directive. | lexical |
| `document_borne` | Instructions hidden inside an uploaded invoice, receipt or application. | lexical |
| `fake_policy` | Fabricated network rules, regulations or internal policies demanding an action. | lexical |
| `context_poisoning` | Assertions of prior state -- 'you already approved', 'as noted in the case file'. | lexical |
| `tool_manipulation` | Text that names or spells out tool / function calls for the agent to make. | lexical |
| `multi_turn_escalation` | Trust built across a thread; the payload lands (or is split) across later turns. | session |
| `unicode_obfuscation` | Homoglyphs, zero-width characters or full-width forms used to evade detection. | normalisation |
| `indirect_injection` | Instructions arriving via third-party content the agent reads (merchant site, email). | lexical |
| `adjudication_gaming` | No injection at all -- a false factual claim in persuasive prose. The honest hard case. | evidence |
| `financial_social_engineering` | Urgency, loyalty, sympathy or threat used to pressure a favourable outcome. | lexical |
| `capability_escalation` | The model is induced to request a capability outside its surface (unfreeze, change payout, release funds, close case, alter risk, skip review). | structural |
| `model_output_injection` | Untrusted text that mimics the agent's own output format (an 'assistant:' turn, a JSON tool call, a chat-template marker) so a parser or a model treats it as the model's decision. | lexical + structural |
| `false_evidence` | A verifiable-sounding fact asserted in prose -- a tracking status, a 'your own system shows' claim -- that the trusted records refute. Nothing to detect; the contradiction engine decides. | evidence |
| `synthetic_evidence` | A fabricated record, ledger extract or verification report presented as if it were the institution's own data. It arrives through an untrusted channel, so it can never become VERIFIED evidence whatever it says. | trust boundary |

15 classes; rendered from `security/threats.py`. Only the lexical rows are (partly) detectable by inspecting text; `docs/SECURITY_MODEL.md` has the full table with typical targets.
<!-- /gen:threat-taxonomy -->

Primary controls by kind: the lexical classes are flagged by the gateway and
backstopped by evidence and policy; `multi_turn_escalation` by the session
model, which inspects the whole transcript; `unicode_obfuscation` by
normalisation before detection; `indirect_injection` by provenance-aware
reclassification; `adjudication_gaming` and `false_evidence` by
**trusted-evidence reconciliation** (the honest hard case -- nothing to
detect); `capability_escalation` by model-output inspection, the registry
and authorization; `model_output_injection` by a parser that reads only the
provider's structured tool call plus a gateway check for output-format
mimicry; `synthetic_evidence` by the type system, since an untrusted channel
cannot produce VERIFIED evidence whatever the text claims to be. The security
case does **not** depend on detection: the ablation shows detection alone
leaks the classes with nothing to detect, and trusted-evidence adjudication
closes them.

## Controls, mapped to failure modes

| Failure mode | Control | Where tested |
|---|---|---|
| prose reaches the decision | typed boundary; `_TrustedView` has no model/prose field | `test_trust_boundary.py`, `test_invariants.py` (1, 3) |
| model executes a capability | registry: AI_AGENT allowed on no consequential capability; composer never executes the model's request | invariants 2, 6; `test_capabilities.py` |
| model requests off-surface capability | gateway `inspect_model_output` → CRITICAL escalation → BLOCK + P1 case | `test_security_gateway.py`, `test_cases.py` |
| unknown / unverifiable claim | INSUFFICIENT → REQUIRE_HUMAN_REVIEW | invariant 4 |
| malformed input | validation → fail-safe human review; a malformed or negative number in a trusted record (ledger amount, KYB flags) is a human review, never a coerced 0 | invariant 5, `test_policy_adversarial.py` |
| high-value effect | policy thresholds + registry human-review thresholds | invariant 6 |
| audit tampering | tamper-evident chain; verify names the first modified, deleted, inserted or reordered record; a signed, anchored checkpoint detects a consistent rewrite of everything before it (INV-AUDIT-2) | invariant 7, `test_audit_chain.py`, `test_audit_indexing.py`, `test_audit_anchoring.py` |
| text mimicking the model's own output | the parser reads only the provider's structured tool call; output-format mimicry is a gateway finding | `test_model_output_separation.py` |
| fabricated records in prose | an untrusted channel cannot produce VERIFIED evidence (type system) | `test_evidence.py`, `test_trust_boundary.py` |
| future data influencing a past decision | point-in-time baselines, as-of entity profiles, time-aware graph, bounded monitoring windows; the temporal suite | `test_temporal_leakage.py`, `test_entity_pointintime.py`, `test_graph_temporal.py` |
| a second decision engine in the console | the console holds no decision logic and calls only real routes | `test_ui_api_contract.py` |
| an older policy or risk model, or fewer controls, selected by request | evaluation authority in the engine: `_finish` refuses to record a run whose inputs are not the active policy / model with every control; evaluate routes 403 every what-if switch; what-if runs never persist | `test_evaluation_authority.py`, `test_rc_hardening.py` |
| a model or caller driving a consequential capability | candidate capability fixed per workflow or from the caller's structured request, never model output; registry + policy + evidence gate it; human-reserved capabilities never execute through the system | `test_capability_trace.py`, `test_policy_adversarial.py` |
| a case closed without a human verdict, or by a system / agent name, or approved below the required level | RESOLVED is absent from the status table; `record_human_decision` refuses reserved actors and checks the registry-derived level | `test_case_lifecycle.py`, `test_rc_hardening.py` |
| a policy edited in place, mistyped or with a gate that can never fire | pinned manifest; strict documents; typed evaluation; store cross-check | `test_policy_adversarial.py` |
| replay reporting "no change" for a rewritten record | the recorded side is anchored to the audit event and the snapshot to its recorded hash | `test_replay_integrity.py` |
| a corrupted audit file crashing or passing verification | every unreadable / modified / missing / reordered record is an AUDIT INTEGRITY ERROR with exit 2 | `test_audit_corruption.py` |
| an edited audit index redirecting a lookup | SQLite index columns are cross-checked against the hashed payload | `test_rc_hardening.py` |
| silent policy drift | explicit versions, effective dates, replay | invariant 8 |
| provenance loss | trust preserved through evidence, snapshot, audit | invariant 9 |
| parallel business logic | one application layer; static check on API/CLI/UI sources | invariant 10 |
| policy misconfiguration | schema validation at load; unknown fields rejected; linter for rules that can never fire | `test_policy_engine.py`, `test_policy_lint.py` |
| information leakage | audit stores hashes; spans hashed; no stack traces; secrets from env only | `test_audit_chain.py`, `test_api_v1.py` |
| abuse of the API | body cap, per-client rate limit, optional bearer auth (constant-time compare), request ids, static path containment, 403 on control switches | `test_api_v1.py`, `test_api_path_containment.py` |

## Explicitly out of scope

- **Whether an issuer's record is true.** Sentinel verifies *who* stated a
  record and that it was not altered, replayed or revoked. It does not verify
  that the ledger itself is correct: poisoning the issuer is a different
  threat, with different controls.
- **Binary document parsing.** Uploads are treated as untrusted *text*.
- **Real sanctions / AML providers, regulatory filing.** The monitoring layer
  is a labelled simulation.
- **Universal security.** Sentinel closes a specific, important class: the
  authoritative decision no longer reads attacker prose or model opinion. It
  is evaluated on synthetic corpora and a synthetic dataset.

## Residual risk

- Detection is lexical and evadable (held-out recall is reported honestly);
  the architecture, not the detector, carries the guarantee.
- The claim classifier is lexical too: an unrecognised legitimate phrasing
  degrades to a fail-safe human review -- a classifier false negative that
  costs review time, never money. The
  held-out set exists to find these; it found one in v2 ("called off the
  booking") and the *general* pattern was fixed, not the string.
- The offline agent is a deterministic simulation of the documented failure
  mode (a gullible tool-calling agent), not a measurement of any real model
  and not proof that a specific production LLM fails identically. `make live-check`
  and `sentinel eval run --suite models` exist to probe a real model. Its
  attack-success rate is a property of the simulator, which shares an author
  with the corpus.
- Record facts in a request body (`ledger`, `records`, `transaction`,
  `session`) are `UNTRUSTED`: they can make an outcome stricter but never
  execute a capability.
- `TRUSTED_LOCAL` records are trusted because of where they are stored, so a
  DB-write attacker can change an unsigned record. Where the store is not a
  sufficient boundary, require signed facts (`SENTINEL_REQUIRE_SIGNED_FACTS`,
  plus a trust store).
- The demo's issuer is an ephemeral in-process key. It demonstrates the
  mechanism, not an external trust relationship.
- Auth is optional, and the server only warns when it starts open on a
  non-loopback bind. What-if switches are refused on the evaluate routes.
- Policy versions are signed releases, explicitly activated (D34): a writer
  of the policy directory cannot make an edited or unsigned policy decide. The
  shipped trust root lives in the package, so someone who can rewrite the
  installed package can replace it; a deployment sets `SENTINEL_POLICY_TRUST`
  to a root it controls. A signer can still release a bad policy: replay is
  how one finds out.
- The audit chain detects modification, deletion, insertion and reordering by
  anyone who cannot recompute it. A storage attacker **can** recompute it: a
  consistent rewrite of the events after the last checkpoint passes both
  `verify` and checkpoint verification (verified in the 2.3 trust audit).
  Only events up to a checkpoint the operator holds outside the store are
  protected. A signed, anchored checkpoint (Ed25519, an `audit-checkpoint`
  key, an append-only anchor) is verifiable without the ability to forge, and
  replay reports each decision as `anchored`, `not_anchored` or
  `anchor_mismatch`; the legacy HMAC checkpoint (`SENTINEL_AUDIT_KEY`) can be
  forged by anyone who can verify it. The chain is a tamper-evident
  application audit chain, not a blockchain and not an immutable ledger.
- A clean merchant whose upload carries a HIGH or CRITICAL injection is held
  or blocked rather than approved (5 of the 12 such applications in the KYB
  suite); lower-severity text does not stop an approval the records support
  (the other 7). The KYB suite reports the cost as the any-input
  false-positive rate (`docs/LIMITATIONS.md`).
- The temporal-leakage suite is a deterministic check over several seeded
  generator worlds (nine record kinds, four offsets; sizes in EVALUATION §I); the
  per-feature tests cover the mechanisms, but it is not a proof over every
  record. A status with no recorded start and a merchant's registration-time
  flags are current-state by nature.
- A message the claim classifier cannot read is held for a human rather than
  denied. That is the designed fail-safe on an unsupporting ledger; the human
  reviewer is then the last control against social engineering, and the review
  packet is built to keep the ledger facts first.
- The API has no roles: any caller with the (optional) bearer token can record
  a human decision under a (non-reserved) reviewer name and declare its level.
  The structure is enforced -- only a human decision resolves, and the level
  the registry requires is checked -- but the identity is not. Production
  needs per-user identity before the human path means anything.
