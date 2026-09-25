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
| Third-party content | emails, pages, order-status text the agent reads | anything trusted |
| Compromised / over-permissive AI agent | its own output: recommendations and tool calls | authorization |
| Malicious model output | the same channel as above | evidence status |
| Insider / operator error | policy misconfiguration | the field catalog / validation |
| Storage attacker | records at rest | undetected edits to the audit chain |

## Trust boundary

Every piece of information that enters the decision system carries a
`TrustClass`. Only `TRUSTED_INTERNAL` and `VERIFIED_EXTERNAL` can produce
`VERIFIED` evidence; the type system refuses the rest
(`Evidence.__post_init__`). Model output is `MODEL_GENERATED` -- untrusted --
even though it came from "our" AI.

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
| malformed input | validation → fail-safe human review; numbers coerce to 0 | invariant 5 |
| high-value effect | policy thresholds + registry human-review thresholds | invariant 6 |
| audit tampering | tamper-evident chain; verify names the first modified, deleted, inserted or reordered record; a signed checkpoint detects a consistent rewrite | invariant 7, `test_audit_chain.py`, `test_audit_indexing.py` |
| text mimicking the model's own output | the parser reads only the provider's structured tool call; output-format mimicry is a gateway finding | `test_model_output_separation.py` |
| fabricated records in prose | an untrusted channel cannot produce VERIFIED evidence (type system) | `test_evidence.py`, `test_trust_boundary.py` |
| future data influencing a past decision | point-in-time baselines, as-of entity profiles, time-aware graph, bounded monitoring windows; the temporal suite | `test_temporal_leakage.py`, `test_entity_pointintime.py`, `test_graph_temporal.py` |
| a second decision engine in the console | the console holds no decision logic and calls only real routes | `test_ui_api_contract.py` |
| silent policy drift | explicit versions, effective dates, replay | invariant 8 |
| provenance loss | trust preserved through evidence, snapshot, audit | invariant 9 |
| parallel business logic | one application layer; static check on API/CLI/UI sources | invariant 10 |
| policy misconfiguration | schema validation at load; unknown fields rejected; linter for rules that can never fire | `test_policy_engine.py`, `test_policy_lint.py` |
| information leakage | audit stores hashes; spans hashed; no stack traces; secrets from env only | `test_audit_chain.py`, `test_api_v1.py` |
| abuse of the API | body cap, per-client rate limit, optional bearer auth (constant-time compare), request ids, static path containment, 403 on control switches | `test_api_v1.py`, `test_api_path_containment.py` |

## Explicitly out of scope

- **Ledger integrity.** Sentinel decides over records it is given; poisoning
  the ledger is a different threat with different controls.
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
  degrades to a fail-safe human review, which is a false positive. The
  held-out set exists to find these; it found one in v2 ("called off the
  booking") and the *general* pattern was fixed, not the string.
- The offline agent is a faithful simulation of the documented failure mode,
  not proof that a specific production LLM fails identically. `make live-check`
  and `sentinel eval run --suite models` exist to probe a real model. Its
  attack-success rate is a property of the simulator, which shares an author
  with the corpus.
- The API's trusted inputs (`ledger`, `records`, `transaction`, `session`)
  are trusted by contract, not by proof: the caller is assumed to be the
  system of record. Auth is optional; the server warns when it starts open on
  a non-loopback bind. Ablation controls are refused on the evaluate routes
  unless `SENTINEL_ALLOW_UNGUARDED=1`.
- Policy versions are labels. Every decision pins the policy content hash and
  replay reports `policy_drift`, but nothing prevents editing a shipped
  version in place; production would make policy files immutable artifacts.
- The audit chain detects modification, deletion, insertion and reordering.
  A consistent rewrite of the whole chain from genesis is detected only
  against a checkpoint (`sentinel audit checkpoint`, HMAC-signed with
  `SENTINEL_AUDIT_KEY`) that the operator must store outside the audit store;
  the chain is a tamper-evident application audit chain, not a blockchain and
  not an immutable ledger.
- A clean merchant whose upload carries an injection is held for a human
  rather than approved: a CRITICAL security finding blocks automatic approval
  by design. The KYB suite reports this as the any-input false-positive rate
  (`docs/LIMITATIONS.md`).
- The temporal-leakage suite samples a subset of transactions and three
  future offsets; the per-feature tests cover the mechanisms, but the suite
  is a spot check over the generator, not a proof over every record.
