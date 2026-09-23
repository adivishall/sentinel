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

## Threat taxonomy (twelve classes)

| Class | Mechanism | Primary control |
|---|---|---|
| direct_injection | explicit override instructions | gateway detection; evidence + policy backstop |
| authority_spoof | impersonated system / compliance directives | gateway; evidence + policy |
| document_borne | instructions inside uploads | provenance (DOCUMENT_CONTROLLED); gateway; evidence |
| fake_policy | fabricated rules / regulations | gateway; the real policy is code |
| context_poisoning | "you already approved" / "as in the case file" | gateway; the composer holds no conversational state |
| tool_manipulation | spelled-out tool calls | gateway; capability registry |
| multi_turn_escalation | payload split or leveraged across turns | session model inspects the whole transcript |
| unicode_obfuscation | homoglyphs, zero-width, full-width | normalisation before detection |
| indirect_injection | via third-party content | provenance-aware reclassification |
| adjudication_gaming | no injection; a false factual claim | **trusted-evidence reconciliation** (the honest hard case) |
| financial_social_engineering | urgency, loyalty, threats | evidence + policy; pressure changes no fact |
| capability_escalation | agent induced to request an off-surface capability | model-output inspection; registry; authorization |

Only the first eight are (partly) detectable by inspecting text. The
security case does **not** depend on detection: the ablation shows detection
alone leaks the false-claim classes, and trusted-evidence adjudication closes
them.

## Controls, mapped to failure modes

| Failure mode | Control | Where tested |
|---|---|---|
| prose reaches the decision | typed boundary; `_TrustedView` has no model/prose field | `test_trust_boundary.py`, `test_invariants.py` (1, 3) |
| model executes a capability | registry: AI_AGENT allowed on no consequential capability; composer never executes the model's request | invariants 2, 6; `test_capabilities.py` |
| model requests off-surface capability | gateway `inspect_model_output` → CRITICAL escalation → BLOCK + P1 case | `test_security_gateway.py`, `test_cases.py` |
| unknown / unverifiable claim | INSUFFICIENT → REQUIRE_HUMAN_REVIEW | invariant 4 |
| malformed input | validation → fail-safe human review; numbers coerce to 0 | invariant 5 |
| high-value effect | policy thresholds + registry human-review thresholds | invariant 6 |
| audit tampering | hash chain; verify names the first bad record | invariant 7 |
| silent policy drift | explicit versions, effective dates, replay | invariant 8 |
| provenance loss | trust preserved through evidence, snapshot, audit | invariant 9 |
| parallel business logic | one application layer; static check on API/CLI/UI sources | invariant 10 |
| policy misconfiguration | schema validation at load; unknown fields rejected | `test_policy_engine.py` |
| information leakage | audit stores hashes; spans hashed; no stack traces; secrets from env only | `test_audit_chain.py`, `test_api_v1.py` |
| abuse of the API | body cap, per-client rate limit, optional bearer auth, request ids | `test_api_v1.py` |

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
  and `sentinel eval run --suite models` exist to probe a real model.
