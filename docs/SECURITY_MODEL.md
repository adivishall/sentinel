# Security model

Rendered by `make docs` from `sentinel/domain/enums.py`,
`sentinel/security/capabilities.py`, `sentinel/security/threats.py`,
`sentinel/security/injection.py` and `sentinel/cases/rules.py`. Nothing in
this file is typed by hand except the prose; the tables are the code.

## The principle

```text
AI may recommend. Trusted evidence, deterministic risk controls and explicit policy authorize.

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
| `TRUSTED_INTERNAL` | our own ledger, records and policies | **yes** |
| `VERIFIED_EXTERNAL` | acquirer / network records the institution verified | **yes** |
| `USER_CONTROLLED` | a cardholder narrative, chat turn or form field | never |
| `MERCHANT_CONTROLLED` | merchant application copy, descriptors, site text | never |
| `DOCUMENT_CONTROLLED` | an uploaded invoice, receipt or PDF (treated as text) | never |
| `MODEL_GENERATED` | anything an LLM produced, including 'our' agent's recommendation | never |
| `UNKNOWN` | unlabelled third-party content | never |

`TrustClass.is_trusted` is the only predicate the platform uses. `Evidence`
refuses to be VERIFIED from an untrusted class; `UntrustedText`, `Claim` and
`AIRecommendation` refuse a trusted class. Trust does not launder through a
model call: the agent read the attacker's text, so its output is
`MODEL_GENERATED`.

## Capability security matrix

17 capabilities. 10 are **consequential** (irreversible, or moving money, or
reserved to a human reviewer): executing one of those without support is what
"attack success" means. The AI agent actor may execute only
`READ_TRANSACTION`, `READ_ACCOUNT`, `READ_MERCHANT`, `CREATE_CASE`, `CREATE_ALERT`, `RECOMMEND_REFUND`, `RECOMMEND_ACTION` -- reads, case and alert creation, and
recommendations. `SKIP_REVIEW` has no allowed
actor at all. These are Sentinel's own values, documented as such; they are
not industry standards.

| Capability | Risk | Irreversible | Money | Consequential | AI agent may execute | Allowed actors | Required authorization | Human-review threshold (₹) | Policy gates |
|---|---|---|---|---|---|---|---|---|---|
| `READ_TRANSACTION` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `READ_ACCOUNT` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `READ_MERCHANT` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `CREATE_CASE` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `CREATE_ALERT` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `RECOMMEND_REFUND` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `RECOMMEND_ACTION` | LOW | no | no | no | yes | AI_AGENT, HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | NONE | — | — |
| `APPROVE_REFUND` | HIGH | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | 50,000 | — |
| `APPROVE_TRANSACTION` | HIGH | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | 150,000 | — |
| `APPROVE_MERCHANT` | HIGH | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | — | — |
| `FREEZE_ACCOUNT` | MEDIUM | no | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER, SYSTEM | SYSTEM_POLICY | — | — |
| `UNFREEZE_ACCOUNT` | HIGH | no | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER | HUMAN_REVIEWER | — | `account-security@v1:review-sensitive-capability` |
| `CHANGE_PAYOUT` | CRITICAL | yes | yes | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER | HUMAN_REVIEWER | 0 | `account-security@v1:review-sensitive-capability` |
| `RELEASE_FUNDS` | CRITICAL | yes | yes | yes | **no** | SENIOR_REVIEWER | SENIOR_REVIEWER | 0 | — |
| `CLOSE_CASE` | MEDIUM | no | no | yes | **no** | HUMAN_REVIEWER, SENIOR_REVIEWER | HUMAN_REVIEWER | — | — |
| `ALTER_RISK` | HIGH | no | no | yes | **no** | SENIOR_REVIEWER | SENIOR_REVIEWER | — | — |
| `SKIP_REVIEW` | CRITICAL | yes | yes | yes | **no** | nobody | SENIOR_REVIEWER | — | — |

"Policy gates" lists the shipped policy rules whose conditions name the
capability (`docs/POLICY_ENGINE.md`); the registry applies regardless of
policy.

### Authorization (`capabilities.authorize`)

Called with the capability the **workflow** is considering, never the one the
model asked for. In order:

1. no consequential capability requested → GRANTED;
2. the actor is not in the capability's allowed actors → DENIED;
3. policy outcome BLOCK → DENIED;
4. a consequential capability whose verified evidence does not support the
   request → DENIED;
5. policy outcome REQUIRE_HUMAN_REVIEW or TEMPORARY_HOLD → PENDING_HUMAN;
6. the automated path (SYSTEM) on a capability that requires a human or
   senior reviewer → PENDING_HUMAN;
7. SYSTEM above the capability's human-review amount threshold → PENDING_HUMAN;
8. otherwise GRANTED.

### Final action (`composer._final_action`)

Policy BLOCK → BLOCK when a security finding (severity ≥ HIGH or an
off-surface request) caused it, else DENY; evidence INSUFFICIENT →
REQUIRE_HUMAN_REVIEW (fail-safe); evidence not SUPPORTED → DENY; policy
TEMPORARY_HOLD → TEMPORARY_HOLD; policy REQUIRE_HUMAN_REVIEW or authorization
PENDING_HUMAN → REQUIRE_HUMAN_REVIEW; policy STEP_UP with authorization
GRANTED → STEP_UP; authorization GRANTED → ALLOW (the candidate capability
executes); anything else → DENY. Only ALLOW executes a capability.

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
| the console holds no decision logic and calls only real routes | `tests/test_ui_api_contract.py` |
| the evaluate routes refuse `unguarded` / `options.controls` | `tests/test_api_v1.py` |
| headline results recompute from `results/` | `tests/test_results_regression.py` |
