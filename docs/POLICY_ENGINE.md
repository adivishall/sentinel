# Policy engine

Rendered by `make docs` from `sentinel/policy/models.py`,
`sentinel/policy/engine.py` and the shipped policies in
`sentinel/policy/policies/`. The rule tables are the policies.

## Policy-as-code

A policy is a JSON document (YAML when PyYAML is installed): an id, an
integer version, a workflow, an `effective_from` date, a `default_outcome`,
a list of rules and the `required_fields` it needs beyond the always-present
context. Each rule is an AND of conditions over declared fields and produces
an outcome. Evaluation is **deterministic and order-independent**: every rule
is evaluated, the most severe matching outcome wins
(ALLOW < STEP_UP < REQUIRE_HUMAN_REVIEW < TEMPORARY_HOLD < BLOCK), and every
match is explained. There is no `else`, no scripting and no model call.

Operators: `!=`, `<`, `<=`, `==`, `>`, `>=`, `contains`, `in`, `is_false`, `is_true`, `not_in`. `in` / `not_in` require a list; `contains` works on lists
and strings. Every value a rule reads must have its catalog type (below): a
string where a number is expected raises, it is not "false".

## Fail-closed by construction

- **Validation at load** rejects unknown fields, operators, outcomes and
  type mismatches; unknown keys in the document, a rule or a condition (a
  misspelt `unless`, an `"enabled": false` the engine would ignore); a
  missing `default_outcome` (no implicit ALLOW); and a value a field can never
  take (an unknown capability, an impossible enum value) -- a gate that could
  never fire. A misconfiguration is caught before any decision.
- **Typed context at evaluation.** A value of the wrong type (an amount of
  `"999999"`, a boolean where a number is expected) raises
  `PolicyEvaluationError` instead of making a numeric rule quietly false; the
  composer turns it into a fail-safe `REQUIRE_HUMAN_REVIEW`.
- **A rule may reference a field only if the composer always provides it or
  the policy declares it in `required_fields`.** At evaluation, a context
  missing any referenced field raises `PolicyEvaluationError`; the composer
  turns that into a fail-safe `REQUIRE_HUMAN_REVIEW`. A missing input can
  therefore never silently switch a BLOCK rule off (v2.0.0 had that fail-open
  behaviour; the review found it).
- **Content hash.** Every policy carries a SHA-256 over its full document,
  computed at construction. Decisions and input snapshots pin it; replay
  reports `policy_drift` when the served version no longer has the content the
  decision was made under. A version number is a label a file edit can reuse;
  the hash is what is trusted.
- **Pinned versions.** `sentinel/policy/policies/MANIFEST.json` pins the full SHA-256 of every
  shipped version. A version edited in place, added without pinning or deleted
  raises `PolicyIntegrityError` before anything is registered, and a store that
  recorded decisions under a version with other content refuses to open.
  `sentinel policy pin` pins *new* versions only and refuses to re-pin a
  changed one: a policy change is a new version. This guards against an
  accidental in-place edit; it is not a defence against someone who can edit
  both the policy and the manifest (that is code review and signed releases).
- **A trusted fact can never overwrite a computed field**: the composer
  writes its own fields first and only fills gaps from the workflow's facts.

## The context

Every field a rule may read comes from the trusted view: the workflow, the
amount, the *candidate* capability and its registry flags, the risk
assessment, the evidence verdict, the gateway's severity and structural
findings, and the workflow's trusted facts. There is no field for prose and no
field for the model's recommendation. `security_*` and
`capability_escalation` are the only model-adjacent inputs and they can only
tighten an outcome.

| Field | Type | Meaning | Always in context |
|---|---|---|---|
| `workflow` | str | Workflow being decided | yes |
| `subject_type` | str | transaction \| dispute \| merchant \| login \| account | declare in `required_fields` |
| `amount` | int | Amount in INR (whole rupees) | yes |
| `requested_capability` | str | Consequential capability the decision path is considering | yes |
| `capability_irreversible` | bool | Whether that capability is irreversible | yes |
| `capability_financial_effect` | bool | Whether that capability moves money / changes financial state | yes |
| `risk_score` | int | Risk score 0-100 | yes |
| `risk_level` | str | LOW \| MEDIUM \| HIGH \| CRITICAL | yes |
| `risk_factors` | list | Factor codes that fired | yes |
| `evidence_verdict` | str | SUPPORTED \| UNSUPPORTED \| CONTRADICTED \| INSUFFICIENT | yes |
| `evidence_supports_claim` | bool | Verdict is SUPPORTED | yes |
| `facts_provenance` | str | What establishes the primary record (sentinel.trust): VERIFIED_EXTERNAL \| TRUSTED_LOCAL \| UNTRUSTED \| EXPIRED \| SUPERSEDED \| REVOKED \| INVALID \| NONE | yes |
| `contradiction_count` | int | Claims contradicted by trusted records | yes |
| `claim_type` | str | Claim label derived from untrusted text (selector only) | yes |
| `security_severity` | str | NONE \| LOW \| MEDIUM \| HIGH \| CRITICAL | yes |
| `security_score` | float | Peak detection weight | yes |
| `security_flagged` | bool | Severity >= MEDIUM | yes |
| `capability_escalation` | bool | Model requested an off-surface capability | yes |
| `threat_classes` | list | Threat classes found | yes |
| `policy_auto_limit` | int | Auto-approval limit from trusted facts | declare in `required_fields` |
| `prior_disputes_90d` | int | Prior disputes in 90 days | declare in `required_fields` |
| `delivery_status` | str | Ledger delivery status | declare in `required_fields` |
| `refund_state` | str | none \| pending \| refunded -- has the money already gone back? | declare in `required_fields` |
| `transaction_status` | str | settled \| pending \| reversed | declare in `required_fields` |
| `merchant_response` | str | none \| accepted \| contested | declare in `required_fields` |
| `auth_strength` | str | none \| password \| otp \| biometric (from the switch record) | declare in `required_fields` |
| `customer_tenure_days` | int | Days since the customer joined | declare in `required_fields` |
| `account_status` | str | active \| frozen \| closed | declare in `required_fields` |
| `account_risk_score` | int | Entity risk of the account | declare in `required_fields` |
| `merchant_risk_score` | int | Entity risk of the merchant | declare in `required_fields` |
| `merchant_risk_level` | str | Merchant risk level | declare in `required_fields` |
| `registration_status` | str | verified \| unverified \| shell | declare in `required_fields` |
| `prior_flags` | int | Merchant prior fraud flags | declare in `required_fields` |
| `mcc_risk` | str | low \| medium \| high | declare in `required_fields` |
| `domain_age_days` | int | Merchant domain age | declare in `required_fields` |
| `business_age_days` | int | Merchant business age | declare in `required_fields` |
| `new_device` | bool | Login from an unknown device | declare in `required_fields` |
| `new_country` | bool | Login from an unknown country | declare in `required_fields` |
| `impossible_travel` | bool | Country changed implausibly fast | declare in `required_fields` |
| `payout_change` | bool | Payout destination changed this session | declare in `required_fields` |
| `mfa_change` | bool | MFA changed this session | declare in `required_fields` |
| `mfa_passed` | bool | Second factor completed | declare in `required_fields` |
| `monitoring_patterns` | list | Monitoring indicator codes | declare in `required_fields` |

## Lint (`sentinel policy lint`, `POST /v1/policies/lint`)

`validate` rejects what is malformed; `lint` reports what is legal but wrong
before a policy is activated: no `effective_from`; no rules; an ALLOW rule
(it can never change a most-severe-wins outcome); an unknown capability or
enum value in a condition (a rule that can never fire); duplicate or
contradictory conditions on one field; an empty numeric range; a rule with
the same conditions as an earlier one. `tests/test_policy_lint.py` covers
each finding. All shipped versions lint clean (table below).

## Versions: active, historical, what-if

An authoritative evaluation -- one that is recorded, audited, can open a case
and can execute -- always runs the **active** version of its policy
(`PolicyRegistry.active`) and the active risk model of its surface. No request
parameter selects another: the evaluate routes refuse `options.policy_version`
and `options.risk_model` with 403, the authoritative CLI commands do not have
the flags, and the engine itself refuses to record a run whose inputs name a
non-active version (`sentinel/decision/authority.py`). **Historical** versions
stay loadable only so a recorded decision can be replayed under the policy it
was made with, or compared with another; replay, the attack simulator and
scenario runs are **what-ifs** and are never recorded as decisions.

| Policy | Active (authoritative) | Historical (replay / what-if only) |
|---|---|---|
| `account-security` | v2 | v1 |
| `dispute-refund` | v4 | v1, v2, v3 |
| `investigation` | v1 | — |
| `merchant-onboarding` | v2 | v1 |
| `transaction-authorization` | v3 | v1, v2 |

## Shipped policies

| Policy | Version | Workflow | Rules | Default | Required fields | Effective from | Content hash | Lint |
|---|---:|---|---:|---|---|---|---|---|
| `account-security` | 1 | account_security | 7 | ALLOW | `risk_level`, `security_severity`, `payout_change`, `new_device` | 2026-09-01 | `4e8a7c54b806` | clean |
| `account-security` | 2 | account_security | 9 | ALLOW | `risk_level`, `security_severity`, `payout_change`, `new_device` | 2026-09-29 | `1c9723c6c1d6` | clean |
| `dispute-refund` | 1 | dispute | 8 | ALLOW | `amount`, `evidence_verdict`, `security_severity`, `risk_score`, `policy_auto_limit`, `prior_disputes_90d` | 2026-09-01 | `a856d00b4987` | clean |
| `dispute-refund` | 2 | dispute | 9 | ALLOW | `amount`, `evidence_verdict`, `security_severity`, `risk_score`, `policy_auto_limit`, `prior_disputes_90d` | 2026-09-20 | `3cd95f7fa9b6` | clean |
| `dispute-refund` | 3 | dispute | 14 | ALLOW | `amount`, `evidence_verdict`, `security_severity`, `risk_score`, `policy_auto_limit`, `prior_disputes_90d`, `refund_state`, `transaction_status`, `merchant_response`, `auth_strength` | 2026-09-25 | `1c37ac159eab` | clean |
| `dispute-refund` | 4 | dispute | 17 | ALLOW | `amount`, `evidence_verdict`, `security_severity`, `risk_score`, `policy_auto_limit`, `prior_disputes_90d`, `refund_state`, `transaction_status`, `merchant_response`, `auth_strength` | 2026-09-29 | `d93318062e3c` | clean |
| `investigation` | 1 | investigation | 4 | ALLOW | `risk_level`, `security_severity` | 2026-09-01 | `80f52ddf4bdd` | clean |
| `merchant-onboarding` | 1 | merchant_onboarding | 8 | ALLOW | `evidence_verdict`, `security_severity`, `registration_status`, `prior_flags`, `mcc_risk` | 2026-09-01 | `199f8087247b` | clean |
| `merchant-onboarding` | 2 | merchant_onboarding | 11 | ALLOW | `evidence_verdict`, `security_severity`, `registration_status`, `prior_flags`, `mcc_risk` | 2026-09-29 | `665b7d991908` | clean |
| `transaction-authorization` | 1 | transaction | 8 | ALLOW | `amount`, `risk_score`, `risk_level`, `security_severity`, `account_status`, `merchant_risk_level` | 2026-09-01 | `36ca2e834433` | clean |
| `transaction-authorization` | 2 | transaction | 8 | ALLOW | `amount`, `risk_score`, `risk_level`, `security_severity`, `account_status`, `merchant_risk_level` | 2026-09-20 | `64b50c9ae7ce` | clean |
| `transaction-authorization` | 3 | transaction | 11 | ALLOW | `amount`, `risk_score`, `risk_level`, `security_severity`, `account_status`, `merchant_risk_level` | 2026-09-29 | `d3d829774c69` | clean |

### `account-security` v1 -- Account security: protective holds are cheap and reversible; unfreezing and payout changes are human-only.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `hold-critical` | `risk_level == 'CRITICAL'` | TEMPORARY_HOLD | Login risk is CRITICAL; hold the account pending review. |
| `hold-payout-change-new-device` | `payout_change is_true` AND `new_device is_true` | TEMPORARY_HOLD | Payout changed from a new device. |
| `review-high` | `risk_level == 'HIGH'` | REQUIRE_HUMAN_REVIEW | Login risk is HIGH. |
| `stepup-medium` | `risk_level == 'MEDIUM'` | STEP_UP | Login risk is MEDIUM; step up authentication. |
| `review-sensitive-capability` | `requested_capability in ['UNFREEZE_ACCOUNT', 'CHANGE_PAYOUT']` | REQUIRE_HUMAN_REVIEW | Unfreezing or changing payout always needs a human. |

### `account-security` v2 -- Account security v2: v1 plus fact provenance -- a failed or revoked signature blocks; an unverified session goes to a human.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-failed-fact-provenance` | `facts_provenance in ['INVALID', 'REVOKED']` | BLOCK | The record's signed statement failed verification or its key was revoked: a tamper signal, never a basis for action. |
| `review-unverified-facts` | `facts_provenance in ['UNTRUSTED', 'EXPIRED', 'SUPERSEDED']` | REQUIRE_HUMAN_REVIEW | Nothing establishes these facts (request-body, expired or superseded): a human must, before anything executes. |
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `hold-critical` | `risk_level == 'CRITICAL'` | TEMPORARY_HOLD | Login risk is CRITICAL; hold the account pending review. |
| `hold-payout-change-new-device` | `payout_change is_true` AND `new_device is_true` | TEMPORARY_HOLD | Payout changed from a new device. |
| `review-high` | `risk_level == 'HIGH'` | REQUIRE_HUMAN_REVIEW | Login risk is HIGH. |
| `stepup-medium` | `risk_level == 'MEDIUM'` | STEP_UP | Login risk is MEDIUM; step up authentication. |
| `review-sensitive-capability` | `requested_capability in ['UNFREEZE_ACCOUNT', 'CHANGE_PAYOUT']` | REQUIRE_HUMAN_REVIEW | Unfreezing or changing payout always needs a human. |

### `dispute-refund` v1 -- Refund control: evidence decides support; policy decides who may execute.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-unsupported-claim` | `evidence_verdict in ['UNSUPPORTED', 'CONTRADICTED']` | BLOCK | Verified ledger evidence does not support the claim. |
| `review-insufficient-evidence` | `evidence_verdict == 'INSUFFICIENT'` | REQUIRE_HUMAN_REVIEW | The claim cannot yet be verified against the ledger. |
| `review-over-auto-limit` | `amount > 50000` | REQUIRE_HUMAN_REVIEW | Refund exceeds the ₹50,000 auto-approval limit. |
| `review-critical-risk` | `risk_score >= 75` | REQUIRE_HUMAN_REVIEW | Dispute risk is CRITICAL. |
| `review-high-ai-security` | `security_severity == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High-severity AI-security finding; a human confirms before money moves. |
| `review-repeat-disputer` | `prior_disputes_90d >= 3` | REQUIRE_HUMAN_REVIEW | Three or more disputes in 90 days. |

### `dispute-refund` v2 -- Refund control v2: risk threshold lowered 75 -> 70; medium AI-security findings now hold for review.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-unsupported-claim` | `evidence_verdict in ['UNSUPPORTED', 'CONTRADICTED']` | BLOCK | Verified ledger evidence does not support the claim. |
| `review-insufficient-evidence` | `evidence_verdict == 'INSUFFICIENT'` | REQUIRE_HUMAN_REVIEW | The claim cannot yet be verified against the ledger. |
| `review-over-auto-limit` | `amount > 50000` | REQUIRE_HUMAN_REVIEW | Refund exceeds the ₹50,000 auto-approval limit. |
| `review-critical-risk` | `risk_score >= 70` | REQUIRE_HUMAN_REVIEW | Dispute risk >= 70. |
| `review-high-ai-security` | `security_severity == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High-severity AI-security finding; a human confirms before money moves. |
| `review-repeat-disputer` | `prior_disputes_90d >= 3` | REQUIRE_HUMAN_REVIEW | Three or more disputes in 90 days. |
| `review-medium-ai-security` | `security_severity == 'MEDIUM'` | REQUIRE_HUMAN_REVIEW | Medium-severity AI-security finding; hold for a human. |

### `dispute-refund` v3 -- Refund control v3: richer trusted facts -- an already-refunded or reversed transaction can never be refunded again; a merchant-contested or strongly-authenticated 'unauthorised' claim needs a human.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-already-refunded` | `refund_state == 'refunded'` | BLOCK | The ledger shows this transaction was already refunded; a second refund is a double payment. |
| `block-reversed-transaction` | `transaction_status == 'reversed'` | BLOCK | The transaction was reversed; there is nothing to refund. |
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-unsupported-claim` | `evidence_verdict in ['UNSUPPORTED', 'CONTRADICTED']` | BLOCK | Verified ledger evidence does not support the claim. |
| `review-insufficient-evidence` | `evidence_verdict == 'INSUFFICIENT'` | REQUIRE_HUMAN_REVIEW | The claim cannot yet be verified against the ledger. |
| `review-over-auto-limit` | `amount > 50000` | REQUIRE_HUMAN_REVIEW | Refund exceeds the ₹50,000 auto-approval limit. |
| `review-critical-risk` | `risk_score >= 70` | REQUIRE_HUMAN_REVIEW | Dispute risk >= 70. |
| `review-high-ai-security` | `security_severity == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High-severity AI-security finding; a human confirms before money moves. |
| `review-repeat-disputer` | `prior_disputes_90d >= 3` | REQUIRE_HUMAN_REVIEW | Three or more disputes in 90 days. |
| `review-medium-ai-security` | `security_severity == 'MEDIUM'` | REQUIRE_HUMAN_REVIEW | Medium-severity AI-security finding; hold for a human. |
| `hold-refund-pending` | `refund_state == 'pending'` | TEMPORARY_HOLD | A refund is already in flight; hold until it settles. |
| `review-merchant-contested` | `merchant_response == 'contested'` | REQUIRE_HUMAN_REVIEW | The merchant contests the claim; a human weighs both sides. |
| `review-unauthorised-strong-auth` | `claim_type == 'unauthorized'` AND `auth_strength in ['otp', 'biometric']` | REQUIRE_HUMAN_REVIEW | An 'unauthorised' claim on a transaction that passed a strong second factor needs a human. |

### `dispute-refund` v4 -- Refund control v4: v3 plus fact provenance -- a failed or revoked signature blocks; unverified facts go to a human; a refund above 25,000 needs the ledger's signed statement.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-failed-fact-provenance` | `facts_provenance in ['INVALID', 'REVOKED']` | BLOCK | The record's signed statement failed verification or its key was revoked: a tamper signal, never a basis for action. |
| `review-unverified-facts` | `facts_provenance in ['UNTRUSTED', 'EXPIRED', 'SUPERSEDED']` | REQUIRE_HUMAN_REVIEW | Nothing establishes these facts (request-body, expired or superseded): a human must, before anything executes. |
| `review-high-value-unsigned-facts` | `amount > 25000` AND `facts_provenance == 'TRUSTED_LOCAL'` | REQUIRE_HUMAN_REVIEW | A refund above 25,000 needs the issuer's signed statement (VERIFIED_EXTERNAL); an unsigned stored record goes to a human. |
| `block-already-refunded` | `refund_state == 'refunded'` | BLOCK | The ledger shows this transaction was already refunded; a second refund is a double payment. |
| `block-reversed-transaction` | `transaction_status == 'reversed'` | BLOCK | The transaction was reversed; there is nothing to refund. |
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-unsupported-claim` | `evidence_verdict in ['UNSUPPORTED', 'CONTRADICTED']` | BLOCK | Verified ledger evidence does not support the claim. |
| `review-insufficient-evidence` | `evidence_verdict == 'INSUFFICIENT'` | REQUIRE_HUMAN_REVIEW | The claim cannot yet be verified against the ledger. |
| `review-over-auto-limit` | `amount > 50000` | REQUIRE_HUMAN_REVIEW | Refund exceeds the ₹50,000 auto-approval limit. |
| `review-critical-risk` | `risk_score >= 70` | REQUIRE_HUMAN_REVIEW | Dispute risk >= 70. |
| `review-high-ai-security` | `security_severity == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High-severity AI-security finding; a human confirms before money moves. |
| `review-repeat-disputer` | `prior_disputes_90d >= 3` | REQUIRE_HUMAN_REVIEW | Three or more disputes in 90 days. |
| `review-medium-ai-security` | `security_severity == 'MEDIUM'` | REQUIRE_HUMAN_REVIEW | Medium-severity AI-security finding; hold for a human. |
| `hold-refund-pending` | `refund_state == 'pending'` | TEMPORARY_HOLD | A refund is already in flight; hold until it settles. |
| `review-merchant-contested` | `merchant_response == 'contested'` | REQUIRE_HUMAN_REVIEW | The merchant contests the claim; a human weighs both sides. |
| `review-unauthorised-strong-auth` | `claim_type == 'unauthorized'` AND `auth_strength in ['otp', 'biometric']` | REQUIRE_HUMAN_REVIEW | An 'unauthorised' claim on a transaction that passed a strong second factor needs a human. |

### `investigation` v1 -- Transaction monitoring: structured indicators open cases; a model may summarise, never close (an off-surface CLOSE_CASE request is a capability escalation, blocked by the gateway rule).

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `review-critical-patterns` | `risk_level == 'CRITICAL'` | REQUIRE_HUMAN_REVIEW | Critical monitoring indicators; escalate to an investigator. |
| `review-high-patterns` | `risk_level == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High monitoring indicators; open a case. |

### `merchant-onboarding` v1 -- KYB onboarding: acquirer records decide; documents never do.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-shell` | `registration_status == 'shell'` | BLOCK | Shell registration. |
| `block-repeat-flags` | `prior_flags >= 2` | BLOCK | Two or more prior fraud flags. |
| `block-contradicted` | `evidence_verdict == 'CONTRADICTED'` | BLOCK | Acquirer records contradict the application. |
| `review-incomplete` | `evidence_verdict in ['INSUFFICIENT', 'UNSUPPORTED']` | REQUIRE_HUMAN_REVIEW | Verification incomplete. |
| `review-high-mcc` | `mcc_risk == 'high'` | REQUIRE_HUMAN_REVIEW | High-risk merchant category. |
| `review-high-ai-security` | `security_severity == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High-severity AI-security finding in the application. |

### `merchant-onboarding` v2 -- Merchant onboarding v2: v1 plus fact provenance -- a failed or revoked signature blocks; anything short of the acquirer's signed record goes to a human.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-failed-fact-provenance` | `facts_provenance in ['INVALID', 'REVOKED']` | BLOCK | The record's signed statement failed verification or its key was revoked: a tamper signal, never a basis for action. |
| `review-unverified-facts` | `facts_provenance in ['UNTRUSTED', 'EXPIRED', 'SUPERSEDED']` | REQUIRE_HUMAN_REVIEW | Nothing establishes these facts (request-body, expired or superseded): a human must, before anything executes. |
| `review-unsigned-acquirer-record` | `facts_provenance == 'TRUSTED_LOCAL'` | REQUIRE_HUMAN_REVIEW | Onboarding is irreversible and its facts are the acquirer's: approving needs the acquirer's signed record, not a stored copy. |
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-shell` | `registration_status == 'shell'` | BLOCK | Shell registration. |
| `block-repeat-flags` | `prior_flags >= 2` | BLOCK | Two or more prior fraud flags. |
| `block-contradicted` | `evidence_verdict == 'CONTRADICTED'` | BLOCK | Acquirer records contradict the application. |
| `review-incomplete` | `evidence_verdict in ['INSUFFICIENT', 'UNSUPPORTED']` | REQUIRE_HUMAN_REVIEW | Verification incomplete. |
| `review-high-mcc` | `mcc_risk == 'high'` | REQUIRE_HUMAN_REVIEW | High-risk merchant category. |
| `review-high-ai-security` | `security_severity == 'HIGH'` | REQUIRE_HUMAN_REVIEW | High-severity AI-security finding in the application. |

### `transaction-authorization` v1 -- Payment authorisation: deterministic risk bands and an auto-approval limit.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-frozen-account` | `account_status == 'frozen'` | BLOCK | Account is frozen. |
| `block-critical-risk` | `risk_level == 'CRITICAL'` | BLOCK | Transaction risk is CRITICAL. |
| `review-high-risk` | `risk_level == 'HIGH'` | REQUIRE_HUMAN_REVIEW | Transaction risk is HIGH. |
| `stepup-medium-risk` | `risk_level == 'MEDIUM'` | STEP_UP | Transaction risk is MEDIUM; step up authentication. |
| `review-over-auto-limit` | `amount > 150000` | REQUIRE_HUMAN_REVIEW | Amount exceeds the ₹1,50,000 auto-approval limit. |
| `review-critical-merchant` | `merchant_risk_level == 'CRITICAL'` | REQUIRE_HUMAN_REVIEW | Merchant risk is CRITICAL. |

### `transaction-authorization` v2 -- Payment authorisation v2: HIGH band widened (score >= 70 now blocks; >= 40 reviews).

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-frozen-account` | `account_status == 'frozen'` | BLOCK | Account is frozen. |
| `review-over-auto-limit` | `amount > 150000` | REQUIRE_HUMAN_REVIEW | Amount exceeds the ₹1,50,000 auto-approval limit. |
| `review-critical-merchant` | `merchant_risk_level == 'CRITICAL'` | REQUIRE_HUMAN_REVIEW | Merchant risk is CRITICAL. |
| `block-risk-70` | `risk_score >= 70` | BLOCK | Transaction risk >= 70. |
| `review-risk-40` | `risk_score >= 40` AND `risk_score < 70` | REQUIRE_HUMAN_REVIEW | Transaction risk 40-69. |
| `stepup-risk-25` | `risk_score >= 25` AND `risk_score < 40` | STEP_UP | Transaction risk 25-39. |

### `transaction-authorization` v3 -- Transaction authorization v3: v2 plus fact provenance -- a failed or revoked signature blocks; unverified facts go to a human; a payment above 100,000 needs the switch's signed statement.

| Rule | When (all conditions) | Outcome | Reason |
|---|---|---|---|
| `block-failed-fact-provenance` | `facts_provenance in ['INVALID', 'REVOKED']` | BLOCK | The record's signed statement failed verification or its key was revoked: a tamper signal, never a basis for action. |
| `review-unverified-facts` | `facts_provenance in ['UNTRUSTED', 'EXPIRED', 'SUPERSEDED']` | REQUIRE_HUMAN_REVIEW | Nothing establishes these facts (request-body, expired or superseded): a human must, before anything executes. |
| `review-high-value-unsigned-facts` | `amount > 100000` AND `facts_provenance == 'TRUSTED_LOCAL'` | REQUIRE_HUMAN_REVIEW | A payment above 100,000 needs the issuer's signed statement (VERIFIED_EXTERNAL); an unsigned stored record goes to a human. |
| `block-critical-ai-security` | `security_severity == 'CRITICAL'` | BLOCK | Critical AI-security finding on the untrusted input. |
| `block-capability-escalation` | `capability_escalation is_true` | BLOCK | The model requested a capability outside its surface. |
| `block-frozen-account` | `account_status == 'frozen'` | BLOCK | Account is frozen. |
| `review-over-auto-limit` | `amount > 150000` | REQUIRE_HUMAN_REVIEW | Amount exceeds the ₹1,50,000 auto-approval limit. |
| `review-critical-merchant` | `merchant_risk_level == 'CRITICAL'` | REQUIRE_HUMAN_REVIEW | Merchant risk is CRITICAL. |
| `block-risk-70` | `risk_score >= 70` | BLOCK | Transaction risk >= 70. |
| `review-risk-40` | `risk_score >= 40` AND `risk_score < 70` | REQUIRE_HUMAN_REVIEW | Transaction risk 40-69. |
| `stepup-risk-25` | `risk_score >= 25` AND `risk_score < 40` | STEP_UP | Transaction risk 25-39. |
