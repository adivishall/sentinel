# Architecture

Sentinel is a **modular monolith**: one Python package, one process, one SQLite
file, one decision engine. Every surface (CLI, HTTP API, console, evaluation)
calls the same application layer. There is no second implementation of any
decision anywhere in the repository (tested by `tests/test_invariants.py::test_invariant_10_*`).

## The principle

```text
AI may recommend. Trusted evidence, deterministic policy and authorization decide.

AUTHORITATIVE_DECISION = f(TRUSTED_FACTS, VERIFIED_EVIDENCE, RISK_STATE, POLICY, AUTHORIZATION)
AUTHORITATIVE_DECISION ≠ f(ATTACKER_CONTROLLED_TEXT)
AUTHORITATIVE_DECISION ≠ f(MODEL_OUTPUT)
```

## The pipeline

```text
                         SENTINEL

              ┌──────────────────────────┐
              │   Financial Event Layer  │  transactions · disputes · merchant
              │                          │  applications · login sessions ·
              │                          │  AI-agent inputs and outputs
              └─────────────┬────────────┘
                            ▼
              ┌──────────────────────────┐
              │  Provenance + Ingestion  │  every span typed by TrustClass;
              │  sentinel/security       │  validation; unicode normalisation
              └─────────────┬────────────┘
             ┌──────────────┴──────────────┐
             ▼                             ▼
   ┌──────────────────┐         ┌────────────────────┐
   │ Financial Risk   │         │ AI Security Gateway │
   │ sentinel/risk    │         │ sentinel/security   │
   │ transaction      │         │ injection · document│
   │ behavioural      │         │ context poisoning   │
   │ entity · graph   │         │ tool manipulation   │
   │ monitoring       │         │ model-output checks │
   └─────────┬────────┘         └─────────┬──────────┘
             └─────────────┬──────────────┘
                           ▼
                ┌───────────────────────┐
                │ Evidence + Adjudication│  claims vs trusted records;
                │ sentinel/evidence      │  contradiction engine; the model's
                │                        │  recommendation recorded as a claim
                └──────────┬────────────┘
                           ▼
                ┌───────────────────────┐
                │ Policy / Capability   │  versioned policy-as-code
                │ sentinel/policy       │  (JSON, schema-validated) and the
                │ sentinel/security/    │  capability registry (who may make
                │   capabilities.py     │  what happen, under what authorization)
                └──────────┬────────────┘
                           ▼
                ┌───────────────────────┐
                │  Decision Composer    │  the ONE place an outcome is computed
                │  sentinel/decision    │  from a _TrustedView that has no
                └──────────┬────────────┘  model-recommendation field
               ┌───────────┴───────────┐
               ▼                       ▼
        ┌─────────────┐        ┌────────────────┐
        │ Auto Action │        │ Human Review   │  cases; human-only resolution
        └──────┬──────┘        └───────┬────────┘
               └────────────┬──────────┘
                            ▼
                    ┌───────────────┐
                    │ Audit / Case  │  tamper-evident audit chain + signed
                    │ / Replay      │  checkpoints; replay and backtest from input snapshots
                    └───────────────┘
```

## Primitives

Everything composes nine typed, immutable primitives (`sentinel/domain` and the modules named):

| Primitive | Module | Notes |
|---|---|---|
| Entity | `domain/entities.py` | Customer, Account, Merchant, Device, PaymentInstrument, Transaction, Dispute, KYBApplication, LoginSession |
| Evidence | `domain/evidence.py` | `Evidence` with `TrustClass` + `EvidenceStatus`; **untrusted sources can never be VERIFIED** (enforced in `__post_init__`) |
| RiskAssessment | `domain/risk.py` | score, level, named factors with points and evidence ids, feature snapshot for replay |
| SecurityEvent | `domain/security.py` | severity, threat classes, hashed findings, the capability the model asked for |
| Capability | `domain/enums.py` + `security/capabilities.py` | READ_* … APPROVE_REFUND, CHANGE_PAYOUT, RELEASE_FUNDS, CLOSE_CASE, ALTER_RISK, SKIP_REVIEW |
| Policy | `policy/models.py` | versioned rules over a declared field catalog |
| Decision | `domain/decisions.py` | the canonical record; carries the AI recommendation but is not computed from it |
| Case | `domain/cases.py` | investigation with a guarded lifecycle and human-only resolution |
| AuditEvent | `audit/chain.py` | tamper-evident chain (each event hashes its body plus the previous hash); stores hashes of untrusted content, never prose; Ed25519 checkpoints in an append-only anchor (`audit/anchor.py`) |

## Trust classes

```text
TRUSTED_INTERNAL      a record read from our store; policies   may authorize
VERIFIED_EXTERNAL     a record whose issuer's signature        may authorize
                      verified against the trust store
UNVERIFIED_RECORD     body facts; failed / stale signatures    never
USER_CONTROLLED       cardholder text, chat turns, forms       never
MERCHANT_CONTROLLED   applications, descriptors, site copy     never
DOCUMENT_CONTROLLED   uploaded invoices, receipts, PDFs        never
MODEL_GENERATED       anything an LLM produced                 never
UNKNOWN               unlabelled third-party content           never
```

`TrustClass.is_trusted` is the only predicate the platform uses, and it is true
for exactly the first two. `UntrustedContent`, `UntrustedText`, `Claim` and
`AIRecommendation` all refuse to be constructed with a trusted class.

A record's class comes from its fact provenance (`sentinel/trust/`,
`docs/SECURITY_MODEL.md`). Each workflow computes it in `_resolve_facts`,
before any `TrustedFacts` exists:

- an issuer's signed envelope is verified against the runtime's trust store
  and anti-rollback sequences;
- a store read is `TRUSTED_LOCAL`;
- a request body is `UNTRUSTED`.

The decision, its snapshot and its audit event carry the result and the
payload digest.

## The trust boundary as types (`security/trust_boundary.py`)

- `UntrustedText` is opaque: it yields a `ClaimType` (a selector for *which*
  trusted field to check), read by a deterministic classifier
  (`security/claims.py`: weighted pattern families, a negation guard, a hedge
  detector, a conflict rule) that reports a confidence and the signals that
  fired and **abstains** when it cannot read a claim. It has no accessor that
  returns evidence. An abstain reconciles to INSUFFICIENT and is held for a
  human; a recognised non-claim stays UNSUPPORTED.
- `TrustedFacts` (`DisputeFacts`, `KYBFacts`) is built only from records and
  renders itself as VERIFIED `Evidence`. `supports(ClaimType)` is a pure function
  of the facts.
- The reconciliation engine (`evidence/reconcile.py`) compares claims to facts
  and produces a typed verdict: SUPPORTED, UNSUPPORTED, CONTRADICTED or
  INSUFFICIENT (fail-safe to a human). The contradiction engine
  (`evidence/contradiction.py`) is a compatibility table per field.

## The composer (`decision/composer.py`)

`compose(DecisionInputs) -> Decision` builds a `_TrustedView` -- a dataclass
that has **no field for the model recommendation** -- and computes policy
outcome, authorization and final action from it. The model's wish is recorded
on the `Decision` (`ai_recommendation`, `ai_agreed`, `blocked_by`) for
explainability and measurement only. The only model-derived signal that
reaches policy is the gateway's structural check on the model's *output*
(did it request a capability outside its surface), and that can only tighten
an outcome.

Final-action mapping (in order): policy BLOCK → BLOCK (if a security finding
caused it) or DENY; evidence INSUFFICIENT → REQUIRE_HUMAN_REVIEW; evidence not
supported → DENY; TEMPORARY_HOLD; REQUIRE_HUMAN_REVIEW (policy or pending
authorization); STEP_UP; authorization GRANTED → ALLOW (the candidate
capability executes); otherwise DENY. The invariant with its ceiling: on a
supporting ledger nothing exceeds the plain claim's outcome; on an
unsupporting ledger nothing executes and nothing rises above a human review.
Authoritative evaluation always runs every control, the active policy version
and the active risk model of its surface; `sentinel/decision/authority.py`
checks the inputs a decision was composed from before anything is recorded,
and what-if runs (the simulator, scenario runs, replay) go to a runtime that
never persists. Older versions and other models exist only for those what-ifs.

`controls` exists for the ablation study only. Switching a control off
reproduces the behaviour of a system that lacks it; the protected path is
always `FULL`.

## Capability security (`security/capabilities.py`)

Each capability declares risk, reversibility, monetary impact, required
authorization level, allowed actors and a human-review amount threshold
(Sentinel demo values, not industry standards). A capability is
**consequential** when it is irreversible, moves money, or is reserved to a
human reviewer -- closing a case or overriding a risk score has no direct
monetary effect, but an agent doing it is exactly the failure the registry
exists to prevent, so it counts as a breach when it executes.
`ActorKind.AI_AGENT` is not in the allowed-actor set of any consequential
capability; `SKIP_REVIEW` has no allowed actor at all. `authorize()` is
deterministic and is called with the capability the *workflow* is
considering, never the one the model asked for. The full matrix is rendered
in `docs/SECURITY_MODEL.md` and served by `GET /v1/capabilities`.

## Policy-as-code (`policy/`)

Policies are JSON documents (YAML accepted when PyYAML is present) validated
against a field catalog (`policy/models.py::FIELD_CATALOG`) -- unknown fields,
operators, outcomes and type mismatches are rejected at load time. Evaluation
is deterministic and order-independent: all rules are evaluated, the most
severe outcome wins, every match is explained, and a missing required field
raises (the composer turns that into a fail-safe human review). A linter
(`sentinel policy lint`) reports rules that can never fire, contradictory or
duplicate conditions and missing effective dates. Every rule of every shipped
version is listed in `docs/POLICY_ENGINE.md`.

<!-- gen:shipped-policies -->
Shipped policies: `account-security` v1/v2, `dispute-refund` v1/v2/v3/v4, `investigation` v1, `merchant-onboarding` v1/v2, `transaction-authorization` v1/v2/v3 (12 versions, all lint-clean; every rule is listed in `docs/POLICY_ENGINE.md`).
<!-- /gen:shipped-policies -->

## Risk (`risk/`)

Deterministic, versioned point tables (`risk/scoring.py`) over feature
snapshots; every factor, condition and point value is rendered in
`docs/RISK_ENGINE.md`. Transaction risk (`txn-2.0`) reads point-in-time
behavioural baselines, device and geography history, short-window velocity
and inter-arrival timing, the trusted account-security events of the previous
24 hours, payout-instrument sharing, merchant and linked-entity profiles;
account-security risk reads the session record; the monitoring engine
recognises structuring-like transfers, rapid movement, velocity, geography
shifts, high-risk exposure, circular transfers bounded to a window, dormant
activation and graph-linked rings. Entity profiles are computed in a fixed
order (device → merchant → account → customer) so nothing is circular, and
**as of a time**: profiles are cached per `(entity, as_of)` and read only
records at or before it. The `EntityGraph` is time-aware -- every edge carries
a timestamp and every query takes `as_of` -- so a relationship does not exist
at every point in time merely because it exists somewhere in the dataset.
Feature snapshots are stored with each decision so replay can re-score under
another model version without touching source systems. The invariant *data
available after T never influences a decision made at T* is measured by the
temporal suite (`results/temporal.json`).

## Workflows (`decision/workflows.py`)

`run_dispute`, `run_transaction`, `run_kyb`, `run_account_security`,
`run_investigation`, `run_ai_security`. Each: validates and inspects untrusted
input, computes risk from trusted records, lets the (deliberately naive) agent
recommend, reconciles evidence, evaluates the versioned policy, authorizes,
opens a case when a deterministic rule fires, appends an audit event and
returns a `DecisionBundle`. Invalid input never approves -- it goes to a human.
A recording runtime refuses what-if options (`_admit`) and records only an
authoritative run (`_finish` → `authority.require_authoritative`); a
multi-turn dispute is one decision (`DisputeSession.decide`).

## Storage (`data/store.py`)

SQLite via the standard library. Entity tables plus `risk_assessments`,
`risk_factors`, `evidence`, `security_events`, `decisions` (with the replayable
input snapshot), `policy_decisions`, `ai_recommendations`, `cases`,
`audit_events`, `replays`, `policy_versions`. All SQL lives in this module;
repository adapters (`SqliteAuditBackend`, `SqliteCaseRepository`) keep the
audit chain and case service storage-agnostic.

## Systems of record (`data/providers.py`)

The decision logic never reads storage; `SentinelApp` reads through three
interfaces, so a deployment can answer them from a payment processor, a
ledger, an acquirer or a KYC/KYB provider without touching a decision rule:
`RecordProvider` (the records a decision is about, by id), `FactProvider`
(issuers' signed statements about them) and `RiskContextProvider` (history
around a record, as of a moment -- point-in-time reads only). The shipped
`SentinelStore` over a generated, synthetic dataset is the only
implementation; a test asserts that no decision, risk, evidence, policy or
security module imports the store. No real bank system is integrated.

## Application layer and surfaces

`sentinel/app.py::SentinelApp` owns the store, the runtime (policies,
gateway, cases, audit chain, provider) and the entity graph. The
CLI (`sentinel/cli`), the API (`sentinel/api`) and the console (`ui/`) only
call it. The evaluation suites call the workflows directly with `persist=False`.

## Dependency direction

```text
domain  ←  policy, audit, agents, security, trust
trust  ←  (domain; pyca/cryptography for Ed25519, the only runtime dependency)
security  ←  risk, evidence, cases
decision  ←  (agents, audit, cases, evidence, policy, risk, security, trust)
data  ←  (audit, risk)          replay  ←  (decision, policy, risk)
app  ←  (audit, cases, data, decision, policy, replay, risk, security)
api, cli, evaluation  ←  app and the layers below
```

Read "A ← B" as "B imports A". Two imports are deferred to call time to avoid a
cycle and are the only exceptions: `security.capabilities.matrix()` reads the
policy registry (for the policy-gate column), and `cases.service` type-checks
against `audit.chain` (the case service writes to the audit chain it is
given). `mypy` runs over the whole package in CI.

## Reference documents (rendered from the code by `make docs`)

| Document | Rendered from |
|---|---|
| `docs/SECURITY_MODEL.md` | trust classes, the capability matrix, the threat taxonomy, case rules |
| `docs/RISK_ENGINE.md` | every risk model's factors, conditions, point values and thresholds |
| `docs/POLICY_ENGINE.md` | the field catalog, the engine's semantics, every rule of every shipped policy with its content hash |
| `docs/EVIDENCE_MODEL.md` | evidence kinds and statuses, claim types, the compatibility table, reconciliation verdicts |
| `docs/AUDIT_MODEL.md` | the audit record, verification, backends, checkpoints |
| `docs/EVALUATION.md`, `docs/PERFORMANCE.md` | `results/*.json` |

## What is deliberately not here

No Kafka, Redis, Neo4j, microservices, Kubernetes or Terraform, and no event
bus: each workflow is a synchronous function whose only side effects are the
audit append and the case it opens. The dict-backed graph and SQLite are
honest choices for a portfolio system; `docs/INTERVIEW.md` covers where each
would change at scale.
