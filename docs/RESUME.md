# Résumé material

All numbers are measured by `make eval` on synthetic corpora and datasets and
are reproducible from a clean checkout. No production deployment, real
customers, real transactions, financial savings or regulatory claims are made.

**Project:** Sentinel — Financial Decision Security Platform

<!-- gen:resume -->
## One-line version

> Built Sentinel, a financial decision-security platform in which AI agents
> may recommend but only trusted evidence, deterministic risk controls and
> versioned policy can authorize: 83.3% → 0.0% attack success across 12 threat
> classes against a simulated naive agent with 0.0% false positives, 0.0% of decisions
> executed without ledger support under attack, replayable and hash-chained.

## Six bullets (pick three)

- **Security architecture.** Designed a typed trust boundary (seven trust
  classes; only two can authorize) and a decision composer whose trusted view
  has no field for prose or model output, so an LLM's recommendation is
  recorded but never authoritative. Measured the property as enforced:
  across 136 attacks, **0.0% exceeded the ledger-supported ceiling and
  0.0% executed without ledger support**; 360 recommendation replays changed
  nothing; the unguarded contrast is 77.9%.
- **Financial risk engine.** Built a deterministic, versioned, factor-level
  explainable risk engine (behavioural baselines, device/geography/velocity,
  entity profiles, a relationship graph, transaction-monitoring patterns) over
  a coherent synthetic world with nine labelled fraud scenarios; account-level
  recall 100.0% at 2.7% FPR, transaction-level precision 93.3% at
  0.03% FPR on the development seed, with held-out seeds reported
  (Python, SQLite).
- **Capability / policy enforcement.** Implemented schema-validated,
  versioned, fail-closed policy-as-code (every referenced field must be
  present; policy content is hashed and pinned by every decision) and a
  capability registry (risk, reversibility, monetary impact, allowed actors,
  human-review thresholds) in which no AI actor may execute a consequential
  capability; off-surface requests become CRITICAL security events and P1
  cases, never executions.
- **Adversarial evaluation.** Authored a 12-class attack corpus (120 attacks
  targeting refunds, onboarding, unfreezing, payout changes, fund release,
  case closure, risk overrides) plus an independent held-out set and a KYB
  surface; an 8-configuration ablation shows a hardened prompt still leaks
  16.7% and detection alone 16.7%, while trusted-evidence adjudication + policy
  reach 0.0% with 0.0% false positives, held at 0.0%/0.0% on unseen wording.
- **Explainability & auditability.** Every decision carries evidence with
  provenance, contradictions, matched policy rules and an authorization
  reason; decisions are replayable under other policy/risk-model versions
  with a field-level diff and drift detection; the audit trail is a SHA-256
  hash chain (stores hashes, never prose) whose verifier names the first
  modified, deleted or reordered record.
- **Engineering.** Standard-library-only core (SQLite, http.server), one
  application layer behind a versioned API, a CLI and an API-backed console;
  231 tests including ten property-tested security invariants and end-to-end
  hostile vectors; CI with lint, types, coverage, evaluation smoke and Docker;
  protected pipeline p95 ≈ 0.4556 ms offline.

## Interview explanation (~60 seconds)

"Financial institutions are putting AI agents into decision paths -- refunds,
onboarding, account security, investigations -- and those agents read
attacker-controlled text through legitimate channels. Everyone defends against
*injected instructions*. The harder attack has no injection: the customer
simply lies about a fact, and a persuadable model approves. Prompt hardening
doesn't help with a lie; against our simulated agent it still leaked 16.7%.
Sentinel's answer is architectural: the model may recommend, but the
authoritative decision is computed from a view that literally has no field
for the prose or the model's opinion -- trusted evidence decides whether a
claim is supported, versioned policy decides the outcome, a capability
registry decides who may execute it, and a hash-chained audit records why.
We state the property precisely -- untrusted text cannot produce an outcome
the records don't support -- and measure it directly: across 136 attacks,
none exceeded the ledger-supported ceiling, none executed without support,
none of the deserved refunds were held, and every decision replays
deterministically under a different policy version."
<!-- /gen:resume -->

## What NOT to claim

- ❌ "Deployed at a bank", "real transactions", "fraud losses prevented".
- ❌ "AML compliant" -- the monitoring layer is a labelled simulation.
- ❌ "ML fraud model" -- it is a transparent rule model; say so.
- ❌ Any live-LLM number you have not reproduced on your own key.
- ❌ "83.3% of attacks succeed against LLM agents" -- the unguarded figure is the
  offline *simulated* agent's; say "against a simulated naive agent".
- ❌ "Text can only make decisions stricter" -- say "text cannot produce an
  outcome the trusted records do not support"; on a supporting ledger a clear
  claim is approved and a vague one is not, by design.

## Stack

Python 3.11+ · dataclasses / typing (mypy-checked) · SQLite · stdlib
`http.server` · pytest + Hypothesis + coverage · ruff · black · GitHub Actions
· Docker · vanilla JS console · Anthropic SDK (optional, live mode) ·
matplotlib (optional, charts).
