# Résumé material

All numbers are measured by `make eval` on synthetic corpora and datasets and
are reproducible from a clean checkout; the generated block below is rendered
from `results/` by `make docs`. No production deployment, real customers, real
transactions, financial savings or regulatory claims are made.

**Project:** Sentinel — Financial Decision Security Infrastructure
(Python, standard library only; SQLite; versioned HTTP API; CLI; console)

<!-- gen:resume -->
## One-line version

> Built Sentinel, a financial decision-security platform in which AI agents
> may recommend but only trusted evidence, deterministic risk controls and
> versioned policy can authorize: 90.0% → 0.0% attack success across 15 threat
> classes against a simulated naive agent with 0.0% false positives, 0.0% of decisions
> executed without ledger support under attack, replayable and hash-chained.

## Six bullets (pick three)

- **Security architecture.** Designed a typed trust boundary (seven trust
  classes; only two can authorize) and a decision composer whose trusted view
  has no field for prose or model output, so an LLM's recommendation is
  recorded but never authoritative. Measured the property as enforced:
  across 170 attacks, **0.0% exceeded the ledger-supported ceiling and
  0.0% executed without ledger support**; 360 recommendation replays changed
  nothing; the unguarded contrast is 83.5%.
- **Financial risk engine.** Built a deterministic, versioned, factor-level
  explainable risk engine (point-in-time behavioural baselines,
  device/geography/velocity, as-of entity profiles, a time-aware relationship
  graph, transaction-monitoring patterns) over a coherent synthetic world with
  labelled fraud scenarios and a temporal-leakage benchmark (0 leaks in 3,648 decisions);
  transaction-level precision 86.7% / recall 67.2% at 0.19% FPR and
  account-level precision 90.0% / recall 90.0% on the development seed, with
  held-out seeds reported (Python, SQLite).
- **Capability / policy enforcement.** Implemented schema-validated,
  versioned, fail-closed policy-as-code (every referenced field present and
  correctly typed; shipped versions pinned by digest; content hashed into
  every decision; a linter for rules that can never fire), engine-enforced
  evaluation authority (no request can select an older policy or risk model
  or switch a control off), and a capability registry (risk,
  reversibility, monetary impact, allowed actors, human-review thresholds) in
  which no AI actor may execute a consequential capability; off-surface
  requests become CRITICAL security events and P1 cases, never executions.
- **Adversarial evaluation.** Authored a 15-class attack corpus (200 attacks
  over dispute, transaction, account-security and investigation surfaces,
  targeting refunds, authorisations, freezes, unfreezes, payout changes, fund
  release, case closure and risk overrides) plus an independent held-out set
  and a balanced 47-case KYB benchmark; an 8-configuration ablation shows a
  hardened prompt still leaks 23.3% and detection alone 20.0%, while
  trusted-evidence adjudication + policy reach 0.0% with 0.0% false
  positives, held at 0.0%/0.0% on unseen wording.
- **Explainability & auditability.** Every decision carries evidence with
  provenance, contradictions, matched policy rules and an authorization
  reason; decisions are replayable under other policy/risk-model versions
  with a field-level diff and policy / engine drift detection, anchored to
  the audit chain so a rewritten record cannot replay as unchanged; the
  tamper-evident audit chain stores hashes, never prose, reports every
  modified, deleted, inserted, reordered or unreadable record, and exports
  HMAC-signed checkpoints.
- **Engineering.** Standard-library-only core (SQLite, http.server), one
  application layer behind a versioned API, a CLI and an API-backed console
  with no decision logic; 564 tests including property-tested security
  invariants and end-to-end hostile vectors; CI with lint, types, coverage,
  evaluation smoke and Docker; protected pipeline p95 ≈ 0.7267 ms offline.

## Interview explanation (~60 seconds)

"Financial institutions are putting AI agents into decision paths -- refunds,
onboarding, account security, investigations -- and those agents read
attacker-controlled text through legitimate channels. Everyone defends against
*injected instructions*. The harder attack has no injection: the customer
simply lies about a fact, and a persuadable model approves. Prompt hardening
doesn't help with a lie; against our simulated agent it still leaked 23.3%.
Sentinel's answer is architectural: the model may recommend, but the
authoritative decision is computed from a view that literally has no field
for the prose or the model's opinion -- trusted evidence decides whether a
claim is supported, versioned policy decides the outcome, a capability
registry decides who may execute it, and a tamper-evident audit chain records
why. We state the property precisely -- untrusted text cannot produce an
outcome the records don't support -- and measure it directly: across 170
attacks, none exceeded the ledger-supported ceiling, none executed without
support, none of the deserved refunds were held, and every decision replays
deterministically under a different policy version."
<!-- /gen:resume -->

## Which three to pick

The strongest set, in order, when the role is fintech / risk / AI security:

1. **Security architecture** (trusted evidence decides; the model recommends).
2. **Financial risk engine** (point-in-time correctness, explainable, honest
   about being a rule model).
3. **Adversarial evaluation** (four surfaces, held-out set, balanced KYB,
   ablation).

For a platform / backend role swap the third for **Explainability &
auditability** (replay with drift detection, tamper-evident audit chain with
signed checkpoints).

## What NOT to claim

- ❌ "Deployed at a bank", "real transactions", "fraud losses prevented".
- ❌ "AML compliant" -- the monitoring layer is a synthetic investigation
  simulation.
- ❌ "ML fraud model" -- it is a transparent rule model; say so.
- ❌ Any live-LLM number you have not reproduced on your own key.
- ❌ "N% of attacks succeed against LLM agents" -- the unguarded figure is the
  offline *simulated* agent's; say "against a simulated naive agent". The
  WITHOUT / WITH comparison is not a real-world LLM experiment.
- ❌ "Text can only make decisions stricter" -- say "text cannot produce an
  outcome the trusted records do not support"; on a supporting ledger a clear
  claim is approved and a vague one is held for a human, by design.
- ❌ "Blockchain", "immutable ledger" -- it is a tamper-evident application
  audit chain with an exportable signed checkpoint.
- ❌ "Industry-standard risk weights" -- the point values are Sentinel
  heuristics tuned on one synthetic seed.
- ❌ "Revolutionary", "enterprise-grade", "production-ready", "bank-grade".
  The docs say lab-grade with production-shaped boundaries; keep it that way.

## Stack

Python 3.11+ · dataclasses / typing (mypy-checked) · SQLite · stdlib
`http.server` · pytest + Hypothesis + coverage · ruff · black · GitHub Actions
· Docker · vanilla JS console · Anthropic SDK (optional, live mode) ·
matplotlib (optional, charts).
