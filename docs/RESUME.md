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

## Three bullets

- **Financial decision-security architecture.** Designed and built Sentinel,
  a Python decision-security layer in which an LLM agent may recommend but only
  trusted records, versioned policy and a capability registry can authorize a
  refund, payout change, merchant approval or account action: the decision is
  computed from a view with no field for prose or model output, and the engine
  refuses to record any evaluation run with a weakened control, a historical
  policy or a historical risk model. Across 170 attacks, attacker text loosened
  0.0% of protected decisions (vs 83.5% with no controls) and 360
  model-recommendation replays changed none.
- **Point-in-time risk engineering.** Built an explainable, versioned
  rule-based risk engine -- point-in-time behavioural baselines, a time-aware
  relationship graph, as-of entity profiles and transaction monitoring -- over
  a seeded synthetic world, and a temporal-leakage benchmark that re-scored
  3,648 decisions against nine kinds of later record with 0 leaks (after it
  found two current-state reads, which were fixed); transaction precision
  86.7% / recall 67.2% at 0.19% FPR on the development seed, with held-out seeds
  reported and early-burst misses explained rather than tuned away.
- **Adversarial evaluation, policy and authorization.** Authored a
  15-class, 200-attack corpus across four surfaces plus a held-out set and a
  balanced 47-case KYB benchmark; an ablation shows prompt hardening still
  leaks 23.3% and detection alone 20.0%, while trusted-evidence adjudication with
  fail-closed, digest-pinned policy-as-code and actor-scoped authorization
  holds unauthorised execution at 0.0% with 0.0% false positives against a
  simulated naive agent; every decision replays against a tamper-evident
  application audit chain.

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

## Why these three

They cover the three things a fintech, risk or AI-security reviewer checks
first: that the security property is architectural (bullet 1), that the risk
engineering is careful about time (bullet 2), and that the claims were
attacked rather than asserted (bullet 3). Every number is generated from
`results/` by `make docs`; if a number changes, the bullet changes with it.

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
