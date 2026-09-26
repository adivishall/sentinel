# Résumé material

**Sentinel — Financial Decision Security for AI-assisted finance**
(Python, standard library only · SQLite · versioned HTTP API · CLI · web console)

Three bullets, rendered from `results/` by `make docs`: if a number changes,
the bullet changes with it. Every number is measured on synthetic corpora and
datasets against an offline simulated agent and is reproducible from a clean
checkout with `make eval`. No production deployment, real customers, real
transactions, fraud savings or regulatory compliance are claimed.

<!-- gen:resume -->
- **Financial decision-security architecture.** Designed and built Sentinel, a
  standard-library Python system between LLM agents and consequential financial
  actions (refunds, payment authorisation, merchant onboarding, account
  security): agents may recommend, but only trusted records, versioned
  fail-closed policy and a capability registry can authorize, and the
  authoritative decision is computed from a view with no field for untrusted
  text or model output. Across 170 attacks (main and held-out corpora), attacker
  text loosened 0.0% of protected decisions, against 83.5% with no controls.
- **Point-in-time risk engineering.** Built an explainable, versioned risk
  engine -- as-of behavioural baselines, a time-aware relationship graph,
  entity profiles and account monitoring -- and a temporal-leakage benchmark
  (3,648 checks, 9 kinds of later record) that found two current-state
  reads; 0 observed leaks after the fix. On the synthetic development seed:
  transaction precision 86.7% / recall 67.2% at 0.19% FPR, account-level
  90.0% / 90.0%, with held-out seeds reported and early-burst misses
  explained rather than tuned away.
- **Adversarial evaluation, policy and authorization.** Built a 15-class
  adversarial evaluation (150-attack main corpus, 20 held-out, 30 on three
  other surfaces, a 47-application KYB benchmark) with ablations: against a
  simulated naive agent, prompt hardening still leaked 23.3% and detection
  alone 20.0%, while trusted-evidence adjudication, digest-pinned
  policy-as-code and workflow-scoped authorization held unauthorised execution
  at 0.0% with 0.0% false positives; every decision replays against a
  tamper-evident, hash-chained audit log.
<!-- /gen:resume -->

## Why these three

They cover what a fintech, risk or AI-security reviewer checks first: that the
security property is architectural (bullet 1), that the risk engineering is
careful about time (bullet 2), and that the claims were attacked rather than
asserted (bullet 3). The 60-second pitch and the hard questions are in
[INTERVIEW.md](INTERVIEW.md).

## What not to claim

| Don't say | Say instead |
|---|---|
| "Deployed at a bank", "real transactions", "fraud losses prevented" | synthetic data and an offline simulated agent |
| "AML compliant" | the monitoring layer is a synthetic investigation simulation |
| "ML fraud model" | a transparent, versioned rule model (point values are Sentinel heuristics tuned on one synthetic seed) |
| "N% of attacks succeed against LLM agents" | "against a simulated naive agent" -- the WITHOUT / WITH comparison is not a live-model experiment |
| any live-LLM number | the live row is `not_run` until you run it on your own key |
| "text can only make decisions stricter" | "text cannot produce an outcome the trusted records do not support" (a clear claim on a supporting ledger is approved, by design) |
| "blockchain", "immutable ledger" | a tamper-evident application audit chain with an exportable signed checkpoint |
| "0 temporal leaks proves correctness" | "0 observed temporal leaks across the tested synthetic benchmark" |
| "the classifier reads 17/21 unseen phrasings" | 7/21 on the first, blind run; 17/21 after changes by an author who had seen the misses |
| "revolutionary", "enterprise-grade", "production-ready", "bank-grade" | lab-grade, with production-shaped boundaries |

**Stack:** Python 3.11+ · dataclasses / typing (mypy-checked) · SQLite ·
stdlib `http.server` · pytest + Hypothesis + coverage · ruff · black · GitHub
Actions · Docker · vanilla JS console · Anthropic SDK (optional, live mode) ·
matplotlib (optional, charts).
