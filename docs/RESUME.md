# Résumé material

**Sentinel — Financial Decision Security for AI-assisted finance**
(Python standard library + pyca/cryptography · SQLite · versioned HTTP API · CLI · web console)

Three bullets, rendered from `results/` by `make docs`: if a number changes,
the bullet changes with it. Every number is measured on synthetic corpora and
datasets against an offline simulated agent and is reproducible from a clean
checkout with `make eval`. No production deployment, real customers, real
transactions, fraud savings or regulatory compliance are claimed.

<!-- gen:resume -->
- **Financial decision-security architecture.** Designed and built Sentinel, a
  Python system (standard library plus one cryptography dependency) between LLM
  agents and consequential financial actions (refunds, payment authorisation,
  merchant onboarding, account security): agents may recommend, but only
  verified facts, a signed and activated policy and a capability registry can
  authorize, and the authoritative decision is computed from a view with no
  field for untrusted text or model output. Across 170 attacks (main and
  held-out corpora), attacker text loosened 0.0% of protected decisions, against
  83.5% with no controls.
- **Cryptographic provenance and accountable review.** Made every decision state
  what establishes its facts: Ed25519-signed issuer statements verified against
  a trust store (scopes, rotation, revocation, expiry, anti-rollback), signed
  and explicitly activated policy releases with a trust root outside the policy
  directory, authenticated reviewers with authority limits and four-eyes
  approval, and signed audit checkpoints in an append-only anchor, so a rewrite
  of history is detectable wherever a checkpoint covers it. An adversarial
  review of every change found real defects -- among them a record-id spelling
  that let a refunded dispute be paid twice -- each fixed with a regression test.
- **Adversarial and temporal evaluation.** Built a 15-class adversarial
  evaluation (150-attack main corpus, 20 held-out, 30 on three other
  surfaces, a 47-application KYB benchmark) and a seeded black-box red team
  (5,749 distinct mutated queries, 25 structured attacks on facts, ids,
  capabilities, time, identity and policy): the lexical detector missed
  8.0% / 9.7% of mutated variants of attacks it caught unmutated, while capability /
  policy evasion was 0.0%, trusted-fact manipulation 0.0% and authoritative bypasses
  0 (structural: text never reaches the facts that decide). A temporal-leakage
  benchmark (9,443 checks over 4 seeds) found two current-state reads; 0
  observed leaks after the fix.
<!-- /gen:resume -->

## Why these three

They cover what a fintech, risk or AI-security reviewer checks first: that the
security property is architectural (bullet 1), that the facts, the policy, the
people and the record each carry verifiable provenance (bullet 2), and that the
claims were attacked rather than asserted, including against time (bullet 3). The 60-second pitch and the hard questions are in
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
| "blockchain", "immutable ledger" | a tamper-evident application audit chain with Ed25519 checkpoints in an append-only anchor |
| "cryptographically verified facts" (as if true) | a signature proves *who* stated a fact, not that it is true |
| "the red team proved it unbreakable" | 0 bypasses in a seeded search whose zero is structural; the one real bypass of the release was found by an adversarial review and fixed |
| "SSO", "enterprise identity" | authenticated reviewer credentials from a registry; no SSO / OIDC |
| "0 temporal leaks proves correctness" | "0 observed temporal leaks across the tested synthetic benchmark" |
| "the classifier reads 17/21 unseen phrasings" | 7/21 on its first run; 17/21 after changes by an author who had seen the misses; 24/40 on a set frozen before its first run |
| "revolutionary", "enterprise-grade", "production-ready", "bank-grade" | lab-grade, with production-shaped boundaries |

**Stack:** Python 3.11+ · dataclasses / typing (mypy-checked) · SQLite ·
stdlib `http.server` · pytest + Hypothesis + coverage · ruff · black · GitHub
Actions · Docker · vanilla JS console · Anthropic SDK (optional, live mode) ·
matplotlib (optional, charts).
