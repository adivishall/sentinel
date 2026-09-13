# Résumé material

All numbers are measured by `make offline` and reproducible. No invented metrics,
no claim of production deployment, real customers, or universal security.

**Project:** Sentinel — an AI firewall for high-stakes back-office LLM agents.

## One-line version

> Built Sentinel, an AI firewall that stops prompt-injection **and** "adjudication
> gaming" attacks against bank back-office LLM agents by making the authoritative
> decision from verified records, not attacker text — 83.3% → 0% attack success
> with 0% false positives, held at 0% on an independent held-out set.

## Three-bullet résumé entry

- **Designed and built a four-layer "AI firewall" (Python)** protecting LLM agents
  that trigger irreversible actions (auto-refunds, merchant onboarding); the core
  idea — the authoritative decision is computed from structured trusted facts, not
  attacker prose — is enforced as a **type-checked trust boundary** (`UntrustedText`
  vs `TrustedFacts`) with tests proving prose cannot cross it.
- **Cut attack success from 83.3% to 0% with 0% false positives** across 60 attacks
  in 6 classes, and **held 0%/0% on an independently authored held-out set**; an
  ablation shows detection alone still leaks 6.7% and that fact-based adjudication
  is the load-bearing layer — beating a hardened-prompt baseline that fails 100% on
  false-claim attacks.
- **Shipped it as a real, inspectable system:** deterministic offline mode (no API
  key) *and* a live-Claude mode running the identical firewall, a zero-dependency
  HTTP API, Docker deployment, an interactive web console, 83 tests at ~91%
  coverage, and CI (ruff/black/mypy/pytest + a security smoke test).

## Interview explanation (~60 seconds)

"Banks are putting their own LLMs in decision paths — a chargeback-triage agent
reads what a cardholder types and can issue a refund. That text is attacker
-controlled through a legitimate channel. Everyone defends against *injected
instructions*, but the harder attack is **adjudication gaming**: no injection at
all, the customer just *lies* — 'my order never arrived' — and a persuadable model
approves. Hardened prompts don't help; 'ignore instructions' says nothing about a
lie. Sentinel's fix is structural: the final decision is never computed from the
prose. I extract structured facts from the bank's own records and a second
adjudicator decides on those alone; the narrative only contributes a coarse claim
*type* that selects which verified fact to check. I made that boundary a Python
type — `UntrustedText` is opaque, only `TrustedFacts` has an evidence method — so
mypy and a regression test guarantee prose can't reach the decision. Measured: 83%
→ 0% attack success, 0% false positives, and — the honest part — 0% on a held-out
set I wrote separately so it's not circular. The same firewall protects a second
surface (KYB onboarding) unchanged."

## What NOT to claim

- ❌ "100% secure" / "universal protection" — it closes a specific class; the
  evaluation is on synthetic corpora.
- ❌ "Deployed at a bank" / "real users" — it is a lab prototype of a control.
- ❌ Any live-LLM number you have not personally reproduced on your own key.

## Stack

Python 3.11 · dataclasses/typing (mypy-checked) · stdlib `http.server` API ·
pytest + coverage · ruff · black · GitHub Actions · Docker · matplotlib (charts) ·
Anthropic SDK (optional, live mode).
