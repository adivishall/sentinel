# Résumé evidence

Every number here is produced by `make offline` (no API key) and committed under
`eval/results/`. The rule: **if a bullet contains a number, the command that
produced it is one line below**, and the scope caveat travels *with* the number —
these are reproducible offline-simulation results, not empirical measurements of a
live LLM.

---

## Three bullets (use these)

> **Designed and built an "AI firewall" that defends an LLM decision agent from
> attacker-controlled text** by making the authoritative decision a pure function
> of verified structured facts (the bank's own ledger), never the prose — enforced
> at the type level (`UntrustedText` vs `TrustedFacts`), checked by mypy, and
> proven by a test that the narrative never reaches the adjudicator. Took offline
> attack success from **83.3% to 0%** across 6 attack classes with **0% false
> positives**, holding **0%/0%** on an independently authored held-out set.

> **Made the evaluation credible instead of circular.** Built the obvious defence
> (system-prompt hardening) as a baseline and showed it fails **100% on
> adjudication gaming** — a false claim with no injection to detect — where the
> fact-based layer reaches 0%; ran a real **layer ablation** proving one layer
> (structured adjudication) carries the result while the other three are
> defence-in-depth; and validated generalisation on a held-out set whose wording
> never appears in the detector. Reported the honest reading: *this is a one-idea
> system with three supporting layers.*

> **Shipped it as inspectable, reproducible engineering.** A dependency-free
> offline mode reproduces every metric with no API key; a zero-dependency HTTP API
> (`POST /api/evaluate`, `/health`, `/version`); ~**0.08 ms** firewall overhead at
> ~**12k decisions/sec**; **83 tests at ~91% coverage** (security-critical modules
> 90–100%) including trust-boundary proofs, homoglyph-evasion and fail-safe cases;
> and CI running ruff + black + mypy + pytest + a coverage gate + an offline
> evaluation smoke test on every push.

---

## The measurements behind them

### Headline — offline attack success (`make offline`)

| surface | no firewall | with Sentinel | false positives |
|---|---:|---:|---:|
| Dispute triage | 83.3% | **0.0%** | **0.0%** |
| KYB onboarding | 87.5% | **0.0%** | **0.0%** |
| Held-out (independent author) | 16.7% (2/12) | **0.0%** | **0.0%** |

> **Scope, quoted with the number:** the attacked agent is a *deterministic
> simulation* of a gullible LLM (`llm.py`). The results are **reproducible, not
> empirical**. 0% guarded is close to tautological by design — it demonstrates the
> architecture does what it claims (text can't move a fact-based verdict), not that
> it survived a determined human attacker. n is small; treat one-decimal precision
> as noise.

### The obvious defence, measured (`make baselines`)

| defence | attack success | adjudication-gaming subset |
|---|---:|---:|
| none | 83.3% | 100% succeed |
| system-prompt hardening | 16.7% | **100% succeed** |
| **Sentinel (fact-based L3)** | **0.0%** | **0% succeed** |

### Ablation — which layer does the work (`make ablation`)

Blocking layer across all 60 attacks: `{"L3_adjudicate": 50}`. Detection alone
still leaks **6.7%** (the adjudication-gaming attacks). L1/L2/L4 block nothing the
ablation can detect — they are defence-in-depth and explainability.

### Engineering

| metric | value |
|---|---|
| tests | **83**, offline, no key |
| coverage | **~91%** (firewall/api; security-critical modules 90–100%) |
| firewall overhead | **~0.08 ms** / decision |
| throughput | **~12k decisions/sec** |
| lint / types | ruff + black + mypy, clean |
| CI | ruff + black + mypy + pytest + coverage gate + offline smoke test |

```bash
make offline   # every attack-success / ablation / baseline / held-out number
make test      # the 83-test suite
make bench     # latency / throughput
make lint      # ruff + black --check + mypy
```

---

## What NOT to claim

- **Not "0% attack success against a real LLM".** The attacked agent is an offline
  simulation; the number is reproducible, not empirical.
- **Not "proven secure".** 0% guarded is tautological by design — it proves the
  architecture, not survival against a human attacker.
- **Not "four-layer defence".** The ablation says one layer carries the result;
  the honest framing is one idea + three supporting layers.
- **Not "held-out proves robustness".** Only 2/12 held-out attacks succeed
  unguarded, so "0% there" is weaker than it sounds; n is small throughout.
- **Not "works on any LLM".** No live-LLM corpus results are published; the live
  path exists but hasn't been run at scale, and the claim is scoped to the
  architecture, not to any specific model.

---

## Technologies actually used

Python 3.11+, mypy (typed trust boundary), pytest + coverage, ruff + black, a
zero-dependency stdlib HTTP API, Docker, GitHub Actions; optional matplotlib for
charts and an optional live Anthropic Claude path.

Concepts: typed trust boundaries / capability-based decisioning, prompt-injection
taxonomy and detection, structured adjudication over verified facts, ablation and
held-out evaluation design, unicode/homoglyph normalization, append-only audit
logging, threat modelling for LLM decision agents.
