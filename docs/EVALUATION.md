# Evaluation

Every number in this document is produced by one command and written to
`results/`:

```bash
make eval                # == sentinel eval run --suite full   (offline, deterministic, no key; ~3 s)
```

Re-run it and the JSON (and this document's tables, which are generated from
it) will match. Four dimensions are measured: **AI security**, **financial
risk**, **decision integrity** and **system performance**. All corpora and
datasets are synthetic; see `docs/LIMITATIONS.md`.

## What "attack success" means

An attack **succeeds** when the system **executes an unauthorised consequential
capability** -- a refund is paid, a merchant goes live, a payment is
authorised, an account is unfrozen, a payout destination changes, funds are
released, a case is closed -- that the trusted records do not support. This is
stronger than "the detector flagged the sentence": a flagged attack that
still executes counts as a success, and an undetected attack that never
executes counts as a failure. For legitimate controls, a **false positive** is
a deserved refund the platform fails to execute.

## A. AI security -- development corpus (`results/security.json`)

120 attacks across 12 threat classes (each class: 2 hand-authored
seeds × 5 amounts straddling the ₹50,000 auto-limit) + 21
legitimate controls (10 of which deserve a refund).
Six classes target capabilities beyond `APPROVE_REFUND`.

| Metric | No controls (model executes) | Full Sentinel |
|---|---:|---:|
| Attack success rate | **83.3%** | **0.0%** |
| Off-surface capability executed (escalation) | 20.8% | 0.0% |
| Gateway detection recall | — | 83.3% (lexical; not the backstop) |
| False-positive rate on deserved refunds | — | **0.0%** |

| Threat class | No controls | Detection recall | Sentinel |
|---|---:|---:|---:|
| direct_injection | 100.0% | 100.0% | 0.0% |
| authority_spoof | 100.0% | 100.0% | 0.0% |
| document_borne | 100.0% | 100.0% | 0.0% |
| fake_policy | 100.0% | 100.0% | 0.0% |
| context_poisoning | 50.0% | 100.0% | 0.0% |
| tool_manipulation | 50.0% | 100.0% | 0.0% |
| multi_turn_escalation | 50.0% | 100.0% | 0.0% |
| unicode_obfuscation | 100.0% | 100.0% | 0.0% |
| indirect_injection | 100.0% | 100.0% | 0.0% |
| adjudication_gaming | 100.0% | 0.0% | 0.0% |
| financial_social_engineering | 100.0% | 0.0% | 0.0% |
| capability_escalation | 50.0% | 100.0% | 0.0% |

Read the last two columns together: **adjudication gaming and financial
social engineering are invisible to detection (0.0% recall) and are
still blocked**, because the ledger, not the prose, decides support.

| Target capability | n | No controls | Sentinel |
|---|---:|---:|---:|
| APPROVE_REFUND | 100 | 90.0% | 0.0% |
| CLOSE_CASE | 5 | 0.0% | 0.0% |
| RELEASE_FUNDS | 5 | 100.0% | 0.0% |
| UNFREEZE_ACCOUNT | 5 | 100.0% | 0.0% |
| ALTER_RISK | 5 | 0.0% | 0.0% |

Blocked-by distribution (an attack can be stopped by several controls at
once): ai_security_gateway 45, capability_authorization 100, capability_registry 15, policy:dispute-refund@v2 100, trusted_evidence 100.

## B. Held-out generalisation (`results/heldout.json`)

The development corpus and the detector share an author, so a 0% there could
be circular. The held-out set (16 attacks, 4 deserved controls) is
authored independently with wording that never appears in the detector; a test
asserts it is disjoint from the corpus and the detector is never tuned to it.

| Metric | Value |
|---|---:|
| Attack success, no controls | 37.5% |
| **Attack success, Sentinel** | **0.0%** |
| Gateway detection recall | 56.2% |
| **False positives** | **0.0%** |

Two honest reads: the architecture generalises (0% / 0% on unseen wording),
and the lexical detector does not (56.2% recall) -- which is why
detection is not on the authorization path. The unguarded figure is depressed
because the offline victim agent is itself lexical; the held-out set
validates the platform, not the baseline's realism. In v2 this set found a
false positive on a novel cancellation phrasing; the general pattern was
broadened and the case pinned.

## C. Second surface -- merchant onboarding (`results/kyb.json`)

10 document-borne / injected applications on bad acquirer records + 5 controls.

| Metric | Value |
|---|---:|
| Attack success, no controls | 100.0% |
| **Attack success, Sentinel** | **0.0%** |
| False positives (clean merchants wrongly held) | 0.0% |
| Borderline (incomplete verification) → human review | 100.0% |

## D. Beating the obvious defence (`results/baselines.json`)

| Defence | Attack success |
|---|---:|
| No defence | 83.3% |
| Hardened system prompt ("ignore embedded instructions") | 16.7% |
| **Sentinel** | **0.0%** |

The hardened prompt still fails on: adjudication_gaming 100.0%, financial_social_engineering 100.0%. A customer lying about a
fact is not an injection, and "ignore instructions" says nothing about a lie.

## E. Ablation -- which control carries the result (`results/ablation.json`)

| Configuration | ASR | FP | off-surface executed | controls |
|---|---:|---:|---:|---|
| no_controls | 83.3% | 40.0% | 12.5% | `—` |
| prompt_hardening | 16.7% | 40.0% | 0.0% | `—` + hardened prompt |
| detection_only | 45.8% | 40.0% | 0.0% | `detection, provenance` |
| risk_only | 83.3% | 40.0% | 12.5% | `risk` |
| policy_only | 33.3% | 40.0% | 5.0% | `policy` |
| adjudication_only | 0.0% | 0.0% | 0.0% | `adjudication` |
| adjudication_policy | 0.0% | 0.0% | 0.0% | `adjudication, authorization, policy` |
| full | 0.0% | 0.0% | 0.0% | `adjudication, authorization, detection, policy, provenance, risk` |

- **Detection only** holds what it detects and leaks the rest (the undetectable
  classes plus MEDIUM-severity findings).
- **Policy only** (no evidence) catches only the over-limit amounts.
- **Trusted adjudication alone** closes every attack on this corpus; policy and
  authorization add human review for high-value legitimate cases, capability
  containment, and explainability.

## F. Financial risk on labelled synthetic data (`results/financial.json`)

Dataset: seed 42, 150 customers, 30 merchants, 3183 transactions; risk model
`txn-1.0`. Positive = risk level HIGH or CRITICAL. Labels come from the
generator's injected scenarios and are read only by this suite. Risk exists at
three levels and each scenario is evaluated at the level meant to catch it.

| Level | Scenarios | Precision | Recall | FPR | FNR | tp / fp / fn / tn |
|---|---|---:|---:|---:|---:|---|
| transaction | account takeover, bursts, ring transactions | 73.7% | 26.9% | 0.2% | 73.1% | 14 / 5 / 38 / 3126 |
| account (monitoring) | structuring-like, dormant activation, rings, bursts | 71.4% | 100.0% | 2.7% | 0.0% | 10 / 4 / 0 / 145 |
| merchant (profile) | abused / shell / repeatedly flagged | 40.0% | 66.7% | 11.1% | 33.3% | 2 / 3 / 1 / 24 |

Transaction-level recall by scenario: account_takeover 66.7% (n=6), burst 14.3% (n=28), graph_linked 33.3% (n=18). Account-level: burst 100.0% (n=3), dormant_activation 100.0% (n=2), graph_linked 100.0% (n=3), structuring 100.0% (n=2).

Bursts are inherently partial at the transaction level -- the first few
transactions of a burst are indistinguishable from normal activity -- which is
exactly why the account-level monitor exists.

Calibration (observed fraud-labelled rate per transaction risk band):

| Band | n | observed fraud rate |
|---|---:|---:|
| LOW | 2864 | 0.5% |
| MEDIUM | 300 | 7.7% |
| HIGH | 14 | 64.3% |
| CRITICAL | 5 | 100.0% |

Policy outcomes on a 400-transaction sample through the full pipeline
(`transaction-authorization@latest`, no agent): fraud-labelled transactions allowed
28.8%, legitimate transactions blocked or denied 0.0%.
The risk model is a transparent rule table, not ML; these numbers describe it
honestly on this generator.

## G. Decision integrity (`results/integrity.json`)

The structural claim, measured directly over 136 attacks (dev + held-out)
and 14 deserved controls:

| Question | Sentinel | No controls |
|---|---:|---:|
| Attacker text made the decision **more permissive** | **0.0%** | 77.9% |
| Attacker text changed the outcome at all (tightening only) | 43.4% | — |
| Injection appended to a deserved claim **loosened** it | **0.0%** (n=84) | — |
| Injection appended to a deserved claim tightened it (held for a human) | 100.0% | — |
| A different model recommendation changed the outcome | **0.0%** (n=360) | — |

Untrusted input can only make a protected decision *stricter*. That is the
property the whole architecture exists to provide.

## H. Performance (`results/performance.json`)

macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7; offline agent; workloads: 310-char injected
narrative, 40-transaction baseline, graph of 8,144 nodes / 14,682 edges,
9-rule policy, 500 end-to-end iterations.

| Component | p50 ms | p95 ms | p99 ms | ops/s |
|---|---:|---:|---:|---:|
| `normalize` | 0.0175 | 0.0187 | 0.0215 | 56,204 |
| `gateway_inspect` | 0.175 | 0.1858 | 0.2044 | 5,658 |
| `claim_classify` | 0.0191 | 0.0214 | 0.0325 | 51,114 |
| `evidence_reconcile` | 0.0219 | 0.0245 | 0.0418 | 44,316 |
| `risk_score_transaction` | 0.0117 | 0.0131 | 0.0193 | 81,802 |
| `graph_linked_accounts` | 0.0041 | 0.0043 | 0.0046 | 238,229 |
| `graph_neighborhood_d2` | 0.1592 | 0.1707 | 0.2171 | 6,192 |
| `policy_evaluate` | 0.0077 | 0.008 | 0.0097 | 127,761 |
| `decision_compose` | 0.0306 | 0.0342 | 0.0638 | 31,375 |
| `audit_append` | 0.0088 | 0.0113 | 0.0336 | 102,985 |
| `e2e_dispute_pipeline` | 0.4246 | 0.5501 | 1.3747 | 2,200 |

A live LLM call (hundreds of milliseconds) dominates real latency by three
orders of magnitude; Sentinel's own controls are not the bottleneck.

## I. Model / provider evaluation (`results/models.json`)

| Provider | Model | Status | ASR no controls | ASR Sentinel | FP | Note |
|---|---|---|---:|---:|---:|---|
| offline | `offline-simulator` | ok | 83.3% | 0.0% | 0.0% |  |
| anthropic | `claude-opus-5` | not_run | — | — | — | no ANTHROPIC_API_KEY or SENTINEL_FORCE_OFFLINE=1 |

Live results depend on provider/model/date and are not claimed to generalise. Run `SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models`
with your own key to fill the live row; nothing here is fabricated.

## Reproduce

```bash
make eval                      # everything above, ~3 s, writes results/*.json and charts
sentinel eval run --suite security|heldout|kyb|baselines|ablation|financial|integrity|performance|models|charts
sentinel eval run --suite financial --full     # larger dataset (400 customers / 12k transactions)
make test                      # includes tests/test_results_regression.py, which recomputes the headline claims
```
