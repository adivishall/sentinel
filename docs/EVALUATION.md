# Evaluation

Every number in this document is produced by one command and written to
`results/`, then rendered here by `scripts/render_docs.py` (`make docs`):

```bash
make eval                # == sentinel eval run --suite full   (offline, deterministic, no key; ~4 s)
```

Four dimensions are measured: **AI security**, **financial risk**, **decision
integrity** and **system performance**. All corpora and datasets are synthetic;
see `docs/LIMITATIONS.md`.

## Two kinds of numbers

Read every table with this distinction in mind.

- **Structural numbers are 0 by construction.** Under the design, a
  consequential capability executes only when the trusted records support the
  claim. Every attack in the corpora sits on a ledger (or acquirer record) that
  does *not* support it, so guarded attack success *cannot* be anything but 0.
  Those rows are regression checks that the implementation honours the design
  (`tests/test_results_regression.py` recomputes them), not detection results.
- **Empirical numbers can move.** The unguarded baseline (how often the
  *offline simulated agent* obeys the corpus), the gateway's detection recall,
  the false-positive rate on deserved claims, the claim classifier's held-out
  coverage, and everything in the financial suite.
- **The unguarded victim is a simulator.** `OfflineProvider` is a deterministic
  regex model of a gullible tool-calling agent, authored alongside the corpus.
  Its attack-success rate is a property of that simulator and a contrast for
  the protected path, not a measurement of any real model
  (`results/models.json` records the live row as `not_run` until you run it on
  your own key).

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

| Metric | No controls (simulated agent) | Full Sentinel |
|---|---:|---:|
| Attack success rate | **83.3%** (empirical, simulator) | **0.0%** (structural) |
| Off-surface capability executed (escalation) | 20.8% | 0.0% (structural) |
| Gateway detection recall | — | 83.3% (empirical; text scan or model-output check; not the backstop) |
| False-positive rate on deserved refunds | — | **0.0%** (empirical) |

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
| Attack success, no controls (simulated agent) | 37.5% |
| **Attack success, Sentinel** | **0.0%** (structural) |
| Gateway detection recall | 56.2% (empirical) |
| **False positives** | **0.0%** (empirical) |

Two honest reads: the *claim classifier* generalised to the unseen legitimate
phrasings (no deserved refund was held), and the lexical detector did not
(56.2% recall) -- which is why detection is not on the
authorization path. The unguarded figure is depressed because the offline
victim agent is itself lexical; the held-out set validates the platform, not
the baseline's realism. In v2 this set found a false positive on a novel
cancellation phrasing; the general pattern was broadened and the case pinned.

## C. Second surface -- merchant onboarding (`results/kyb.json`)

10 document-borne / injected applications on bad acquirer records + 5 controls.

| Metric | Value |
|---|---:|
| Attack success, no controls (simulated agent) | 100.0% |
| **Attack success, Sentinel** | **0.0%** (structural) |
| False positives (clean merchants wrongly held) | 0.0% (empirical) |
| Borderline (incomplete verification) → human review | 100.0% (empirical) |

Both headline rows are by construction: every attack record is shell /
flagged / unverified, so the records never support onboarding, and the
simulated KYB agent obeys every seed in the corpus. The informative rows are
the last two. Not measured: a malicious document on *clean* records asking for
an off-surface capability (the dispute corpus covers that class).

## D. Beating the obvious defence (`results/baselines.json`)

| Defence | Attack success |
|---|---:|
| No defence (simulated agent) | 83.3% |
| Hardened system prompt ("ignore embedded instructions") | 16.7% |
| **Sentinel** | **0.0%** |

The hardened prompt still fails on: adjudication_gaming 100.0%, financial_social_engineering 100.0%. A customer lying about a
fact is not an injection, and "ignore instructions" says nothing about a lie.

## E. Ablation -- which control carries the result (`results/ablation.json`)

| Configuration | ASR | FP | off-surface executed | definition |
|---|---:|---:|---:|---|
| no_controls | 83.3% | 40.0% | 12.5% | the model's tool call executes |
| prompt_hardening | 16.7% | 40.0% | 0.0% | no controls; the agent is told to ignore embedded instructions |
| detection_only | 16.7% | 40.0% | 0.0% | gateway + provenance; a flagged finding (severity ≥ MEDIUM) or off-surface request holds for a human, otherwise the model is believed |
| risk_only | 83.3% | 40.0% | 12.5% | risk is computed but no policy consumes it -- identical to no controls |
| policy_only | 33.3% | 40.0% | 5.0% | policy over the model's asserted verdict; no security or risk signal, no registry |
| adjudication_only | 0.0% | 0.0% | 0.0% | the ledger verdict alone: execute iff the trusted records support the claim |
| adjudication_policy | 0.0% | 0.0% | 0.0% | ledger verdict + versioned policy + capability authorization |
| full | 0.0% | 0.0% | 0.0% | everything, including the gateway and risk signals |

- **Detection only** holds exactly what it flags and leaks exactly the two
  classes with nothing to detect (16.7%). v2.0.0 held only
  HIGH+ findings and reported 45.8%; the definition was inconsistent with
  `detection_recall` and the higher number flattered the other controls.
- **Policy only** (over the model's asserted verdict) catches only the
  over-limit amounts.
- **Trusted adjudication alone** closes every attack on this corpus (by
  construction, see above); policy and authorization add human review for
  high-value legitimate cases, capability containment, and explainability.
- The FP column is the simulated agent's: with adjudication off, the naive
  agent denies 40.0% of deserved refunds because it does not
  recognise their wording.

## F. Financial risk on labelled synthetic data (`results/financial.json`)

Dataset: seed 42, 150 customers, 30 merchants, 3183 transactions; risk model
`txn-1.0`. Positive = risk level HIGH or CRITICAL. Labels come from the
generator's injected scenarios and are read only by this suite. Risk exists at
three levels and each scenario is evaluated at the level meant to catch it.

**The rule weights were tuned while looking at seed 42**, so the table
below is the development figure; the held-out seeds further down were never
inspected.

| Level | Scenarios | Precision | Recall | FPR | FNR | tp / fp / fn / tn |
|---|---|---:|---:|---:|---:|---|
| transaction | account takeover, bursts, ring transactions | 93.3% | 26.9% | 0.03% | 73.1% | 14 / 1 / 38 / 3130 |
| account (monitoring) | structuring-like, dormant activation, rings, bursts | 71.4% | 100.0% | 2.68% | 0.0% | 10 / 4 / 0 / 145 |
| merchant (profile) | abused / shell / repeatedly flagged (n=3 positives) | 40.0% | 66.7% | 11.11% | 33.3% | 2 / 3 / 1 / 24 |

Transaction-level recall by scenario: account_takeover 66.7% (n=6), burst 14.3% (n=28), graph_linked 33.3% (n=18). Account-level: burst 100.0% (n=3), dormant_activation 100.0% (n=2), graph_linked 100.0% (n=3), structuring 100.0% (n=2).

Why the numbers look the way they do:

- **Account-level recall is 100% by construction.** Each account scenario is
  the mirror image of a monitoring rule (structuring = three transfers at
  80–100% of the threshold within 7 days; the generator emits four in four
  days). The four seed-42 false positives are legitimate accounts whose
  random baseline transfers form a cycle somewhere in 240 days: the
  circular-transfer indicator is not bounded to the monitoring window. Left as
  is and documented rather than tuned.
- **Transaction-level recall is low by construction.** The first several
  transactions of a burst carry no velocity yet; the second account-takeover
  transaction is in the same country as the first, so impossible travel does
  not fire; and the generator registers the attacker's device as a known
  account device, so `new_device` never fires on takeover transactions (a
  generator realism bug that *depresses* recall; documented, not patched).
- **Transaction-level precision moved from 73.7% to 93.3%** in
  v2.0.1 without a weight change: the baseline was counting disputes filed
  *after* the transaction being scored (temporal leakage), which inflated
  legitimate transactions' chargeback factor. Recall was unaffected.
- **Merchant-level has n=3 positives**, two defined by fields the
  profile reads directly; it is reported for completeness, not as a result.

### Held-out seeds (weights never inspected against these)

| Seed | Level | Precision | Recall | FPR | tp / fp / fn / tn |
|---|---|---:|---:|---:|---|
| seed 7 | transaction | 93.3% | 26.9% | 0.03% | 14 / 1 / 38 / 3129 |
| seed 7 | account (monitoring) | 100.0% | 100.0% | 0.00% | 10 / 0 / 0 / 147 |
| seed 7 | merchant (profile) | 66.7% | 66.7% | 3.70% | 2 / 1 / 1 / 26 |
| seed 2024 | transaction | 85.7% | 40.7% | 0.13% | 24 / 4 / 35 / 3116 |
| seed 2024 | account (monitoring) | 100.0% | 100.0% | 0.00% | 10 / 0 / 0 / 144 |
| seed 2024 | merchant (profile) | 100.0% | 100.0% | 0.00% | 2 / 0 / 0 / 28 |

Range across all three seeds:

| Level | Precision | Recall | FPR |
|---|---:|---:|---:|
| transaction | 85.7%–93.3% | 26.9%–40.7% | 0.0%–0.1% |
| account (monitoring) | 71.4%–100.0% | 100.0%–100.0% | 0.0%–2.7% |
| merchant (profile) | 40.0%–100.0% | 66.7%–100.0% | 0.0%–11.1% |

Calibration (observed fraud-labelled rate per transaction risk band, seed 42):

| Band | n | observed fraud rate |
|---|---:|---:|
| LOW | 2954 | 0.5% |
| MEDIUM | 214 | 10.8% |
| HIGH | 10 | 90.0% |
| CRITICAL | 5 | 100.0% |

Policy outcomes on a 400-transaction sample through the full pipeline
(`transaction-authorization@latest`, no agent): fraud-labelled transactions allowed
28.8%, legitimate transactions blocked or denied 0.0%.
The risk model is a transparent rule table, not ML; these numbers describe it
honestly on this generator.

## G. Decision integrity (`results/integrity.json`)

The invariant, stated precisely: **untrusted text and model output cannot
produce an outcome the trusted records do not support.** Untrusted text does
select *which* trusted fact is checked (the claim type); it never exceeds the
ledger-supported ceiling. Measured over 136 attacks (dev + held-out)
and 14 deserved controls:

| Question | Sentinel | No controls | kind |
|---|---:|---:|---|
| Attacker text made the decision **more permissive** (unsupporting ledgers) | **0.0%** | 77.9% | structural |
| Attacker text changed the outcome at all (tightening only) | 43.4% | — | empirical |
| Injection appended to a deserved claim **loosened** it (n=84) | **0.0%** | — | structural |
| Injection appended to a deserved claim tightened it (held for a human) | 100.0% | — | empirical |
| A different model recommendation changed the outcome (n=360) | **0.0%** | — | structural |
| *Supporting ledger:* attacker text exceeded the ledger-supported ceiling | **0.0%** | — | structural |
| *Supporting ledger:* a capability executed without ledger support | **0.0%** | — | structural |
| *Supporting ledger:* attacker text changed the outcome vs a neutral message (selected the claim) | 61.8% | — | by design |
| *Supporting ledger:* attacker text was approved (a deserved refund, whatever the prose) | 8.1% | — | by design |

The structural rows are expected to be 0 -- the attack ledgers do not support
the claims -- and are kept as regression checks. The last two rows are the
honest shape of the property: text can choose which fact is checked, and a
refund the ledger supports is paid even when the message around it is an
attack.

## H. Performance (`results/performance.json`)

macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7; offline agent; workloads: 310-char injected
narrative, 40-transaction baseline, graph of 8,144 nodes / 14,682 edges,
9-rule policy, 500 end-to-end iterations. Sequential, single-threaded,
persistence excluded; machine-dependent.

| Component | p50 ms | p95 ms | p99 ms | ops/s |
|---|---:|---:|---:|---:|
| `normalize` | 0.0174 | 0.0184 | 0.0211 | 56,869 |
| `gateway_inspect` | 0.1736 | 0.1832 | 0.2002 | 5,716 |
| `claim_classify` | 0.019 | 0.0202 | 0.0241 | 51,935 |
| `evidence_reconcile` | 0.0216 | 0.0241 | 0.0304 | 45,546 |
| `risk_score_transaction` | 0.0117 | 0.0126 | 0.0149 | 83,930 |
| `graph_linked_accounts` | 0.0041 | 0.0042 | 0.0051 | 239,075 |
| `graph_neighborhood_d2` | 0.1567 | 0.1735 | 0.1934 | 6,258 |
| `policy_evaluate` | 0.0088 | 0.0094 | 0.0153 | 109,427 |
| `decision_compose` | 0.0317 | 0.0349 | 0.0431 | 31,082 |
| `audit_append` | 0.0085 | 0.0101 | 0.0142 | 112,422 |
| `e2e_dispute_pipeline` | 0.4181 | 0.4556 | 0.5725 | 2,354 |

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
make eval                      # everything above, writes results/*.json and charts
make docs                      # re-render this file and the README / résumé numbers from results/
sentinel eval run --suite security|heldout|kyb|baselines|ablation|financial|integrity|performance|models|charts
sentinel eval run --suite financial --full     # larger dataset (400 customers / 12k transactions)
make test                      # 231 tests, incl. tests/test_results_regression.py which recomputes the headline claims
```
