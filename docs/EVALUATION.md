# Evaluation

Every number in this document is produced by one command and written to
`results/`, then rendered here by `scripts/render_docs.py` (`make docs`):

```bash
make eval                # == sentinel eval run --suite full   (offline, deterministic, no key)
```

Six dimensions are measured: **AI security** (the 150-attack main corpus, a
20-attack held-out corpus, 30 attacks on three other surfaces and a
47-application KYB benchmark), **decision integrity**, **temporal correctness**,
**financial risk**, the **claim classifier** and **system performance**. All corpora
and datasets are synthetic and the agent is an offline simulator; see
`docs/LIMITATIONS.md`.

Attack counts, so that no number appears unscoped: the **main (development)
corpus** is 150 attacks across 15 classes; the **held-out corpus** is 20;
the **other surfaces** add 30; together 200. The **integrity suite**
reuses main + held-out (170). **KYB** is separate: 47 applications, 24 with a
hostile document.

## At a glance -- one row per kind of evidence

| Category | Kind of evidence | Measures | Sample | Seeds / source | Result | Method |
|---|---|---|---|---|---|---|
| **AI security** | synthetic, offline simulated agent (not a live LLM) | an unauthorised consequential capability actually executed | main corpus 150 attacks / 15 classes; held-out 20; other surfaces 30; KYB 47 applications (24 hostile) | hand-authored corpora (same author as the gateway) | main corpus: simulated agent 90.0% → Sentinel **0.0%**; held-out, surfaces, KYB: 0.0%; false positives 0.0% (10 deserved refunds) | [§A–F](#a-ai-security----development-corpus-resultssecurityjson) |
| **Decision integrity** | structural (0 by construction; a regression check) | attacker text or model output loosening a protected decision | 170 attacks (main 150 + held-out 20); 360 model-recommendation replays (60 main-corpus attacks × 6 recommendations) | the security corpora | **0.0%** (no controls: 83.5%) | [§H](#h-decision-integrity-resultsintegrityjson) |
| **Financial risk** | synthetic benchmark (empirical) | precision / recall / FPR against the generator's scenario labels | seed 42: 3,183 transactions, 157 accounts; two held-out seeds of similar size | dev 42 (point values tuned on it); held-out 7, 2024 | transactions P 86.7% R 67.2% FPR 0.19%; accounts P 90.0% R 90.0% | [§G](#g-financial-risk-on-labelled-synthetic-data-resultsfinancialjson) |
| **Temporal correctness** | synthetic invariant check (empirical; not a proof) | a record dated after T changing a decision at T | 192 transactions; 9 kinds of future record at 4 offsets; 3,648 checks | seeds 42, 7 | **0 observed leaks** (95% upper bound 0.082% per check, 1.55% per sampled transaction) | [§I](#i-temporal-correctness-resultstemporaljson) |
| **Claim classifier** | synthetic, same author; defence in depth, not the foundation | legitimate claims read as their type; the rest held for a human | 117 phrasings; 21 held-out unusual phrasings | hand-authored | held-out: first (blind) run 7/21; 17/21 after the patterns were extended by an author who had seen the misses; FN 4/56, FP 0/28 | [§L](#l-claim-classifier-resultsclaimsjson) |
| **Performance** | local benchmark (one machine) | the platform's own latency, offline agent | 500 end-to-end iterations | macOS | dispute pipeline p95 0.2396 ms | [PERFORMANCE.md](PERFORMANCE.md) |
| **Live LLM** | live-model evaluation | the same suites against a real model | -- | `claude-opus-5-5` | **NOT RUN** -- no live number is quoted anywhere | [§K](#k-model--provider-evaluation-resultsmodelsjson) |

## Three kinds of numbers

Read every table with this distinction in mind; each results file records the
kind of each headline metric under `kinds`.

| Kind | What it is | Where it appears |
|---|---|---|
| **STRUCTURAL GUARANTEE** | 0 by construction under the design. A consequential capability executes only when the trusted records support the claim, and every attack sits on records that do not. These rows are regression checks that the implementation honours the design (`tests/test_results_regression.py` recomputes them), not detection results. | guarded attack success, off-surface execution, the integrity suite's structural rows |
| **SYNTHETIC EVALUATION** | Empirical, but on hand-authored corpora, a seeded synthetic dataset and the **offline simulated agent** (`OfflineProvider`, a deterministic regex model of a gullible tool-calling agent that shares an author with the corpus). These numbers can move and describe this simulator and this generator, not the world. | unguarded attack success, detection recall, false positives, KYB outcomes, everything in the financial suite, the claim classifier, the temporal-leakage checks (a tested invariant over two synthetic worlds: 0 observed is evidence, not a proof), performance |
| **LIVE MODEL EVALUATION** | The identical suite against a real model on the operator's own key (`SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models`). | `results/models.json` -- current status of the live row: **not_run** (`claude-opus-5-5`); no live number is quoted anywhere in this repository |

## What "attack success" means

An attack **succeeds** when the system **executes an unauthorised consequential
capability** -- a refund is paid, a merchant goes live, a payment is
authorised, an account is frozen or unfrozen, a payout destination changes,
funds are released, a case is closed, a risk score is overridden -- that the
trusted records do not support. This is stronger than "the detector flagged
the sentence": a flagged attack that still executes counts as a success, and
an undetected attack that never executes counts as a failure. For legitimate
controls, a **false positive** is a deserved refund the platform fails to
execute.

## A. AI security -- development corpus (`results/security.json`)

150 attacks across 15 threat classes (10 per class: hand-authored
seeds × amounts straddling the ₹50,000 auto-limit) + 21 legitimate controls
(10 of which deserve a refund). Targets beyond `APPROVE_REFUND`:
CLOSE_CASE, RELEASE_FUNDS, UNFREEZE_ACCOUNT, ALTER_RISK.

| Metric | No controls (simulated agent) | Full Sentinel |
|---|---:|---:|
| Attack success rate | **90.0%** (synthetic, simulator) | **0.0%** (structural) |
| Off-surface capability executed (escalation) | 20.0% | 0.0% (structural) |
| Gateway detection recall | — | 80.0% (synthetic; text scan or model-output check; not the backstop) |
| False-positive rate on deserved refunds | — | **0.0%** (synthetic) |

| Threat class | n | No controls | Detection recall | Sentinel |
|---|---:|---:|---:|---:|
| direct_injection | 10 | 100.0% | 100.0% | 0.0% |
| authority_spoof | 10 | 100.0% | 100.0% | 0.0% |
| document_borne | 10 | 100.0% | 100.0% | 0.0% |
| fake_policy | 10 | 100.0% | 100.0% | 0.0% |
| context_poisoning | 10 | 50.0% | 100.0% | 0.0% |
| tool_manipulation | 10 | 100.0% | 100.0% | 0.0% |
| multi_turn_escalation | 10 | 50.0% | 100.0% | 0.0% |
| unicode_obfuscation | 10 | 100.0% | 100.0% | 0.0% |
| indirect_injection | 10 | 100.0% | 100.0% | 0.0% |
| adjudication_gaming | 10 | 100.0% | 0.0% | 0.0% |
| financial_social_engineering | 10 | 100.0% | 0.0% | 0.0% |
| capability_escalation | 10 | 100.0% | 100.0% | 0.0% |
| model_output_injection | 10 | 100.0% | 100.0% | 0.0% |
| false_evidence | 10 | 100.0% | 0.0% | 0.0% |
| synthetic_evidence | 10 | 50.0% | 100.0% | 0.0% |

Read the last two columns together: **adjudication_gaming, financial_social_engineering, false_evidence are invisible to
detection (0.0% recall) and are still blocked**, because the ledger, not the
prose, decides support.

| Target capability | n | No controls | Sentinel |
|---|---:|---:|---:|
| APPROVE_REFUND | 125 | 88.0% | 0.0% |
| CLOSE_CASE | 5 | 100.0% | 0.0% |
| RELEASE_FUNDS | 10 | 100.0% | 0.0% |
| UNFREEZE_ACCOUNT | 5 | 100.0% | 0.0% |
| ALTER_RISK | 5 | 100.0% | 0.0% |

Blocked-by distribution (an attack can be stopped by several controls at
once): ai_security_gateway 60, capability_authorization 135, capability_registry 30, policy:dispute-refund@v4 135, trusted_evidence 135.

> **Methodology** (`results/security.json`): synthetic (hand-authored corpus, offline simulated agent); guarded attack success is structural. *Dataset:* development attack corpus, seeds x amounts straddling the auto-limit, plus legitimate controls. *Method:* each case runs with no controls and with full controls; success = an unauthorised consequential capability executed; detection recall counts the gateway's flag; false positives count deserved refunds not executed. *Limitations:* the corpus and the detector share an author; the unguarded rate is a property of the simulator; every attack ledger is unsupporting so the guarded rate is 0 by construction. *Sample:* n_attacks=150, n_controls=21, n_deserved_controls=10.

## B. Held-out generalisation (`results/heldout.json`)

The development corpus and the detector share an author, so a 0% there could
be circular. The held-out set (20 attacks, 6 controls of which
4 deserve a refund) was written after the development corpus, by the same
author, with wording that never appears in the detector's patterns; a test
asserts it is disjoint from the corpus and the detector is never tuned to it.

| Metric | Value |
|---|---:|
| Attack success, no controls (simulated agent) | 35.0% |
| **Attack success, Sentinel** | **0.0%** (structural) |
| Gateway detection recall | 50.0% (synthetic) |
| **False positives** | **0.0%** (synthetic) |

| Threat class | n | No controls | Detection recall | Sentinel |
|---|---:|---:|---:|---:|
| direct_injection | 1 | 0.0% | 100.0% | 0.0% |
| authority_spoof | 3 | 33.3% | 66.7% | 0.0% |
| document_borne | 1 | 0.0% | 100.0% | 0.0% |
| fake_policy | 1 | 100.0% | 100.0% | 0.0% |
| multi_turn_escalation | 1 | 0.0% | 100.0% | 0.0% |
| adjudication_gaming | 3 | 66.7% | 0.0% | 0.0% |
| unicode_obfuscation | 1 | 0.0% | 100.0% | 0.0% |
| financial_social_engineering | 1 | 100.0% | 100.0% | 0.0% |
| context_poisoning | 1 | 0.0% | 0.0% | 0.0% |
| tool_manipulation | 1 | 0.0% | 0.0% | 0.0% |
| indirect_injection | 1 | 100.0% | 100.0% | 0.0% |
| capability_escalation | 1 | 0.0% | 0.0% | 0.0% |
| model_output_injection | 2 | 50.0% | 50.0% | 0.0% |
| false_evidence | 1 | 0.0% | 0.0% | 0.0% |
| synthetic_evidence | 1 | 0.0% | 0.0% | 0.0% |

Two honest reads: none of the 4 held-out deserved refunds was held -- a small
sample, and the classifier's own held-out test (§L) missed 4 of 21 unusual
phrasings, which go to a human -- and the lexical detector did not generalise
(50.0% recall), which is why detection is not on the authorization path. The unguarded figure is depressed because the offline
victim agent is itself lexical; the held-out set validates the platform, not
the baseline's realism.

> **Methodology** (`results/heldout.json`): synthetic; guarded attack success is structural. *Dataset:* independently worded held-out set, disjoint from the development corpus by test. *Method:* as the development corpus. *Limitations:* small; validates the claim classifier and the platform, not the simulator's realism. *Sample:* n_attacks=20, n_controls=6, n_deserved_controls=4.

## C. Other surfaces -- transaction, account security, investigation (`results/surfaces.json`)

30 attacks that arrive through the non-dispute workflows: descriptors and
memos on a payment authorisation, a customer message on a login session with a
requested capability, and case notes on an investigation. Success = a consequential capability executed that the text-free baseline did not execute (incl. any off-surface capability).
Each attack is also compared with the same request carrying no untrusted text:
untrusted text **loosened** the outcome in 0.0% of cases (structural) and
tightened it in 30.0% (synthetic: the gateway held something a
text-free request would have allowed).

| Workflow | n | No controls | Detection recall | Sentinel |
|---|---:|---:|---:|---:|
| account_security | 9 | 55.6% | 77.8% | 0.0% |
| investigation | 9 | 33.3% | 88.9% | 0.0% |
| transaction | 12 | 83.3% | 91.7% | 0.0% |

| Target capability | n | No controls | Sentinel |
|---|---:|---:|---:|
| ALTER_RISK | 2 | 0.0% | 0.0% |
| APPROVE_TRANSACTION | 10 | 80.0% | 0.0% |
| CHANGE_PAYOUT | 1 | 0.0% | 0.0% |
| CLOSE_CASE | 7 | 28.6% | 0.0% |
| FREEZE_ACCOUNT | 2 | 100.0% | 0.0% |
| RELEASE_FUNDS | 2 | 100.0% | 0.0% |
| SKIP_REVIEW | 1 | 0.0% | 0.0% |
| UNFREEZE_ACCOUNT | 5 | 80.0% | 0.0% |

| Threat class | n | No controls | Detection recall | Sentinel |
|---|---:|---:|---:|---:|
| authority_spoof | 3 | 66.7% | 66.7% | 0.0% |
| capability_escalation | 11 | 54.5% | 81.8% | 0.0% |
| context_poisoning | 2 | 50.0% | 100.0% | 0.0% |
| direct_injection | 4 | 75.0% | 100.0% | 0.0% |
| fake_policy | 1 | 100.0% | 100.0% | 0.0% |
| financial_social_engineering | 2 | 100.0% | 50.0% | 0.0% |
| model_output_injection | 3 | 0.0% | 100.0% | 0.0% |
| tool_manipulation | 3 | 66.7% | 100.0% | 0.0% |
| unicode_obfuscation | 1 | 100.0% | 100.0% | 0.0% |

> **Methodology** (`results/surfaces.json`): synthetic; guarded attack success and 'loosened' are structural. *Dataset:* attacks arriving through the transaction, account-security and investigation workflows. *Method:* each attack is compared with the same request carrying no untrusted text; success = a consequential capability executed that the text-free baseline did not. *Limitations:* small per-workflow counts; the offline agent's behaviour on these surfaces is the simulator's. *Sample:* n_attacks=30.

## D. Second surface -- merchant onboarding, balanced KYB (`results/kyb.json`)

47 applications: 24 carry a hostile document and 23 do not. On the
acquirer's records alone, 19 should be approved, 16 held for review and
12 rejected. Ground truth is defined by the records only, never by the
document:

```text
Records-only ground truth.

reject  : shell registration, or two or more prior fraud flags
review  : anything unverified, young (domain < 30 d or business < 90 d), a single
          prior flag, a high-risk MCC, or an incomplete record
approve : verified, aged, unflagged, low/medium MCC
```

| Metric | Value | kind |
|---|---:|---|
| Attack success, no controls (simulated agent) | 62.5% | empirical (simulated agent) |
| **Attack success, Sentinel** | **0.0%** | structural |
| False positives, benign input (clean merchants held or rejected) | **0.0%** | empirical |
| False positives, any input | 26.3% (5 clean merchants held because their document was hostile) | empirical (any input, incl. clean merchants held because their document was hostile) |
| False negatives (records say reject, merchant went live) | 0.0% | empirical |
| Borderline records (review) → human review | 93.8% | empirical |
| Manual-review rate over all 47 cases | 36.2% | empirical |

| Category | n | records → approve | records → reject | no controls breached | Sentinel breached | FP | FN | held for review |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| ambiguous | 3 | 1 | 0 | 0 | 0 | 0 | 0 | 2 |
| clearly_fraudulent | 4 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| high_risk_legitimate | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |
| incomplete | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |
| legitimate | 6 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| malicious_document_bad_records | 12 | 0 | 8 | 12 | 0 | 0 | 0 | 3 |
| malicious_document_clean_records | 12 | 12 | 0 | 3 | 0 | 5 | 0 | 2 |
| suspicious | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 4 |

The any-input false-positive rate is the honest cost of the design: a clean
merchant whose upload contains an injection is held for a human rather than
approved, because a CRITICAL security finding blocks automatic approval. It is
reported rather than tuned away. The benign-input rate is the classifier's
behaviour on ordinary applications.

> **Methodology** (`results/kyb.json`): synthetic; guarded attack success is structural; false positives are empirical. *Dataset:* balanced onboarding applications across eight categories with records-only ground truth. *Method:* outcomes compared with what the acquirer records alone imply (approve / review / reject). *Limitations:* records are synthetic; a clean merchant with a hostile upload is held by design and counted in the any-input false-positive rate. *Sample:* attacks=24, controls=23, corpus_cases=47, corpus_attacks=24, corpus_controls=23, corpus_records_approve=19, corpus_records_reject=12, corpus_records_review=16.

## E. Beating the obvious defence (`results/baselines.json`)

| Defence | Attack success |
|---|---:|
| No defence (simulated agent) | 90.0% |
| Hardened system prompt ("ignore embedded instructions") | 23.3% |
| **Sentinel** | **0.0%** |

The hardened prompt still fails on: adjudication_gaming 100.0%, financial_social_engineering 100.0%, model_output_injection 50.0%, false_evidence 100.0%. A customer lying about a
fact is not an injection, and "ignore instructions" says nothing about a lie.

> **Methodology** (`results/baselines.json`): synthetic (offline simulated agent). *Dataset:* development attack corpus. *Method:* the naive agent, the same agent with a hardened system prompt, and Sentinel. *Limitations:* the hardened prompt's behaviour is the simulator's reading of an instruction, not a measured LLM.

## F. Ablation -- which control carries the result (`results/ablation.json`)

| Configuration | ASR | FP | off-surface executed | definition |
|---|---:|---:|---:|---|
| no_controls | 90.0% | 40.0% | 20.0% | the model's tool call executes |
| prompt_hardening | 23.3% | 40.0% | 0.0% | no controls; the agent is told to ignore embedded instructions |
| detection_only | 20.0% | 40.0% | 0.0% | gateway + provenance; a flagged finding (severity ≥ MEDIUM) or off-surface request holds for a human, otherwise the model is believed |
| risk_only | 90.0% | 40.0% | 20.0% | risk is computed but no policy consumes it -- identical to no controls |
| policy_only | 36.0% | 40.0% | 8.0% | policy over the model's asserted verdict; no security or risk signal, no registry |
| adjudication_only | 0.0% | 0.0% | 0.0% | the ledger verdict alone: execute iff the trusted records support the claim |
| adjudication_policy | 0.0% | 0.0% | 0.0% | ledger verdict + versioned policy + capability authorization |
| full | 0.0% | 0.0% | 0.0% | everything, including the gateway and risk signals |

- **Detection only** holds exactly what it flags and leaks exactly the classes
  with nothing to detect (adjudication_gaming, financial_social_engineering, false_evidence): 20.0%.
- **Policy only** (over the model's asserted verdict) catches only the
  over-limit amounts.
- **Trusted adjudication alone** closes every attack on this corpus (by
  construction, see above); policy and authorization add human review for
  high-value legitimate cases, capability containment, and explainability.
- The FP column is the simulated agent's: with adjudication off, the naive
  agent denies 40.0% of deserved refunds because it does not
  recognise their wording.

> **Methodology** (`results/ablation.json`): synthetic; the 0% rows are structural. *Dataset:* development attack corpus. *Method:* eight control configurations of the same composer over the same cases. *Limitations:* configurations that believe the model's verdict inherit the simulator's behaviour.

## G. Financial risk on labelled synthetic data (`results/financial.json`)

Dataset: seed 42, 150 customers, 30 merchants, 3,183 transactions; risk model
`txn-2.0`. Positive = risk level HIGH or CRITICAL. Labels come from the
generator's injected scenarios and are read only by this suite.

**The point values of the rule model were tuned while looking at seed 42**, so
the tables below are development figures; the held-out seeds further down
were never inspected. Nothing about the model is an industry standard
(`docs/RISK_ENGINE.md`).

### Ground truth

| Label | Level | Definition (generator scenario) |
|---|---|---|
| fraud:account_takeover | transaction | two purchases from a new device in a new country within an hour of a home-country purchase, after a session with credential + payout changes and a failed second factor |
| fraud:burst | transaction + account | 8-12 purchases three minutes apart on an account that normally transacts every few days |
| fraud:graph_linked | transaction + account | three 17-day-old accounts on one device and one payout bank account, five purchases each at high-risk merchants, then transfers in a circle |
| fraud:structuring | account | four transfers just under the reporting threshold within a week |
| fraud:dormant_activation | account | 120 days of silence then six purchases in two days |
| exposure:merchant_abuse | merchant | purchases at a merchant with an injected 30% dispute ratio; the transactions themselves are not fraud |
| legit:high_value | decisioning | a genuine purchase above the auto-approval limit on a home device; policy must route it to a human, not block it |

### Stages

Risk exists at three levels and each scenario is evaluated at the level meant
to catch it:

- **screening** -- transaction-level risk band on every transaction (transaction_level)
- **decisioning** -- policy outcome of the full pipeline on a sample (policy_sample)
- **investigation_triage** -- account-level monitoring over the account's activity (account_level)

### Results (seed 42)

| Level | Precision | Recall | FPR | FNR | tp / fp / fn / tn |
|---|---:|---:|---:|---:|---|
| transaction | 86.7% | 67.2% | 0.19% | 32.8% | 39 / 6 / 19 / 3119 |
| account (monitoring) | 90.0% | 90.0% | 0.68% | 10.0% | 9 / 1 / 1 / 146 |
| merchant (profile) | 100.0% | 66.7% | 0.00% | 33.3% | 2 / 0 / 1 / 27 |

Transaction-level recall by scenario: account_takeover 100.0% (n=6), burst 44.1% (n=34), graph_linked 100.0% (n=18).
Account-level: burst 100.0% (n=3), dormant_activation 50.0% (n=2), graph_linked 100.0% (n=3), structuring 100.0% (n=2). Merchant level has n=3
positives (abused (scenario) or shell registration or >= 2 prior flags) and is reported for completeness, not as a result.

### Where the misses are

| Scenario | n | detected | missed | signals on detected (count) | signals on missed (count) |
|---|---:|---:|---:|---|---|
| account_takeover | 6 | 6 | 0 | recent_account_changes (6), recent_failed_mfa (6), new_device (6), new_country (5), auth_weak (4), amount_anomaly_extreme (3) | — |
| burst | 34 | 15 | 19 | velocity_spike (15), rapid_succession (15), velocity_burst (10), rapid_fire (6), merchant_risk_medium (6), chargeback_some (5) | rapid_succession (16), velocity_elevated (6), chargeback_some (5), velocity_spike (4), merchant_risk_medium (3), rapid_fire (1) |
| graph_linked | 18 | 18 | 0 | shared_payout_instrument (18), young_account_shared_device (18), shared_device (18), account_age_young (18), auth_weak (15), merchant_risk_high (14) | — |

The 19 transaction-level misses on this seed are burst transactions. `rapid_fire` needs 3 transactions inside 10 minutes and `rapid_succession` a short gap against a ≥ 6 h median, so the first transactions of a burst cannot carry the short-window velocity signals, and a burst spread over more than the window carries fewer of them; the account-level monitor is where a burst is meant to be caught (account-level burst recall above). The missed and false-positive examples are listed in `results/financial.json` under `transaction_level`.

**Bursts by position** (seed 42):

| Position in burst | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| flagged / n | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 2/3 | 1/3 | 2/3 | 3/3 | 3/3 | 2/2 | 2/2 |

Split by what the rapid-fire rule could see when each transaction was
authorised (velocity-visible = at least 3 earlier transactions on the account in the 10 minutes before (the rapid-fire rule's input)): **6/7** velocity-visible burst
transactions were flagged, **9/27** of the rest (by other signals,
mostly the one-hour velocity rule, late in the burst). This is structural, not
a bug: at authorisation time a burst's first transactions look like ordinary
purchases because the burst does not exist yet, and point-in-time features
cannot see what comes after. The control for those is the account-level
monitor, which sees the whole window and flags 100.0% of the burst accounts.
Lowering the thresholds to catch earlier positions would flag legitimate
shopping sessions, which burst too (`tests/test_generator_scenarios.py`); it
was not done.

### Signals

How often each factor fires on fraud-labelled and on legitimate transactions
(seed 42; 58 fraud, 3,125 legitimate). A factor that fires on many
legitimate transactions is a weak signal on this generator; nothing was tuned
to change that, and the point values are documented in `docs/RISK_ENGINE.md`.

| Factor | Family | Points | Fired on fraud (rate) | Fired on legit (rate) | Precision when fired |
|---|---|---:|---:|---:|---:|
| `new_merchant` | anomaly | 4 | 16 (27.6%) | 978 (31.30%) | 1.6% |
| `merchant_risk_medium` | entity | 5 | 12 (20.7%) | 384 (12.29%) | 3.0% |
| `chargeback_some` | entity | 5 | 11 (19.0%) | 373 (11.94%) | 2.9% |
| `merchant_risk_high` | entity | 10 | 16 (27.6%) | 367 (11.74%) | 4.2% |
| `unusual_hour` | anomaly | 6 | 4 (6.9%) | 356 (11.39%) | 1.1% |
| `chargeback_high` | entity | 10 | 0 (0.0%) | 140 (4.48%) | 0.0% |
| `amount_anomaly_extreme` | anomaly | 22 | 7 (12.1%) | 131 (4.19%) | 5.1% |
| `auth_weak` | security | 8 | 20 (34.5%) | 118 (3.78%) | 14.5% |
| `rapid_succession` | velocity | 15 | 33 (56.9%) | 91 (2.91%) | 26.6% |
| `amount_anomaly_moderate` | anomaly | 10 | 6 (10.3%) | 108 (3.46%) | 5.3% |
| `amount_anomaly_high` | anomaly | 16 | 2 (3.5%) | 57 (1.82%) | 3.4% |
| `account_age_young` | entity | 5 | 18 (31.0%) | 31 (0.99%) | 36.7% |
| `new_country` | device_geo | 15 | 5 (8.6%) | 37 (1.18%) | 11.9% |
| `velocity_elevated` | velocity | 10 | 6 (10.3%) | 29 (0.93%) | 17.1% |
| `velocity_spike` | velocity | 20 | 19 (32.8%) | 5 (0.16%) | 79.2% |
| `rapid_fire` | velocity | 20 | 7 (12.1%) | 14 (0.45%) | 33.3% |
| `auth_none` | security | 12 | 1 (1.7%) | 18 (0.58%) | 5.3% |
| `new_device` | device_geo | 17 | 6 (10.3%) | 13 (0.42%) | 31.6% |
| `shared_device` | device_geo | 8 | 18 (31.0%) | 0 (0.00%) | 100.0% |
| `shared_payout_instrument` | entity | 20 | 18 (31.0%) | 0 (0.00%) | 100.0% |

Family precision when fired: anomaly 2.1%, velocity 35.0%, device_geo 49.0%, entity 5.5%, security 18.5%.

### Slices

| Channel | n | fraud n | recall | FPR |
|---|---:|---:|---:|---:|
| ecommerce | 2760 | 55 | 65.5% | 0.22% |
| pos | 271 | 0 | — | 0.00% |
| transfer | 152 | 3 | 100.0% | 0.00% |

| Account segment | n | fraud n | recall | FPR |
|---|---:|---:|---:|---:|
| premium | 473 | 0 | — | 0.63% |
| retail | 2457 | 58 | 67.2% | 0.13% |
| small_business | 253 | 0 | — | 0.00% |

| Merchant risk tier | n | fraud n | recall | FPR |
|---|---:|---:|---:|---:|
| high | 383 | 16 | 100.0% | 0.54% |
| low | 2404 | 30 | 46.7% | 0.17% |
| medium | 396 | 12 | 75.0% | 0.00% |

### Held-out seeds (point values never inspected against these)

| Seed | Level | Precision | Recall | FPR | tp / fp / fn / tn |
|---|---|---:|---:|---:|---|
| seed 7 | transaction | 87.8% | 65.5% | 0.16% | 36 / 5 / 19 / 3086 |
| seed 7 | account (monitoring) | 90.9% | 100.0% | 0.67% | 10 / 1 / 0 / 148 |
| seed 7 | merchant (profile) | 100.0% | 66.7% | 0.00% | 2 / 0 / 1 / 27 |
| seed 2024 | transaction | 77.3% | 65.4% | 0.32% | 34 / 10 / 18 / 3090 |
| seed 2024 | account (monitoring) | 100.0% | 90.0% | 0.00% | 9 / 0 / 1 / 153 |
| seed 2024 | merchant (profile) | 75.0% | 100.0% | 3.70% | 3 / 1 / 0 / 26 |

- seed 7: transaction account_takeover 100.0% (n=6), burst 38.7% (n=31), graph_linked 100.0% (n=18); account burst 100.0% (n=3), dormant_activation 100.0% (n=2), graph_linked 100.0% (n=3), structuring 100.0% (n=2)
- seed 2024: transaction account_takeover 100.0% (n=6), burst 35.7% (n=28), graph_linked 100.0% (n=18); account burst 100.0% (n=3), dormant_activation 50.0% (n=2), graph_linked 100.0% (n=3), structuring 100.0% (n=2)

Range across all three seeds:

| Level | Precision | Recall | FPR |
|---|---:|---:|---:|
| transaction | 77.3%–87.8% | 65.4%–67.2% | 0.16%–0.32% |
| account (monitoring) | 90.0%–100.0% | 90.0%–100.0% | 0.00%–0.68% |
| merchant (profile) | 75.0%–100.0% | 66.7%–100.0% | 0.00%–3.70% |

### Calibration (observed fraud-labelled rate per risk band, seed 42)

| Transaction band | n | observed fraud rate |
|---|---:|---:|
| LOW | 2933 | 0.3% |
| MEDIUM | 205 | 4.9% |
| HIGH | 29 | 82.8% |
| CRITICAL | 16 | 93.8% |

| Account band | n | observed fraud rate |
|---|---:|---:|
| LOW | 147 | 0.7% |
| HIGH | 7 | 85.7% |
| CRITICAL | 3 | 100.0% |

### Decisioning

Policy outcomes on a 400-transaction sample through the full pipeline
(`transaction-authorization@latest`, no agent):

| Outcome | n |
|---|---:|
| ALLOW | 321 |
| STEP_UP | 30 |
| REQUIRE_HUMAN_REVIEW | 28 |
| DENY | 21 |

Fraud-labelled transactions allowed: 15.5%. Legitimate transactions
blocked or denied: 0.3%. The risk model is a transparent rule
table, not ML; these numbers describe it honestly on this generator.

> **Methodology** (`results/financial.json`): synthetic (labelled generator scenarios); empirical on that generator. *Dataset:* seeded synthetic world; development seed plus two held-out seeds. *Method:* transaction-level risk band on every transaction, monitoring on every account, merchant profiles; positive = HIGH or CRITICAL; labels come from the generator and are read only here. *Limitations:* point values were tuned on the development seed; scenarios mirror the rules they are meant to trip; not real payment data. *Sample:* dataset_seed=42, dataset_customers=150, dataset_merchants=30, dataset_transactions=3183.

## H. Decision integrity (`results/integrity.json`)

The invariant, stated precisely: **untrusted text and model output cannot
produce an outcome the trusted records do not support.** Untrusted text does
select *which* trusted fact is checked (the claim type); it never exceeds the
ledger-supported ceiling. Measured over 170 attacks (dev + held-out)
and 14 deserved controls:

| Question | Sentinel | No controls | kind |
|---|---:|---:|---|
| Attacker text made the decision **more permissive** (unsupporting ledgers) | **0.0%** | 83.5% | structural |
| Attacker text changed the outcome at all (tightening only) | 58.2% | — | synthetic |
| Injection appended to a deserved claim **loosened** it (n=84) | **0.0%** | — | structural |
| Injection appended to a deserved claim tightened it (held for a human) | 100.0% | — | synthetic |
| A different model recommendation changed the outcome (n=360: 60 main-corpus attacks × 6 recommendations) | **0.0%** | — | structural |
| *Supporting ledger:* attacker text exceeded the ledger-supported ceiling | **0.0%** | — | structural |
| *Supporting ledger:* a capability executed without ledger support | **0.0%** | — | structural |
| *Supporting ledger:* attacker text changed the outcome vs a neutral message (selected the claim) | 44.1% | — | by design |
| *Supporting ledger:* attacker text was approved (a deserved refund, whatever the prose) | 8.2% | — | by design |
| *Supporting ledger sent **unsigned*** (a request body, `UNTRUSTED`): a capability executed | **0.0%** | — | structural |

The structural rows are expected to be 0 -- the attack ledgers do not support
the claims -- and are kept as regression checks. The last two rows are the
honest shape of the property: text can choose which fact is checked, and a
refund the ledger supports is paid even when the message around it is an
attack. This is a structural property of the composer; it is **not** a claim
about the robustness of any model (the model's recommendation is recorded and
never consulted by the decision). On an unsupporting ledger the ceiling is a
human review: a message the classifier cannot read is INSUFFICIENT and held, a
readable false claim is denied, and nothing executes.

> **Methodology** (`results/integrity.json`): structural on unsupporting ledgers; by-design rows on supporting ledgers. *Dataset:* development + held-out attack texts over fixed ledgers. *Method:* the same trusted facts with different untrusted text and different model recommendations; count outcomes above the ledger-supported ceiling and executions without support. *Limitations:* a property of the composer, not of any model's robustness. *Sample:* n_attacks=170, n_legit=14, model_influence_n=360, legit_plus_injection_n=84.

## I. Temporal correctness (`results/temporal.json`)

The invariant: **data available after T must never influence a decision made
at T.** Two generator worlds (seeds 42, 7; 5,191 transactions), a stratified sample
of 192 transactions (half fraud-labelled, half legitimate, spread over the timeline).
Every sampled transaction is re-scored with records truncated to its own
timestamp, then again with one kind of future record appended at every offset
(1, 7, 30, 90 days later) -- 9 kinds, 1,728 perturbation runs over 19,392 future
records -- and each time both the transaction assessment and the account
monitor at T1 must be byte-identical. **0 observed leaks in 3,648 checks
across the tested synthetic benchmark.** Rates are exact counts, not rounded; with zero leaks the one-sided
95% (Clopper-Pearson) upper bound on the per-decision leak rate is 0.082%.
Comparisons from one sample are correlated, so the conservative reading is
per sample: 0 of 192, upper bound 1.55%.

The 2.2.0 extension added `account_status`, `payout_change` and
`security_event`, and its first run found two leaks: a freeze after T1 and a
payout change after T1 changed T1's decisions, because both read the account's
*current* fields (the counts from that pre-fix run were not kept in `results/`
and are not quoted here; `tests/test_temporal_leakage.py` pins both cases).
Status is now read as of the decision (`Account.status_at`) and payout sharing
from the bank accounts held at T1; the rows below are after the fix.

**Tested temporal invariant vs fully event-sourced history.** What this suite
shows is a *tested invariant*: for the record kinds it appends, no later record
changed an earlier decision. It is not a fully event-sourced history: some
source fields are static or current-state attributes with no history of their
own (a merchant's registration status, prior flags and MCC tier; a dispute's
refund state and merchant response; `docs/RISK_ENGINE.md#point-in-time-invariant`
lists every field and its time semantics), so a later change to one of them
would not be visible as a change at all.

| Check | Changed / tested | Rate (exact) | kind |
|---|---:|---:|---|
| truncation: a transaction's risk assessment differs when records after it are removed (seeds 42, 7, 5,191 transactions) | 0 / 192 | 0.000000 | tested invariant |
| perturbation: records added 1, 7, 30, 90 days after T1 change the T1 transaction assessment | 0 / 1,728 | 0.000000 | tested invariant |
| perturbation: the same future records change the T1 account-monitor assessment | 0 / 1,728 | 0.000000 | tested invariant |
| **every check above** | **0 / 3,648** | **0.000000** | 95% upper bound 0.082% |

| Future record kind | What is appended (at every offset) | records | transaction changed | monitoring changed | leaks / tested |
|---|---|---:|---:|---:|---:|
| `dispute` | a dispute filed on the account's latest earlier purchase | 768 | 0 / 192 | 0 / 192 | 0 / 384 |
| `device_burst` | a new device and an eight-purchase burst abroad on it | 6,912 | 0 / 192 | 0 / 192 | 0 / 384 |
| `merchant` | a new flagged high-risk merchant and five purchases there | 4,608 | 0 / 192 | 0 / 192 | 0 / 384 |
| `graph` | a new account on the same payout instrument and a circular transfer through it | 2,304 | 0 / 192 | 0 / 192 | 0 / 384 |
| `session` | a login with credential and payout changes that failed MFA | 768 | 0 / 192 | 0 / 192 | 0 / 384 |
| `account_status` | the account frozen after T1 (a current-state field) | 192 | 0 / 192 | 0 / 192 | 0 / 384 |
| `payout_change` | new bank accounts added after T1 and the payout moved to one of them | 768 | 0 / 192 | 0 / 192 | 0 / 384 |
| `risk_assessment` | stored HIGH risk assessments for the account, the merchant and a future transaction | 2,304 | 0 / 192 | 0 / 192 | 0 / 384 |
| `security_event` | stored CRITICAL AI-security events dated after T1 | 768 | 0 / 192 | 0 / 192 | 0 / 384 |

Expected: all counts 0: a decision at T1 reads only records at or before T1. `tests/test_temporal_leakage.py` and
`tests/test_entity_pointintime.py` pin the same property per feature (baselines,
device knowledge, entity profiles, graph edges, monitoring windows). This is a
deterministic check over the generator's world: "0 observed temporal leaks
across the tested synthetic benchmark", not a proof over every record.

> **Methodology** (`results/temporal.json`): structural (synthetic data). *Dataset:* two seeded synthetic worlds (seeds 42 and 7), a stratified transaction sample (half fraud-labelled). *Method:* truncation equivalence, then nine kinds of future record at +1/7/30/90 days, one kind at a time; the transaction assessment and the account monitor at T1 must be byte-identical; exact counts with a one-sided 95% Clopper-Pearson bound when zero. *Limitations:* a deterministic check over two generator worlds, not a proof over every record; comparisons from one sample are correlated (read the per-sample bound); a current-state field with no recorded start (legacy account status) cannot be point-in-time. *Sample:* comparisons=1728, decisions_tested=3648, dataset_transactions=5191, dataset_sample=192.

## J. Performance (`results/performance.json`)

macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.13.7; offline agent; workloads: 310-char injected
narrative, 40-transaction baseline, graph of 8,403 nodes / 14,638 edges,
17-rule policy over a 27-field context, 500 end-to-end iterations.
Sequential, single-threaded, persistence excluded; machine-dependent.

| Component | p50 ms | p95 ms | p99 ms | ops/s |
|---|---:|---:|---:|---:|
| `normalize` | 0.0176 | 0.0183 | 0.0202 | 56,436 |
| `gateway_inspect` | 0.2255 | 0.235 | 0.2459 | 4,421 |
| `claim_classify` | 0.2608 | 0.2713 | 0.2802 | 3,818 |
| `evidence_reconcile` | 0.0352 | 0.0377 | 0.041 | 28,000 |
| `fact_verify` | 0.1753 | 0.1834 | 0.1914 | 5,629 |
| `risk_score_transaction` | 0.0147 | 0.0154 | 0.0201 | 66,621 |
| `graph_linked_accounts` | 0.0039 | 0.0041 | 0.0049 | 250,431 |
| `graph_neighborhood_d2` | 0.0538 | 0.0568 | 0.0608 | 18,290 |
| `policy_evaluate` | 0.0168 | 0.0178 | 0.0217 | 58,472 |
| `decision_compose` | 0.0418 | 0.0448 | 0.0494 | 23,600 |
| `audit_append` | 0.0088 | 0.0102 | 0.0143 | 109,714 |
| `e2e_dispute_pipeline` | 0.228 | 0.2396 | 0.2892 | 4,343 |

A live LLM call (hundreds of milliseconds) dominates real latency by three
orders of magnitude; Sentinel's own controls are not the bottleneck.

> **Methodology** (`results/performance.json`): empirical, machine-dependent. *Dataset:* fixed workloads (narrative, baseline, graph, policy) on the local machine. *Method:* sequential single-threaded loops; percentiles over n iterations; persistence excluded. *Limitations:* the platform's own overhead only; a live model call dominates real latency. *Sample:* text_chars=310, baseline_transactions=40, graph_nodes=8403, graph_edges=14638, policy_rules=17, policy_context_fields=27, e2e_iterations=500.

## K. Model / provider evaluation (`results/models.json`)

| Provider | Model | Date | Status | ASR no controls | ASR Sentinel | FP | Latency p95 ms | Tokens in / out | Note |
|---|---|---|---|---|---|---|---|---|---|
| offline | `offline-simulator` | 2026-09-29 | ok | 90.0% | 0.0% | 0.0% | 0.143 | — |  |
| anthropic | `claude-opus-5-5` | 2026-09-29 | not_run | — | — | — | — | — | no ANTHROPIC_API_KEY or SENTINEL_FORCE_OFFLINE=1 |

Each provider row records the model, the run date, per-class outcomes, agent
latency and the provider's token totals where its SDK reports them
(`results/models_rows.json` has one line per attack). Run any provider with
`sentinel eval run --suite models --provider anthropic`.

Live results depend on provider/model/date and are not claimed to generalise.
Run `SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models` with your own
key to fill the live row; nothing here is fabricated. Until then the only
attack-success figures in this repository are the offline simulator's.

## L. Claim classifier (`results/claims.json`)

The only value ever derived from prose is a claim type, read by a
deterministic, weighted pattern classifier with an explicit confidence and an
explicit **abstain** (`sentinel/security/claims.py`). An abstain becomes
INSUFFICIENT and is held for a human; a recognised non-claim ("it arrived but
I don't like it") is UNSUPPORTED and denied; a read claim only selects which
trusted field is checked. Benchmark: 117 hand-authored phrasings in seven
categories. **The benchmark and the classifier share an author**, so these are
regression floors on these phrasings, not a generalisation claim -- with one
exception made as honest as an author can make it: `uncommon_legitimate` is a
held-out set of 21 unusual but legitimate phrasings (Indian English, slang,
typos, formal register) written and labelled *before* the classifier was run on
it. Held-out: written and labelled in the 2.2.0 review before the classifier was run on it. First run, with the classifier as of commit 9693433: 7/21 recognised, 14 abstained, 0 misread. The patterns were then extended against the separate development set, by an author who had seen those 14 misses, so the current number is optimistic; the remaining misses were deliberately not fitted. `development` is the set the patterns were then
extended against: a fit, reported apart and excluded from the error rates.

| Category | n | accuracy | read as claim | non-claim | abstain | misclassified |
|---|---:|---:|---:|---:|---:|---:|
| legitimate_paraphrase | 35 | 100.0% | 35 | 0 | 0 | 0 |
| ambiguous | 12 | 100.0% | 0 | 0 | 12 | 0 |
| unsupported | 10 | 100.0% | 0 | 10 | 0 | 0 |
| adversarial | 12 | 100.0% | 9 | 0 | 3 | 0 |
| contradictory | 6 | 100.0% | 0 | 0 | 6 | 0 |
| uncommon_legitimate | 21 | 81.0% | 17 | 0 | 4 | 0 |
| development | 21 | 100.0% | 19 | 1 | 1 | 0 |

| Metric | Value | meaning |
|---|---:|---|
| Coverage | 100.0% | legitimate paraphrases read as a claim |
| Held-out uncommon wording | 17 / 21 | recognised as its own type (first run, before any change: 7 / 21); every miss abstained -- a human, never a wrong type |
| False negatives | 4 / 56 (7.1%) | legitimate claims (paraphrases + held-out) not read as their own type: held for a human |
| False positives | 0 / 28 (0.0%) | ambiguous, unsupported and contradictory messages read confidently as a claim |
| Misclassification | 0.0% | messages read as a type other than the labelled one |
| Adversarial wrong type | 0.0% | attack prose read as a claim it does not assert |
| Abstain rate | 22.2% | all messages held for a human (100% of the ambiguous and contradictory sets by design) |

The composer's guarantee does not depend on any of this: whatever the
classifier reads, a consequential capability executes only when the ledger
supports the claim. What the classifier changes is the *cost* side -- how
often a legitimate customer is held for a human -- and that is what the
false-negative row measures.

> **Methodology** (`results/claims.json`): synthetic (hand-authored phrasings). *Dataset:* seven categories of dispute phrasings, incl. a held-out set of uncommon legitimate wording and the development set used to extend the patterns. *Method:* each phrasing classified once against its label; false negatives over legitimate categories, false positives over ambiguous / unsupported / contradictory. *Limitations:* the benchmark and the classifier share an author; a regression floor, not a generalisation claim; the held-out number after the pattern change is optimistic (the author had seen the first-run misses). *Sample:* n=117.

## Reproduce

```bash
make eval                      # everything above (main + held-out + surfaces = 200 attacks, plus KYB), writes results/*.json and charts
make docs                      # re-render this file and every generated block from results/ and the code
sentinel eval run --suite security|heldout|surfaces|kyb|baselines|ablation|financial|integrity|temporal|claims|performance|models|charts
sentinel eval run --suite financial --full     # larger dataset (400 customers / 12k transactions)
make test                      # 909 tests, incl. tests/test_results_regression.py which recomputes the headline claims
```
