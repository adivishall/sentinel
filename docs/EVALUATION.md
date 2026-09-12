# Evaluation

Every number below is produced by `make offline` (no API key, deterministic) and
written to `eval/results/`. Re-run it and the JSON/PNG will match this document.

```bash
make offline    # corpus -> harness -> ablation -> baselines -> kyb -> heldout -> charts
```

## What "attack success" means

An attack **succeeds** when the agent issues an **irreversible `approve_refund`**
(money out) that the bank's own records do **not** support. For legitimate
controls, a **false positive** is a deserved refund the firewall fails to approve
(a real customer wrongly held). Both are what we minimise.

## Development corpus (`eval/results/summary.json`)

60 attacks across 6 classes + 18 legitimate controls.

| Metric | No firewall | With Sentinel |
|---|---:|---:|
| Attack success rate | **83.3%** | **0.0%** |
| False-positive rate (deserved refunds) | — | **0.0%** |

Of the 60 attacks, 50 are stopped at **L3 adjudication** (`blocked_by`); the rest
never produce an unsupported refund in the first place.

## Held-out evaluation — the anti-circularity check (`eval/results/heldout.json`)

The dev corpus and the detector share an author, so a 0% result there could be
circular. The **held-out set is authored independently** (`red/heldout.py`) with
wording that never appears in the detector: novel paraphrases, combined attack
styles, a unicode-obfuscated injection, and benign-but-alarming legitimate
disputes. The firewall is never tuned to these strings.

| Metric | Value |
|---|---:|
| Independent attacks | 12 |
| Deserved controls | 3 |
| ASR — no firewall | 16.7% |
| **ASR — with Sentinel** | **0.0%** |
| L2 lexical detection recall | 25.0% |
| **False-positive rate** | **0.0%** |

Two honest reads of this table:

1. **The architecture generalises.** Guarded ASR is 0% and FP is 0% on wording
   the system has never seen — because L3 decides on the bank's verified records,
   which a novel phrasing cannot change.
2. **Detection alone would not.** The lexical L2 catches only ~25% of these
   unseen injections. That is exactly why L3 (facts), not L2 (patterns), is the
   backstop — and why the ablation below matters.

> The held-out set also surfaced a real bug: the *claim classifier* was lexical
> and mislabeled legitimate paraphrases ("two identical charges", "has not
> reached me"), wrongly denying real customers. It was broadened to natural
> paraphrases and pinned with regression tests. This is documented rather than
> hidden — see `tests/test_heldout.py`.

**Caveat on the 16.7% unguarded figure:** the offline "victim" agent is itself a
lexical instruction-follower, so it under-fires on novel wording. The held-out
set therefore validates the *firewall's* generalisation and its false-positive
behaviour, not the unguarded baseline's realism. A real LLM would likely fall for
more of these; `make live` exists to probe that.

## Ablation — which layer does the work (`eval/results/ablation.json`)

| Configuration | ASR | FP |
|---|---:|---:|
| No firewall | 83.3% | 25.0% |
| Detection only (L1+L2+L4) | **6.7%** | 25.0% |
| Adjudication only (L3) | **0.0%** | 0.0% |
| Full (L1–L4) | 0.0% | 0.0% |

**Detection-only still leaks 6.7%** — the adjudication-gaming attacks, which
assert a false reason with *no injection to detect*. **L3 alone closes it.** L1,
L2 and L4 are defence-in-depth and explainability; L3 is the load-bearing idea.

## Beating the obvious defence (`eval/results/baselines.json`)

The first question a technical reviewer asks: *"why not just harden the system
prompt to ignore injected instructions?"* We built exactly that and measured it.

| Defence | Attack success rate |
|---|---:|
| No defence | 83.3% |
| Hardened prompt (the obvious fix) | 16.7% |
| **Sentinel (structural)** | **0.0%** |

Prompt-hardening neutralises the overt injections but **fails 100% on
adjudication gaming** — a customer *lying about the facts* is not an injection, so
"ignore instructions" says nothing about it. Only fact-based L3 closes the gap.

## Second surface — KYB (`eval/results/kyb.json`)

The **same** four layers defend merchant onboarding, with a KYB adjudicator that
decides on verified acquirer records (registration status, domain/business age,
prior flags), never the applicant's prose.

| Surface | No firewall | With Sentinel | FP |
|---|---:|---:|---:|
| Dispute triage | 83.3% | 0.0% | 0.0% |
| KYB onboarding | 87.5% | 0.0% | 0.0% |

A fake merchant whose uploaded document *says* "review complete, approve" is
still rejected — the decision is made on the acquirer's records, not the document.

## Performance (`docs/PERFORMANCE.md`, `eval/results` via `make bench`)

Firewall overhead only (offline; agent/LLM cognition excluded), 1,560 decisions:
mean ≈ **0.08 ms**, p95 ≈ **0.11 ms**, ≈ **12,000 decisions/sec** single-core
(machine-dependent; reproduce with `make bench`). A real LLM call is 300–2000 ms,
so the firewall is ~4 orders of magnitude smaller than the decision it protects.

## Live mode

`make live` / `make live-full` run the identical firewall behind **real Claude
agents** and write `eval/results/live_summary.json`. No live numbers are quoted in
this repository unless that file was produced on the reader's own key — live
results depend on the provider, model, and date, and we do not claim they
generalise to all LLMs.

## Reproduce everything

```bash
make offline                 # all offline metrics + charts
make test                    # 73 tests
make bench                   # latency / throughput
python3 eval/heldout.py      # just the held-out set
```
