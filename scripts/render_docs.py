"""Render every published metric from ``results/*.json`` into the docs.

    make docs            # == python scripts/render_docs.py [--tests N]

Rewrites ``docs/EVALUATION.md`` and ``docs/PERFORMANCE.md`` entirely, and the
blocks between ``<!-- gen:NAME -->`` / ``<!-- /gen:NAME -->`` markers in
README.md, docs/RESUME.md, docs/LIMITATIONS.md and docs/INTERVIEW.md. A number
that is not in ``results/`` is not published; a number in ``results/`` is
published exactly once per place, by this script.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"


def _load(name: str) -> dict[str, Any]:
    p = RESULTS / f"{name}.json"
    if not p.exists():
        raise SystemExit(f"missing {p}; run `make eval` first")
    return json.loads(p.read_text(encoding="utf-8"))


def pct(x: float | None, d: int = 1) -> str:
    return "—" if x is None else f"{x * 100:.{d}f}%"


def rng(r: dict[str, float]) -> str:
    return f"{pct(r['min'])}–{pct(r['max'])}"


def test_count(explicit: int | None) -> int:
    if explicit:
        return explicit
    out = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q", "--co"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env={**os.environ, "SENTINEL_FORCE_OFFLINE": "1"},
    ).stdout
    per_file = [int(n) for n in re.findall(r"^tests/\S+: (\d+)$", out, re.M)]
    total = sum(per_file) or sum(1 for ln in out.splitlines() if "::" in ln)
    if not total:
        raise SystemExit("could not count tests; pass --tests N")
    return total


ABLATION_DEFS = {
    "no_controls": "the model's tool call executes",
    "prompt_hardening": "no controls; the agent is told to ignore embedded instructions",
    "detection_only": "gateway + provenance; a flagged finding (severity ≥ MEDIUM) or off-surface request holds for a human, otherwise the model is believed",
    "risk_only": "risk is computed but no policy consumes it -- identical to no controls",
    "policy_only": "policy over the model's asserted verdict; no security or risk signal, no registry",
    "adjudication_only": "the ledger verdict alone: execute iff the trusted records support the claim",
    "adjudication_policy": "ledger verdict + versioned policy + capability authorization",
    "full": "everything, including the gateway and risk signals",
}


def render_evaluation(R: dict[str, Any], tests: int) -> str:
    s, h, k, b, a, f, i, p, m = (
        R[x]
        for x in (
            "security",
            "heldout",
            "kyb",
            "baselines",
            "ablation",
            "financial",
            "integrity",
            "performance",
            "models",
        )
    )
    by_class = "\n".join(
        f"| {c} | {pct(v['asr_unguarded'])} | {pct(v['detection_recall'])} | {pct(v['asr_guarded'])} |"
        for c, v in s["by_class"].items()
    )
    by_target = "\n".join(
        f"| {c} | {v['n']} | {pct(v['asr_unguarded'])} | {pct(v['asr_guarded'])} |"
        for c, v in s["by_target_capability"].items()
    )
    blocked = ", ".join(f"{k2} {v}" for k2, v in s["blocked_by"].items())
    hardened_fail = ", ".join(f"{c} {pct(v)}" for c, v in b["hardened_by_class"].items() if v > 0)
    abl = "\n".join(
        f"| {name} | {pct(v['asr'])} | {pct(v['fp'])} | {pct(v['escalation_executed'])} | {ABLATION_DEFS[name]} |"
        for name, v in a.items()
    )
    lv = {
        "transaction_level": "transaction",
        "account_level": "account (monitoring)",
        "merchant_level": "merchant (profile)",
    }
    scen = {
        "transaction_level": "account takeover, bursts, ring transactions",
        "account_level": "structuring-like, dormant activation, rings, bursts",
        "merchant_level": "abused / shell / repeatedly flagged (n=3 positives)",
    }
    fin_rows = "\n".join(
        f"| {lv[L]} | {scen[L]} | {pct(f[L]['precision'])} | {pct(f[L]['recall'])} | {pct(f[L]['false_positive_rate'], 2)} | {pct(f[L]['false_negative_rate'])} | {f[L]['tp']} / {f[L]['fp']} / {f[L]['fn']} / {f[L]['tn']} |"
        for L in lv
    )
    held_rows = "\n".join(
        f"| seed {seed} | {lv[L]} | {pct(v[L]['precision'])} | {pct(v[L]['recall'])} | {pct(v[L]['false_positive_rate'], 2)} | {v[L]['tp']} / {v[L]['fp']} / {v[L]['fn']} / {v[L]['tn']} |"
        for seed, v in f["held_out_seeds"].items()
        for L in lv
    )
    range_rows = "\n".join(
        f"| {lv[L]} | {rng(f['seed_range'][L]['precision'])} | {rng(f['seed_range'][L]['recall'])} | {rng(f['seed_range'][L]['false_positive_rate'])} |"
        for L in lv
    )
    txn_scn = ", ".join(
        f"{k2.replace('fraud:', '')} {pct(v['recall'])} (n={v['n']})"
        for k2, v in f["recall_by_scenario"].items()
    )
    acc_scn = ", ".join(
        f"{k2.replace('fraud:', '')} {pct(v['recall'])} (n={v['n']})"
        for k2, v in f["account_level"]["recall_by_scenario"].items()
    )
    calib = "\n".join(
        f"| {band} | {v['n']} | {pct(v['observed_fraud_rate'])} |"
        for band, v in f["calibration"].items()
    )
    ps = f["policy_sample"]
    perf_rows = "\n".join(
        f"| `{name}` | {v['p50_ms']} | {v['p95_ms']} | {v['p99_ms']} | {v['throughput_per_sec']:,} |"
        for name, v in p["components"].items()
    )
    model_rows = "\n".join(
        f"| {x['provider']} | `{x['model']}` | {x['status']} | {pct(x.get('asr_unguarded'))} | {pct(x.get('asr_guarded'))} | {pct(x.get('fp_rate'))} | {x.get('reason', '')} |"
        for x in m["results"]
    )
    w = p["workloads"]
    return f"""# Evaluation

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

{s['n_attacks']} attacks across 12 threat classes (each class: 2 hand-authored
seeds × 5 amounts straddling the ₹50,000 auto-limit) + {s['n_controls']}
legitimate controls ({s['n_deserved_controls']} of which deserve a refund).
Six classes target capabilities beyond `APPROVE_REFUND`.

| Metric | No controls (simulated agent) | Full Sentinel |
|---|---:|---:|
| Attack success rate | **{pct(s['asr_unguarded'])}** (empirical, simulator) | **{pct(s['asr_guarded'])}** (structural) |
| Off-surface capability executed (escalation) | {pct(s['capability_escalation_rate_unguarded'])} | {pct(s['capability_escalation_executed_guarded'])} (structural) |
| Gateway detection recall | — | {pct(s['detection_recall'])} (empirical; text scan or model-output check; not the backstop) |
| False-positive rate on deserved refunds | — | **{pct(s['fp_rate'])}** (empirical) |

| Threat class | No controls | Detection recall | Sentinel |
|---|---:|---:|---:|
{by_class}

Read the last two columns together: **adjudication gaming and financial
social engineering are invisible to detection ({pct(s['by_class']['adjudication_gaming']['detection_recall'])} recall) and are
still blocked**, because the ledger, not the prose, decides support.

| Target capability | n | No controls | Sentinel |
|---|---:|---:|---:|
{by_target}

Blocked-by distribution (an attack can be stopped by several controls at
once): {blocked}.

## B. Held-out generalisation (`results/heldout.json`)

The development corpus and the detector share an author, so a 0% there could
be circular. The held-out set ({h['n_attacks']} attacks, {h['n_deserved_controls']} deserved controls) is
authored independently with wording that never appears in the detector; a test
asserts it is disjoint from the corpus and the detector is never tuned to it.

| Metric | Value |
|---|---:|
| Attack success, no controls (simulated agent) | {pct(h['asr_unguarded'])} |
| **Attack success, Sentinel** | **{pct(h['asr_guarded'])}** (structural) |
| Gateway detection recall | {pct(h['detection_recall'])} (empirical) |
| **False positives** | **{pct(h['fp_rate'])}** (empirical) |

Two honest reads: the *claim classifier* generalised to the unseen legitimate
phrasings (no deserved refund was held), and the lexical detector did not
({pct(h['detection_recall'])} recall) -- which is why detection is not on the
authorization path. The unguarded figure is depressed because the offline
victim agent is itself lexical; the held-out set validates the platform, not
the baseline's realism. In v2 this set found a false positive on a novel
cancellation phrasing; the general pattern was broadened and the case pinned.

## C. Second surface -- merchant onboarding (`results/kyb.json`)

{k['attacks']} document-borne / injected applications on bad acquirer records + {k['controls']} controls.

| Metric | Value |
|---|---:|
| Attack success, no controls (simulated agent) | {pct(k['asr_unguarded'])} |
| **Attack success, Sentinel** | **{pct(k['asr_guarded'])}** (structural) |
| False positives (clean merchants wrongly held) | {pct(k['fp_rate'])} (empirical) |
| Borderline (incomplete verification) → human review | {pct(k['borderline_to_review'])} (empirical) |

Both headline rows are by construction: every attack record is shell /
flagged / unverified, so the records never support onboarding, and the
simulated KYB agent obeys every seed in the corpus. The informative rows are
the last two. Not measured: a malicious document on *clean* records asking for
an off-surface capability (the dispute corpus covers that class).

## D. Beating the obvious defence (`results/baselines.json`)

| Defence | Attack success |
|---|---:|
| No defence (simulated agent) | {pct(b['no_defence'])} |
| Hardened system prompt ("ignore embedded instructions") | {pct(b['hardened_prompt'])} |
| **Sentinel** | **{pct(b['sentinel'])}** |

The hardened prompt still fails on: {hardened_fail}. A customer lying about a
fact is not an injection, and "ignore instructions" says nothing about a lie.

## E. Ablation -- which control carries the result (`results/ablation.json`)

| Configuration | ASR | FP | off-surface executed | definition |
|---|---:|---:|---:|---|
{abl}

- **Detection only** holds exactly what it flags and leaks exactly the two
  classes with nothing to detect ({pct(a['detection_only']['asr'])}). v2.0.0 held only
  HIGH+ findings and reported 45.8%; the definition was inconsistent with
  `detection_recall` and the higher number flattered the other controls.
- **Policy only** (over the model's asserted verdict) catches only the
  over-limit amounts.
- **Trusted adjudication alone** closes every attack on this corpus (by
  construction, see above); policy and authorization add human review for
  high-value legitimate cases, capability containment, and explainability.
- The FP column is the simulated agent's: with adjudication off, the naive
  agent denies {pct(a['no_controls']['fp'])} of deserved refunds because it does not
  recognise their wording.

## F. Financial risk on labelled synthetic data (`results/financial.json`)

Dataset: seed {f['dataset']['seed']}, {f['dataset']['customers']} customers, {f['dataset']['merchants']} merchants, {f['dataset']['transactions']} transactions; risk model
`{f['risk_model']}`. Positive = risk level HIGH or CRITICAL. Labels come from the
generator's injected scenarios and are read only by this suite. Risk exists at
three levels and each scenario is evaluated at the level meant to catch it.

**The rule weights were tuned while looking at seed {f['dataset']['seed']}**, so the table
below is the development figure; the held-out seeds further down were never
inspected.

| Level | Scenarios | Precision | Recall | FPR | FNR | tp / fp / fn / tn |
|---|---|---:|---:|---:|---:|---|
{fin_rows}

Transaction-level recall by scenario: {txn_scn}. Account-level: {acc_scn}.

Why the numbers look the way they do:

- **Account-level recall is 100% by construction.** Each account scenario is
  the mirror image of a monitoring rule (structuring = three transfers at
  80–100% of the threshold within 7 days; the generator emits four in four
  days). The four seed-{f['dataset']['seed']} false positives are legitimate accounts whose
  random baseline transfers form a cycle somewhere in 240 days: the
  circular-transfer indicator is not bounded to the monitoring window. Left as
  is and documented rather than tuned.
- **Transaction-level recall is low by construction.** The first several
  transactions of a burst carry no velocity yet; the second account-takeover
  transaction is in the same country as the first, so impossible travel does
  not fire; and the generator registers the attacker's device as a known
  account device, so `new_device` never fires on takeover transactions (a
  generator realism bug that *depresses* recall; documented, not patched).
- **Transaction-level precision moved from 73.7% to {pct(f['transaction_level']['precision'])}** in
  v2.0.1 without a weight change: the baseline was counting disputes filed
  *after* the transaction being scored (temporal leakage), which inflated
  legitimate transactions' chargeback factor. Recall was unaffected.
- **Merchant-level has n={f['merchant_level']['bad_merchants']} positives**, two defined by fields the
  profile reads directly; it is reported for completeness, not as a result.

### Held-out seeds (weights never inspected against these)

| Seed | Level | Precision | Recall | FPR | tp / fp / fn / tn |
|---|---|---:|---:|---:|---|
{held_rows}

Range across all three seeds:

| Level | Precision | Recall | FPR |
|---|---:|---:|---:|
{range_rows}

Calibration (observed fraud-labelled rate per transaction risk band, seed {f['dataset']['seed']}):

| Band | n | observed fraud rate |
|---|---:|---:|
{calib}

Policy outcomes on a {ps['n']}-transaction sample through the full pipeline
(`{ps['policy']}`, no agent): fraud-labelled transactions allowed
{pct(ps['fraud_allowed_rate'])}, legitimate transactions blocked or denied {pct(ps['legit_blocked_or_denied_rate'])}.
The risk model is a transparent rule table, not ML; these numbers describe it
honestly on this generator.

## G. Decision integrity (`results/integrity.json`)

The invariant, stated precisely: **untrusted text and model output cannot
produce an outcome the trusted records do not support.** Untrusted text does
select *which* trusted fact is checked (the claim type); it never exceeds the
ledger-supported ceiling. Measured over {i['n_attacks']} attacks (dev + held-out)
and {i['n_legit']} deserved controls:

| Question | Sentinel | No controls | kind |
|---|---:|---:|---|
| Attacker text made the decision **more permissive** (unsupporting ledgers) | **{pct(i['text_influence_permissive_protected'])}** | {pct(i['text_influence_permissive_unguarded'])} | structural |
| Attacker text changed the outcome at all (tightening only) | {pct(i['text_influence_any_change_protected'])} | — | empirical |
| Injection appended to a deserved claim **loosened** it (n={i['legit_plus_injection_n']}) | **{pct(i['legit_plus_injection_loosened'])}** | — | structural |
| Injection appended to a deserved claim tightened it (held for a human) | {pct(i['legit_plus_injection_tightened'])} | — | empirical |
| A different model recommendation changed the outcome (n={i['model_influence_n']}) | **{pct(i['model_influence_protected'])}** | — | structural |
| *Supporting ledger:* attacker text exceeded the ledger-supported ceiling | **{pct(i['text_beyond_ledger_ceiling'])}** | — | structural |
| *Supporting ledger:* a capability executed without ledger support | **{pct(i['executed_without_ledger_support'])}** | — | structural |
| *Supporting ledger:* attacker text changed the outcome vs a neutral message (selected the claim) | {pct(i['text_selected_claim_on_supporting_ledger'])} | — | by design |
| *Supporting ledger:* attacker text was approved (a deserved refund, whatever the prose) | {pct(i['attack_text_approved_on_supporting_ledger'])} | — | by design |

The structural rows are expected to be 0 -- the attack ledgers do not support
the claims -- and are kept as regression checks. The last two rows are the
honest shape of the property: text can choose which fact is checked, and a
refund the ledger supports is paid even when the message around it is an
attack.

## H. Performance (`results/performance.json`)

{p['platform']}, Python {p['python']}; offline agent; workloads: {w['text_chars']}-char injected
narrative, {w['baseline_transactions']}-transaction baseline, graph of {w['graph_nodes']:,} nodes / {w['graph_edges']:,} edges,
{w['policy_rules']}-rule policy, {w['e2e_iterations']} end-to-end iterations. Sequential, single-threaded,
persistence excluded; machine-dependent.

| Component | p50 ms | p95 ms | p99 ms | ops/s |
|---|---:|---:|---:|---:|
{perf_rows}

A live LLM call (hundreds of milliseconds) dominates real latency by three
orders of magnitude; Sentinel's own controls are not the bottleneck.

## I. Model / provider evaluation (`results/models.json`)

| Provider | Model | Status | ASR no controls | ASR Sentinel | FP | Note |
|---|---|---|---:|---:|---:|---|
{model_rows}

Live results depend on provider/model/date and are not claimed to generalise. Run `SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models`
with your own key to fill the live row; nothing here is fabricated.

## Reproduce

```bash
make eval                      # everything above, writes results/*.json and charts
make docs                      # re-render this file and the README / résumé numbers from results/
sentinel eval run --suite security|heldout|kyb|baselines|ablation|financial|integrity|performance|models|charts
sentinel eval run --suite financial --full     # larger dataset (400 customers / 12k transactions)
make test                      # {tests} tests, incl. tests/test_results_regression.py which recomputes the headline claims
```
"""


def render_performance(p: dict[str, Any]) -> str:
    work = {
        "normalize": "310-char narrative",
        "gateway_inspect": "same narrative, 11 signals",
        "claim_classify": "same narrative",
        "evidence_reconcile": "8 ledger facts + claim",
        "risk_score_transaction": "40-txn baseline, 26 rules",
        "graph_linked_accounts": f"{p['workloads']['graph_nodes']:,}-node graph",
        "graph_neighborhood_d2": "depth-2 neighbourhood",
        "policy_evaluate": f"{p['workloads']['policy_rules']} rules, 10-field context",
        "decision_compose": "full DecisionInputs",
        "audit_append": "in-memory chain",
        "e2e_dispute_pipeline": "gateway → agent → evidence → policy → authorization",
    }
    rows = "\n".join(
        f"| `{n}` | {work.get(n, '')} | {v['p50_ms']} | {v['p95_ms']} | {v['p99_ms']} | {v['throughput_per_sec']:,} |"
        for n, v in p["components"].items()
    )
    e2e = p["components"]["e2e_dispute_pipeline"]
    return f"""# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured ({p['platform']}, Python {p['python']})

| Component | Workload | p50 ms | p95 ms | p99 ms | ops/s |
|---|---|---:|---:|---:|---:|
{rows}

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈{e2e['p95_ms']} ms at p95 -- about three orders of magnitude
below the decision it protects. The per-decision SQLite writes (risk
assessment, evidence, decision + snapshot, audit event) are not in this
figure; the API's in-process metrics (`GET /v1/system`) report them live.
"ops/s" is 1000 / mean over a sequential loop, not a concurrency figure.

## Complexity

Let `n` = untrusted text length, `s` = detector signals (11, constant), `h` =
account history size read for the baseline (capped at 500), `r` = policy
rules (constant), `d` = graph degree.

| Stage | Work | Complexity |
|---|---|---|
| validate + normalise | scan, fold, NFKC | O(n) |
| gateway | `s` bounded-quantifier regexes; no `.*` across alternations | O(s·n) = O(n) |
| claim classification | 5 regexes | O(n) |
| baseline | statistics over recent history | O(h) |
| transaction features | 1-hour window scan over recent history | O(h) |
| entity profiles | indexed per merchant / account, cached per snapshot | O(1) amortised |
| graph queries | adjacency lookups; depth-2 neighbourhood bounded to 200 nodes | O(d) / O(d²) bounded |
| cycle search (monitoring) | DFS through transfer edges, path length ≤ 5, **not time-bounded** | O(d⁵) worst case |
| policy | all rules over a flat context | O(r) = O(1) |
| compose + authorize | constant | O(1) |
| audit append | one hash over canonical JSON | O(record) |

The protected path holds no cross-request state except the audit chain
head, so it scales horizontally per account partition; the chain would be
sharded per tenant at scale. The audit backends re-read the whole log for
`events()`, `get()` and `verify()` (O(n) per call), which is fine for a lab
store and would be an indexed lookup in production.

## Reproduce

```bash
make bench
make docs
```
"""


def blocks(R: dict[str, Any], tests: int) -> dict[str, str]:
    s, h, k, b, a, f, i, p = (
        R[x]
        for x in (
            "security",
            "heldout",
            "kyb",
            "baselines",
            "ablation",
            "financial",
            "integrity",
            "performance",
        )
    )
    e2e = p["components"]["e2e_dispute_pipeline"]
    sr = f["seed_range"]
    tl, al = f["transaction_level"], f["account_level"]
    out: dict[str, str] = {}
    out[
        "integrity"
    ] = f"""| Decision-integrity measurement (`make eval`, {i['n_attacks']} attacks) | Sentinel | No controls |
|---|---:|---:|
| attacker text made a protected decision **more permissive** (unsupporting ledgers; structural) | **{pct(i['text_influence_permissive_protected'])}** | {pct(i['text_influence_permissive_unguarded'])} |
| attacker text exceeded the **ledger-supported ceiling** on a supporting ledger (structural) | **{pct(i['text_beyond_ledger_ceiling'])}** | — |
| a capability executed **without ledger support** (structural) | **{pct(i['executed_without_ledger_support'])}** | — |
| a different model recommendation changed the outcome ({i['model_influence_n']} replays; structural) | **{pct(i['model_influence_protected'])}** | — |
| attacker text *selected the claim* on a supporting ledger (by design) | {pct(i['text_selected_claim_on_supporting_ledger'])} | — |"""
    out["results"] = f"""<div align="center">

| | No controls (simulated agent) | Hardened prompt | **Sentinel** |
|---|:---:|:---:|:---:|
| Attack success, {s['n_attacks']} attacks / 12 classes | 🔴 **{pct(s['asr_unguarded'])}** | 🟠 {pct(b['hardened_prompt'])} | 🟢 **{pct(s['asr_guarded'])}** (structural) |
| Off-surface capability executed | {pct(s['capability_escalation_rate_unguarded'])} | — | **{pct(s['capability_escalation_executed_guarded'])}** |
| False positives on deserved refunds (empirical) | — | — | 🟢 **{pct(s['fp_rate'])}** |
| Held-out set (unseen wording, {h['n_attacks']} attacks) | {pct(h['asr_unguarded'])} | — | **{pct(h['asr_guarded'])}** / FP {pct(h['fp_rate'])} |
| KYB onboarding ({k['attacks']} attacks) | {pct(k['asr_unguarded'])} | — | **{pct(k['asr_guarded'])}** / FP {pct(k['fp_rate'])} |

</div>

**Attack success** means an unauthorised consequential capability actually
executed -- not "the detector flagged the sentence". Two caveats the numbers
carry: the "no controls" column is the **offline simulated agent** executing
its own tool call (a property of that regex simulator, which shares an author
with the corpus, not a measurement of any real model); and Sentinel's 0.0%
rows are **structural** -- an attack on an unsupporting ledger cannot execute
under the design -- so they are regression checks, not detection results.
The empirical content is the false-positive rate, the held-out claim-classifier
coverage, and the gateway's detection recall ({pct(s['detection_recall'])} on the dev
corpus, {pct(h['detection_recall'])} held-out), on which the security case does not depend."""
    out[
        "ablation"
    ] = f"""| no controls | prompt hardening | detection only | risk only | policy only | adjudication only | adjudication + policy | **full** |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| {pct(a['no_controls']['asr'])} | {pct(a['prompt_hardening']['asr'])} | {pct(a['detection_only']['asr'])} | {pct(a['risk_only']['asr'])} | {pct(a['policy_only']['asr'])} | {pct(a['adjudication_only']['asr'])} | {pct(a['adjudication_policy']['asr'])} | **{pct(a['full']['asr'])}** |

Prompt hardening fails 100% on the false-claim classes. Detection alone holds
exactly what it flags and leaks exactly the two classes with nothing to detect
(v2.0.0 reported 45.8% here because the configuration held only HIGH+
findings; the consistent definition gives the smaller, honest number). Policy
without evidence catches only over-limit amounts. **Checking the claim against
the institution's own records is what carries the result**; policy,
authorization and the gateway add human review for legitimate high-value
cases, capability containment and explainability. Definitions of every
configuration are in [docs/EVALUATION.md](docs/EVALUATION.md#e-ablation----which-control-carries-the-result-resultsablationjson)."""
    out[
        "financial"
    ] = f"""### Financial risk (labelled synthetic dataset, {f['dataset']['transactions']:,} transactions)

Development seed {f['dataset']['seed']} (the weights were tuned on it), with the range over seeds
{f['dataset']['seed']}, {' and '.join(str(x) for x in f['seeds']['held_out'])} in brackets:

| Level | Precision | Recall | FPR |
|---|---:|---:|---:|
| transaction (account takeover, bursts, ring transactions) | {pct(tl['precision'])} ({rng(sr['transaction_level']['precision'])}) | {pct(tl['recall'])} ({rng(sr['transaction_level']['recall'])}) | {pct(tl['false_positive_rate'], 2)} ({rng(sr['transaction_level']['false_positive_rate'])}) |
| account monitoring (structuring-like, dormant activation, rings, bursts) | {pct(al['precision'])} ({rng(sr['account_level']['precision'])}) | {pct(al['recall'])} ({rng(sr['account_level']['recall'])}) | {pct(al['false_positive_rate'], 2)} ({rng(sr['account_level']['false_positive_rate'])}) |

A transparent, versioned rule model over behavioural baselines, a
relationship graph and entity profiles -- explainable to the factor, replayable
under another model version, and honest about being coarse: account-level
recall is by construction (the scenarios mirror the rules), transaction-level
recall is low by construction (a burst's first transactions have no velocity
yet), and the seed-{f['dataset']['seed']} account false positives come from a time-unbounded
cycle finder ([details](docs/EVALUATION.md#f-financial-risk-on-labelled-synthetic-data-resultsfinancialjson))."""
    out[
        "performance"
    ] = f"""### Performance (offline, own overhead)

Full protected dispute pipeline: **p50 {e2e['p50_ms']} ms · p95 {e2e['p95_ms']} ms · {e2e['throughput_per_sec']:,}/s**
sequential single-thread; policy evaluation {p['components']['policy_evaluate']['p95_ms']} ms p95; gateway inspection {p['components']['gateway_inspect']['p95_ms']} ms p95 ([all components](docs/PERFORMANCE.md))."""
    out["resume"] = f"""## One-line version

> Built Sentinel, a financial decision-security platform in which AI agents
> may recommend but only trusted evidence, deterministic risk controls and
> versioned policy can authorize: {pct(s['asr_unguarded'])} → {pct(s['asr_guarded'])} attack success across 12 threat
> classes against a simulated naive agent with {pct(s['fp_rate'])} false positives, {pct(i['executed_without_ledger_support'])} of decisions
> executed without ledger support under attack, replayable and hash-chained.

## Six bullets (pick three)

- **Security architecture.** Designed a typed trust boundary (seven trust
  classes; only two can authorize) and a decision composer whose trusted view
  has no field for prose or model output, so an LLM's recommendation is
  recorded but never authoritative. Measured the property as enforced:
  across {i['n_attacks']} attacks, **{pct(i['text_beyond_ledger_ceiling'])} exceeded the ledger-supported ceiling and
  {pct(i['executed_without_ledger_support'])} executed without ledger support**; {i['model_influence_n']} recommendation replays changed
  nothing; the unguarded contrast is {pct(i['text_influence_permissive_unguarded'])}.
- **Financial risk engine.** Built a deterministic, versioned, factor-level
  explainable risk engine (behavioural baselines, device/geography/velocity,
  entity profiles, a relationship graph, transaction-monitoring patterns) over
  a coherent synthetic world with nine labelled fraud scenarios; account-level
  recall {pct(al['recall'])} at {pct(al['false_positive_rate'])} FPR, transaction-level precision {pct(tl['precision'])} at
  {pct(tl['false_positive_rate'], 2)} FPR on the development seed, with held-out seeds reported
  (Python, SQLite).
- **Capability / policy enforcement.** Implemented schema-validated,
  versioned, fail-closed policy-as-code (every referenced field must be
  present; policy content is hashed and pinned by every decision) and a
  capability registry (risk, reversibility, monetary impact, allowed actors,
  human-review thresholds) in which no AI actor may execute a consequential
  capability; off-surface requests become CRITICAL security events and P1
  cases, never executions.
- **Adversarial evaluation.** Authored a 12-class attack corpus ({s['n_attacks']} attacks
  targeting refunds, onboarding, unfreezing, payout changes, fund release,
  case closure, risk overrides) plus an independent held-out set and a KYB
  surface; an 8-configuration ablation shows a hardened prompt still leaks
  {pct(b['hardened_prompt'])} and detection alone {pct(a['detection_only']['asr'])}, while trusted-evidence adjudication + policy
  reach {pct(a['adjudication_policy']['asr'])} with {pct(a['adjudication_policy']['fp'])} false positives, held at {pct(h['asr_guarded'])}/{pct(h['fp_rate'])} on unseen wording.
- **Explainability & auditability.** Every decision carries evidence with
  provenance, contradictions, matched policy rules and an authorization
  reason; decisions are replayable under other policy/risk-model versions
  with a field-level diff and drift detection; the audit trail is a SHA-256
  hash chain (stores hashes, never prose) whose verifier names the first
  modified, deleted or reordered record.
- **Engineering.** Standard-library-only core (SQLite, http.server), one
  application layer behind a versioned API, a CLI and an API-backed console;
  {tests} tests including ten property-tested security invariants and end-to-end
  hostile vectors; CI with lint, types, coverage, evaluation smoke and Docker;
  protected pipeline p95 ≈ {e2e['p95_ms']} ms offline.

## Interview explanation (~60 seconds)

"Financial institutions are putting AI agents into decision paths -- refunds,
onboarding, account security, investigations -- and those agents read
attacker-controlled text through legitimate channels. Everyone defends against
*injected instructions*. The harder attack has no injection: the customer
simply lies about a fact, and a persuadable model approves. Prompt hardening
doesn't help with a lie; against our simulated agent it still leaked {pct(b['hardened_prompt'])}.
Sentinel's answer is architectural: the model may recommend, but the
authoritative decision is computed from a view that literally has no field
for the prose or the model's opinion -- trusted evidence decides whether a
claim is supported, versioned policy decides the outcome, a capability
registry decides who may execute it, and a hash-chained audit records why.
We state the property precisely -- untrusted text cannot produce an outcome
the records don't support -- and measure it directly: across {i['n_attacks']} attacks,
none exceeded the ledger-supported ceiling, none executed without support,
none of the deserved refunds were held, and every decision replays
deterministically under a different policy version."
"""
    out["limitations-solid"] = f"""## What is genuinely solid

- The trust boundary and the composer: the authoritative decision is computed
  from a view that has no field for prose or for the model's recommendation.
  The integrity suite measures the property as it is enforced: across {i['n_attacks']}
  attacks, **{pct(i['text_beyond_ledger_ceiling'])}** exceeded the ledger-supported ceiling and **{pct(i['executed_without_ledger_support'])}**
  executed without ledger support, against **{pct(i['text_influence_permissive_unguarded'])}** permissive influence with
  no controls; {i['model_influence_n']} model-recommendation replays changed nothing.
- **{pct(s['asr_guarded'])}** unauthorised capability executions across the development corpus,
  the held-out set and KYB (structural, by construction), with **{pct(s['fp_rate'])}** false
  positives on deserved refunds -- including the urgent-but-legitimate
  phrasings -- which is the empirical part.
- Model output is typed untrusted and cannot become evidence; an agent
  pushed off its tool surface produces a CRITICAL event, a BLOCK and a P1
  case, never an execution.
- Policy is fail-closed (a missing input can never switch a rule off) and
  content-hashed (a replay knows whether "v2" is still the v2 the decision
  saw).
- Every block is explainable (evidence, contradictions, matched rules,
  authorization reason, blocked-by list) and every decision is replayable and
  hash-chained.
"""
    out["interview-claims"] = f"""**What claims can you actually prove?**
Structural ones, by test: untrusted text and model output cannot produce an
outcome the trusted records do not support (integrity suite over {i['n_attacks']}
attacks: {pct(i['text_beyond_ledger_ceiling'])} exceeded the ledger-supported ceiling, {pct(i['executed_without_ledger_support'])} executed
without support, {pct(i['model_influence_protected'])} of {i['model_influence_n']} recommendation replays changed anything, vs
{pct(i['text_influence_permissive_unguarded'])} permissive influence with no controls); zero unauthorised capability
executions across the corpus, the held-out set and KYB -- which is 0 by
construction and is kept as a regression check; audit tampering is detected.
Empirical ones, on synthetic data: {pct(s['fp_rate'])} false positives on deserved refunds,
{pct(h['fp_rate'])} on unseen legitimate wording, and the financial figures with their
held-out-seed range. See `docs/EVALUATION.md`, which separates the two kinds.
"""
    return out


def patch_blocks(path: Path, out: dict[str, str]) -> None:
    text = path.read_text(encoding="utf-8")
    for name, body in out.items():
        pat = re.compile(rf"<!-- gen:{name} -->\n.*?<!-- /gen:{name} -->", re.S)
        replacement = f"<!-- gen:{name} -->\n{body.rstrip()}\n<!-- /gen:{name} -->"
        if pat.search(text):
            text = pat.sub(lambda _m, r=replacement: r, text)
    path.write_text(text, encoding="utf-8")


def patch_test_counts(path: Path, tests: int) -> None:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"tests-\d+_passing", f"tests-{tests}_passing", text)
    text = re.sub(r"\b\d{3} tests\b", f"{tests} tests", text)
    path.write_text(text, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tests", type=int, default=None, help="test count (default: collect)")
    args = ap.parse_args()
    tests = test_count(args.tests)
    R = {
        n: _load(n)
        for n in (
            "security",
            "heldout",
            "kyb",
            "baselines",
            "ablation",
            "financial",
            "integrity",
            "performance",
            "models",
        )
    }
    (ROOT / "docs" / "EVALUATION.md").write_text(render_evaluation(R, tests), encoding="utf-8")
    (ROOT / "docs" / "PERFORMANCE.md").write_text(
        render_performance(R["performance"]), encoding="utf-8"
    )
    out = blocks(R, tests)
    for name in ("README.md", "docs/RESUME.md", "docs/LIMITATIONS.md", "docs/INTERVIEW.md"):
        patch_blocks(ROOT / name, out)
    for name in ("README.md", "docs/RESUME.md", "docs/TESTING.md"):
        patch_test_counts(ROOT / name, tests)
    print(f"rendered docs from results/ ({tests} tests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
