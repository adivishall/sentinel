"""One place that says, for every published suite, what kind of number it produces,
what it was measured on and what it cannot claim. Attached to each results file as
``methodology`` and rendered into docs/EVALUATION.md, so the labels cannot drift
from the code that produced the numbers."""

from __future__ import annotations

from typing import Any

_STATIC: dict[str, dict[str, str]] = {
    "redteam": {
        "kind": "synthetic (seeded black-box search against the offline simulated agent); the bypass count is structural, detector evasion is empirical",
        "dataset": "every development-corpus attack as a seed (contradicted objective) and its over-limit variants with a supporting ledger (over-limit objective), plus a structured-channel campaign through the API handlers",
        "method": "per seed, a hill-climbing attacker applies seeded mutation operators and keeps the variant scoring best on what the API returns (executed, policy ALLOW, lower detector rating); four metrics are reported separately",
        "limitations": "the operators and the detector share an author; the victim agent is the offline simulator (it always complies), so the search pressure is on the deterministic layers, not a real model's judgement; a hand-written operator set is not an exhaustive attacker",
    },
    "security": {
        "kind": "synthetic (hand-authored corpus, offline simulated agent); guarded attack success is structural",
        "dataset": "development attack corpus, seeds x amounts straddling the auto-limit, plus legitimate controls",
        "method": "each case runs with no controls and with full controls; success = an unauthorised consequential capability executed; detection recall counts the gateway's flag; false positives count deserved refunds not executed",
        "limitations": "the corpus and the detector share an author; the unguarded rate is a property of the simulator; every attack ledger is unsupporting so the guarded rate is 0 by construction",
    },
    "heldout": {
        "kind": "synthetic; guarded attack success is structural",
        "dataset": "independently worded held-out set, disjoint from the development corpus by test",
        "method": "as the development corpus",
        "limitations": "small; validates the claim classifier and the platform, not the simulator's realism",
    },
    "surfaces": {
        "kind": "synthetic; guarded attack success and 'loosened' are structural",
        "dataset": "attacks arriving through the transaction, account-security and investigation workflows",
        "method": "each attack is compared with the same request carrying no untrusted text; success = a consequential capability executed that the text-free baseline did not",
        "limitations": "small per-workflow counts; the offline agent's behaviour on these surfaces is the simulator's",
    },
    "kyb": {
        "kind": "synthetic; guarded attack success is structural; false positives are empirical",
        "dataset": "balanced onboarding applications across eight categories with records-only ground truth",
        "method": "outcomes compared with what the acquirer records alone imply (approve / review / reject)",
        "limitations": "records are synthetic; a clean merchant with a hostile upload is held by design and counted in the any-input false-positive rate",
    },
    "baselines": {
        "kind": "synthetic (offline simulated agent)",
        "dataset": "development attack corpus",
        "method": "the naive agent, the same agent with a hardened system prompt, and Sentinel",
        "limitations": "the hardened prompt's behaviour is the simulator's reading of an instruction, not a measured LLM",
    },
    "ablation": {
        "kind": "synthetic; the 0% rows are structural",
        "dataset": "development attack corpus",
        "method": "eight control configurations of the same composer over the same cases",
        "limitations": "configurations that believe the model's verdict inherit the simulator's behaviour",
    },
    "financial": {
        "kind": "synthetic (labelled generator scenarios); empirical on that generator",
        "dataset": "seeded synthetic world; development seed plus two held-out seeds",
        "method": "transaction-level risk band on every transaction, monitoring on every account, merchant profiles; positive = HIGH or CRITICAL; labels come from the generator and are read only here",
        "limitations": "point values were tuned on the development seed; scenarios mirror the rules they are meant to trip; not real payment data",
    },
    "integrity": {
        "kind": "structural on unsupporting ledgers; by-design rows on supporting ledgers",
        "dataset": "development + held-out attack texts over fixed ledgers",
        "method": "the same trusted facts with different untrusted text and different model recommendations; count outcomes above the ledger-supported ceiling and executions without support",
        "limitations": "a property of the composer, not of any model's robustness",
    },
    "temporal": {
        "kind": "structural (synthetic data)",
        "dataset": "two seeded synthetic worlds (seeds 42 and 7), a stratified transaction sample (half fraud-labelled)",
        "method": "truncation equivalence, then nine kinds of future record at +1/7/30/90 days, one kind at a time; the transaction assessment and the account monitor at T1 must be byte-identical; exact counts with a one-sided 95% Clopper-Pearson bound when zero",
        "limitations": "a deterministic check over two generator worlds, not a proof over every record; comparisons from one sample are correlated (read the per-sample bound); a current-state field with no recorded start (legacy account status) cannot be point-in-time",
    },
    "performance": {
        "kind": "empirical, machine-dependent",
        "dataset": "fixed workloads (narrative, baseline, graph, policy) on the local machine",
        "method": "sequential single-threaded loops; percentiles over n iterations; persistence excluded",
        "limitations": "the platform's own overhead only; a live model call dominates real latency",
    },
    "claims": {
        "kind": "synthetic (hand-authored phrasings)",
        "dataset": "seven categories of dispute phrasings, incl. a held-out set of uncommon legitimate wording and the development set used to extend the patterns",
        "method": "each phrasing classified once against its label; false negatives over legitimate categories, false positives over ambiguous / unsupported / contradictory",
        "limitations": "the benchmark and the classifier share an author; a regression floor, not a generalisation claim; the held-out number after the pattern change is optimistic (the author had seen the first-run misses)",
    },
}


def methodology(suite: str, result: dict[str, Any]) -> dict[str, Any]:
    """The static description plus the sample sizes actually observed in ``result``."""
    d: dict[str, Any] = dict(_STATIC[suite])
    sample: dict[str, Any] = {}
    for key in (
        "n_attacks",
        "n_controls",
        "n_deserved_controls",
        "n_legit",
        "attacks",
        "controls",
        "model_influence_n",
        "legit_plus_injection_n",
        "comparisons",
        "decisions_tested",
        "n",
    ):
        if key in result and isinstance(result[key], (int, float)):
            sample[key] = result[key]
    if isinstance(result.get("corpus"), dict):
        sample.update({f"corpus_{k}": v for k, v in result["corpus"].items()})
    if isinstance(result.get("dataset"), dict):
        sample.update({f"dataset_{k}": v for k, v in result["dataset"].items()})
    if isinstance(result.get("workloads"), dict):
        sample.update({k: v for k, v in result["workloads"].items() if isinstance(v, int)})
    if isinstance(result.get("seeds"), dict):
        sample["seeds"] = result["seeds"]
    d["sample"] = sample
    return d
