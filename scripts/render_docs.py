"""Render every published metric and every code-defined table into the docs.

    make docs            # == python scripts/render_docs.py [--tests N]

Rewritten entirely from ``results/*.json`` and the package itself:
``docs/EVALUATION.md``, ``docs/PERFORMANCE.md``, ``docs/SECURITY_MODEL.md``,
``docs/RISK_ENGINE.md``, ``docs/POLICY_ENGINE.md``, ``docs/EVIDENCE_MODEL.md``
and ``docs/AUDIT_MODEL.md``. Patched between ``<!-- gen:NAME -->`` /
``<!-- /gen:NAME -->`` markers: README.md, docs/RESUME.md, docs/LIMITATIONS.md,
docs/INTERVIEW.md, docs/THREAT_MODEL.md, docs/ARCHITECTURE.md and docs/DEMO.md.

A number that is not in ``results/`` is not published; a table that describes
code (weights, rules, fields, capabilities, threat classes, audit fields) is
read from the code, so it cannot go stale without this script failing.
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
sys.path.insert(0, str(ROOT))

SUITES = (
    "security",
    "heldout",
    "surfaces",
    "kyb",
    "baselines",
    "ablation",
    "financial",
    "integrity",
    "temporal",
    "performance",
    "models",
    "claims",
)

GEN_TARGETS = (
    "README.md",
    "docs/RESUME.md",
    "docs/LIMITATIONS.md",
    "docs/INTERVIEW.md",
    "docs/THREAT_MODEL.md",
    "docs/ARCHITECTURE.md",
    "docs/DEMO.md",
)


def _load(name: str) -> dict[str, Any]:
    p = RESULTS / f"{name}.json"
    if not p.exists():
        raise SystemExit(f"missing {p}; run `make eval` first")
    return json.loads(p.read_text(encoding="utf-8"))


def pct(x: float | None, d: int = 1) -> str:
    return "—" if x is None else f"{x * 100:.{d}f}%"


def rng(r: dict[str, float], d: int = 1) -> str:
    return f"{pct(r['min'], d)}–{pct(r['max'], d)}"


def tbl(headers: list[str], rows: list[list[object]], align: str = "") -> str:
    """Markdown table. ``align`` is one char per column: l, r or c (default l)."""
    sep = []
    for i, _ in enumerate(headers):
        a = align[i] if i < len(align) else "l"
        sep.append({"l": "---", "r": "---:", "c": ":---:"}[a])
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(sep) + "|"]
    out += ["| " + " | ".join(str(c).replace("|", "\\|") for c in r) + " |" for r in rows]
    return "\n".join(out)


def yn(b: object) -> str:
    return "yes" if b else "no"


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

LEVELS = {
    "transaction_level": "transaction",
    "account_level": "account (monitoring)",
    "merchant_level": "merchant (profile)",
}


def _live_row(m: dict[str, Any]) -> dict[str, Any]:
    rows = [x for x in m["results"] if x.get("provider") != "offline"]
    return rows[0] if rows else {"status": "not_run", "model": "—"}


def _meth(r: dict[str, Any], file: str) -> str:
    """One line per section: what kind of number, on what, how, and what it cannot claim."""
    m = r.get("methodology")
    if not m:
        return ""
    sample = m.get("sample") or {}
    ss = ", ".join(f"{k}={v}" for k, v in sample.items() if not isinstance(v, (dict, list)))
    return (
        f"> **Methodology** (`results/{file}.json`): {m['kind']}. *Dataset:* {m['dataset']}. "
        f"*Method:* {m['method']}. *Limitations:* {m['limitations']}."
        + (f" *Sample:* {ss}." if ss else "")
    )


def _mi_scope(i: dict[str, Any]) -> str:
    """What the model-influence replays cover (the first N main-corpus attacks × each
    recommendation), so '360' is never read as 'the 170 attacks'."""
    d, r = i.get("model_influence_decisions"), i.get("model_influence_recommendations")
    return f"{d} main-corpus attacks × {r} recommendations" if d and r else "see §H"


def _scn(d: dict[str, Any]) -> str:
    return ", ".join(
        f"{k.replace('fraud:', '')} {pct(v['recall'])} (n={v['n']})" for k, v in d.items()
    )


# --------------------------------------------------------------------------- CATEGORIES


def evaluation_categories(R: dict[str, Any]) -> str:
    """One row per kind of evidence, never mixed: what it measures, how big, which seeds,
    the result and where the method is."""
    s, h, sf, k, i, f, t, cl, p, m = (
        R[x]
        for x in (
            "security",
            "heldout",
            "surfaces",
            "kyb",
            "integrity",
            "financial",
            "temporal",
            "claims",
            "performance",
            "models",
        )
    )
    tl, al = f["transaction_level"], f["account_level"]
    n_accts = al["tp"] + al["fp"] + al["fn"] + al["tn"]
    live = _live_row(m)
    kc = k.get("corpus", {})
    e2e = p["components"]["e2e_dispute_pipeline"]
    seeds = ", ".join(str(x) for x in t["dataset"]["seeds"])
    return tbl(
        [
            "Category",
            "Kind of evidence",
            "Measures",
            "Sample",
            "Seeds / source",
            "Result",
            "Method",
        ],
        [
            [
                "**AI security**",
                "synthetic, offline simulated agent (not a live LLM)",
                "an unauthorised consequential capability actually executed",
                f"main corpus {s['n_attacks']} attacks / {len(s['by_class'])} classes; held-out "
                f"{h['n_attacks']}; other surfaces {sf['n_attacks']}; KYB {kc.get('cases', 0)} "
                f"applications ({kc.get('attacks', k.get('attacks', 0))} hostile)",
                "hand-authored corpora (same author as the gateway)",
                f"main corpus: simulated agent {pct(s['asr_unguarded'])} → Sentinel "
                f"**{pct(s['asr_guarded'])}**; held-out, surfaces, KYB: "
                f"{pct(max(h['asr_guarded'], sf['asr_guarded'], k['asr_guarded']))}; "
                f"false positives {pct(s['fp_rate'])} ({s['n_deserved_controls']} deserved refunds)",
                "[§A–F](docs/EVALUATION.md#a-ai-security----development-corpus-resultssecurityjson)",
            ],
            [
                "**Decision integrity**",
                "structural (0 by construction; a regression check)",
                "attacker text or model output loosening a protected decision",
                f"{i['n_attacks']} attacks (main {s['n_attacks']} + held-out {h['n_attacks']}); "
                f"{i['model_influence_n']} model-recommendation replays ({_mi_scope(i)})",
                "the security corpora",
                f"**{pct(i['text_influence_permissive_protected'])}** (no controls: {pct(i['text_influence_permissive_unguarded'])})",
                "[§H](docs/EVALUATION.md#h-decision-integrity-resultsintegrityjson)",
            ],
            [
                "**Financial risk**",
                "synthetic benchmark (empirical)",
                "precision / recall / FPR against the generator's scenario labels",
                f"seed {f['dataset']['seed']}: {f['dataset']['transactions']:,} transactions, "
                f"{n_accts} accounts; two held-out seeds of similar size",
                f"dev {f['dataset']['seed']} (point values tuned on it); held-out "
                + ", ".join(str(x) for x in f["seeds"]["held_out"]),
                f"transactions P {pct(tl['precision'])} R {pct(tl['recall'])} FPR {pct(tl['false_positive_rate'], 2)}; "
                f"accounts P {pct(al['precision'])} R {pct(al['recall'])}",
                "[§G](docs/EVALUATION.md#g-financial-risk-on-labelled-synthetic-data-resultsfinancialjson)",
            ],
            [
                "**Temporal correctness**",
                "synthetic invariant check (empirical; not a proof)",
                "a record dated after T changing a decision at T",
                f"{t['dataset']['sample']} transactions; {len(t['kinds'])} kinds of future record at "
                f"{len(t['future_offsets_days'])} offsets; {t['decisions_tested']:,} checks",
                f"seeds {seeds}",
                (
                    f"**{t['leakage_count']} observed leaks** (95% upper bound {t['leakage_upper_95']:.3%} "
                    f"per check, {t['sample_leakage_upper_95']:.2%} per sampled transaction)"
                    if t.get("leakage_upper_95") is not None
                    else f"**{t['leakage_count']} observed leaks**"
                ),
                "[§I](docs/EVALUATION.md#i-temporal-correctness-resultstemporaljson)",
            ],
            [
                "**Claim classifier**",
                "synthetic, same author; defence in depth, not the foundation",
                "legitimate claims read as their type; the rest held for a human",
                f"{cl['n']} phrasings; {cl['uncommon_n']} held-out unusual phrasings",
                "hand-authored",
                f"held-out: first (blind) run 7/{cl['uncommon_n']}; "
                f"{cl['uncommon_recognised']}/{cl['uncommon_n']} after the patterns were extended by "
                f"an author who had seen the misses; FN {cl['false_negatives']}/{cl['false_negative_n']}, "
                f"FP {cl['false_positives']}/{cl['false_positive_n']}",
                "[§L](docs/EVALUATION.md#l-claim-classifier-resultsclaimsjson)",
            ],
            [
                "**Performance**",
                "local benchmark (one machine)",
                "the platform's own latency, offline agent",
                f"{p['workloads']['e2e_iterations']} end-to-end iterations",
                p["platform"].split("-")[0],
                f"dispute pipeline p95 {e2e['p95_ms']} ms",
                "[PERFORMANCE.md](docs/PERFORMANCE.md)",
            ],
            [
                "**Live LLM**",
                "live-model evaluation",
                "the same suites against a real model",
                "--",
                f"`{live['model']}`",
                f"**{str(live['status']).upper().replace('_', ' ')}** -- no live number is quoted anywhere",
                "[§K](docs/EVALUATION.md#k-model--provider-evaluation-resultsmodelsjson)",
            ],
        ],
    )


# --------------------------------------------------------------------------- EVALUATION


def render_evaluation(R: dict[str, Any], tests: int) -> str:
    cats_md = (
        evaluation_categories(R)
        .replace("(docs/EVALUATION.md#", "(#")
        .replace("(docs/PERFORMANCE.md)", "(PERFORMANCE.md)")
    )
    s, h, sf, k, b, a, f, i, t, p, m, cl = (R[x] for x in SUITES)
    live = _live_row(m)
    n_classes = len(s["by_class"])
    per_class = s["n_attacks"] // n_classes

    by_class = tbl(
        ["Threat class", "n", "No controls", "Detection recall", "Sentinel"],
        [
            [c, v["n"], pct(v["asr_unguarded"]), pct(v["detection_recall"]), pct(v["asr_guarded"])]
            for c, v in s["by_class"].items()
        ],
        "lrrrr",
    )
    by_target = tbl(
        ["Target capability", "n", "No controls", "Sentinel"],
        [
            [c, v["n"], pct(v["asr_unguarded"]), pct(v["asr_guarded"])]
            for c, v in s["by_target_capability"].items()
        ],
        "lrrr",
    )
    undetected = [c for c, v in s["by_class"].items() if v["detection_recall"] == 0]
    blocked = ", ".join(f"{k2} {v}" for k2, v in s["blocked_by"].items())
    held_class = tbl(
        ["Threat class", "n", "No controls", "Detection recall", "Sentinel"],
        [
            [c, v["n"], pct(v["asr_unguarded"]), pct(v["detection_recall"]), pct(v["asr_guarded"])]
            for c, v in h["by_class"].items()
        ],
        "lrrrr",
    )
    surf_wf = tbl(
        ["Workflow", "n", "No controls", "Detection recall", "Sentinel"],
        [
            [w, v["n"], pct(v["asr_unguarded"]), pct(v["detection_recall"]), pct(v["asr_guarded"])]
            for w, v in sf["by_workflow"].items()
        ],
        "lrrrr",
    )
    surf_target = tbl(
        ["Target capability", "n", "No controls", "Sentinel"],
        [
            [c, v["n"], pct(v["asr_unguarded"]), pct(v["asr_guarded"])]
            for c, v in sf["by_target_capability"].items()
        ],
        "lrrr",
    )
    surf_class = tbl(
        ["Threat class", "n", "No controls", "Detection recall", "Sentinel"],
        [
            [c, v["n"], pct(v["asr_unguarded"]), pct(v["detection_recall"]), pct(v["asr_guarded"])]
            for c, v in sf["by_class"].items()
        ],
        "lrrrr",
    )
    kc = k["corpus"]
    kyb_cat = tbl(
        [
            "Category",
            "n",
            "records → approve",
            "records → reject",
            "no controls breached",
            "Sentinel breached",
            "FP",
            "FN",
            "held for review",
        ],
        [
            [
                c,
                v["n"],
                v["n_approve"],
                v["n_reject"],
                v["ug_breach"],
                v["g_breach"],
                v["fp"],
                v["fn"],
                v["reviewed"],
            ]
            for c, v in k["by_category"].items()
        ],
        "lrrrrrrrr",
    )
    hardened_fail = ", ".join(f"{c} {pct(v)}" for c, v in b["hardened_by_class"].items() if v > 0)
    abl = tbl(
        ["Configuration", "ASR", "FP", "off-surface executed", "definition"],
        [
            [name, pct(v["asr"]), pct(v["fp"]), pct(v["escalation_executed"]), ABLATION_DEFS[name]]
            for name, v in a.items()
            if name != "methodology"
        ],
        "lrrrl",
    )
    leaked_detect = [c for c, v in s["by_class"].items() if v["detection_recall"] == 0]

    gt = tbl(
        ["Label", "Level", "Definition (generator scenario)"],
        [[lab, v["level"], v["definition"]] for lab, v in f["ground_truth"].items()],
    )
    stages = "\n".join(f"- **{st}** -- {desc}" for st, desc in f["stages"].items())
    tl, al, ml = f["transaction_level"], f["account_level"], f["merchant_level"]
    fin_rows = tbl(
        ["Level", "Precision", "Recall", "FPR", "FNR", "tp / fp / fn / tn"],
        [
            [
                LEVELS[L],
                pct(f[L]["precision"]),
                pct(f[L]["recall"]),
                pct(f[L]["false_positive_rate"], 2),
                pct(f[L]["false_negative_rate"]),
                f"{f[L]['tp']} / {f[L]['fp']} / {f[L]['fn']} / {f[L]['tn']}",
            ]
            for L in LEVELS
        ],
        "lrrrrl",
    )
    mb = tl["miss_breakdown"]

    def _sig(d: dict[str, int]) -> str:
        return ", ".join(f"{k2} ({v})" for k2, v in d.items()) or "—"

    miss_rows = tbl(
        [
            "Scenario",
            "n",
            "detected",
            "missed",
            "signals on detected (count)",
            "signals on missed (count)",
        ],
        [
            [
                sc.replace("fraud:", ""),
                v["n"],
                v["detected"],
                v["missed"],
                _sig(v["dominant_signals_detected"]),
                _sig(v["dominant_signals_missed"]),
            ]
            for sc, v in mb.items()
        ],
        "lrrrll",
    )
    missed_scn = [sc.replace("fraud:", "") for sc, v in mb.items() if v["missed"]]
    total_missed = sum(v["missed"] for v in mb.values())
    burst_note = (
        f" `rapid_fire` needs {int(_thr('rapid_fire_count'))} transactions inside "
        f"{int(_thr('rapid_window_minutes'))} minutes and `rapid_succession` a short gap against a "
        f"≥ {int(_thr('baseline_gap_hours'))} h median, so the first transactions of a burst cannot "
        "carry the short-window velocity signals, and a burst spread over more than the window "
        "carries fewer of them; the account-level monitor is where a burst is meant to be caught "
        "(account-level burst recall above)."
        if "burst" in missed_scn
        else ""
    )
    bp = tl.get("burst_by_position") or {}
    burst_md = ""
    if bp:
        vis, hid = bp["velocity_visible"], bp["not_yet_visible"]
        burst_md = (
            tbl(
                ["Position in burst"] + list(bp["by_position"]),
                [
                    ["flagged / n"]
                    + [f"{v['flagged']}/{v['n']}" for v in bp["by_position"].values()]
                ],
            )
            + f"""

Split by what the rapid-fire rule could see when each transaction was
authorised ({bp['definition']}): **{vis['flagged']}/{vis['n']}** velocity-visible burst
transactions were flagged, **{hid['flagged']}/{hid['n']}** of the rest (by other signals,
mostly the one-hour velocity rule, late in the burst). This is structural, not
a bug: at authorisation time a burst's first transactions look like ordinary
purchases because the burst does not exist yet, and point-in-time features
cannot see what comes after. The control for those is the account-level
monitor, which sees the whole window and flags {pct(al['recall_by_scenario']['fraud:burst']['recall'])} of the burst accounts.
Lowering the thresholds to catch earlier positions would flag legitimate
shopping sessions, which burst too (`tests/test_generator_scenarios.py`); it
was not done."""
        )
    miss_prose = (
        f"The {total_missed} transaction-level misses on this seed are {' / '.join(missed_scn)} "
        f"transactions.{burst_note} The missed and false-positive examples are listed in "
        "`results/financial.json` under `transaction_level`."
        if total_missed
        else "No transaction-level misses on this seed."
    )
    ss = tl.get("signal_stats", {})
    sig_rows = tbl(
        [
            "Factor",
            "Family",
            "Points",
            "Fired on fraud (rate)",
            "Fired on legit (rate)",
            "Precision when fired",
        ],
        [
            [
                f"`{c}`",
                v["family"],
                v["points"],
                f"{v['fired_on_fraud']} ({pct(v['fraud_fire_rate'])})",
                f"{v['fired_on_legit']} ({pct(v['legit_fire_rate'], 2)})",
                pct(v["precision_when_fired"]),
            ]
            for c, v in list(ss.items())[:20]
        ],
        "llrrrr",
    )
    fam_line = ", ".join(
        f"{k} {pct(v['precision_when_fired'])}" for k, v in tl.get("family_stats", {}).items()
    )

    def _slice(d: dict[str, Any], label: str) -> str:
        return tbl(
            [label, "n", "fraud n", "recall", "FPR"],
            [
                [k2, v["n"], v["fraud_n"], pct(v["recall"]), pct(v["false_positive_rate"], 2)]
                for k2, v in d.items()
            ],
            "lrrrr",
        )

    slices = "\n\n".join(
        [
            _slice(tl["by_channel"], "Channel"),
            _slice(tl["by_account_segment"], "Account segment"),
            _slice(tl["by_merchant_tier"], "Merchant risk tier"),
        ]
    )
    held_rows = tbl(
        ["Seed", "Level", "Precision", "Recall", "FPR", "tp / fp / fn / tn"],
        [
            [
                f"seed {seed}",
                LEVELS[L],
                pct(v[L]["precision"]),
                pct(v[L]["recall"]),
                pct(v[L]["false_positive_rate"], 2),
                f"{v[L]['tp']} / {v[L]['fp']} / {v[L]['fn']} / {v[L]['tn']}",
            ]
            for seed, v in f["held_out_seeds"].items()
            for L in LEVELS
        ],
        "llrrrl",
    )
    held_scn = "\n".join(
        f"- seed {seed}: transaction {_scn(v['recall_by_scenario'])}; account {_scn(v['account_level']['recall_by_scenario'])}"
        for seed, v in f["held_out_seeds"].items()
    )
    range_rows = tbl(
        ["Level", "Precision", "Recall", "FPR"],
        [
            [
                LEVELS[L],
                rng(f["seed_range"][L]["precision"]),
                rng(f["seed_range"][L]["recall"]),
                rng(f["seed_range"][L]["false_positive_rate"], 2),
            ]
            for L in LEVELS
        ],
        "lrrr",
    )
    calib = tbl(
        ["Transaction band", "n", "observed fraud rate"],
        [[band, v["n"], pct(v["observed_fraud_rate"])] for band, v in f["calibration"].items()],
        "lrr",
    )
    acc_calib = tbl(
        ["Account band", "n", "observed fraud rate"],
        [[band, v["n"], pct(v["observed_fraud_rate"])] for band, v in al["calibration"].items()],
        "lrr",
    )
    ps = f["policy_sample"]
    ps_rows = tbl(["Outcome", "n"], [[o, n] for o, n in ps["outcomes"].items()], "lr")
    perf_rows = tbl(
        ["Component", "p50 ms", "p95 ms", "p99 ms", "ops/s"],
        [
            [f"`{name}`", v["p50_ms"], v["p95_ms"], v["p99_ms"], f"{v['throughput_per_sec']:,}"]
            for name, v in p["components"].items()
        ],
        "lrrrr",
    )
    model_rows = tbl(
        [
            "Provider",
            "Model",
            "Date",
            "Status",
            "ASR no controls",
            "ASR Sentinel",
            "FP",
            "Latency p95 ms",
            "Tokens in / out",
            "Note",
        ],
        [
            [
                x["provider"],
                f"`{x['model']}`",
                x.get("date") or str(x.get("timestamp", ""))[:10],
                x["status"],
                pct(x.get("asr_unguarded")),
                pct(x.get("asr_guarded")),
                pct(x.get("fp_rate")),
                x.get("agent_latency_p95_ms", "—"),
                (
                    f"{x['input_tokens']} / {x['output_tokens']}"
                    if x.get("input_tokens") is not None
                    else "—"
                ),
                x.get("reason", ""),
            ]
            for x in m["results"]
        ],
    )
    w = p["workloads"]
    td = t["dataset"]
    seeds = ", ".join(str(x) for x in td["seeds"])
    offs = ", ".join(str(d) for d in t["future_offsets_days"])
    bykind = t.get("perturbation_by_kind", {})
    txn_ch = sum(v["transaction_changed"] for v in bykind.values())
    mon_ch = sum(v["monitoring_changed"] for v in bykind.values())
    ub = t.get("leakage_upper_95")
    ub_s = f"{ub:.3%}" if ub is not None else "n/a -- leaks found"
    temporal_rows = tbl(
        ["Check", "Changed / tested", "Rate (exact)", "kind"],
        [
            [
                f"truncation: a transaction's risk assessment differs when records after it are removed (seeds {seeds}, {td['transactions']:,} transactions)",
                f"{t['truncation_mismatch_count']} / {td['sample']}",
                f"{t['truncation_mismatch_rate']:.6f}",
                "tested invariant",
            ],
            [
                f"perturbation: records added {offs} days after T1 change the T1 transaction assessment",
                f"{txn_ch} / {t['comparisons']:,}",
                f"{t['perturbation_transaction_change_rate']:.6f}",
                "tested invariant",
            ],
            [
                "perturbation: the same future records change the T1 account-monitor assessment",
                f"{mon_ch} / {t['comparisons']:,}",
                f"{t['perturbation_monitoring_change_rate']:.6f}",
                "tested invariant",
            ],
            [
                "**every check above**",
                f"**{t['leakage_count']} / {t['decisions_tested']:,}**",
                f"**{t['leakage_rate']:.6f}**",
                f"95% upper bound {ub_s}",
            ],
        ],
        "lrrl",
    )
    n_all_attacks = s["n_attacks"] + h["n_attacks"] + sf["n_attacks"]
    temporal_kinds = tbl(
        [
            "Future record kind",
            "What is appended (at every offset)",
            "records",
            "transaction changed",
            "monitoring changed",
            "leaks / tested",
        ],
        [
            [
                f"`{kd}`",
                v["description"],
                f"{v['future_records']:,}",
                f"{v['transaction_changed']} / {v['n']}",
                f"{v['monitoring_changed']} / {v['n']}",
                f"{v['leakage_count']} / {v['tested']}",
            ]
            for kd, v in t.get("perturbation_by_kind", {}).items()
        ],
        "llrrrr",
    )
    cl_cat = tbl(
        ["Category", "n", "accuracy", "read as claim", "non-claim", "abstain", "misclassified"],
        [
            [
                c,
                v["n"],
                pct(v["accuracy"]),
                v["claim"],
                v["non_claim"],
                v["abstain"],
                v["misclassified"],
            ]
            for c, v in cl["by_category"].items()
        ],
        "lrrrrrr",
    )
    return f"""# Evaluation

Every number in this document is produced by one command and written to
`results/`, then rendered here by `scripts/render_docs.py` (`make docs`):

```bash
make eval                # == sentinel eval run --suite full   (offline, deterministic, no key)
```

Six dimensions are measured: **AI security** (the {s['n_attacks']}-attack main corpus, a
{h['n_attacks']}-attack held-out corpus, {sf['n_attacks']} attacks on three other surfaces and a
{k['corpus']['cases']}-application KYB benchmark), **decision integrity**, **temporal correctness**,
**financial risk**, the **claim classifier** and **system performance**. All corpora
and datasets are synthetic and the agent is an offline simulator; see
`docs/LIMITATIONS.md`.

Attack counts, so that no number appears unscoped: the **main (development)
corpus** is {s['n_attacks']} attacks across {n_classes} classes; the **held-out corpus** is {h['n_attacks']};
the **other surfaces** add {sf['n_attacks']}; together {s['n_attacks'] + h['n_attacks'] + sf['n_attacks']}. The **integrity suite**
reuses main + held-out ({i['n_attacks']}). **KYB** is separate: {k['corpus']['cases']} applications, {k['corpus']['attacks']} with a
hostile document.

## At a glance -- one row per kind of evidence

{cats_md}

## Three kinds of numbers

Read every table with this distinction in mind; each results file records the
kind of each headline metric under `kinds`.

| Kind | What it is | Where it appears |
|---|---|---|
| **STRUCTURAL GUARANTEE** | 0 by construction under the design. A consequential capability executes only when the trusted records support the claim, and every attack sits on records that do not. These rows are regression checks that the implementation honours the design (`tests/test_results_regression.py` recomputes them), not detection results. | guarded attack success, off-surface execution, the integrity suite's structural rows |
| **SYNTHETIC EVALUATION** | Empirical, but on hand-authored corpora, a seeded synthetic dataset and the **offline simulated agent** (`OfflineProvider`, a deterministic regex model of a gullible tool-calling agent that shares an author with the corpus). These numbers can move and describe this simulator and this generator, not the world. | unguarded attack success, detection recall, false positives, KYB outcomes, everything in the financial suite, the claim classifier, the temporal-leakage checks (a tested invariant over two synthetic worlds: 0 observed is evidence, not a proof), performance |
| **LIVE MODEL EVALUATION** | The identical suite against a real model on the operator's own key (`SENTINEL_FORCE_OFFLINE=0 sentinel eval run --suite models`). | `results/models.json` -- current status of the live row: **{live['status']}** (`{live.get('model', '—')}`); no live number is quoted anywhere in this repository |

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

{s['n_attacks']} attacks across {n_classes} threat classes ({per_class} per class: hand-authored
seeds × amounts straddling the ₹50,000 auto-limit) + {s['n_controls']} legitimate controls
({s['n_deserved_controls']} of which deserve a refund). Targets beyond `APPROVE_REFUND`:
{', '.join(c for c in s['by_target_capability'] if c != 'APPROVE_REFUND')}.

| Metric | No controls (simulated agent) | Full Sentinel |
|---|---:|---:|
| Attack success rate | **{pct(s['asr_unguarded'])}** (synthetic, simulator) | **{pct(s['asr_guarded'])}** (structural) |
| Off-surface capability executed (escalation) | {pct(s['capability_escalation_rate_unguarded'])} | {pct(s['capability_escalation_executed_guarded'])} (structural) |
| Gateway detection recall | — | {pct(s['detection_recall'])} (synthetic; text scan or model-output check; not the backstop) |
| False-positive rate on deserved refunds | — | **{pct(s['fp_rate'])}** (synthetic) |

{by_class}

Read the last two columns together: **{', '.join(undetected)} are invisible to
detection (0.0% recall) and are still blocked**, because the ledger, not the
prose, decides support.

{by_target}

Blocked-by distribution (an attack can be stopped by several controls at
once): {blocked}.

{_meth(s, "security")}

## B. Held-out generalisation (`results/heldout.json`)

The development corpus and the detector share an author, so a 0% there could
be circular. The held-out set ({h['n_attacks']} attacks, {h['n_controls']} controls of which
{h['n_deserved_controls']} deserve a refund) was written after the development corpus, by the same
author, with wording that never appears in the detector's patterns; a test
asserts it is disjoint from the corpus and the detector is never tuned to it.

| Metric | Value |
|---|---:|
| Attack success, no controls (simulated agent) | {pct(h['asr_unguarded'])} |
| **Attack success, Sentinel** | **{pct(h['asr_guarded'])}** (structural) |
| Gateway detection recall | {pct(h['detection_recall'])} (synthetic) |
| **False positives** | **{pct(h['fp_rate'])}** (synthetic) |

{held_class}

Two honest reads: none of the {h['n_deserved_controls']} held-out deserved refunds was held -- a small
sample, and the classifier's own held-out test (§L) missed {cl['uncommon_n'] - cl['uncommon_recognised']} of {cl['uncommon_n']} unusual
phrasings, which go to a human -- and the lexical detector did not generalise
({pct(h['detection_recall'])} recall), which is why detection is not on the authorization path. The unguarded figure is depressed because the offline
victim agent is itself lexical; the held-out set validates the platform, not
the baseline's realism.

{_meth(h, "heldout")}

## C. Other surfaces -- transaction, account security, investigation (`results/surfaces.json`)

{sf['n_attacks']} attacks that arrive through the non-dispute workflows: descriptors and
memos on a payment authorisation, a customer message on a login session with a
requested capability, and case notes on an investigation. {sf['definition'].replace('success = ', 'Success = ')}.
Each attack is also compared with the same request carrying no untrusted text:
untrusted text **loosened** the outcome in {pct(sf['loosened_vs_baseline'])} of cases (structural) and
tightened it in {pct(sf['tightened_vs_baseline'])} (synthetic: the gateway held something a
text-free request would have allowed).

{surf_wf}

{surf_target}

{surf_class}

{_meth(sf, "surfaces")}

## D. Second surface -- merchant onboarding, balanced KYB (`results/kyb.json`)

{kc['cases']} applications: {kc['attacks']} carry a hostile document and {kc['controls']} do not. On the
acquirer's records alone, {kc['records_approve']} should be approved, {kc['records_review']} held for review and
{kc['records_reject']} rejected. Ground truth is defined by the records only, never by the
document:

```text
{k['ground_truth'].strip()}
```

| Metric | Value | kind |
|---|---:|---|
| Attack success, no controls (simulated agent) | {pct(k['asr_unguarded'])} | {k['kinds']['asr_unguarded']} |
| **Attack success, Sentinel** | **{pct(k['asr_guarded'])}** | {k['kinds']['asr_guarded']} |
| False positives, benign input (clean merchants held or rejected) | **{pct(k['fp_rate_benign_input'])}** | {k['kinds']['fp_rate_benign_input']} |
| False positives, any input | {pct(k['fp_rate'])} ({k['fp_attack_input_held']} clean merchants held because their document was hostile) | {k['kinds']['fp_rate']} |
| False negatives (records say reject, merchant went live) | {pct(k['fn_rate'])} | {k['kinds']['fn_rate']} |
| Borderline records (review) → human review | {pct(k['borderline_to_review'])} | empirical |
| Manual-review rate over all {kc['cases']} cases | {pct(k['manual_review_rate'])} | {k['kinds']['manual_review_rate']} |

{kyb_cat}

The any-input false-positive rate is the honest cost of the design: a clean
merchant whose upload contains an injection is held for a human rather than
approved, because a CRITICAL security finding blocks automatic approval. It is
reported rather than tuned away. The benign-input rate is the classifier's
behaviour on ordinary applications.

{_meth(k, "kyb")}

## E. Beating the obvious defence (`results/baselines.json`)

| Defence | Attack success |
|---|---:|
| No defence (simulated agent) | {pct(b['no_defence'])} |
| Hardened system prompt ("ignore embedded instructions") | {pct(b['hardened_prompt'])} |
| **Sentinel** | **{pct(b['sentinel'])}** |

The hardened prompt still fails on: {hardened_fail}. A customer lying about a
fact is not an injection, and "ignore instructions" says nothing about a lie.

{_meth(b, "baselines")}

## F. Ablation -- which control carries the result (`results/ablation.json`)

{abl}

- **Detection only** holds exactly what it flags and leaks exactly the classes
  with nothing to detect ({', '.join(leaked_detect)}): {pct(a['detection_only']['asr'])}.
- **Policy only** (over the model's asserted verdict) catches only the
  over-limit amounts.
- **Trusted adjudication alone** closes every attack on this corpus (by
  construction, see above); policy and authorization add human review for
  high-value legitimate cases, capability containment, and explainability.
- The FP column is the simulated agent's: with adjudication off, the naive
  agent denies {pct(a['no_controls']['fp'])} of deserved refunds because it does not
  recognise their wording.

{_meth(a, "ablation")}

## G. Financial risk on labelled synthetic data (`results/financial.json`)

Dataset: seed {f['dataset']['seed']}, {f['dataset']['customers']} customers, {f['dataset']['merchants']} merchants, {f['dataset']['transactions']:,} transactions; risk model
`{f['risk_model']}`. Positive = {f['positive_definition']}. Labels come from the
generator's injected scenarios and are read only by this suite.

**The point values of the rule model were tuned while looking at seed {f['dataset']['seed']}**, so
the tables below are development figures; the held-out seeds further down
were never inspected. Nothing about the model is an industry standard
(`docs/RISK_ENGINE.md`).

### Ground truth

{gt}

### Stages

Risk exists at three levels and each scenario is evaluated at the level meant
to catch it:

{stages}

### Results (seed {f['dataset']['seed']})

{fin_rows}

Transaction-level recall by scenario: {_scn(f['recall_by_scenario'])}.
Account-level: {_scn(al['recall_by_scenario'])}. Merchant level has n={ml['bad_merchants']}
positives ({ml['definition']}) and is reported for completeness, not as a result.

### Where the misses are

{miss_rows}

{miss_prose}

**Bursts by position** (seed {f['dataset']['seed']}):

{burst_md}

### Signals

How often each factor fires on fraud-labelled and on legitimate transactions
(seed {f['dataset']['seed']}; {tl['fraud_n']} fraud, {tl['legit_n']:,} legitimate). A factor that fires on many
legitimate transactions is a weak signal on this generator; nothing was tuned
to change that, and the point values are documented in `docs/RISK_ENGINE.md`.

{sig_rows}

Family precision when fired: {fam_line}.

### Slices

{slices}

### Held-out seeds (point values never inspected against these)

{held_rows}

{held_scn}

Range across all three seeds:

{range_rows}

### Calibration (observed fraud-labelled rate per risk band, seed {f['dataset']['seed']})

{calib}

{acc_calib}

### Decisioning

Policy outcomes on a {ps['n']}-transaction sample through the full pipeline
(`{ps['policy']}`, no agent):

{ps_rows}

Fraud-labelled transactions allowed: {pct(ps['fraud_allowed_rate'])}. Legitimate transactions
blocked or denied: {pct(ps['legit_blocked_or_denied_rate'])}. The risk model is a transparent rule
table, not ML; these numbers describe it honestly on this generator.

{_meth(f, "financial")}

## H. Decision integrity (`results/integrity.json`)

The invariant, stated precisely: **untrusted text and model output cannot
produce an outcome the trusted records do not support.** Untrusted text does
select *which* trusted fact is checked (the claim type); it never exceeds the
ledger-supported ceiling. Measured over {i['n_attacks']} attacks (dev + held-out)
and {i['n_legit']} deserved controls:

| Question | Sentinel | No controls | kind |
|---|---:|---:|---|
| Attacker text made the decision **more permissive** (unsupporting ledgers) | **{pct(i['text_influence_permissive_protected'])}** | {pct(i['text_influence_permissive_unguarded'])} | structural |
| Attacker text changed the outcome at all (tightening only) | {pct(i['text_influence_any_change_protected'])} | — | synthetic |
| Injection appended to a deserved claim **loosened** it (n={i['legit_plus_injection_n']}) | **{pct(i['legit_plus_injection_loosened'])}** | — | structural |
| Injection appended to a deserved claim tightened it (held for a human) | {pct(i['legit_plus_injection_tightened'])} | — | synthetic |
| A different model recommendation changed the outcome (n={i['model_influence_n']}: {_mi_scope(i)}) | **{pct(i['model_influence_protected'])}** | — | structural |
| *Supporting ledger:* attacker text exceeded the ledger-supported ceiling | **{pct(i['text_beyond_ledger_ceiling'])}** | — | structural |
| *Supporting ledger:* a capability executed without ledger support | **{pct(i['executed_without_ledger_support'])}** | — | structural |
| *Supporting ledger:* attacker text changed the outcome vs a neutral message (selected the claim) | {pct(i['text_selected_claim_on_supporting_ledger'])} | — | by design |
| *Supporting ledger:* attacker text was approved (a deserved refund, whatever the prose) | {pct(i['attack_text_approved_on_supporting_ledger'])} | — | by design |

The structural rows are expected to be 0 -- the attack ledgers do not support
the claims -- and are kept as regression checks. The last two rows are the
honest shape of the property: text can choose which fact is checked, and a
refund the ledger supports is paid even when the message around it is an
attack. This is a structural property of the composer; it is **not** a claim
about the robustness of any model (the model's recommendation is recorded and
never consulted by the decision). On an unsupporting ledger the ceiling is a
human review: a message the classifier cannot read is INSUFFICIENT and held, a
readable false claim is denied, and nothing executes.

{_meth(i, "integrity")}

## I. Temporal correctness (`results/temporal.json`)

The invariant: **data available after T must never influence a decision made
at T.** Two generator worlds (seeds {seeds}; {td['transactions']:,} transactions), a stratified sample
of {td['sample']} transactions (half fraud-labelled, half legitimate, spread over the timeline).
Every sampled transaction is re-scored with records truncated to its own
timestamp, then again with one kind of future record appended at every offset
({offs} days later) -- {len(t['kinds'])} kinds, {t['comparisons']:,} perturbation runs over {t['future_records']:,} future
records -- and each time both the transaction assessment and the account
monitor at T1 must be byte-identical. **{t['leakage_count']} observed leaks in {t['decisions_tested']:,} checks
across the tested synthetic benchmark.** Rates are exact counts, not rounded; with zero leaks the one-sided
95% (Clopper-Pearson) upper bound on the per-decision leak rate is {ub_s}.
Comparisons from one sample are correlated, so the conservative reading is
per sample: 0 of {td['sample']}, upper bound {t['sample_leakage_upper_95']:.2%}.

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

{temporal_rows}

{temporal_kinds}

Expected: {t['expected']}. `tests/test_temporal_leakage.py` and
`tests/test_entity_pointintime.py` pin the same property per feature (baselines,
device knowledge, entity profiles, graph edges, monitoring windows). This is a
deterministic check over the generator's world: "0 observed temporal leaks
across the tested synthetic benchmark", not a proof over every record.

{_meth(t, "temporal")}

## J. Performance (`results/performance.json`)

{p['platform']}, Python {p['python']}; offline agent; workloads: {w['text_chars']}-char injected
narrative, {w['baseline_transactions']}-transaction baseline, graph of {w['graph_nodes']:,} nodes / {w['graph_edges']:,} edges,
{w['policy_rules']}-rule policy over a {w['policy_context_fields']}-field context, {w['e2e_iterations']} end-to-end iterations.
Sequential, single-threaded, persistence excluded; machine-dependent.

{perf_rows}

A live LLM call (hundreds of milliseconds) dominates real latency by three
orders of magnitude; Sentinel's own controls are not the bottleneck.

{_meth(p, "performance")}

## K. Model / provider evaluation (`results/models.json`)

{model_rows}

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
trusted field is checked. Benchmark: {cl['n']} hand-authored phrasings in seven
categories. **The benchmark and the classifier share an author**, so these are
regression floors on these phrasings, not a generalisation claim -- with one
exception made as honest as an author can make it: `uncommon_legitimate` is a
held-out set of {cl['uncommon_n']} unusual but legitimate phrasings (Indian English, slang,
typos, formal register) written and labelled *before* the classifier was run on
it. {cl['category_notes']['uncommon_legitimate'][0].upper() + cl['category_notes']['uncommon_legitimate'][1:]}. `development` is the set the patterns were then
extended against: a fit, reported apart and excluded from the error rates.

{cl_cat}

| Metric | Value | meaning |
|---|---:|---|
| Coverage | {pct(cl['coverage'])} | legitimate paraphrases read as a claim |
| Held-out uncommon wording | {cl['uncommon_recognised']} / {cl['uncommon_n']} | recognised as its own type (first run, before any change: 7 / 21); every miss abstained -- a human, never a wrong type |
| False negatives | {cl['false_negatives']} / {cl['false_negative_n']} ({pct(cl['false_negative_rate'])}) | legitimate claims (paraphrases + held-out) not read as their own type: held for a human |
| False positives | {cl['false_positives']} / {cl['false_positive_n']} ({pct(cl['false_positive_rate'])}) | ambiguous, unsupported and contradictory messages read confidently as a claim |
| Misclassification | {pct(cl['misclassification_rate'])} | messages read as a type other than the labelled one |
| Adversarial wrong type | {pct(cl['adversarial_wrong_type_rate'])} | attack prose read as a claim it does not assert |
| Abstain rate | {pct(cl['abstain_rate'])} | all messages held for a human (100% of the ambiguous and contradictory sets by design) |

The composer's guarantee does not depend on any of this: whatever the
classifier reads, a consequential capability executes only when the ledger
supports the claim. What the classifier changes is the *cost* side -- how
often a legitimate customer is held for a human -- and that is what the
false-negative row measures.

{_meth(cl, "claims")}

## Reproduce

```bash
make eval                      # everything above (main + held-out + surfaces = {n_all_attacks} attacks, plus KYB), writes results/*.json and charts
make docs                      # re-render this file and every generated block from results/ and the code
sentinel eval run --suite security|heldout|surfaces|kyb|baselines|ablation|financial|integrity|temporal|claims|performance|models|charts
sentinel eval run --suite financial --full     # larger dataset (400 customers / 12k transactions)
make test                      # {tests} tests, incl. tests/test_results_regression.py which recomputes the headline claims
```
"""


def _thr(name: str) -> float:
    from sentinel.risk import scoring

    return scoring.TRANSACTION_DEFAULT.t(name, 0)


# --------------------------------------------------------------------------- PERFORMANCE


def render_performance(p: dict[str, Any]) -> str:
    from sentinel.risk import scoring, transaction
    from sentinel.security import injection

    w = p["workloads"]
    n_sig = len(injection.SIGNALS)
    n_rules = len(transaction.RULES)
    cycle_days = int(scoring.MONITORING_V1.t("cycle_window_days", 30))
    work = {
        "normalize": f"{w['text_chars']}-char narrative",
        "gateway_inspect": f"same narrative, {n_sig} signals",
        "claim_classify": "same narrative",
        "evidence_reconcile": "ledger facts + claim",
        "risk_score_transaction": f"{w['baseline_transactions']}-txn baseline, {n_rules} rules",
        "graph_linked_accounts": f"{w['graph_nodes']:,}-node graph",
        "graph_neighborhood_d2": "depth-2 neighbourhood",
        "policy_evaluate": f"{w['policy_rules']} rules, {w['policy_context_fields']}-field context (the composer's real context)",
        "decision_compose": "full DecisionInputs",
        "audit_append": "in-memory chain",
        "e2e_dispute_pipeline": "gateway → agent → evidence → policy → authorization",
    }
    rows = tbl(
        ["Component", "Workload", "p50 ms", "p95 ms", "p99 ms", "ops/s"],
        [
            [
                f"`{n}`",
                work.get(n, ""),
                v["p50_ms"],
                v["p95_ms"],
                v["p99_ms"],
                f"{v['throughput_per_sec']:,}",
            ]
            for n, v in p["components"].items()
        ],
        "llrrrr",
    )
    e2e = p["components"]["e2e_dispute_pipeline"]
    return f"""# Performance & complexity

All figures are the platform's **own** overhead in offline mode (no model
latency), measured by `sentinel bench` / `sentinel eval run --suite performance`
and written to `results/performance.json`; this file is rendered from it by
`make docs`. Sequential, single-threaded, persistence excluded;
machine-dependent -- reproduce locally.

## Measured ({p['platform']}, Python {p['python']})

{rows}

Context: a real back-office LLM call is 300–2,000 ms. The full protected
pipeline adds ≈{e2e['p95_ms']} ms at p95 -- about three orders of magnitude
below the decision it protects. The per-decision SQLite writes (risk
assessment, evidence, decision + snapshot, audit event) are not in this
figure; the API's in-process metrics (`GET /v1/system`) report them live.
"ops/s" is 1000 / mean over a sequential loop, not a concurrency figure.

## Complexity

Let `n` = untrusted text length, `s` = detector signals ({n_sig}, constant), `h` =
account history size read for the baseline (capped at 500), `r` = policy
rules (constant), `d` = graph degree, `w` = edges inside a time window.

| Stage | Work | Complexity |
|---|---|---|
| validate + normalise | scan, fold, NFKC | O(n) |
| gateway | `s` bounded-quantifier regexes; no `.*` across alternations | O(s·n) = O(n) |
| claim classification | weighted pattern families (~60 patterns), negation and hedge guards | O(n) |
| baseline | statistics over the account's history before the transaction | O(h) |
| transaction features | 1-hour / {int(scoring.TRANSACTION_DEFAULT.t('rapid_window_minutes', 10))}-minute window scans over recent history; 24 h session window | O(h) |
| entity profiles | indexed per merchant / account, cached per (entity, as-of) | O(1) amortised |
| graph queries | adjacency lookups filtered by edge timestamp; depth-2 neighbourhood bounded to 200 nodes; the API/console rendering bounded to 80 nodes | O(d) / O(d²) bounded |
| cycle search (monitoring) | DFS through transfer edges, path length ≤ 5, **every hop inside the last {cycle_days} days** (`cycle_window_days`) | O(w⁵) worst case, w ≪ d |
| policy | all rules over a flat context | O(r) = O(1) |
| compose + authorize | constant | O(1) |
| audit append | one hash over canonical JSON | O(record) |
| audit lookup by id / decision | indexed (`find`) on the JSONL and SQLite backends | O(1) / O(log n) |
| audit verify | recompute from genesis | O(n) |

The protected path holds no cross-request state except the audit chain
head, so it scales horizontally per account partition; the chain would be
sharded per tenant at scale. `verify()` is a full re-computation by design;
a checkpoint (`docs/AUDIT_MODEL.md`) lets an operator confirm that the stored
prefix still hashes to a known-good head.

## Reproduce

```bash
make bench
make docs
```
"""


# --------------------------------------------------------------------------- SECURITY MODEL

TRUST_NOTES = {
    "TRUSTED_INTERNAL": "our own ledger, records and policies",
    "VERIFIED_EXTERNAL": "acquirer / network records the institution verified",
    "USER_CONTROLLED": "a cardholder narrative, chat turn or form field",
    "MERCHANT_CONTROLLED": "merchant application copy, descriptors, site text",
    "DOCUMENT_CONTROLLED": "an uploaded invoice, receipt or PDF (treated as text)",
    "MODEL_GENERATED": "anything an LLM produced, including 'our' agent's recommendation",
    "UNKNOWN": "unlabelled third-party content",
}

CASE_RULES = [
    (
        "capability_escalation",
        "P1",
        "a CRITICAL security event with the registry in `blocked_by`, or the model requested a capability other than the workflow's and the request was blocked",
    ),
    (
        "critical_risk_financial",
        "P1",
        "risk level CRITICAL on a request for a consequential capability",
    ),
    ("ai_security_block", "P2", "final action BLOCK with security severity ≥ HIGH"),
    (
        "human_review_required",
        "P1 / P2",
        "final action REQUIRE_HUMAN_REVIEW or TEMPORARY_HOLD; P1 above ₹1,50,000 or on a hold, else P2",
    ),
    ("monitoring_patterns", "P2", "an investigation whose account risk is HIGH or CRITICAL"),
]


def render_security_model() -> str:
    from sentinel.domain.enums import TrustClass
    from sentinel.security import capabilities, injection
    from sentinel.security.threats import TAXONOMY

    for tc in TrustClass:
        assert tc.value in TRUST_NOTES, f"undocumented trust class {tc}"
    trust_rows = tbl(
        ["Trust class", "Source", "May reach the authoritative decision"],
        [
            [f"`{tc.value}`", TRUST_NOTES[tc.value], "**yes**" if tc.is_trusted else "never"]
            for tc in TrustClass
        ],
    )
    rows = capabilities.matrix()
    cap_rows = tbl(
        [
            "Capability",
            "Risk",
            "Irreversible",
            "Money",
            "Consequential",
            "AI agent may execute",
            "Allowed actors",
            "Required authorization",
            "Human-review threshold (₹)",
            "Executable from",
            "Policy gates",
        ],
        [
            [
                f"`{r['capability']}`",
                r["risk"],
                yn(r["irreversible"]),
                yn(r["financial_effect"]),
                yn(r["consequential"]),
                "**no**" if not r["ai_agent_allowed"] else "yes",
                ", ".join(r["allowed_actors"]) or "nobody",
                r["required_authorization"],
                (
                    f"{r['human_review_threshold']:,}"
                    if r["human_review_threshold"] is not None
                    else "—"
                ),
                ", ".join(r["workflows"])
                or ("no workflow (a human, via the case service)" if r["consequential"] else "—"),
                ", ".join(f"`{g}`" for g in r["policy_gates"]) or "—",
            ]
            for r in rows
        ],
    )
    n_conseq = sum(1 for r in rows if r["consequential"])
    ai_allowed = [r["capability"] for r in rows if r["ai_agent_allowed"]]
    ai_conseq = [r["capability"] for r in rows if r["ai_agent_allowed"] and r["consequential"]]
    assert not ai_conseq, f"AI_AGENT allowed on consequential capabilities: {ai_conseq}"
    nobody = [r["capability"] for r in rows if not r["allowed_actors"]]
    threat_rows = tbl(
        ["Class", "Name", "Mechanism", "Detection kind", "Typical targets"],
        [
            [
                f"`{tc.value}`",
                info.name,
                info.description,
                info.detection,
                ", ".join(c.value for c in info.typical_targets),
            ]
            for tc, info in TAXONOMY.items()
        ],
    )
    by_kind: dict[str, list[str]] = {}
    for tc, info in TAXONOMY.items():
        by_kind.setdefault(info.detection, []).append(tc.value)
    kinds = "\n".join(f"- **{kd}**: {', '.join(v)}" for kd, v in by_kind.items())
    case_rows = tbl(
        ["Rule", "Priority", "Fires when"], [[f"`{r}`", p, w] for r, p, w in CASE_RULES]
    )
    from sentinel.api.schemas import USER_OPTIONS, WHAT_IF_OPTIONS
    from sentinel.cases.service import (
        DECIDABLE_FROM,
        RESERVED_ACTORS,
        TRANSITIONS,
        required_authorization,
    )
    from sentinel.domain.enums import CaseStatus

    assert all(CaseStatus.RESOLVED not in v for v in TRANSITIONS.values())
    sm_rows = tbl(
        ["From", "Status moves (any actor)", "Human decision allowed"],
        [
            [
                f"`{st.value}`",
                ", ".join(f"`{x.value}`" for x in sorted(TRANSITIONS[st], key=lambda c: c.value))
                or "— (final)",
                "yes" if st in DECIDABLE_FROM else "no",
            ]
            for st in CaseStatus
        ],
    )
    # ---- the consequential-capability trace, checked against the workflow source ----
    import inspect

    from sentinel.decision import workflows as wf

    src = {
        "dispute": inspect.getsource(wf.run_dispute),
        "transaction": inspect.getsource(wf.run_transaction),
        "merchant": inspect.getsource(wf.run_kyb),
        "account": inspect.getsource(wf.run_account_security),
        "investigation": inspect.getsource(wf.run_investigation),
    }
    assert "candidate_capability=Capability.APPROVE_REFUND" in src["dispute"]
    assert "candidate_capability=Capability.APPROVE_TRANSACTION" in src["transaction"]
    assert "candidate_capability=Capability.APPROVE_MERCHANT" in src["merchant"]
    assert "cap = req.requested_capability" in src["account"]
    assert '"payout_change" in s.events' in src["account"]
    assert "candidate_capability=None" in src["investigation"]
    for name, code in src.items():
        assert (
            "ai.requested_capability" not in code.split("DecisionInputs(")[-1].split(")")[0]
        ), name
    reach = {
        "APPROVE_REFUND": "dispute workflow -- fixed candidate",
        "APPROVE_TRANSACTION": "transaction workflow -- fixed candidate",
        "APPROVE_MERCHANT": "merchant-onboarding workflow -- fixed candidate",
        "CHANGE_PAYOUT": "account-security workflow -- the caller's structured `requested_capability`, or a `payout_change` event in the trusted session record",
        "FREEZE_ACCOUNT": "account-security workflow -- the caller's structured `requested_capability`",
        "UNFREEZE_ACCOUNT": "account-security workflow -- the caller's structured `requested_capability`",
        "RELEASE_FUNDS": "account-security workflow -- the caller's structured `requested_capability`",
        "CLOSE_CASE": "account-security `requested_capability` only; the investigation workflow never has a candidate. Closing a *case* is `record_human_decision`, never a capability execution",
        "ALTER_RISK": "account-security workflow -- the caller's structured `requested_capability`",
        "SKIP_REVIEW": "account-security workflow -- the caller's structured `requested_capability` (no actor may be granted it)",
    }
    trace_rows = []
    for r in rows:
        if not r["consequential"]:
            continue
        cap = capabilities.Capability(r["capability"])
        sp = capabilities.spec(cap)
        system_ok = capabilities.ActorKind.SYSTEM in sp.allowed_actors
        human = r["required_authorization"] in ("HUMAN_REVIEWER", "SENIOR_REVIEWER")
        trace_rows.append(
            [
                f"`{cap.value}`",
                reach[cap.value],
                "recorded, never read",
                "SUPPORTED required",
                "must not BLOCK / hold / review",
                (
                    "SYSTEM may execute"
                    + (
                        f" up to ₹{sp.human_review_threshold:,}"
                        if sp.human_review_threshold
                        else ""
                    )
                    if system_ok and not human
                    else ("nobody" if not sp.allowed_actors else "human only -- never the system")
                ),
                (
                    required_authorization(cap)
                    + (" to approve" if required_authorization(cap) != "NOBODY" else "")
                ),
                "decision event (action, capability, facts source, snapshot hash)",
            ]
        )
    assert {r[0].strip("`") for r in trace_rows} == set(reach)
    trace_md = tbl(
        [
            "Capability",
            "How a decision path can consider it",
            "Model's request",
            "Evidence",
            "Policy",
            "Authorization (registry)",
            "Human review (who may approve a held case)",
            "Audit",
        ],
        trace_rows,
    )
    need_rows = ", ".join(
        f"`{c['capability']}` → {required_authorization(capabilities.Capability(c['capability']))}"
        for c in rows
        if c["consequential"]
    )
    return f"""# Security model

Rendered by `make docs` from `sentinel/domain/enums.py`,
`sentinel/security/capabilities.py`, `sentinel/security/threats.py`,
`sentinel/security/injection.py` and `sentinel/cases/rules.py`. Nothing in
this file is typed by hand except the prose; the tables are the code.

## The principle

```text
AI may recommend. Trusted evidence, deterministic policy and authorization decide.

AUTHORITATIVE_DECISION = f(TRUSTED_FACTS, VERIFIED_EVIDENCE, RISK_STATE, POLICY, AUTHORIZATION)
AUTHORITATIVE_DECISION ≠ f(ATTACKER_CONTROLLED_TEXT)
AUTHORITATIVE_DECISION ≠ f(MODEL_OUTPUT)
```

Stated precisely: untrusted text and model output cannot produce an outcome
the trusted records do not support. Untrusted text selects *which* trusted
fact is checked (a `ClaimType`); it never exceeds the ledger-supported
ceiling. This is a **structural** property of the composer
(`sentinel/decision/composer.py`: the `_TrustedView` has no field for prose or
for the model's recommendation) and is measured as enforced in
`docs/EVALUATION.md` §H. It is not a claim about any model's robustness.

## Trust classes

{trust_rows}

`TrustClass.is_trusted` is the only predicate the platform uses. `Evidence`
refuses to be VERIFIED from an untrusted class; `UntrustedText`, `Claim` and
`AIRecommendation` refuse a trusted class. Trust does not launder through a
model call: the agent read the attacker's text, so its output is
`MODEL_GENERATED`.

## Capability security matrix

{len(rows)} capabilities. {n_conseq} are **consequential** (irreversible, or moving money, or
reserved to a human reviewer): executing one of those without support is what
"attack success" means. The AI agent actor may execute only
{', '.join(f'`{c}`' for c in ai_allowed)} -- reads, case and alert creation, and
recommendations. {', '.join(f'`{c}`' for c in nobody) or 'No capability'} has no allowed
actor at all. These are Sentinel's own values, documented as such; they are
not industry standards.

{cap_rows}

"Policy gates" lists the shipped policy rules whose conditions name the
capability (`docs/POLICY_ENGINE.md`); the registry applies regardless of
policy.

### Authorization (`capabilities.authorize`)

Called with the capability the **workflow** is considering, never the one the
model asked for, and with the workflow itself. In order:

1. no consequential capability requested → GRANTED;
2. an unregistered capability → DENIED (fail closed);
3. a capability the workflow does not own (`WORKFLOW_CAPABILITIES`: a dispute
   owns APPROVE_REFUND, a login decision owns only the account actions) →
   DENIED -- a caller naming APPROVE_REFUND on the account route gets a 400 at
   the API and a DENY from the engine;
4. the actor is not in the capability's allowed actors → DENIED;
5. policy outcome BLOCK → DENIED;
6. a consequential capability whose verified evidence does not support the
   request → DENIED;
7. policy outcome REQUIRE_HUMAN_REVIEW or TEMPORARY_HOLD → PENDING_HUMAN;
8. the automated path (SYSTEM) on a capability that requires a human or
   senior reviewer → PENDING_HUMAN;
9. SYSTEM above the capability's human-review amount threshold → PENDING_HUMAN;
10. otherwise GRANTED.

A human approval of a case gets the same answer for the reviewer's actor kind
(`CaseService.approval`): a policy BLOCK is final for every actor and records
that contradict the claim cannot be approved.

### Final action (`composer._final_action`)

Policy BLOCK → BLOCK when a security finding (severity ≥ HIGH or an
off-surface request) caused it, else DENY; evidence INSUFFICIENT →
REQUIRE_HUMAN_REVIEW (fail-safe); evidence not SUPPORTED → DENY; policy
TEMPORARY_HOLD → TEMPORARY_HOLD; policy REQUIRE_HUMAN_REVIEW or authorization
PENDING_HUMAN → REQUIRE_HUMAN_REVIEW; policy STEP_UP with authorization
GRANTED → STEP_UP; authorization GRANTED → ALLOW (the candidate capability
executes); anything else → DENY. Only ALLOW executes a capability.

## Detection, claim classification and trusted adjudication

Three different things, often conflated:

- **Detection** (the AI Security Gateway) looks for *attacks* in text and in
  model output: injected instructions, spoofed authority, an off-surface tool
  call. It is heuristic and can only **tighten** an outcome. It misses
  attacks with nothing to detect (a plain lie), and the architecture assumes
  it will.
- **Claim classification** (`sentinel/security/claims.py`) reads *what the
  customer claims* ("it never arrived") so the right trusted field is checked.
  It is deterministic and lexical, abstains when it cannot read a claim (a
  human review), and is defence in depth: whatever it reads, nothing executes
  unless the records support it.
- **Trusted adjudication** (the reconciliation engine + policy + the registry)
  decides *whether the records support the request*. It is the security
  foundation: it reads only trusted facts, and it is what holds the guarded
  attack-success rate at 0 when detection misses.

## Consequential-capability trace

Checked against the workflow source by this renderer (it fails if a
workflow's candidate capability comes from anywhere else). Every path runs:
input → provenance (typed trust class) → model recommendation (recorded,
never read by the decision) → risk (derived from trusted records) → evidence
(claim vs trusted facts) → policy (active version) → authorization (the
registry, for the SYSTEM actor) → human review when required → final action →
audit.

{trace_md}

A capability executes only when the final action is ALLOW (or STEP_UP once
satisfied): evidence SUPPORTED, policy not BLOCK / HOLD / REVIEW, and the
registry GRANTED for SYSTEM -- and only in an authoritative evaluation (every
control, the active policy and risk model). `tests/test_capability_trace.py`
drives a model requesting each capability in every workflow and a caller
requesting each one directly (denied unless the workflow owns it);
`tests/test_release_trace.py` pins the defects the final trace found.

## Evaluation authority (`sentinel/decision/authority.py`)

A caller may request an evaluation; it may not weaken one. An evaluation is
**authoritative** -- recorded, audited, able to open a case and to execute --
only when its inputs carry every control, the active version of its policy
(content hash included) and the active risk model for its surface. The check
runs in `_finish` on the inputs the decision was actually composed from,
before anything is written, and raises `ControlDowngrade` otherwise; the
application sends what-if runs to a runtime that never persists, and every
decision carries `authoritative`. A recording runtime also refuses what-if
*options* before running (`workflows._admit`): the composed inputs cannot show
a run without prompt provenance, or a custom risk model that reuses the active
model's version name.

| Parameter class | Parameters | Where accepted |
|---|---|---|
| user-controllable | {', '.join(f'`{o}`' for o in sorted(USER_OPTIONS))} | every route and command |
| what-if (system-controlled on the authoritative path) | {', '.join(f'`{o}`' for o in sorted(WHAT_IF_OPTIONS))}, top-level `unguarded`, investigation `as_of` | `/v1/attacks/simulate`, `/v1/scenarios/{{key}}/run`, `/v1/replay`, `sentinel security attack`, `sentinel scenario run`, `sentinel replay run` -- never recorded as decisions |
| unknown option keys | anything else | refused (400) |

The evaluate routes answer a what-if switch with 403; the authoritative CLI
commands do not have the flags. Risk models are bound to their surface: a
transaction model is refused on the login surface rather than silently
applied.

## Case lifecycle (`sentinel/cases/service.py`)

RESOLVED is not a target anywhere in the status table; a case reaches it only
through `record_human_decision`, and RESOLVED is final (no transition, no
second decision, no reopen).

{sm_rows}

A human decision recorded under a reserved system or model actor name
({', '.join(f'`{a}`' for a in sorted(RESERVED_ACTORS))}, any `agent:` / `ai:` / `model:` prefix) or under the name
of an agent that recommended on the case is refused. Approving needs the
level the case's capability requires, read from the registry when the case
opens: {need_rows}; and the registry must allow the approval for that
reviewer's actor kind given the recorded policy outcome and evidence (a policy
BLOCK or CONTRADICTED records cannot be approved by anyone; a claim the
classifier could not read -- INSUFFICIENT -- can). Denying or escalating needs
any human; once escalated, the case is decided by a SENIOR_REVIEWER. Every
human action -- a manual case, a status change, a decision -- is appended to
the audit chain before the case is saved (notes and titles hashed), so a
resolution cannot be written into the case table without a chained record.
The reviewer's name and level are *declared* -- there is no identity system
(`docs/LIMITATIONS.md`).

## Threat taxonomy ({len(TAXONOMY)} classes)

{threat_rows}

By how each class is caught:

{kinds}

Only the lexical classes are (partly) detectable by inspecting text; the
gateway carries {len(injection.SIGNALS)} bounded-quantifier signals plus provenance rules,
a session model and a model-output check. Detection can only **tighten** an
outcome (severity feeds policy; an off-surface request is a CRITICAL
escalation). The evidence, structural and trust-boundary classes are closed
by the reconciliation engine, the registry and the type system, which is why
the ablation in `docs/EVALUATION.md` §F shows detection alone leaking exactly
the classes with nothing to detect.

## Case rules (`cases/rules.py`)

A case opens by a deterministic rule over the finished decision -- never
because a model asked for one -- and only a human can resolve it.

{case_rows}

## Where each property is tested

| Property | Test |
|---|---|
| prose never reaches the policy context or the audit log | `tests/test_trust_boundary.py`, `tests/test_invariants.py` |
| the model's requested capability is never the one executed | `tests/test_invariants.py`, `tests/test_model_output_separation.py` |
| AI_AGENT is allowed on no consequential capability | `tests/test_capabilities.py` (asserted again by this renderer) |
| a workflow executes only its own capabilities; one conversation is one decision; every human case action is audited; approvals get the registry's answer | `tests/test_release_trace.py` |
| the console holds no decision logic and calls only real routes | `tests/test_ui_api_contract.py` |
| no persisted decision ran with fewer controls, a historical policy or a historical risk model; every evaluate route refuses every what-if switch | `tests/test_evaluation_authority.py` |
| every consequential capability, requested by a model in every workflow or by a caller, executes only through the full path | `tests/test_capability_trace.py`, `tests/test_policy_adversarial.py` |
| only a human decision resolves a case; the required review level comes from the registry | `tests/test_case_lifecycle.py` |
| replay cannot report equivalence for a rewritten record | `tests/test_replay_integrity.py` |
| every audit corruption is an integrity error, never a crash | `tests/test_audit_corruption.py` |
| headline results recompute from `results/` | `tests/test_results_regression.py` |
"""


# --------------------------------------------------------------------------- RISK ENGINE


def _txn_conditions(m: Any) -> dict[str, str]:
    z_e, z_h, z_m = m.t("z_extreme", 4), m.t("z_high", 3), m.t("z_moderate", 2)
    vx, vsx = m.t("velocity_x", 3), m.t("velocity_spike_x", 5)
    rw, rc, rg, bg, sh = (
        int(m.t("rapid_window_minutes", 10)),
        int(m.t("rapid_fire_count", 3)),
        int(m.t("rapid_gap_minutes", 15)),
        int(m.t("baseline_gap_hours", 6)),
        int(m.t("security_event_hours", 24)),
    )
    return {
        "amount_anomaly_extreme": f"amount z-score ≥ {z_e:g}σ above the account baseline mean",
        "amount_anomaly_high": f"{z_h:g}σ ≤ z < {z_e:g}σ",
        "amount_anomaly_moderate": f"{z_m:g}σ ≤ z < {z_h:g}σ",
        "amount_ratio_small_baseline": "baseline has < 5 transactions and the amount is ≥ 10× its mean",
        "velocity_burst": "≥ 8 transactions in the previous hour",
        "velocity_spike": f"transactions in the previous hour ≥ max(5, {vsx:g} × baseline daily count)",
        "velocity_elevated": f"≥ max(3, {vx:g} × baseline daily count) in the previous hour, below the spike threshold",
        "rapid_fire": f"≥ {rc} transactions in the previous {rw} minutes",
        "rapid_succession": f"gap since the previous transaction < {rg} min while the account's median gap is ≥ {bg} h",
        "recent_account_changes": f"a payout, credential or MFA change on a trusted session in the {sh} h before the transaction",
        "recent_failed_mfa": f"a trusted session in the {sh} h before did not pass the second factor",
        "shared_payout_instrument": "≥ 2 accounts share a bank account this account held at the time of the transaction",
        "new_device": "device not registered on the account (24 h rule) and first seen < 24 h ago, or never",
        "young_account_shared_device": "account < 30 days old on a device shared by ≥ 3 accounts",
        "shared_device": "device shared by ≥ 3 accounts (as of the transaction)",
        "impossible_travel": "any transaction from a different country within the previous 2 hours",
        "new_country": "country not among the baseline's usual countries",
        "merchant_risk_critical": "merchant entity score ≥ 75",
        "merchant_risk_high": "merchant entity score 50–74, or a high-risk MCC with a score < 50",
        "merchant_risk_medium": "medium-risk MCC with a merchant score < 50",
        "account_age_new": "account < 7 days old",
        "account_age_young": "account 7–29 days old",
        "new_instrument": "payment instrument added < 1 day ago",
        "auth_none": "no customer authentication on the transaction",
        "auth_weak": "password-only authentication",
        "chargeback_high": "account chargeback rate ≥ 10% (disputes filed before the transaction only)",
        "chargeback_some": "chargeback rate 3–10%",
        "unusual_hour": "hour outside the baseline's usual hours (baseline ≥ 10 transactions)",
        "new_merchant": "merchant never used by this account before (non-empty baseline)",
        "repeat_merchant_burst": "≥ 3 transactions at the same merchant in the previous hour",
        "linked_entity_critical": "worst linked-entity risk ≥ 75",
        "linked_entity_high": "worst linked-entity risk 50–74",
        "linked_entity_medium": "worst linked-entity risk 25–49",
    }


# source of each transaction feature, its time semantics, and the value range it reads
FEATURE_META: dict[str, tuple[str, str, str]] = {
    "amount_anomaly_extreme": (
        "account baseline (earlier transactions)",
        "as of the transaction",
        "z-score, unbounded",
    ),
    "amount_anomaly_high": ("account baseline", "as of the transaction", "z-score"),
    "amount_anomaly_moderate": ("account baseline", "as of the transaction", "z-score"),
    "amount_ratio_small_baseline": (
        "account baseline (< 5 transactions)",
        "as of the transaction",
        "ratio to mean",
    ),
    "velocity_burst": ("account's earlier transactions", "previous 60 minutes", "count"),
    "velocity_spike": (
        "account's earlier transactions + baseline daily count",
        "previous 60 minutes",
        "count vs baseline",
    ),
    "velocity_elevated": (
        "account's earlier transactions + baseline daily count",
        "previous 60 minutes",
        "count vs baseline",
    ),
    "rapid_fire": ("account's earlier transactions", "previous 10 minutes", "count"),
    "rapid_succession": (
        "previous transaction + baseline median gap",
        "gap to the previous transaction",
        "minutes vs hours",
    ),
    "recent_account_changes": ("authentication service sessions", "previous 24 hours", "event set"),
    "recent_failed_mfa": ("authentication service sessions", "previous 24 hours", "boolean"),
    "shared_payout_instrument": (
        "entity graph (account -> bank-account instrument, by identity)",
        "instruments added and edges dated at or before the transaction; not the account's current payout field",
        "account count",
    ),
    "new_device": (
        "entity graph (account -> device)",
        "registered or used >= 24 h before the transaction",
        "boolean + hours",
    ),
    "young_account_shared_device": (
        "account record + entity graph",
        "as of the transaction",
        "days, account count",
    ),
    "shared_device": (
        "entity graph (device -> accounts)",
        "edges dated at or before the transaction",
        "account count",
    ),
    "impossible_travel": ("account's earlier transactions", "previous 2 hours", "country change"),
    "new_country": ("account baseline (usual countries)", "as of the transaction", "boolean"),
    "merchant_risk_critical": ("merchant entity profile", "as of the transaction", "0-100"),
    "merchant_risk_high": (
        "merchant entity profile + MCC tier",
        "as of the transaction",
        "0-100 / tier",
    ),
    "merchant_risk_medium": (
        "merchant entity profile + MCC tier",
        "as of the transaction",
        "0-100 / tier",
    ),
    "account_age_new": ("account record", "as of the transaction", "days"),
    "account_age_young": ("account record", "as of the transaction", "days"),
    "new_instrument": ("payment instrument record", "as of the transaction", "days"),
    "auth_none": ("payment-switch record", "the transaction itself", "enum"),
    "auth_weak": ("payment-switch record", "the transaction itself", "enum"),
    "chargeback_high": (
        "disputes filed before the transaction",
        "as of the transaction",
        "rate 0-1",
    ),
    "chargeback_some": (
        "disputes filed before the transaction",
        "as of the transaction",
        "rate 0-1",
    ),
    "unusual_hour": (
        "account baseline (usual hours, >= 10 transactions)",
        "as of the transaction",
        "hour",
    ),
    "new_merchant": ("account baseline (merchants seen)", "as of the transaction", "boolean"),
    "repeat_merchant_burst": ("account's earlier transactions", "previous 60 minutes", "count"),
    "linked_entity_critical": (
        "worst linked device / account profile",
        "as of the transaction, account status included (Account.status_at)",
        "0-100",
    ),
    "linked_entity_high": (
        "worst linked device / account profile",
        "as of the transaction, account status included (Account.status_at)",
        "0-100",
    ),
    "linked_entity_medium": (
        "worst linked device / account profile",
        "as of the transaction",
        "0-100",
    ),
}


def _mon_conditions(m: Any) -> dict[str, str]:
    thr = int(m.t("reporting_threshold", 50_000))
    band = m.t("structuring_band", 0.8)
    cyc = int(m.t("cycle_window_days", 30))
    dorm = int(m.t("dormant_days", 90))
    return {
        "structuring_like": f"≥ 3 transfers between {band:.0%} and 100% of the ₹{thr:,} reporting threshold within 7 days",
        "rapid_movement": "≥ 80% of an inbound transfer moved out by transfer within 24 h",
        "velocity": "daily count in the window ≥ 3× the account's baseline daily count",
        "velocity_burst_24h": "densest 24 h in the window ≥ max(6, 4 × baseline daily count)",
        "geo_shift": "≥ 3 countries within any 7-day span of the window",
        "high_risk_merchant_exposure": "≥ 40% of non-transfer spend in the window at high-risk-MCC merchants",
        "circular_transfers": f"a transfer cycle back to the account, path length ≤ 5, **every hop inside the last {cyc} days**",
        "dormant_activation": f"≥ {dorm} days of silence before the window, then ≥ 5 transactions in the first 3 days",
        "shared_device_ring": "≥ 3 accounts on a device this account uses (as of the window end)",
        "linked_entity_risk": "worst precomputed risk among linked accounts / devices ≥ 50",
    }


def _acct_conditions(m: Any) -> dict[str, str]:
    return {
        "new_device": "login device not among the account's known devices",
        "new_country": "login country not among the account's known countries",
        "impossible_travel": "country differs from the previous login and that login was < 2 h ago",
        "credential_change": "password / email changed in this session",
        "mfa_change": "second factor changed in this session",
        "payout_change": "payout / settlement destination changed in this session",
        "session_anomaly": "the authentication service flagged the session",
        "velocity": f"≥ {int(m.t('velocity_1h', 5))} logins in the previous hour",
        "mfa_not_passed": "second factor not completed",
        "device_history_thin": "a new device on an account with ≤ 1 known device",
    }


DISPUTE_CONDITIONS = {
    "prior_disputes_many": "≥ 2 disputes in the previous 90 days",
    "prior_disputes_some": "exactly 1 dispute in the previous 90 days",
    "amount_over_auto_limit": "amount above the ledger's auto-approval limit",
    "claim_contradicted": "the trusted record disagrees with the claim (contradiction engine)",
    "account_risk_high": "account entity risk ≥ 50",
    "account_risk_medium": "account entity risk 25–49",
    "security_flagged": "the gateway flagged the submission (severity ≥ MEDIUM)",
}

ENTITY_CONDITIONS = {
    "shared_device_many": "≥ 5 accounts use the device (as of)",
    "shared_device": "3–4 accounts use the device (as of)",
    "linked_frozen_account": "an account on the device is frozen",
    "device_new": "device first seen < 7 days before as-of",
    "merchant_unknown": "merchant not in records",
    "dispute_ratio_high": "≥ 5% of the merchant's transactions before as-of were disputed before as-of (≥ 5 transactions)",
    "dispute_ratio_elevated": "2–5% disputed (≥ 5 transactions)",
    "mcc_high": "high-risk merchant category",
    "mcc_medium": "medium-risk merchant category",
    "registration_shell": "registration status `shell`",
    "registration_unverified": "registration status not `verified`",
    "prior_flags": "prior fraud flags (10 per flag, capped at 30)",
    "merchant_young": "registered < 90 days before as-of",
    "owner_linked_flagged": "the owner controls another merchant with prior flags",
    "account_unknown": "account not in records",
    "prior_disputes_many": "≥ 2 disputes in the 90 days before as-of",
    "prior_disputes_some": "1 dispute in the 90 days before as-of",
    "recent_security_events": "a payout, MFA or credential change among the recent trusted session events",
    "account_young": "opened < 30 days before as-of",
    "account_frozen": "account status frozen",
    "linked_device_high": "a device the account uses (as of) scores ≥ 50",
    "linked_device_medium": "a device the account uses (as of) scores 25–49",
    "high_risk_merchant_exposure": "≥ 30% of the account's spend before as-of at high-risk-MCC merchants",
    "worst_account": "the customer's worst account profile (its score, as points)",
}


def _entity_factors() -> list[tuple[str, str, str]]:
    """(code, label, points) parsed from risk/entity.py so the table cannot drift."""
    src = (ROOT / "sentinel" / "risk" / "entity.py").read_text(encoding="utf-8")
    pat = re.compile(r'RiskFactor\(\s*"(\w+)",\s*"([^"]+)",\s*([^,\)]+)', re.S)
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for code, label, points in pat.findall(src):
        if code in seen:
            continue
        seen.add(code)
        pts = points.strip()
        if pts.startswith("min("):
            pts = "10 per flag, max 30"
        elif not pts.isdigit():
            pts = "score of the worst account"
        out.append((code, label, pts))
    return out


def render_risk_engine() -> str:
    from sentinel.domain.enums import RiskLevel
    from sentinel.risk import account_security, dispute, entity, monitoring, scoring, transaction

    bands = tbl(
        ["Band", "Score", "Recommended action (risk engine's own suggestion; policy decides)"],
        [
            ["LOW", "0–24", scoring.recommended_action(RiskLevel.LOW)],
            ["MEDIUM", "25–49", scoring.recommended_action(RiskLevel.MEDIUM)],
            ["HIGH", "50–74", scoring.recommended_action(RiskLevel.HIGH)],
            ["CRITICAL", "75–100", scoring.recommended_action(RiskLevel.CRITICAL)],
        ],
    )
    time_rows = tbl(
        ["Record field read by the engines", "Time semantics", "Consequence"],
        [
            [
                "transactions, disputes (`submitted_at`), login sessions",
                "timestamped; read as of the decision",
                "a later record is invisible to an earlier decision (benchmarked)",
            ],
            [
                "device `first_seen`, instrument `added_at`, graph edges",
                "timestamped; read as of the decision",
                "a later device, instrument or relationship is invisible (benchmarked)",
            ],
            [
                "account `opened_at`, merchant `registered_at`",
                "timestamped; ages measured to the decision",
                "--",
            ],
            [
                "account `status`",
                "as of the decision via `status_since` (2.2.0); a status with no recorded start is read as current",
                "a later freeze is invisible (benchmarked); legacy data without a start date is current state",
            ],
            [
                "account payout destination",
                "the bank accounts held at the decision time",
                "a later payout change is invisible (benchmarked)",
            ],
            [
                "merchant `registration_status`, `prior_flags`, `mcc_risk`",
                "static attributes set at registration; no history",
                "a later re-classification would move earlier merchant scores -- not modelled; would need dated merchant events",
            ],
            [
                "dispute `refund_state`, `merchant_response`, transaction `status`",
                "current state at the time the dispute is decided",
                "correct for a live decision; replay uses the snapshot taken then, not today's values",
            ],
            [
                "stored risk assessments, AI-security events",
                "never read by scoring",
                "cannot leak (benchmarked)",
            ],
        ],
    )
    active = {m.version: surface for surface, m in scoring.ACTIVE.items()}
    models = tbl(
        ["Version", "Surface", "Status", "Factors", "Thresholds", "Description"],
        [
            [
                f"`{v}`",
                scoring.surface_of(m),
                "**active**" if v in active else "historical (replay / what-if only)",
                len(m.weights),
                len(m.thresholds),
                m.description or "—",
            ]
            for v, m in scoring.MODELS.items()
        ],
        "lllrrl",
    )
    tv = [scoring.TRANSACTION_V1, scoring.TRANSACTION_V1_1, scoring.TRANSACTION_V2]
    cond = _txn_conditions(scoring.TRANSACTION_DEFAULT)
    codes = [code for code, _, _ in transaction.RULES]
    missing = [c for c in codes if c not in cond]
    assert not missing, f"undocumented transaction rules: {missing}"
    groups = scoring.FACTOR_GROUPS
    txn_rows = tbl(
        ["Factor", "Label", "Condition (`txn-2.0` thresholds)", "Group"]
        + [f"`{m.version}`" for m in tv],
        [
            [f"`{code}`", label, cond[code], groups.get(code, "—")] + [m.w(code) or "—" for m in tv]
            for code, label, _ in transaction.RULES
        ],
        "llllrrr",
    )
    missing_meta = [c for c in codes if c not in FEATURE_META]
    assert not missing_meta, f"undocumented feature metadata: {missing_meta}"
    meta_rows = tbl(
        ["Factor", "Source (trusted record)", "Time semantics", "Reads"],
        [[f"`{code}`", *FEATURE_META[code]] for code, _, _ in transaction.RULES],
    )
    thr_rows = tbl(
        ["Threshold"] + [f"`{m.version}`" for m in tv],
        [
            [f"`{k}`"] + [m.thresholds.get(k, "—") for m in tv]
            for k in scoring.TRANSACTION_V2.thresholds
        ],
        "lrrr",
    )
    group_rows = tbl(
        ["Component", "Factors"],
        [
            [g, ", ".join(f"`{c}`" for c, gg in groups.items() if gg == g)]
            for g in dict.fromkeys(groups.values())
        ],
    )
    mon = scoring.MONITORING_V1
    mcond = _mon_conditions(mon)
    mcodes = [c for c, _, _ in monitoring.RULES]
    assert all(
        c in mcond for c in mcodes
    ), f"undocumented monitoring rules: {[c for c in mcodes if c not in mcond]}"
    mon_rows = tbl(
        ["Indicator", "Label", "Condition", "Points"],
        [[f"`{c}`", lab, mcond[c], mon.w(c)] for c, lab, _ in monitoring.RULES],
        "lllr",
    )
    mon_thr = tbl(
        ["Threshold", "Value"],
        [
            [f"`{k}`", f"{v:,}" if isinstance(v, int) and v >= 1000 else v]
            for k, v in mon.thresholds.items()
        ],
        "lr",
    )
    acct = scoring.ACCOUNT_SECURITY_V1
    acond = _acct_conditions(acct)
    acodes = [c for c, _, _ in account_security.RULES]
    assert all(
        c in acond for c in acodes
    ), f"undocumented account-security rules: {[c for c in acodes if c not in acond]}"
    acct_rows = tbl(
        ["Factor", "Label", "Condition", "Points"],
        [[f"`{c}`", lab, acond[c], acct.w(c)] for c, lab, _ in account_security.RULES],
        "lllr",
    )
    disp = scoring.DISPUTE_V1
    dcodes = [c for c, _, _ in dispute.RULES]
    assert all(
        c in DISPUTE_CONDITIONS for c in dcodes
    ), f"undocumented dispute rules: {[c for c in dcodes if c not in DISPUTE_CONDITIONS]}"
    disp_rows = tbl(
        ["Factor", "Label", "Condition", "Points"],
        [[f"`{c}`", lab, DISPUTE_CONDITIONS[c], disp.w(c)] for c, lab, _ in dispute.RULES],
        "lllr",
    )
    import dataclasses

    window_days = next(
        fld.default
        for fld in dataclasses.fields(monitoring.MonitoringContext)
        if fld.name == "window_days"
    )
    ef = _entity_factors()
    missing_e = [c for c, _, _ in ef if c not in ENTITY_CONDITIONS]
    assert not missing_e, f"undocumented entity factors: {missing_e}"
    ent_rows = tbl(
        ["Factor", "Label", "Condition", "Points"],
        [[f"`{c}`", lab, ENTITY_CONDITIONS[c], pts] for c, lab, pts in ef],
        "lllr",
    )
    return f"""# Risk engine

Rendered by `make docs` from `sentinel/risk/scoring.py`, `transaction.py`,
`monitoring.py`, `account_security.py`, `dispute.py` and `entity.py`. The
point values and conditions below **are** the model; the prose explains it.

## What this is, and is not

A **deterministic, versioned, factor-level explainable rule model**. Each
factor is a named condition over trusted records; a factor that fires
contributes its point value; the total is capped at 0–100 and banded. Every
assessment stores its feature snapshot so it can be re-scored under another
model version (`sentinel replay run … --risk-model`) without re-reading any
source system. The score is a *recommendation to policy*, never an action.

It is **not** a trained model and the point values are **not industry
standards**. They are Sentinel heuristics chosen while looking at the
development seed of the synthetic generator; `docs/EVALUATION.md` §G reports
how they behave on that seed and on two seeds they never saw. Nothing here is
calibrated on real payment data.

{bands}

## Model versions (`scoring.MODELS`)

{models}

Authoritative evaluation always scores with the active model of its surface
(`scoring.ACTIVE`); a request cannot select another, and a model is only ever
applied to its own surface (`scoring.model_for`). Historical models exist for
replay and what-if comparison (`docs/SECURITY_MODEL.md`, evaluation authority).

`txn-1.0` → `txn-1.1` exists so replay can show a *model* change (geography
weighted up, device weighted down, moderate-amount threshold raised).
`txn-2.0`, the default, adds short-window velocity and inter-arrival timing
(a burst becomes visible on the {int(scoring.TRANSACTION_V2.t('rapid_fire_count', 3)) + 1}th transaction, once {int(scoring.TRANSACTION_V2.t('rapid_fire_count', 3))} precede it inside {int(scoring.TRANSACTION_V2.t('rapid_window_minutes', 10))} minutes, instead of the 9th),
trusted account-security events in the {int(scoring.TRANSACTION_V2.t('security_event_hours', 24))} h before a transaction (the takeover
pattern: a payout change or a failed second factor shortly before a purchase)
and payout-instrument sharing across accounts (the ring pattern).

## Point-in-time invariant

Every feature is computed **as of the transaction** (or the monitoring
window's end): the behavioural baseline reads only earlier transactions and
only disputes filed earlier; device knowledge asks the time-aware graph
whether the device was used on the account at least 24 h *before*; entity
profiles are cached per `(entity, as_of)` and read only records at or before
`as_of`; every graph edge carries a timestamp and queries take `as_of`; the
monitoring cycle finder accepts only hops inside its window; an account's
status counts from when it took effect (`Account.status_at`) and payout
sharing reads the bank accounts held at T, not the current payout field (both
were current-state reads until the 2.2.0 temporal extension found them).

**What this is and is not.** It is a *tested temporal invariant*: every field
the engines read is either timestamped and read as of the decision, or a
static attribute, or deliberately current state -- and the benchmark checks
that nine kinds of later record never move an earlier decision. It is **not**
a fully event-sourced historical model: several fields have no history in the
data model, so a later change to them would not be visible as a change.

{time_rows}

`results/temporal.json` measures it ("0 observed temporal leaks across the
tested synthetic benchmark" -- evidence for the invariant, not a proof); `tests/test_temporal_leakage.py` and
`tests/test_entity_pointintime.py` pin it.

## Transaction model ({len(transaction.RULES)} factors)

Inputs: the transaction; the account's baseline over its earlier history
(`risk/behavioral.py`: mean / stddev / median amount, daily count, median gap,
usual countries / devices / merchants / instruments, usual hours,
point-in-time chargeback rate); the last 24 h of trusted sessions; the
merchant's entity profile; device and instrument sharing from the graph as of
the transaction; the worst linked-entity profile.

{txn_rows}

Where each feature comes from and what point in time it reads. Every source
is a trusted record; prose never enters. Point values are heuristics and every
one of them is a design choice, not a measurement: `docs/EVALUATION.md` §G
reports how often each factor fires on fraud-labelled and on legitimate
transactions, which is the honest measure of how much each one is worth.

{meta_rows}

Thresholds:

{thr_rows}

Components (the auditable breakdown shown on every assessment):

{group_rows}

## Transaction monitoring model (`{mon.version}`, {len(monitoring.RULES)} indicators)

Account-level, over a {window_days}-day window ending at `as_of` (`MonitoringContext.window_days`).
{mon.description} **This is a synthetic transaction-monitoring / investigation
simulation**; it claims no regulatory compliance, no sanctions screening and
no filing capability.

{mon_rows}

{mon_thr}

## Account-security model (`{acct.version}`, {len(account_security.RULES)} factors)

Over one trusted login session and the account's device / country history.

{acct_rows}

## Dispute model (`{disp.version}`, {len(dispute.RULES)} factors)

Over the ledger facts, the contradiction verdict and the account's entity
profile; the claim text never enters.

{disp_rows}

## Entity profiles (`{entity.ENTITY_MODEL_VERSION}`)

Computed in a fixed order -- device → merchant → account → customer -- so
nothing is circular, each as of a given time and cached per `(entity, as_of)`.
Point values are in the code; this table is parsed from it.

{ent_rows}

## How the score is used

Transaction: the assessment's score and level enter the policy context
(`risk_score`, `risk_level`, `risk_factors`) and the merchant / account
profiles feed `merchant_risk_score`, `account_risk_score`. Investigation: the
monitoring indicators enter as `monitoring_patterns`. Policy decides the
outcome; the registry decides who may execute it; the risk engine only ever
recommends. Every factor carries its label, points, detail and evidence ids,
so a block is explainable to the factor.
"""


# --------------------------------------------------------------------------- POLICY ENGINE


def render_policy_engine() -> str:
    from sentinel.policy.engine import lint
    from sentinel.policy.loader import DEFAULT_REGISTRY
    from sentinel.policy.models import CONTEXT_FIELDS, FIELD_CATALOG, OPS

    cat_rows = tbl(
        ["Field", "Type", "Meaning", "Always in context"],
        [
            [f"`{n}`", t, d, "yes" if n in CONTEXT_FIELDS else "declare in `required_fields`"]
            for n, (t, d) in FIELD_CATALOG.items()
        ],
    )
    pols = DEFAULT_REGISTRY.all()
    from sentinel.policy.loader import MANIFEST, POLICY_DIR, policy_digest

    pinned = json.loads((POLICY_DIR / MANIFEST).read_text())["policies"]
    for pol in pols:
        assert pinned.get(pol.key) == policy_digest(pol), f"{pol.key} not pinned"
    ids = sorted({pol.policy_id for pol in pols})
    ver_rows = tbl(
        ["Policy", "Active (authoritative)", "Historical (replay / what-if only)"],
        [
            [
                f"`{pid}`",
                f"v{DEFAULT_REGISTRY.active(pid).version}",
                ", ".join(f"v{v}" for v in DEFAULT_REGISTRY.historical(pid)) or "—",
            ]
            for pid in ids
        ],
    )
    pol_rows = tbl(
        [
            "Policy",
            "Version",
            "Workflow",
            "Rules",
            "Default",
            "Required fields",
            "Effective from",
            "Content hash",
            "Lint",
        ],
        [
            [
                f"`{p.policy_id}`",
                p.version,
                p.workflow.value,
                len(p.rules),
                p.default_outcome.value,
                ", ".join(f"`{f}`" for f in p.required_fields) or "—",
                p.effective_from or "—",
                f"`{p.content_hash[:12]}`",
                "clean" if not lint(p) else f"{len(lint(p))} finding(s)",
            ]
            for p in pols
        ],
        "lrlrllll",
    )
    rule_sections = []
    for p in pols:
        rows = [
            [
                f"`{r.rule_id}`",
                " AND ".join(f"`{c.describe()}`" for c in r.when),
                r.outcome.value,
                r.reason,
            ]
            for r in p.rules
        ]
        rule_sections.append(
            f"### `{p.policy_id}` v{p.version} -- {p.description}\n\n"
            + tbl(["Rule", "When (all conditions)", "Outcome", "Reason"], rows)
        )
    rules_md = "\n\n".join(rule_sections)
    ops = ", ".join(f"`{o}`" for o in sorted(OPS))
    return f"""# Policy engine

Rendered by `make docs` from `sentinel/policy/models.py`,
`sentinel/policy/engine.py` and the shipped policies in
`sentinel/policy/policies/`. The rule tables are the policies.

## Policy-as-code

A policy is a JSON document (YAML when PyYAML is installed): an id, an
integer version, a workflow, an `effective_from` date, a `default_outcome`,
a list of rules and the `required_fields` it needs beyond the always-present
context. Each rule is an AND of conditions over declared fields and produces
an outcome. Evaluation is **deterministic and order-independent**: every rule
is evaluated, the most severe matching outcome wins
(ALLOW < STEP_UP < REQUIRE_HUMAN_REVIEW < TEMPORARY_HOLD < BLOCK), and every
match is explained. There is no `else`, no scripting and no model call.

Operators: {ops}. `in` / `not_in` require a list; `contains` works on lists
and strings. Every value a rule reads must have its catalog type (below): a
string where a number is expected raises, it is not "false".

## Fail-closed by construction

- **Validation at load** rejects unknown fields, operators, outcomes and
  type mismatches; unknown keys in the document, a rule or a condition (a
  misspelt `unless`, an `"enabled": false` the engine would ignore); a
  missing `default_outcome` (no implicit ALLOW); and a value a field can never
  take (an unknown capability, an impossible enum value) -- a gate that could
  never fire. A misconfiguration is caught before any decision.
- **Typed context at evaluation.** A value of the wrong type (an amount of
  `"999999"`, a boolean where a number is expected) raises
  `PolicyEvaluationError` instead of making a numeric rule quietly false; the
  composer turns it into a fail-safe `REQUIRE_HUMAN_REVIEW`.
- **A rule may reference a field only if the composer always provides it or
  the policy declares it in `required_fields`.** At evaluation, a context
  missing any referenced field raises `PolicyEvaluationError`; the composer
  turns that into a fail-safe `REQUIRE_HUMAN_REVIEW`. A missing input can
  therefore never silently switch a BLOCK rule off (v2.0.0 had that fail-open
  behaviour; the review found it).
- **Content hash.** Every policy carries a SHA-256 over its full document,
  computed at construction. Decisions and input snapshots pin it; replay
  reports `policy_drift` when the served version no longer has the content the
  decision was made under. A version number is a label a file edit can reuse;
  the hash is what is trusted.
- **Pinned versions.** `sentinel/policy/policies/MANIFEST.json` pins the full SHA-256 of every
  shipped version. A version edited in place, added without pinning or deleted
  raises `PolicyIntegrityError` before anything is registered, and a store that
  recorded decisions under a version with other content refuses to open.
  `sentinel policy pin` pins *new* versions only and refuses to re-pin a
  changed one: a policy change is a new version. This guards against an
  accidental in-place edit; it is not a defence against someone who can edit
  both the policy and the manifest (that is code review and signed releases).
- **A trusted fact can never overwrite a computed field**: the composer
  writes its own fields first and only fills gaps from the workflow's facts.

## The context

Every field a rule may read comes from the trusted view: the workflow, the
amount, the *candidate* capability and its registry flags, the risk
assessment, the evidence verdict, the gateway's severity and structural
findings, and the workflow's trusted facts. There is no field for prose and no
field for the model's recommendation. `security_*` and
`capability_escalation` are the only model-adjacent inputs and they can only
tighten an outcome.

{cat_rows}

## Lint (`sentinel policy lint`, `POST /v1/policies/lint`)

`validate` rejects what is malformed; `lint` reports what is legal but wrong
before a policy is activated: no `effective_from`; no rules; an ALLOW rule
(it can never change a most-severe-wins outcome); an unknown capability or
enum value in a condition (a rule that can never fire); duplicate or
contradictory conditions on one field; an empty numeric range; a rule with
the same conditions as an earlier one. `tests/test_policy_lint.py` covers
each finding. All shipped versions lint clean (table below).

## Versions: active, historical, what-if

An authoritative evaluation -- one that is recorded, audited, can open a case
and can execute -- always runs the **active** version of its policy
(`PolicyRegistry.active`) and the active risk model of its surface. No request
parameter selects another: the evaluate routes refuse `options.policy_version`
and `options.risk_model` with 403, the authoritative CLI commands do not have
the flags, and the engine itself refuses to record a run whose inputs name a
non-active version (`sentinel/decision/authority.py`). **Historical** versions
stay loadable only so a recorded decision can be replayed under the policy it
was made with, or compared with another; replay, the attack simulator and
scenario runs are **what-ifs** and are never recorded as decisions.

{ver_rows}

## Shipped policies

{pol_rows}

{rules_md}
"""


# --------------------------------------------------------------------------- EVIDENCE MODEL


def render_evidence_model() -> str:
    import dataclasses

    from sentinel.domain.enums import (
        ClaimType,
        EvidenceKind,
        EvidenceStatus,
        EvidenceVerdict,
        TrustClass,
    )
    from sentinel.evidence.contradiction import COMPATIBILITY
    from sentinel.security.trust_boundary import DisputeFacts, KYBFacts

    kind_src = {
        "ledger_fact": "the institution's payment ledger (`DisputeFacts`)",
        "acquirer_record": "verified acquirer records (`KYBFacts`)",
        "session_record": "authentication service",
        "risk_signal": "the risk or monitoring engine (a trusted computation over records)",
        "user_claim": "cardholder prose",
        "merchant_claim": "merchant application copy",
        "document_claim": "an uploaded document",
    }
    for k in EvidenceKind:
        assert k.value in kind_src, f"undocumented evidence kind {k}"
    kinds = tbl(
        ["EvidenceKind", "Typical source"],
        [[f"`{k.value}`", kind_src[k.value]] for k in EvidenceKind],
    )
    status = tbl(
        ["EvidenceStatus", "Meaning"],
        [
            ["`VERIFIED`", "from a trusted source; the only status that can support a claim"],
            ["`CLAIMED`", "asserted by an untrusted party; unverified"],
            ["`CONTRADICTED`", "a claim the trusted record disagrees with"],
        ],
    )
    assert {s.value for s in EvidenceStatus} == {"VERIFIED", "CLAIMED", "CONTRADICTED"}
    verdicts = tbl(
        ["EvidenceVerdict", "Meaning", "Consequence in the composer"],
        [
            [
                "`SUPPORTED`",
                "the trusted records support the claim",
                "the only verdict under which a consequential capability can execute",
            ],
            ["`UNSUPPORTED`", "no trusted record confirms the claim", "DENY"],
            [
                "`CONTRADICTED`",
                "a trusted record says the opposite",
                "DENY, with a `Contradiction` object attached",
            ],
            [
                "`INSUFFICIENT`",
                "the claim cannot be mapped to a trusted fact yet",
                "REQUIRE_HUMAN_REVIEW (fail-safe)",
            ],
        ],
    )
    assert {v.value for v in EvidenceVerdict} == {
        "SUPPORTED",
        "UNSUPPORTED",
        "CONTRADICTED",
        "INSUFFICIENT",
    }
    claims = tbl(
        ["ClaimType", "Checked against", "Values that support it"],
        [
            [
                f"`{ct.value}`",
                f"`{DisputeFacts.CLAIM_FIELDS[ct][0]}`" if ct in DisputeFacts.CLAIM_FIELDS else "—",
                (
                    ", ".join(f"`{v}`" for v in DisputeFacts.CLAIM_FIELDS[ct][1])
                    if ct in DisputeFacts.CLAIM_FIELDS
                    else (
                        "never supported: held for a human (premature dispute) unless the ledger says delivered, which contradicts it"
                        if ct is ClaimType.IN_TRANSIT
                        else "never supported (nothing recognisable to verify)"
                    )
                ),
            ]
            for ct in ClaimType
        ],
    )
    compat = tbl(
        ["Field", "Claimed value", "Recorded values consistent with it"],
        [
            [f"`{fld}`", f"`{cv}`", ", ".join(f"`{r}`" for r in sorted(rec, key=str))]
            for fld, tab in COMPATIBILITY.items()
            for cv, rec in tab.items()
        ],
    )
    dfields = tbl(
        ["`DisputeFacts` field", "Default", "Values"],
        [
            [
                f"`{f.name}`",
                repr(f.default),
                {
                    "delivery_status": "delivered | not_delivered | in_transit | returned | lost",
                    "refund_state": "none | pending | refunded",
                    "transaction_status": "settled | pending | reversed",
                    "merchant_response": "none | accepted | contested",
                    "auth_strength": "none | password | otp | biometric",
                }.get(f.name, ""),
            ]
            for f in dataclasses.fields(DisputeFacts)
        ],
    )
    kfields = tbl(
        ["`KYBFacts` field", "Default"],
        [[f"`{f.name}`", repr(f.default)] for f in dataclasses.fields(KYBFacts)],
    )
    trusted = ", ".join(f"`{t.value}`" for t in TrustClass if t.is_trusted)
    return f"""# Evidence model

Rendered by `make docs` from `sentinel/domain/enums.py`,
`sentinel/domain/evidence.py`, `sentinel/security/trust_boundary.py`,
`sentinel/evidence/contradiction.py` and `sentinel/evidence/reconcile.py`.

## Evidence objects

Every fact the decision sees is an `Evidence` object: an id, a kind, a
source, a trust class, a field, a value, a status and a content hash. Two
constructors exist and the type enforces the boundary: `Evidence.fact` is
VERIFIED and accepts only {trusted}; `Evidence.claim` is CLAIMED and refuses a
trusted class. A `MODEL_GENERATED` value can therefore never become VERIFIED
evidence by any code path, and a fabricated "ledger extract" pasted into a
narrative arrives as a claim, whatever it says (the `synthetic_evidence`
threat class).

{kinds}

{status}

## Claims

Untrusted text is opaque. The only value ever derived from prose is a coarse
`ClaimType`, read by the deterministic claim classifier
(`sentinel/security/claims.py`, called from `UntrustedText.classify`): weighted
pattern families, a negation guard, a hedge detector and a conflict rule, with
an explicit confidence. When it cannot read a claim it **abstains**; a message
it recognises as asserting nothing refundable is a **non-claim**. The claim
type is a **selector** for which trusted field to check -- never evidence. The
classifier is defence in depth, not the security foundation: a wrong reading
can only select a different trusted field, and the records still decide.
`Claim` carries the type, the source, the trust class, the confidence, the
kind (claim / non-claim / abstain), the signals and a hash of the text; the
text itself is not stored on the decision or in the audit chain.

{claims}

`DisputeFacts.supports(claim)` is a pure function of the facts: the claim
only chooses which field to read.

## Trusted facts

`TrustedFacts` subclasses are built from records only (`from_ledger`,
`from_records`), and each constructor reads its declared fields by name: any
other key on the mapping (a `narrative`, `document` or `note`) is never
copied (`tests/test_trust_boundary.py`). Every field renders itself as
VERIFIED evidence.

{dfields}

{kfields}

## Contradictions

A contradiction is a claim and a verified fact on the same field that cannot
both be true. Compatibility is data: for each field, which claimed values are
consistent with which recorded values; a field with no table falls back to
strict equality. An absence of confirmation (`duplicate_confirmed = False`)
is *not* a contradiction -- it leaves the claim UNSUPPORTED, not CONTRADICTED.

{compat}

Each contradiction is a first-class object (`claim_evidence_id`,
`fact_evidence_id`, `field`, `claimed`, `recorded`, `impact`) shown in the
console, the case packet and the decision.

## Reconciliation verdicts

{verdicts}

**Dispute** (`reconcile_dispute`): an abstain is INSUFFICIENT (the claim could
not be read; held for a human); a recognised non-claim is UNSUPPORTED (nothing
refundable asserted); IN_TRANSIT is CONTRADICTED when the ledger says
delivered and INSUFFICIENT otherwise (a premature dispute, held for a human);
any other claim is SUPPORTED when `supports()` holds, CONTRADICTED when the
contradiction engine found a conflict on the claim's field, and UNSUPPORTED
otherwise. Document claims are reconciled alongside the narrative's claim.

**Merchant onboarding** (`reconcile_kyb`): the applicant implicitly claims to
be a verified, clean business. Shell registration or ≥ 2 prior flags →
CONTRADICTED; verified with domain ≥ 30 days, business ≥ 90 days and no flags
→ SUPPORTED; anything else → INSUFFICIENT (human review). The application
text and document can add claims and contradictions; they cannot add facts.

**Records-only workflows** (transaction authorisation, account security,
investigations): the evidence is the trusted records themselves and the
verdict is SUPPORTED; policy and the registry carry the decision.

## The model's recommendation is not evidence

The agent's tool call is interpreted into an `AIRecommendation`
(`MODEL_GENERATED`) and recorded on the `Decision` as `ai_recommendation`, for
explainability and measurement. It is never added to an `EvidenceSet`, never
reconciled and never read by the composer's trusted view; an `Evidence` item
with `MODEL_GENERATED` trust cannot be VERIFIED even if one is built by hand.
`tests/test_model_output_separation.py` and `tests/test_evidence.py` pin this.
"""


# --------------------------------------------------------------------------- AUDIT MODEL


def render_audit_model() -> str:
    import dataclasses

    from sentinel.audit import chain

    body_fields = [
        f.name
        for f in dataclasses.fields(chain.AuditEvent)
        if f.name not in ("previous_hash", "event_hash")
    ]
    fields_md = ", ".join(f"`{f}`" for f in body_fields)
    raw = ", ".join(f"`{k}`" for k in sorted(chain._RAW_TEXT_KEYS))
    cp_fields = ", ".join(f"`{f.name}`" for f in dataclasses.fields(chain.Checkpoint))
    return f"""# Audit model

Rendered by `make docs` from `sentinel/audit/chain.py`.

## Terminology

This is a **tamper-evident application audit chain**. It is not a blockchain
and it is not an immutable ledger: there is no consensus, no distribution and
no guarantee that a record cannot be changed. The guarantee is narrower and
precise -- **any modification, deletion, insertion or reordering of a
recorded event is detected by verification, and the first bad record is
named** -- and the trust root is a checkpoint stored outside the store.

## The record

One `AuditEvent` per recorded event, of three kinds: `decision` (every
authoritative decision; the case it opened is linked to it), `case` (every
human case action: a case opened by hand `CASE_OPENED`, a status change
`CASE_<STATUS>`, a human decision `HUMAN_APPROVE` / `HUMAN_DENY` /
`HUMAN_ESCALATE`, with the declared role and hashes of any note or title) and
`replay`. What-if runs are never chained. The hash covers every field except
the two hashes: {fields_md}.
`event_hash = SHA-256(canonical_json(body) ‖ previous_hash)`; the first
event's `previous_hash` is the genesis constant; `sequence` is contiguous
from 0. `detail` is redacted before hashing: any of {raw} is replaced by its
SHA-256 and length, so **no untrusted prose is ever persisted in the chain**
(detector spans are hashed too).

A decision's event also records, in `detail`, the SHA-256 of the decision's
input snapshot (`snapshot_hash`), the risk-model version and the engine
version. Replay checks the stored snapshot against that hash and takes the
recorded side of its comparison from the event, so a decision row and a
snapshot edited consistently in the database cannot replay as "no change"
(`tests/test_replay_integrity.py`).

## Verification (`sentinel audit verify [--file PATH]`, `GET /v1/audit/verify`)

Recomputes the chain from genesis and reports every problem with its
record index; `--file` verifies an exported JSONL chain (`sentinel audit
export`) without opening a store. A failure prints **AUDIT INTEGRITY ERROR**
with the problem count and the first bad record and exits with status 2 --
never a parser traceback, never a silent pass:

| Tampering | Detected by |
|---|---|
| a field of an event modified | `event_hash` mismatch on that record |
| an event deleted | `sequence` gap on the following record, and its `previous_hash` no longer matches |
| an event inserted | `sequence` collision and a broken link on the record after it |
| events reordered | `previous_hash` mismatch |
| a record unreadable (malformed JSON, truncated line, missing field) | reported as unreadable with the reason; verification continues, so later problems are reported too, and the link from the unreadable record is not assumed |
| the chain truncated at the end | the stored length / head no longer match a checkpoint |

`tests/test_audit_chain.py`, `tests/test_data_store_replay.py`,
`tests/test_rc_hardening.py` and `tests/test_audit_corruption.py` exercise each
row -- malformed JSON, a truncated line, a missing field, a wrong hash, a wrong
predecessor, deleted / inserted / reordered lines, a cut last line -- through
the library and the CLI, and edited rows in the SQLite store.

## Backends and lookups

Memory, JSONL and SQLite backends implement the same protocol: `append`,
`count`, `tail`, `at(sequence)`, `find(event_id | decision_id)` and
`read_all`. Lookups by event id or decision id are indexed (an in-memory index
for JSONL, SQL indexes for SQLite), so the console and the API do not re-read
the log to open one event. `verify()` deliberately does read everything: a
lookup path that skipped records would be a lookup path that skipped tampering
(`tests/test_audit_indexing.py`).

## Checkpoints (`sentinel audit checkpoint`, `make audit-checkpoint`)

A `Checkpoint` ({cp_fields}) states that at `length` events the head hash
was `head_hash`. It is meant to be stored **outside** the audit store -- a
second system, a ticket, a signed release artefact. With `SENTINEL_AUDIT_KEY`
set it is signed with HMAC-SHA256 over its canonical body, so a storage
attacker who rewrites the whole chain consistently from genesis still cannot
produce the recorded head (or forge a checkpoint without the key).
`sentinel audit verify --checkpoint FILE` checks the chain against it: the
stored prefix must still hash to the checkpointed head. Precisely:

- a **signed** checkpoint (key set when it was written and when it is
  checked) detects a consistent rewrite of the whole chain, a truncation below
  its length, and an edited checkpoint (the signature no longer verifies);
- an **unsigned** checkpoint detects the same only if it was stored where the
  attacker could not also rewrite it; checking an unsigned checkpoint while a
  key is set, or a signed one without the key, is reported as a failure, not
  skipped;
- a checkpoint says nothing about events appended after it; the chain
  verification covers those.

The HMAC key is a shared secret, not a public-key signature: anyone who holds
it can also produce checkpoints.

## Exit codes (`sentinel audit ...`)

| Command | 0 | 2 | 1 |
|---|---|---|---|
| `audit verify` | chain intact | **AUDIT INTEGRITY ERROR**: a record modified, deleted, inserted, reordered, unreadable or with a missing field; the first bad record is named | the store or file cannot be opened |
| `audit verify --file PATH` | exported chain intact | AUDIT INTEGRITY ERROR in the exported file | the file does not exist |
| `audit verify --checkpoint FILE` | chain intact and it matches the checkpoint | the chain disagrees with the checkpoint, or the signature / key check fails | the checkpoint file is not valid JSON or lacks a field |
| any command that appends (evaluate, analyze, ...) | -- | AUDIT INTEGRITY ERROR: the store's event count or a sequence no longer matches the chain, so nothing was appended | -- |

## What the chain does not do

- It does not prove *what happened*, only that the record of it was not
  altered since it was written. A compromised process can write a false event
  honestly.
- Without a checkpoint stored elsewhere, a consistent rewrite of the entire
  chain from genesis is undetectable; the checkpoint is the external anchor.
- Key management for `SENTINEL_AUDIT_KEY` is the operator's (environment
  only; never committed or logged).
- Deleting the store deletes the chain; availability is a storage concern.
"""


# --------------------------------------------------------------------------- GEN BLOCKS


def blocks(R: dict[str, Any], tests: int) -> dict[str, str]:
    s, h, sf, k, b, a, f, i, t, p, m, cl = (R[x] for x in SUITES)
    td = t["dataset"]
    seeds = ", ".join(str(x) for x in td["seeds"])
    offs = ", ".join(str(d) for d in t["future_offsets_days"])
    txn_ch = sum(v["transaction_changed"] for v in t["perturbation_by_kind"].values())
    mon_ch = sum(v["monitoring_changed"] for v in t["perturbation_by_kind"].values())
    ub = t.get("leakage_upper_95")
    ub_s = f"{ub:.3%}" if ub is not None else "n/a -- leaks found"
    from sentinel.policy.loader import DEFAULT_REGISTRY
    from sentinel.risk import scoring
    from sentinel.security.threats import TAXONOMY

    n_classes = len(s["by_class"])
    e2e = p["components"]["e2e_dispute_pipeline"]
    sr = f["seed_range"]
    tl, al = f["transaction_level"], f["account_level"]
    seed = f["dataset"]["seed"]
    kc = k["corpus"]
    live = _live_row(m)
    mb = tl["miss_breakdown"]
    missed_scn = " / ".join(sc.replace("fraud:", "") for sc, v in mb.items() if v["missed"])
    total_missed = sum(v["missed"] for v in mb.values())
    cycle_days = int(scoring.MONITORING_V1.t("cycle_window_days", 30))
    undetected = ", ".join(c for c, v in s["by_class"].items() if v["detection_recall"] == 0)
    # burst recall by position: the leading positions with nothing flagged vs the rest
    pos = tl.get("burst_by_position", {}).get("by_position", {})
    early_n = early_f = later_n = later_f = 0
    last_early, first_later = 0, 0
    for k2 in sorted(pos, key=int):
        v = pos[k2]
        if not first_later and v["flagged"] == 0:
            early_n, early_f, last_early = early_n + v["n"], early_f + v["flagged"], int(k2)
        else:
            first_later = first_later or int(k2)
            later_n, later_f = later_n + v["n"], later_f + v["flagged"]
    acct_burst = al["recall_by_scenario"].get("fraud:burst", {"recall": 0, "n": 0})
    vv = tl.get("burst_by_position", {}).get("velocity_visible", {"flagged": 0, "n": 0})
    burst_text = (
        f"A burst's first transactions are authorised before the burst exists: none of the "
        f"{early_n} at positions 1-{last_early} was flagged, while from position {first_later} on "
        f"{later_f} of {later_n} were; where the burst was already visible to the velocity rule "
        f"(three earlier transactions in the ten minutes before), {vv['flagged']} of {vv['n']} were "
        f"flagged. A decision cannot observe its own future, and correct point-in-time scoring "
        f"should not. The account-level monitor, which looks back over the whole window, flags "
        f"{pct(acct_burst['recall'])} of the burst accounts (n={acct_burst['n']})."
        if pos
        else ""
    )
    kyb_rows = json.loads((ROOT / "results" / "kyb_rows.json").read_text(encoding="utf-8"))
    kyb_fp = [r for r in kyb_rows if r["truth"] == "approve" and r["fp"]]
    kyb_fp_blocked = sum(1 for r in kyb_fp if r["guarded_action"] in ("BLOCK", "DENY"))
    kyb_mcr = [r for r in kyb_rows if r["category"] == "malicious_document_clean_records"]
    kyb_mcr_ok = sum(1 for r in kyb_mcr if r["guarded_executed"])
    out: dict[str, str] = {}
    out[
        "integrity"
    ] = f"""| Decision-integrity measurement (`make eval`; {i['n_attacks']} attacks = main corpus {s['n_attacks']} + held-out {h['n_attacks']}) | Sentinel | No controls |
|---|---:|---:|
| attacker text made a protected decision **more permissive** (unsupporting ledgers; structural) | **{pct(i['text_influence_permissive_protected'])}** | {pct(i['text_influence_permissive_unguarded'])} |
| attacker text exceeded the **ledger-supported ceiling** on a supporting ledger (structural) | **{pct(i['text_beyond_ledger_ceiling'])}** | — |
| a capability executed **without ledger support** (structural) | **{pct(i['executed_without_ledger_support'])}** | — |
| a different model recommendation changed the outcome ({i['model_influence_n']} replays: {_mi_scope(i)}; structural) | **{pct(i['model_influence_protected'])}** | — |
| attacker text *selected the claim* on a supporting ledger (by design) | {pct(i['text_selected_claim_on_supporting_ledger'])} | — |"""
    out["results"] = f"""<div align="center">

| | No controls (simulated agent) | Hardened prompt | **Sentinel** |
|---|:---:|:---:|:---:|
| Attack success -- main corpus ({s['n_attacks']} attacks, {n_classes} classes) | 🔴 **{pct(s['asr_unguarded'])}** | 🟠 {pct(b['hardened_prompt'])} | 🟢 **{pct(s['asr_guarded'])}** (structural) |
| Off-surface capability executed (main corpus) | {pct(s['capability_escalation_rate_unguarded'])} | — | **{pct(s['capability_escalation_executed_guarded'])}** |
| False positives on deserved refunds (main corpus, n={s['n_deserved_controls']}) | — | — | 🟢 **{pct(s['fp_rate'])}** |
| Held-out corpus (unseen wording, {h['n_attacks']} attacks) | {pct(h['asr_unguarded'])} | — | **{pct(h['asr_guarded'])}** / FP {pct(h['fp_rate'])} (n={h['n_deserved_controls']}) |
| Other surfaces: transaction · account security · investigation ({sf['n_attacks']} attacks) | {pct(sf['asr_unguarded'])} | — | **{pct(sf['asr_guarded'])}** / loosened {pct(sf['loosened_vs_baseline'])} |
| KYB onboarding ({kc['cases']} applications: {kc['attacks']} with a hostile document, {kc['controls']} without) | {pct(k['asr_unguarded'])} | — | **{pct(k['asr_guarded'])}** / FP {pct(k['fp_rate_benign_input'])} benign, {pct(k['fp_rate'])} any input |

</div>

**Attack success** means an unauthorised consequential capability actually
executed -- not "the detector flagged the sentence". Three kinds of number,
never mixed: the "no controls" column is a **synthetic evaluation** of the
offline simulated agent executing its own tool call (a property of that regex
simulator, which shares an author with the corpus -- not a measurement of any
real model); Sentinel's 0.0% rows are **structural decision integrity** -- an
attack on unsupporting records cannot execute under the design -- kept as
regression checks; the **live-model evaluation** in `results/models.json` is
`{live['status']}`. The empirical content is the false-positive rates, the KYB
any-input cost, the gateway's detection recall ({pct(s['detection_recall'])} main corpus,
{pct(h['detection_recall'])} held-out) and the claim classifier's held-out coverage (optimistic: same
author, §L) -- and the security case depends on none of them."""
    out[
        "ablation"
    ] = f"""| no controls | prompt hardening | detection only | risk only | policy only | adjudication only | adjudication + policy | **full** |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| {pct(a['no_controls']['asr'])} | {pct(a['prompt_hardening']['asr'])} | {pct(a['detection_only']['asr'])} | {pct(a['risk_only']['asr'])} | {pct(a['policy_only']['asr'])} | {pct(a['adjudication_only']['asr'])} | {pct(a['adjudication_policy']['asr'])} | **{pct(a['full']['asr'])}** |

Prompt hardening fails 100% on the false-claim classes. Detection alone holds
exactly what it flags and leaks exactly the classes with nothing to detect
({undetected}). Policy without evidence catches only over-limit amounts.
**Checking the claim against the institution's own records is what carries
the result**; policy, authorization and the gateway add human review for
legitimate high-value cases, capability containment and explainability.
Definitions of every configuration are in [docs/EVALUATION.md](docs/EVALUATION.md#f-ablation----which-control-carries-the-result-resultsablationjson)."""
    out[
        "financial"
    ] = f"""### Financial risk (labelled synthetic dataset, {f['dataset']['transactions']:,} transactions, model `{f['risk_model']}`)

Development seed {seed} (the point values were tuned on it), with the range over seeds
{seed}, {' and '.join(str(x) for x in f['seeds']['held_out'])} in brackets:

| Level | Precision | Recall | FPR |
|---|---:|---:|---:|
| transaction (account takeover, bursts, ring transactions) | {pct(tl['precision'])} ({rng(sr['transaction_level']['precision'])}) | {pct(tl['recall'])} ({rng(sr['transaction_level']['recall'])}) | {pct(tl['false_positive_rate'], 2)} ({rng(sr['transaction_level']['false_positive_rate'], 2)}) |
| account monitoring (structuring-like, dormant activation, rings, bursts) | {pct(al['precision'])} ({rng(sr['account_level']['precision'])}) | {pct(al['recall'])} ({rng(sr['account_level']['recall'])}) | {pct(al['false_positive_rate'], 2)} ({rng(sr['account_level']['false_positive_rate'], 2)}) |

A transparent, versioned rule model (point values are Sentinel heuristics,
not industry weights; [docs/RISK_ENGINE.md](docs/RISK_ENGINE.md)) over
point-in-time behavioural baselines, a time-aware relationship graph and
as-of entity profiles -- explainable to the factor and replayable under
another model version. Transaction-level recall by scenario:
{_scn(f['recall_by_scenario'])}; account-level: {_scn(al['recall_by_scenario'])}.
The {total_missed} transaction-level misses on seed {seed} are {missed_scn} transactions. {burst_text}
This is reported, not tuned away: no threshold was lowered to raise recall; the
monitoring cycle finder is bounded to {cycle_days} days ([details](docs/EVALUATION.md#g-financial-risk-on-labelled-synthetic-data-resultsfinancialjson))."""
    out[
        "performance"
    ] = f"""### Performance (offline, own overhead)

Full protected dispute pipeline: **p50 {e2e['p50_ms']} ms · p95 {e2e['p95_ms']} ms · {e2e['throughput_per_sec']:,}/s**
sequential single-thread; policy evaluation {p['components']['policy_evaluate']['p95_ms']} ms p95 over the composer's real
{p['workloads']['policy_context_fields']}-field context; gateway inspection {p['components']['gateway_inspect']['p95_ms']} ms p95 ([all components](docs/PERFORMANCE.md))."""
    out[
        "temporal"
    ] = f"""| Temporal-leakage benchmark (`results/temporal.json`: seeds {seeds}, {td['transactions']:,} transactions, {td['sample']} sampled, {len(t['kinds'])} future-record kinds at +{offs} days, {t['future_records']:,} future records) | Changed / tested |
|---|---:|
| assessment changes when records after the transaction are removed (truncation) | **{t['truncation_mismatch_count']} / {td['sample']}** |
| transaction assessment changes when future records are added (perturbation) | **{txn_ch} / {t['comparisons']:,}** |
| account-monitor assessment changes under the same perturbation | **{mon_ch} / {t['comparisons']:,}** |
| all checks: observed leaks (exact count; 95% upper bound {ub_s} per check, {t['sample_leakage_upper_95']:.2%} per sampled transaction) | **{t['leakage_count']} / {t['decisions_tested']:,}** |"""
    out[
        "corpus-counts"
    ] = f"""Development corpus: {s['n_attacks']} attacks + {s['n_controls']} controls across {n_classes}
classes. Held-out: {h['n_attacks']} attacks + {h['n_controls']} controls, written after the
development corpus by the same author and kept disjoint by test. Other surfaces: {sf['n_attacks']} attacks. KYB: {kc['cases']} balanced
applications ({kc['attacks']} with a hostile document, {kc['controls']} without). The taxonomy and the
invariants are the claim, not the counts."""
    out[
        "unguarded-baseline"
    ] = f"""{pct(s['asr_unguarded'])} (dev), {pct(h['asr_unguarded'])} (held-out), {pct(sf['asr_unguarded'])} (other surfaces) and
{pct(k['asr_unguarded'])} (KYB) describe how often the deterministic offline agent obeys the
corpus; the corpus and the agent share an author. They are a contrast for
the protected path, not a claim about any real model; the live-model row in
`results/models.json` is `{live['status']}`."""
    out[
        "financial-caveats"
    ] = f"""The point values were tuned on seed {seed}; the suite also runs seeds
{' and '.join(str(x) for x in f['seeds']['held_out'])} and reports the range (transaction precision {rng(sr['transaction_level']['precision'])},
recall {rng(sr['transaction_level']['recall'])}; account recall {rng(sr['account_level']['recall'])}). Transaction-level recall
on seed {seed} is {pct(tl['recall'])}: the {total_missed} misses are {missed_scn} transactions ({pct(f['recall_by_scenario']['fraud:burst']['recall'])} burst
recall, n={f['recall_by_scenario']['fraud:burst']['n']}); a burst's first transactions carry no short-window velocity signal
and, since the generator stopped emitting fixed three-minute gaps, a burst spread
over more than the ten-minute window carries fewer of them -- the account-level
monitor is where a burst is meant to be caught, and its burst recall is
{pct(al['recall_by_scenario']['fraud:burst']['recall'])} (n={al['recall_by_scenario']['fraud:burst']['n']}). Account-level recall is {pct(al['recall'])} ({al['fn']} misses of
{al['tp'] + al['fn']} labelled accounts; {al['fp']} false positives). Merchant level has n={f['merchant_level']['bad_merchants']} positives and is
reported for completeness only. Account-level scenarios remain the mirror
image of the monitoring rules, so their recall says little about generality.
Legitimate accounts now burst, travel, switch phones and fail MFA at realistic
rates, so every signal also fires on legitimate transactions; the per-signal
table in `docs/EVALUATION.md` §G shows how often."""
    out[
        "kyb-caveat"
    ] = f"""The KYB any-input false-positive rate is {pct(k['fp_rate'])}: of the {kc['records_approve']} applications
whose acquirer records alone say *approve*, {len(kyb_fp)} were not approved because their upload
carried an injection ({kyb_fp_blocked} blocked by the CRITICAL security finding, {len(kyb_fp) - kyb_fp_blocked} held for
review). The other {kyb_mcr_ok} of the {len(kyb_mcr)} clean-record applications with a hostile upload were
approved -- correctly: the records supported them and the text changed nothing.
On benign input the rate is {pct(k['fp_rate_benign_input'])}, and no merchant the records say to reject
went live ({pct(k['fn_rate'])} FN). This is the cost of the design and is reported, not
tuned away."""
    nothing_to_detect = [c for c, v in s["by_class"].items() if v["detection_recall"] == 0.0]
    zero_det = "0%" if nothing_to_detect else "(n/a)"  # the classes with no detectable signal
    out["interview-core"] = f"""## The core questions

Each answer separates what is **IMPLEMENTED** (code and a test), what is
**SIMULATED** (it runs, on synthetic or offline stand-ins) and what is **NOT
IMPLEMENTED** (say it before you are asked).

**1. Why isn't the LLM authoritative?**
It reads the attacker's text, so its output is a function of attacker-controlled
input; a customer who simply lies persuades it, and it cannot be replayed or
audited like a rule. **IMPLEMENTED:** agents recommend (`sentinel/agents/`);
their output is typed `MODEL_GENERATED`, never enters an `EvidenceSet`, and the
composer's `_TrustedView` has no field for it; an off-surface tool call is a
CRITICAL escalation; {i['model_influence_n']} replays with a different recommendation changed no
outcome ({_mi_scope(i)}). **SIMULATED:** every "persuaded agent" number
is the offline simulator. **NOT IMPLEMENTED:** a live-model result -- `{live['status']}`.

**2. Why isn't prompt hardening enough?**
Hardening teaches a model to refuse *instructions*; a false claim contains
none. **SIMULATED:** against the offline agent a hardened prompt still leaks
{pct(b['hardened_prompt'])} of the main corpus, and fails 100% on the false-claim classes
(ablation, `docs/EVALUATION.md` §E-F). **IMPLEMENTED:** the protection that works
is not in the prompt -- the records are checked. **NOT IMPLEMENTED:** the same
comparison on a live model.

**3. What is adjudication gaming?**
A narrative engineered to exploit the decision maker's heuristics (loyalty,
urgency, sympathy) while lying about a verifiable fact, with no injected
instruction at all. **IMPLEMENTED:** a threat class with its own corpus rows; the
gateway detects {pct(s['by_class'].get('adjudication_gaming', {}).get('detection_recall', 0))} of it and guarded attack success is still
{pct(s['by_class'].get('adjudication_gaming', {}).get('asr_guarded', 0))}, because the narrative only yields a claim type and the ledger yields the
fact (`make attack-compare` then `--scenario adjudication_gaming`).
**SIMULATED:** the phrasings are hand-authored.

**4. Why does point-in-time data matter?**
A decision scored with data from its own future looks better than it was, in
evaluation and in replay. **IMPLEMENTED:** every feature is as-of; graph edges are
timestamped; account status counts from `status_since`; payout sharing reads the
bank accounts held at T; a benchmark re-scores {t['decisions_tested']:,} checks against
{len(t['kinds'])} kinds of later record: **{t['leakage_count']} observed leaks across the tested synthetic
benchmark** -- and its 2.2.0 extension first found two current-state reads, now
fixed. **NOT IMPLEMENTED:** a fully event-sourced history; merchant registration,
flags and MCC tier are static attributes. Zero observed is evidence for a
tested invariant, not a proof.

**5. Why is the claim classifier not the security foundation?**
It only chooses *which* trusted field is checked. **IMPLEMENTED:** deterministic
pattern families with a confidence; an abstain goes to a human
(INSUFFICIENT), a recognised non-claim is UNSUPPORTED; whatever it reads,
nothing executes unless the selected field supports the claim. A misreading
is a cost (a human review), not a breach. **SIMULATED:** its benchmark shares its
author; on {cl['uncommon_n']} held-out unusual phrasings it read 7 on the first, blind run and
{cl['uncommon_recognised']} after the patterns were extended by someone who had seen the misses --
partially informed, not a clean benchmark. It is defence in depth.

**6. What does the audit chain protect?**
**IMPLEMENTED:** tamper-evidence for every decision, every human case action
(manual case, status change, decision) and every replay: modification,
deletion, insertion, reordering and unreadable records are an AUDIT INTEGRITY
ERROR naming the first bad record (exit 2); a consistent rewrite of the whole
chain is caught only against a checkpoint stored elsewhere, HMAC-signed with a
shared key. It stores hashes of untrusted text, never the text. **NOT
IMPLEMENTED:** proof that an event is true (a compromised writer writes false
events honestly), availability, immutability, key management. It is a
tamper-evident application audit chain -- not a blockchain, not an immutable ledger.

**7. Why is replay useful?**
**IMPLEMENTED:** any recorded decision re-runs from its stored inputs under another
policy version, rule threshold, risk model or recommendation, with a
field-level diff, the versions on each side, policy drift and engine drift;
the recorded side is checked against its audit event, so a rewritten record
cannot replay as unchanged. It answers "what would v1 have done?" (the console
example: a v3 denial of a second refund that v1 would have paid), "did the
engine change?" and "does this record match what was audited?". **NOT
IMPLEMENTED:** bulk backtesting over a history, scheduled drift monitoring.

**8. What can Sentinel actually guarantee?**
**IMPLEMENTED, structural and tested:** no consequential capability executes
unless the trusted records support it, the active policy allows it and the
registry authorizes the actor -- attacker text and model output cannot change
that; a workflow executes only the capabilities it owns; no evaluation with a
weakened control, a historical policy or a historical risk model is recorded;
only a human decision resolves a case, checked against the registry; tampering
with a recorded event is detected; a recorded decision replays
deterministically. **NOT guaranteed:** that the records are true, who the
reviewer is, that detection catches everything, that the risk model is
accurate, temporal correctness beyond the tested record kinds.

**9. What happens if detection misses the attack?**
Nothing changes for execution. **IMPLEMENTED:** three classes
({undetected}) have nothing to detect -- the gateway scores {zero_det} on them --
and their guarded attack success is still {pct(s['asr_guarded'])}; the ablation shows detection alone
leaks exactly those classes. **SIMULATED:** the corpus and the gateway share an author.

**10. What is the trust boundary?**
**IMPLEMENTED:** trust is a type (`TrustClass`); `UntrustedContent` refuses a
trusted class and its source is a sanitised label; `DisputeFacts` / `KYBFacts`
are built from records only, and a malformed record goes to a human; every
decision names where its facts came from (`facts_source`). **SIMULATED:** the
"system of record" is a synthetic SQLite store; the ad-hoc API forms accept
caller-supplied facts, labelled `caller_supplied` or `demo_fixture`. **NOT
IMPLEMENTED:** real systems of record; caller authentication beyond one optional
bearer token.

**11. How would caller-supplied facts be replaced?**
**IMPLEMENTED:** every workflow already has an id form (`dispute_id`,
`transaction_id`, `application_id`, `session_id`, `account_id`) that reads the
facts from the record store and labels the decision `system_of_record`; the
context builders in `sentinel/app.py` are the single seam. **SIMULATED:** the
store is synthetic. **NOT IMPLEMENTED:** production would take identifiers only on
the authoritative API (the fact-carrying forms move to a sandbox), have the
context builders read the ledger, payment switch and KYB provider through
authenticated service calls with freshness checks, and record per fact the
source system and record version.

**12. How would reviewer authentication work?**
**IMPLEMENTED:** the registry defines the level each capability needs; the case
service refuses system and model names, checks the declared level and the
registry's answer for a human actor, requires a senior once a case is
escalated, and chains every human action with the declared role. **NOT
IMPLEMENTED:** identity. Production would take the reviewer from an
authenticated session (SSO / OIDC), roles from the identity provider rather
than the request body, four-eyes approval (two distinct reviewers) above a
threshold, and record the authenticated principal in the audit event.

**13. Why not just use a fraud model?**
A fraud model answers "does this payment look like fraud?", not "is this
claim true?", "may this tool call execute?" or "who may release these funds?".
**IMPLEMENTED:** a transparent, versioned rule model whose score is one input to
policy, every factor explained. **SIMULATED:** labels come from a seeded generator;
a model trained on them would learn the generator. **NOT IMPLEMENTED:** a trained
model -- it would be one more trusted signal, never the authority.

**14. Why aren't synthetic benchmarks enough?**
The corpus and the gateway share an author; the victim agent is a simulator;
the risk labels are the generator's and the point values were tuned on the
development seed; the classifier's held-out score was partially informed.
Structural rows (0 by construction) are regression checks; empirical rows
describe this corpus and this generator. Enough would be labelled real
disputes and transactions, a red-team corpus written by someone else, and a
live-model run.

**15. What would production require?**
Integration with the systems of record behind an identifier-only API;
authentication, roles and four-eyes approval; signed policy releases and key
management; an event-sourced history; a production edge (TLS, a real server,
per-identity rate limits); PII handling and retention; monitoring; a
live-model evaluation; a trained risk model as an extra signal; and regulatory
review. None of it is claimed."""
    out["evaluation-categories"] = evaluation_categories(R)
    out["hero"] = "\n".join(
        [
            "| | |",
            "|---|---|",
            "| **What** | A standard-library Python engine, versioned HTTP API, CLI and web console "
            "that sits between AI agents and the financial actions they might trigger: refunds, "
            "payment authorisation, merchant onboarding, account security, investigations. |",
            "| **Why** | Those decisions read attacker-controlled information through legitimate "
            "channels -- a dispute narrative, an uploaded invoice, a merchant application -- and an "
            "AI agent in the loop can be persuaded, by an injected instruction or by a customer who "
            "simply lies about a fact. |",
            "| **How** | The model may recommend. The institution's own records decide whether the "
            "claim is supported, versioned fail-closed policy decides the outcome, a capability "
            "registry decides who may execute it, and a tamper-evident audit chain records why. |",
            "| **Why different** | The authoritative decision is computed from a view that has *no "
            "field* for the attacker's prose or the model's output. Detection can miss; nothing "
            "executes that the records do not support. |",
            f"| **Result** | On synthetic corpora against an offline *simulated* naive agent: "
            f"unauthorised execution {pct(s['asr_unguarded'])} → **{pct(s['asr_guarded'])}** on the "
            f"{s['n_attacks']}-attack main corpus (structural), with {pct(s['fp_rate'])} false positives "
            f"on deserved refunds; {t['leakage_count']} observed temporal leaks in "
            f"{t['decisions_tested']:,} checks; synthetic transaction risk precision "
            f"{pct(tl['precision'])} / recall {pct(tl['recall'])}. Live-model evaluation: "
            f"**{str(live['status']).replace('_', ' ')}**. |",
        ]
    )
    out["claims"] = f"""The claim classifier is defence in depth, not the security foundation: it
only selects which trusted field is checked. It is deterministic and
explainable (weighted pattern families, a negation guard, a hedge detector)
and reports a confidence. On a
{cl['n']}-phrasing benchmark that shares its author it reads {pct(cl['coverage'])} of ordinary legitimate
paraphrases and never reads attack prose as a claim it does not assert
({pct(cl['adversarial_wrong_type_rate'])}); ambiguous and contradictory messages abstain. On a **held-out**
set of {cl['uncommon_n']} uncommon legitimate phrasings it recognised 7 on the first, blind run
and {cl['uncommon_recognised']} after the patterns were extended against a separate development set --
partially informed (the author had seen the misses), so {cl['uncommon_recognised']}/{cl['uncommon_n']} is not a clean
independent benchmark; every miss abstains, i.e. goes to a human -- a cost,
not a breach. False negatives {cl['false_negatives']} / {cl['false_negative_n']}, false
positives {cl['false_positives']} / {cl['false_positive_n']} (`docs/EVALUATION.md` §L)."""
    out["threat-taxonomy"] = (
        tbl(
            ["Class", "Mechanism", "Caught by"],
            [[f"`{tc.value}`", info.description, info.detection] for tc, info in TAXONOMY.items()],
        )
        + f"\n\n{len(TAXONOMY)} classes; rendered from `security/threats.py`. Only the lexical rows are (partly) detectable by inspecting text; `docs/SECURITY_MODEL.md` has the full table with typical targets."
    )
    pols = DEFAULT_REGISTRY.all()
    by_id: dict[str, list[int]] = {}
    for pol in pols:
        by_id.setdefault(pol.policy_id, []).append(pol.version)
    out["shipped-policies"] = (
        "Shipped policies: "
        + ", ".join(f"`{pid}` " + "/".join(f"v{v}" for v in vs) for pid, vs in by_id.items())
        + f" ({len(pols)} versions, all lint-clean; every rule is listed in `docs/POLICY_ENGINE.md`)."
    )
    out[
        "resume"
    ] = f"""- **Financial decision-security architecture.** Designed and built Sentinel, a
  standard-library Python system between LLM agents and consequential financial
  actions (refunds, payment authorisation, merchant onboarding, account
  security): agents may recommend, but only trusted records, versioned
  fail-closed policy and a capability registry can authorize, and the
  authoritative decision is computed from a view with no field for untrusted
  text or model output. Across {i['n_attacks']} attacks (main and held-out corpora), attacker
  text loosened {pct(i['text_influence_permissive_protected'])} of protected decisions, against {pct(i['text_influence_permissive_unguarded'])} with no controls.
- **Point-in-time risk engineering.** Built an explainable, versioned risk
  engine -- as-of behavioural baselines, a time-aware relationship graph,
  entity profiles and account monitoring -- and a temporal-leakage benchmark
  ({t['decisions_tested']:,} checks, {len(t['kinds'])} kinds of later record) that found two current-state
  reads; {t['leakage_count']} observed leaks after the fix. On the synthetic development seed:
  transaction precision {pct(tl['precision'])} / recall {pct(tl['recall'])} at {pct(tl['false_positive_rate'], 2)} FPR, account-level
  {pct(al['precision'])} / {pct(al['recall'])}, with held-out seeds reported and early-burst misses
  explained rather than tuned away.
- **Adversarial evaluation, policy and authorization.** Built a {n_classes}-class
  adversarial evaluation ({s['n_attacks']}-attack main corpus, {h['n_attacks']} held-out, {sf['n_attacks']} on three
  other surfaces, a {kc['cases']}-application KYB benchmark) with ablations: against a
  simulated naive agent, prompt hardening still leaked {pct(b['hardened_prompt'])} and detection
  alone {pct(a['detection_only']['asr'])}, while trusted-evidence adjudication, digest-pinned
  policy-as-code and workflow-scoped authorization held unauthorised execution
  at {pct(a['full']['asr'])} with {pct(a['full']['fp'])} false positives; every decision replays against a
  tamper-evident, hash-chained audit log."""
    out["interview-pitch"] = f"""## The 60-second pitch

"Banks and fintechs are putting AI agents into decision paths -- refunds,
onboarding, account security -- and those agents read attacker-controlled text
through legitimate channels: a dispute narrative, an uploaded invoice. Most
defences look for injected instructions. The harder attack has none: the
customer simply lies about a fact and a persuadable model approves; a hardened
prompt doesn't help against a lie. Sentinel's answer is architectural: the
model may recommend, but the authoritative decision is computed from a view
that has no field for the prose or the model's opinion. The institution's own
records decide whether the claim is supported, versioned fail-closed policy
decides the outcome, a capability registry decides who may execute it, and a
tamper-evident audit chain records why, so every decision replays. On
synthetic corpora against a simulated naive agent, unauthorised execution
goes from {pct(s['asr_unguarded'])} to {pct(s['asr_guarded'])} with {pct(s['fp_rate'])} false positives on deserved refunds -- and I can
show you exactly what that does and doesn't prove.\""""
    out["limitations-solid"] = f"""## What is genuinely solid

- The trust boundary and the composer: the authoritative decision is computed
  from a view that has no field for prose or for the model's recommendation.
  The integrity suite measures the property as it is enforced: across {i['n_attacks']}
  attacks (main and held-out corpora), **{pct(i['text_beyond_ledger_ceiling'])}** exceeded the ledger-supported ceiling and **{pct(i['executed_without_ledger_support'])}**
  executed without ledger support, against **{pct(i['text_influence_permissive_unguarded'])}** permissive influence with
  no controls; {i['model_influence_n']} model-recommendation replays changed nothing.
- **{pct(s['asr_guarded'])}** unauthorised capability executions across the main corpus ({s['n_attacks']}),
  the held-out corpus ({h['n_attacks']}), the other surfaces ({sf['n_attacks']}) and KYB ({kc['attacks']} hostile)
  (structural, by construction),
  with **{pct(s['fp_rate'])}** false positives on deserved refunds -- including the
  urgent-but-legitimate phrasings -- which is the empirical part.
- **{t['leakage_count']} observed leaks in {t['decisions_tested']:,} checks** on the temporal benchmark
  ({len(t['kinds'])} kinds of later record, {len(t['future_offsets_days'])} offsets, two synthetic worlds): evidence
  for a tested invariant -- for the record kinds tested, a decision at T1 read
  only records at or before T1 -- not a proof, and not a fully event-sourced
  history (see the time-semantics limitation).
- Model output is typed untrusted and cannot become evidence; an agent
  pushed off its tool surface produces a CRITICAL event, a BLOCK and a P1
  case, never an execution.
- Policy is fail-closed (a missing input can never switch a rule off),
  content-hashed (a replay knows whether "v3" is still the v3 the decision
  saw) and linted.
- Every block is explainable (evidence, contradictions, matched rules,
  authorization reason, blocked-by list) and every decision is replayable and
  recorded in a tamper-evident chain with an exportable signed checkpoint.
"""
    out["interview-claims"] = f"""**What claims can you actually prove?**
Structural ones, by test: untrusted text and model output cannot produce an
outcome the trusted records do not support (integrity suite, {i['n_attacks']} attacks = main
{s['n_attacks']} + held-out {h['n_attacks']}: {pct(i['text_beyond_ledger_ceiling'])} exceeded the ledger-supported ceiling, {pct(i['executed_without_ledger_support'])}
executed without support, {pct(i['model_influence_protected'])} of {i['model_influence_n']} recommendation replays changed
anything, vs {pct(i['text_influence_permissive_unguarded'])} permissive influence with no controls); zero unauthorised
capability executions across the main ({s['n_attacks']}), held-out ({h['n_attacks']}) and other-surface ({sf['n_attacks']})
corpora and {kc['attacks']} hostile KYB applications -- 0 by construction, kept as a regression
check; a workflow executes only its own capabilities; audit tampering is
detected. Empirical ones, on synthetic data: {pct(s['fp_rate'])} false positives on the {s['n_deserved_controls']}
deserved refunds of the main corpus and {pct(h['fp_rate'])} on the {h['n_deserved_controls']} of the held-out corpus;
{pct(k['fp_rate'])} of records-approve KYB applications not approved because of a hostile
upload; the financial figures with their held-out-seed range; {t['leakage_count']} observed
temporal leaks in {t['decisions_tested']:,} checks (a tested invariant, not a proof). Nothing about
a live model: the live row is `{live['status']}`. `docs/EVALUATION.md` separates the
three kinds.
"""
    out[
        "interview-numbers"
    ] = f"""The same inputs against the unguarded simulated agent execute {pct(s['asr_unguarded'])} of the
time, a hardened prompt still leaks {pct(b['hardened_prompt'])}, and a detection-only system leaks
{pct(a['detection_only']['asr'])} (exactly the classes with no injection to detect: {undetected}).
On supporting ledgers, {pct(i['text_beyond_ledger_ceiling'])} of attack texts exceed the ledger-supported
ceiling and {pct(i['executed_without_ledger_support'])} execute without support, while {pct(i['text_selected_claim_on_supporting_ledger'])} do change the
outcome relative to a neutral message (they select the claim) and {pct(i['attack_text_approved_on_supporting_ledger'])} are
approved -- deserved refunds, whatever the prose around them."""
    out["interview-classes"] = (
        f"{len(TAXONOMY)} classes (`security/threats.py`): "
        + ", ".join(tc.value.replace("_", " ") for tc in TAXONOMY)
        + ". Each has a development corpus, a held-out variant and, for the non-dispute surfaces, a transaction / account-security / investigation variant."
    )
    out[
        "interview-financial"
    ] = f"""They characterise a hand-weighted rule model on a synthetic generator. The
point values were tuned while looking at seed {seed}, so the suite also runs two
seeds they never saw and reports the range (transaction precision
{rng(sr['transaction_level']['precision'])}, recall {rng(sr['transaction_level']['recall'])}). Transaction-level recall is {pct(tl['recall'])}
on the development seed and the misses are {missed_scn} transactions; a burst's
first transactions carry no short-window signal, and the account-level monitor
catches {pct(al['recall_by_scenario']['fraud:burst']['recall'])} of the burst accounts. Legitimate accounts burst, travel
and switch phones too, so the signals are not free. Account-level recall is {pct(al['recall'])} at
{pct(al['false_positive_rate'])} FPR. A review found the per-transaction baseline counting
disputes filed *after* the transaction; fixing that leak (and then every other
aggregation) is why there is a temporal-leakage benchmark; extending it in 2.2.0 found two
more current-state reads (account status, payout destination), now fixed: {t['leakage_count']} observed
leaks in {t['decisions_tested']:,} checks -- evidence for the invariant, not a proof."""
    out[
        "demo-flagship"
    ] = f"""Flagship attack (`make attack`): the gateway flags the document CRITICAL, the
simulated agent recommends `APPROVE_REFUND`, the ledger says delivered, the
claim is CONTRADICTED, `dispute-refund@v{max(by_id['dispute-refund'])}` blocks, the capability is DENIED,
the final action is BLOCK, a case opens and the audit event is chained. Across
the {s['n_attacks']}-attack development corpus the same path executes {pct(s['asr_guarded'])} of attacks
(structural) against {pct(s['asr_unguarded'])} for the simulated agent with no controls."""
    return out


def patch_blocks(path: Path, out: dict[str, str]) -> int:
    """Replace every generated block; a block opened on an indented line (inside a
    list item) is re-indented by the same amount so the list keeps rendering."""
    text = path.read_text(encoding="utf-8")
    n = 0
    for name, body in out.items():
        pat = re.compile(rf"^([ \t]*)<!-- gen:{name} -->\n.*?<!-- /gen:{name} -->", re.S | re.M)

        def repl(m: re.Match[str], body: str = body, name: str = name) -> str:
            ind = m.group(1)
            lines = [ind + ln if ln.strip() else "" for ln in body.rstrip().splitlines()]
            return f"{ind}<!-- gen:{name} -->\n" + "\n".join(lines) + f"\n{ind}<!-- /gen:{name} -->"

        if pat.search(text):
            text = pat.sub(repl, text)
            n += 1
    path.write_text(text, encoding="utf-8")
    return n


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
    R = {n: _load(n) for n in SUITES}
    docs = ROOT / "docs"
    (docs / "EVALUATION.md").write_text(render_evaluation(R, tests), encoding="utf-8")
    (docs / "PERFORMANCE.md").write_text(render_performance(R["performance"]), encoding="utf-8")
    (docs / "SECURITY_MODEL.md").write_text(render_security_model(), encoding="utf-8")
    (docs / "RISK_ENGINE.md").write_text(render_risk_engine(), encoding="utf-8")
    (docs / "POLICY_ENGINE.md").write_text(render_policy_engine(), encoding="utf-8")
    (docs / "EVIDENCE_MODEL.md").write_text(render_evidence_model(), encoding="utf-8")
    (docs / "AUDIT_MODEL.md").write_text(render_audit_model(), encoding="utf-8")
    out = blocks(R, tests)
    patched = 0
    for name in GEN_TARGETS:
        patched += patch_blocks(ROOT / name, out)
    for name in ("README.md", "docs/RESUME.md", "docs/TESTING.md"):
        patch_test_counts(ROOT / name, tests)
    print(
        f"rendered 7 docs and {patched} generated blocks from results/ and the code ({tests} tests)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
