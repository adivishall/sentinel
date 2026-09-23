"""Render result charts (optional: needs matplotlib; metrics never depend on it)."""

from __future__ import annotations

import json
import os
import sys
from typing import Any

INK, GRID = "#1c2230", "#dcd8d0"
RED, AMBER, BLUE, GREEN = "#c0392b", "#d98b3a", "#2e6da4", "#2e8b57"


def _load(out_dir: str, name: str) -> dict[str, Any] | None:
    p = os.path.join(out_dir, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def main(out_dir: str = "results") -> list[str]:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print(
            "charts: matplotlib not installed -- skipping PNGs (metrics JSON already written)",
            file=sys.stderr,
        )
        return []
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "axes.edgecolor": INK})
    written: list[str] = []

    def save(fig: Any, name: str) -> None:
        p = os.path.join(out_dir, name)
        fig.tight_layout()
        fig.savefig(p, dpi=140)
        plt.close(fig)
        written.append(p)

    sec = _load(out_dir, "security.json")
    if sec:
        classes = list(sec["by_class"])
        ug = [sec["by_class"][k]["asr_unguarded"] * 100 for k in classes]
        g = [sec["by_class"][k]["asr_guarded"] * 100 for k in classes]
        det = [sec["by_class"][k]["detection_recall"] * 100 for k in classes]
        fig, ax = plt.subplots(figsize=(12, 4.8))
        x = range(len(classes))
        w = 0.28
        ax.bar([i - w for i in x], ug, w, label="No controls (model executes)", color=RED)
        ax.bar(list(x), det, w, label="Gateway detection recall", color=AMBER)
        ax.bar([i + w for i in x], g, w, label="Full Sentinel (capability executed)", color=BLUE)
        ax.set_xticks(list(x))
        ax.set_xticklabels([c.replace("_", "\n") for c in classes], fontsize=8)
        ax.set_ylim(0, 105)
        ax.set_ylabel("%")
        ax.set_title(
            "Attack success by threat class: unguarded vs detection vs full Sentinel",
            fontweight="bold",
        )
        ax.legend(frameon=False, fontsize=8)
        ax.grid(axis="y", color=GRID)
        ax.set_axisbelow(True)
        save(fig, "chart_security_by_class.png")

    ab = _load(out_dir, "ablation.json")
    if ab:
        names = list(ab)
        fig, ax = plt.subplots(figsize=(11, 4.6))
        vals = [ab[k]["asr"] * 100 for k in names]
        cols = [RED if v > 20 else AMBER if v > 0 else BLUE for v in vals]
        ax.bar([n.replace("_", "\n") for n in names], vals, color=cols, width=0.6)
        for i, v in enumerate(vals):
            ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold", fontsize=9)
        ax.set_ylim(0, 100)
        ax.set_ylabel("Attack success rate (%)")
        ax.set_title("Ablation: which control carries the result", fontweight="bold")
        ax.grid(axis="y", color=GRID)
        ax.set_axisbelow(True)
        save(fig, "chart_ablation.png")

    base = _load(out_dir, "baselines.json")
    if base:
        fig, ax = plt.subplots(figsize=(6.5, 4.4))
        vals = [base["no_defence"] * 100, base["hardened_prompt"] * 100, base["sentinel"] * 100]
        ax.bar(
            ["No defence", "Hardened prompt\n(the obvious fix)", "Sentinel"],
            vals,
            color=[RED, AMBER, BLUE],
            width=0.55,
        )
        for i, v in enumerate(vals):
            ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold")
        ax.set_ylim(0, 100)
        ax.set_ylabel("Attack success rate (%)")
        ax.set_title("Beating the obvious defence", fontweight="bold")
        ax.grid(axis="y", color=GRID)
        ax.set_axisbelow(True)
        save(fig, "chart_baselines.png")

    ho = _load(out_dir, "heldout.json")
    if sec and ho:
        fig, ax = plt.subplots(figsize=(6.5, 4.4))
        labels = ["Development\ncorpus", "Held-out\n(unseen wording)"]
        ug = [sec["asr_unguarded"] * 100, ho["asr_unguarded"] * 100]
        g = [sec["asr_guarded"] * 100, ho["asr_guarded"] * 100]
        d = [sec["detection_recall"] * 100, ho["detection_recall"] * 100]
        xs = [0, 1]
        w = 0.26
        ax.bar([i - w for i in xs], ug, w, label="No controls", color=RED)
        ax.bar(xs, d, w, label="Detection recall", color=AMBER)
        ax.bar([i + w for i in xs], g, w, label="Full Sentinel", color=BLUE)
        ax.set_xticks(xs)
        ax.set_xticklabels(labels)
        ax.set_ylim(0, 105)
        ax.set_ylabel("%")
        ax.set_title("Generalisation: dev vs held-out", fontweight="bold")
        ax.legend(frameon=False, fontsize=8)
        ax.grid(axis="y", color=GRID)
        ax.set_axisbelow(True)
        save(fig, "chart_heldout.png")

    fin = _load(out_dir, "financial.json")
    if fin:
        fig, axes = plt.subplots(1, 2, figsize=(11, 4.4))
        cal = fin["calibration"]
        bands = [b for b in ("LOW", "MEDIUM", "HIGH", "CRITICAL") if b in cal]
        axes[0].bar(
            bands,
            [cal[b]["observed_fraud_rate"] * 100 for b in bands],
            color=[GREEN, AMBER, RED, "#7b1e1e"][: len(bands)],
        )
        axes[0].set_title("Observed fraud rate by risk band (synthetic)", fontweight="bold")
        axes[0].set_ylabel("% fraud-labelled")
        axes[0].grid(axis="y", color=GRID)
        axes[0].set_axisbelow(True)
        rs = fin["recall_by_scenario"]
        axes[1].barh(
            [k.replace("fraud:", "") for k in rs], [rs[k]["recall"] * 100 for k in rs], color=BLUE
        )
        axes[1].set_xlim(0, 100)
        axes[1].set_title("Recall by injected scenario (HIGH+ = positive)", fontweight="bold")
        axes[1].grid(axis="x", color=GRID)
        axes[1].set_axisbelow(True)
        save(fig, "chart_financial.png")

    integ = _load(out_dir, "integrity.json")
    if integ:
        fig, ax = plt.subplots(figsize=(7.5, 4.2))
        keys = [
            "text_influence_permissive_unguarded",
            "text_influence_permissive_protected",
            "model_influence_protected",
            "legit_plus_injection_loosened",
        ]
        labels = [
            "Text made outcome\nmore permissive\n(no controls)",
            "Text made outcome\nmore permissive\n(Sentinel)",
            "Model output changed\noutcome (Sentinel)",
            "Injection loosened a\nlegit claim (Sentinel)",
        ]
        vals = [integ[k] * 100 for k in keys]
        ax.bar(labels, vals, color=[RED, BLUE, BLUE, BLUE], width=0.55)
        for i, v in enumerate(vals):
            ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold")
        ax.set_ylim(0, 100)
        ax.set_title(
            "Decision integrity: can untrusted input loosen a decision?", fontweight="bold"
        )
        ax.grid(axis="y", color=GRID)
        ax.set_axisbelow(True)
        save(fig, "chart_integrity.png")

    perf = _load(out_dir, "performance.json")
    if perf:
        comps = perf["components"]
        names = list(comps)
        fig, ax = plt.subplots(figsize=(10, 4.6))
        ax.barh(
            [n.replace("_", " ") for n in names], [comps[n]["p95_ms"] for n in names], color=BLUE
        )
        ax.set_xscale("log")
        ax.set_xlabel("p95 latency (ms, log scale)")
        ax.set_title("Component latency (offline, p95)", fontweight="bold")
        ax.grid(axis="x", color=GRID)
        ax.set_axisbelow(True)
        save(fig, "chart_performance.png")
    print("charts:", ", ".join(os.path.basename(w) for w in written))
    return written


if __name__ == "__main__":
    main()
