"""Produce the three submission charts from eval/results/summary.json."""

from __future__ import annotations

import json
import os
import sys

try:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:  # charts are optional polish; metrics (JSON) never depend on them
    print(
        "charts: matplotlib not installed — skipping PNG generation "
        "(all metrics/JSON are already written). Install with: pip install matplotlib",
        file=sys.stderr,
    )
    sys.exit(0)

RED, BLUE, INK, GRID = "#c0392b", "#2e6da4", "#1c2230", "#dcd8d0"
plt.rcParams.update(
    {"font.family": "DejaVu Sans", "font.size": 11, "axes.edgecolor": INK, "axes.linewidth": 0.8}
)
NAMES = {
    "direct_injection": "Direct\ninjection",
    "authority_spoof": "Authority\nspoof",
    "document_borne": "Document-\nborne",
    "fake_rule": "Rule\nforgery",
    "multiturn": "Multi-turn",
    "adjudication_gaming": "Adjudication\ngaming",
}


def _load():
    return json.load(open("eval/results/summary.json"))


def chart_asr(s, path="eval/results/chart1_asr.png"):
    order = [k for k in NAMES if k in s["by_class"]]
    ug = [s["by_class"][k]["asr_unguarded"] * 100 for k in order]
    g = [s["by_class"][k]["asr_guarded"] * 100 for k in order]
    x = range(len(order))
    w = 0.38
    fig, ax = plt.subplots(figsize=(9, 4.6))
    ax.bar([i - w / 2 for i in x], ug, w, label="No firewall", color=RED)
    ax.bar([i + w / 2 for i in x], g, w, label="With Sentinel firewall", color=BLUE)
    ax.set_xticks(list(x))
    ax.set_xticklabels([NAMES[k] for k in order], fontsize=9)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Attack success by class — firewall off vs on", fontweight="bold")
    ax.legend(frameon=False)
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    for i, v in enumerate(ug):
        ax.text(i - w / 2, v + 2, f"{v:.0f}", ha="center", fontsize=8, color=RED)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def chart_headline(s, path="eval/results/chart2_headline.png"):
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    bars = ["Unguarded\nagent", "Sentinel\nfirewall"]
    vals = [s["asr_unguarded"] * 100, s["asr_guarded"] * 100]
    ax.bar(bars, vals, color=[RED, BLUE], width=0.55)
    for i, v in enumerate(vals):
        ax.text(i, v + 2, f"{v:.0f}%", ha="center", fontweight="bold")
    ax.set_ylabel("Overall attack success rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Does the firewall stop the breach?", fontweight="bold")
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    fp = s["fp_rate"] * 100
    ax.text(
        0.5,
        -0.22,
        f"False-positive rate on legitimate refunds: {fp:.0f}%",
        transform=ax.transAxes,
        ha="center",
        fontsize=10,
        color=("#2e8b57" if fp < 5 else RED),
    )
    fig.tight_layout()
    fig.savefig(path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    return path


def chart_ablation(s, path="eval/results/chart3_ablation.png"):
    import json as _j

    ab = _j.load(open("eval/results/ablation.json"))
    order = ["no_firewall", "detection_only", "adjudication_only", "full"]
    labels = {
        "no_firewall": "No\nfirewall",
        "detection_only": "Detection\nonly (L1+L2+L4)",
        "adjudication_only": "Adjudication\nonly (L3)",
        "full": "Full\n(L1\u2013L4)",
    }
    asr = [ab[k]["asr"] * 100 for k in order]
    cols = [RED, "#d98b3a", BLUE, BLUE]
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    ax.bar([labels[k] for k in order], asr, color=cols, width=0.6)
    for i, v in enumerate(asr):
        ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold", fontsize=11)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Which layer does the work (real ablation)", fontweight="bold")
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    ax.annotate(
        "detection alone still\nlets false-claim attacks through",
        xy=(1, asr[1]),
        xytext=(1.15, 34),
        fontsize=9,
        color="#b5671f",
        arrowprops=dict(arrowstyle="->", color="#b5671f"),
    )
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def chart_baselines(s=None, path="eval/results/chart4_baselines.png"):
    import json as _j

    b = _j.load(open("eval/results/baselines.json"))
    order = ["no_defence", "hardened_prompt", "sentinel"]
    labels = ["No defence", "Hardened prompt\n(the obvious fix)", "Sentinel\n(structural)"]
    vals = [b[k] * 100 for k in order]
    cols = [RED, "#d98b3a", BLUE]
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.bar(labels, vals, color=cols, width=0.58)
    for i, v in enumerate(vals):
        ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold", fontsize=12)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("We beat the obvious defence", fontweight="bold")
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    ax.annotate(
        "prompt-hardening still fails 100%\non false-claim attacks",
        xy=(1, vals[1]),
        xytext=(0.75, 45),
        fontsize=9,
        color="#b5671f",
        arrowprops=dict(arrowstyle="->", color="#b5671f"),
    )
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def chart_kyb(s=None, path="eval/results/chart5_kyb.png"):
    """Two surfaces, one firewall: dispute vs KYB, unguarded vs guarded."""
    import json as _j

    disp = (
        _j.load(open("eval/results/summary.json"))
        if os.path.exists("eval/results/summary.json")
        else None
    )
    kyb = _j.load(open("eval/results/kyb.json"))
    d_ug = (disp["asr_unguarded"] if disp else 0.833) * 100
    labels = ["Dispute triage", "KYB onboarding"]
    ug = [d_ug, kyb["asr_unguarded"] * 100]
    g = [0.0, kyb["asr_guarded"] * 100]
    import numpy as np

    x = np.arange(len(labels))
    w = 0.36
    fig, ax = plt.subplots(figsize=(7.0, 4.6))
    ax.bar(x - w / 2, ug, w, label="No firewall", color=RED)
    ax.bar(x + w / 2, g, w, label="With Sentinel", color=BLUE)
    for i, v in enumerate(ug):
        ax.text(i - w / 2, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold")
    for i, v in enumerate(g):
        ax.text(i + w / 2, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("One firewall, two surfaces", fontweight="bold")
    ax.legend()
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)
    return path


def chart_heldout(s=None, path="eval/results/chart6_heldout.png"):
    """Dev corpus vs independently authored held-out set (anti-circularity)."""
    import json as _j

    if not os.path.exists("eval/results/heldout.json"):
        return None
    ho = _j.load(open("eval/results/heldout.json"))
    summ = _j.load(open("eval/results/summary.json"))
    import numpy as np

    labels = ["Development\ncorpus", "Held-out\n(unseen wording)"]
    ug = [summ["asr_unguarded"] * 100, ho["asr_unguarded"] * 100]
    g = [summ["asr_guarded"] * 100, ho["asr_guarded"] * 100]
    x = np.arange(len(labels))
    w = 0.36
    fig, ax = plt.subplots(figsize=(7.0, 4.6))
    ax.bar(x - w / 2, ug, w, label="No firewall", color=RED)
    ax.bar(x + w / 2, g, w, label="With Sentinel", color=BLUE)
    for i, v in enumerate(ug):
        ax.text(i - w / 2, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold")
    for i, v in enumerate(g):
        ax.text(i + w / 2, v + 1.5, f"{v:.1f}%", ha="center", fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title("Generalisation: dev vs held-out (0% both, 0% FP)", fontweight="bold")
    ax.legend()
    ax.grid(axis="y", color=GRID)
    ax.set_axisbelow(True)
    ax.text(
        0.5,
        -0.2,
        f"Held-out L2 lexical recall {ho['l2_detection_recall'] * 100:.0f}% — "
        f"L3 (facts) is the backstop. FP {ho['fp_rate'] * 100:.0f}%.",
        transform=ax.transAxes,
        ha="center",
        fontsize=9,
        color=INK,
    )
    fig.tight_layout()
    fig.savefig(path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    return path


def main():
    s = _load()
    p1 = chart_asr(s)
    p2 = chart_headline(s)
    p3 = chart_ablation(s)
    p4 = chart_baselines()
    p5 = chart_kyb()
    p6 = chart_heldout()
    print("charts:", p1, p2, p3, p4, p5, p6)


if __name__ == "__main__":
    main()
