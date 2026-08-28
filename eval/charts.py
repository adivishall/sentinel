"""Produce the three submission charts from eval/results/summary.json."""
from __future__ import annotations
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RED, BLUE, INK, GRID = "#c0392b", "#2e6da4", "#1c2230", "#dcd8d0"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                     "axes.edgecolor": INK, "axes.linewidth": 0.8})
NAMES = {"direct_injection":"Direct\ninjection","authority_spoof":"Authority\nspoof",
         "document_borne":"Document-\nborne","fake_rule":"Rule\nforgery",
         "multiturn":"Multi-turn","adjudication_gaming":"Adjudication\ngaming"}

def _load():
    return json.load(open("eval/results/summary.json"))

def chart_asr(s, path="eval/results/chart1_asr.png"):
    order = [k for k in NAMES if k in s["by_class"]]
    ug = [s["by_class"][k]["asr_unguarded"]*100 for k in order]
    g  = [s["by_class"][k]["asr_guarded"]*100 for k in order]
    x = range(len(order)); w = 0.38
    fig, ax = plt.subplots(figsize=(9, 4.6))
    ax.bar([i-w/2 for i in x], ug, w, label="No firewall", color=RED)
    ax.bar([i+w/2 for i in x], g, w, label="With Sentinel firewall", color=BLUE)
    ax.set_xticks(list(x)); ax.set_xticklabels([NAMES[k] for k in order], fontsize=9)
    ax.set_ylabel("Attack success rate (%)"); ax.set_ylim(0, 105)
    ax.set_title("Attack success by class — firewall off vs on", fontweight="bold")
    ax.legend(frameon=False); ax.grid(axis="y", color=GRID); ax.set_axisbelow(True)
    for i, v in enumerate(ug):
        ax.text(i-w/2, v+2, f"{v:.0f}", ha="center", fontsize=8, color=RED)
    fig.tight_layout(); fig.savefig(path, dpi=140); plt.close(fig); return path

def chart_headline(s, path="eval/results/chart2_headline.png"):
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    bars = ["Unguarded\nagent", "Sentinel\nfirewall"]
    vals = [s["asr_unguarded"]*100, s["asr_guarded"]*100]
    ax.bar(bars, vals, color=[RED, BLUE], width=0.55)
    for i, v in enumerate(vals):
        ax.text(i, v+2, f"{v:.0f}%", ha="center", fontweight="bold")
    ax.set_ylabel("Overall attack success rate (%)"); ax.set_ylim(0, 100)
    ax.set_title("Does the firewall stop the breach?", fontweight="bold")
    ax.grid(axis="y", color=GRID); ax.set_axisbelow(True)
    fp = s["fp_rate"]*100
    ax.text(0.5, -0.22, f"False-positive rate on legitimate refunds: {fp:.0f}%",
            transform=ax.transAxes, ha="center", fontsize=10,
            color=("#2e8b57" if fp < 5 else RED))
    fig.tight_layout(); fig.savefig(path, dpi=140, bbox_inches="tight"); plt.close(fig); return path

def chart_ablation(s, path="eval/results/chart3_ablation.png"):
    bb = s.get("blocked_by", {})
    labels = {"L2_detect":"L2 Injection\ndetection","L3_adjudicate":"L3 Structured\nadjudication",
              "L4_limits":"L4 Capability\nlimits"}
    keys = [k for k in labels if k in bb] or list(bb)
    vals = [bb[k] for k in keys]
    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    ax.bar([labels.get(k, k) for k in keys], vals, color=BLUE, width=0.5)
    for i, v in enumerate(vals):
        ax.text(i, v+0.5, str(v), ha="center", fontweight="bold")
    ax.set_ylabel("Attacks first stopped at this layer")
    ax.set_title("Which layer catches what (ablation)", fontweight="bold")
    ax.grid(axis="y", color=GRID); ax.set_axisbelow(True)
    fig.tight_layout(); fig.savefig(path, dpi=140); plt.close(fig); return path

def main():
    s = _load()
    p1 = chart_asr(s); p2 = chart_headline(s); p3 = chart_ablation(s)
    print("charts:", p1, p2, p3)

if __name__ == "__main__":
    main()
