"""Generate the two LinkedIn images for Sentinel (clean paper-figure style)."""

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

OUT = os.path.dirname(os.path.abspath(__file__))

# --- restrained technical palette -------------------------------------------
BG = "#FBFBFD"
INK = "#1B2130"
MUTED = "#6B7280"
HAIR = "#D9DEE6"
RED = "#BC4B3C"  # untrusted
RED_BG = "#F7ECE9"
BLUE = "#2A6098"  # trusted
BLUE_BG = "#EAF1F8"
GOLD = "#B07D18"  # L3 accent
GOLD_BG = "#FBF2D9"
GREEN = "#2E7D57"
GREEN_BG = "#E7F2EC"

plt.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "text.color": INK,
        "axes.edgecolor": INK,
    }
)


def _fig():
    fig = plt.figure(figsize=(10.8, 13.5), dpi=100)  # 1080 x 1350 (4:5)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.add_patch(mpatches.Rectangle((0, 0), 1, 1, color=BG, zorder=-10))
    return fig, ax


def wordmark(ax, x=0.075, y=0.955):
    # minimal shield glyph + SENTINEL
    sx, sy, w, h = x, y - 0.016, 0.026, 0.034
    shield = mpatches.FancyBboxPatch(
        (sx, sy),
        w,
        h,
        boxstyle="round,pad=0.001,rounding_size=0.006",
        linewidth=2.2,
        edgecolor=INK,
        facecolor="none",
        zorder=5,
    )
    ax.add_patch(shield)
    ax.plot(
        [sx + w * 0.28, sx + w * 0.46, sx + w * 0.74],
        [sy + h * 0.52, sy + h * 0.34, sy + h * 0.66],
        color=GOLD,
        lw=2.4,
        solid_capstyle="round",
        zorder=6,
    )
    ax.text(
        x + 0.045,
        y,
        "SENTINEL",
        fontsize=20,
        fontweight="bold",
        va="center",
        ha="left",
        color=INK,
        zorder=6,
    )


def box(
    ax,
    cy,
    label,
    sub,
    face,
    edge,
    txt=INK,
    height=0.062,
    width=0.60,
    bold_label=True,
    accent=None,
    subcolor=None,
):
    x0 = 0.5 - width / 2
    y0 = cy - height / 2
    fb = FancyBboxPatch(
        (x0, y0),
        width,
        height,
        boxstyle="round,pad=0.004,rounding_size=0.012",
        linewidth=2.0 if accent is None else 2.8,
        edgecolor=edge,
        facecolor=face,
        zorder=4,
    )
    ax.add_patch(fb)
    if accent:  # left accent bar
        ax.add_patch(
            mpatches.Rectangle((x0, y0 + 0.004), 0.012, height - 0.008, color=accent, zorder=5)
        )
    ax.text(
        0.5,
        cy + (0.010 if sub else 0),
        label,
        fontsize=19,
        fontweight="bold" if bold_label else "normal",
        va="center",
        ha="center",
        color=txt,
        zorder=6,
    )
    if sub:
        ax.text(
            0.5,
            cy - 0.016,
            sub,
            fontsize=12.5,
            va="center",
            ha="center",
            color=subcolor or MUTED,
            zorder=6,
        )
    return cy - height / 2


def down_arrow(ax, y_top, y_bot, x=0.5):
    ax.add_patch(
        FancyArrowPatch(
            (x, y_top),
            (x, y_bot),
            arrowstyle="-|>",
            mutation_scale=18,
            lw=2.0,
            color=MUTED,
            zorder=3,
        )
    )


def vlabel(ax, x, ymid, text, color):
    ax.text(
        x,
        ymid,
        text,
        rotation=90,
        fontsize=14,
        fontweight="bold",
        va="center",
        ha="center",
        color=color,
        zorder=6,
    )


# ============================================================ IMAGE 1: ARCH
def architecture():
    fig, ax = _fig()
    wordmark(ax)
    ax.text(
        0.925,
        0.955,
        "AI firewall for LLM decisions",
        fontsize=13,
        va="center",
        ha="right",
        color=MUTED,
    )
    ax.plot([0.075, 0.925], [0.928, 0.928], color=HAIR, lw=1.2)

    ax.text(
        0.5,
        0.892,
        "Protecting High-Stakes LLM Decisions",
        fontsize=27,
        fontweight="bold",
        va="center",
        ha="center",
        color=INK,
    )
    ax.text(
        0.5,
        0.856,
        "The authoritative decision is made from verified facts,\nnot attacker-controlled prose.",
        fontsize=15,
        va="center",
        ha="center",
        color=MUTED,
        linespacing=1.35,
    )

    BW = 0.56  # box width; leaves a left gutter for the zone labels

    # zone backgrounds
    ua_top, ua_bot = 0.828, 0.502
    tz_top, tz_bot = 0.418, 0.150
    ax.add_patch(
        mpatches.FancyBboxPatch(
            (0.115, ua_bot),
            0.77,
            ua_top - ua_bot,
            boxstyle="round,pad=0.002,rounding_size=0.02",
            facecolor=RED_BG,
            edgecolor=RED,
            lw=1.3,
            alpha=0.85,
            zorder=1,
        )
    )
    ax.add_patch(
        mpatches.FancyBboxPatch(
            (0.115, tz_bot),
            0.77,
            tz_top - tz_bot,
            boxstyle="round,pad=0.002,rounding_size=0.02",
            facecolor=BLUE_BG,
            edgecolor=BLUE,
            lw=1.3,
            alpha=0.85,
            zorder=1,
        )
    )
    vlabel(ax, 0.155, (ua_top + ua_bot) / 2, "UNTRUSTED", RED)
    vlabel(ax, 0.155, (tz_top + tz_bot) / 2, "TRUSTED", BLUE)

    boxes = [
        (0.786, "Untrusted input", "cardholder text / uploaded documents", "#FFFFFF", RED, None),
        (
            0.706,
            "L1 · Provenance",
            "label the span as data, not instruction",
            "#FFFFFF",
            HAIR,
            None,
        ),
        (
            0.626,
            "L2 · Injection detection",
            "flags obvious injected instructions",
            "#FFFFFF",
            HAIR,
            None,
        ),
        (0.546, "LLM agent", "reasons over the sanitised prompt", "#FFFFFF", HAIR, None),
    ]
    prev_bot = None
    for cy, label, sub, face, edge, accent in boxes:
        if prev_bot is not None:
            down_arrow(ax, prev_bot, cy + 0.029)
        prev_bot = box(ax, cy, label, sub, face, edge, accent=accent, height=0.056, width=BW)

    # arrow into the boundary band
    down_arrow(ax, prev_bot, 0.484)

    # TRUST BOUNDARY band (its own whitespace between the two zones)
    yb = 0.460
    ax.plot([0.13, 0.87], [yb, yb], color=INK, lw=2.0, ls=(0, (6, 4)), zorder=5)
    ax.text(
        0.5,
        yb + 0.017,
        "TRUST  BOUNDARY",
        fontsize=13.5,
        fontweight="bold",
        ha="center",
        va="center",
        color=INK,
        zorder=7,
        bbox=dict(boxstyle="round,pad=0.35", fc=BG, ec="none"),
    )
    ax.text(
        0.5,
        yb - 0.017,
        "attacker prose stops here",
        fontsize=11.5,
        ha="center",
        va="center",
        color=MUTED,
        zorder=7,
        bbox=dict(boxstyle="round,pad=0.2", fc=BG, ec="none"),
    )
    down_arrow(ax, 0.436, 0.408 + 0.001)

    # L3 (gold, highlighted, taller)
    b3 = box(
        ax,
        0.372,
        "L3 · Structured adjudication",
        "decides on VERIFIED FACTS only",
        GOLD_BG,
        GOLD,
        height=0.072,
        accent=GOLD,
        subcolor="#7a5a10",
        width=BW,
    )
    down_arrow(ax, b3, 0.288 + 0.028)
    b4 = box(
        ax,
        0.288,
        "L4 · Capability policy",
        "allow / require human review / block",
        "#FFFFFF",
        BLUE,
        height=0.054,
        width=BW,
    )
    down_arrow(ax, b4, 0.200 + 0.031)
    box(
        ax,
        0.200,
        "Final decision  +  audit trail",
        "explainable, reproducible",
        GREEN_BG,
        GREEN,
        txt="#1f5a3e",
        height=0.060,
        accent=GREEN,
        subcolor="#2E7D57",
        width=BW,
    )

    # footer
    ax.plot([0.075, 0.925], [0.112, 0.112], color=HAIR, lw=1.2)
    ax.text(
        0.5,
        0.082,
        "L3 is the backstop: it turns a persuasive false claim into a fact-check.",
        fontsize=13.5,
        ha="center",
        va="center",
        color=INK,
        fontweight="bold",
    )
    ax.text(
        0.5,
        0.050,
        "github.com/adivishall/sentinel",
        fontsize=13,
        ha="center",
        va="center",
        color=MUTED,
    )

    fig.savefig(f"{OUT}/sentinel-architecture.png", dpi=100)
    plt.close(fig)
    print("wrote sentinel-architecture.png")


# ============================================================ IMAGE 2: RESULTS
def results():
    fig, ax = _fig()
    wordmark(ax)
    ax.text(0.925, 0.955, "Evaluation", fontsize=13, va="center", ha="right", color=MUTED)
    ax.plot([0.075, 0.925], [0.928, 0.928], color=HAIR, lw=1.2)

    ax.text(
        0.5,
        0.885,
        "Does the firewall stop the breach?",
        fontsize=27,
        fontweight="bold",
        va="center",
        ha="center",
    )
    ax.text(
        0.5,
        0.850,
        "Attack success rate on the evaluated benchmark",
        fontsize=15,
        va="center",
        ha="center",
        color=MUTED,
    )

    # before / after big cards
    def stat_card(cx, value, label, color, face):
        w, h = 0.34, 0.22
        ax.add_patch(
            FancyBboxPatch(
                (cx - w / 2, 0.60),
                w,
                h,
                boxstyle="round,pad=0.004,rounding_size=0.02",
                facecolor=face,
                edgecolor=color,
                lw=2.4,
                zorder=3,
            )
        )
        ax.text(
            cx,
            0.70,
            value,
            fontsize=58,
            fontweight="bold",
            color=color,
            ha="center",
            va="center",
            zorder=4,
        )
        ax.text(cx, 0.633, label, fontsize=15, color=INK, ha="center", va="center", zorder=4)

    stat_card(0.285, "83.3%", "No firewall", RED, RED_BG)
    stat_card(0.715, "0.0%", "With Sentinel", GREEN, GREEN_BG)
    ax.add_patch(
        FancyArrowPatch(
            (0.47, 0.71),
            (0.53, 0.71),
            arrowstyle="-|>",
            mutation_scale=26,
            lw=3.0,
            color=INK,
            zorder=5,
        )
    )

    ax.text(
        0.5,
        0.565,
        "60 attacks · 6 classes · 18 legitimate controls · 0.0% false positives",
        fontsize=14.5,
        ha="center",
        va="center",
        color=INK,
    )

    # held-out badge
    ax.add_patch(
        FancyBboxPatch(
            (0.16, 0.487),
            0.68,
            0.052,
            boxstyle="round,pad=0.004,rounding_size=0.02",
            facecolor=BLUE_BG,
            edgecolor=BLUE,
            lw=1.8,
            zorder=3,
        )
    )
    ax.text(
        0.5,
        0.513,
        "Held-out set (wording never seen by the detector)",
        fontsize=13.5,
        ha="center",
        va="center",
        color=BLUE,
        fontweight="bold",
        zorder=4,
    )
    ax.text(
        0.5,
        0.498,
        "0.0% attack success   ·   0.0% false positives",
        fontsize=13,
        ha="center",
        va="center",
        color=INK,
        zorder=4,
    )

    # ablation mini bar chart
    ax.text(
        0.5,
        0.435,
        "Which layer does the work?",
        fontsize=17,
        fontweight="bold",
        ha="center",
        va="center",
    )
    labels = ["No firewall", "Detection only\n(L1+L2+L4)", "Full firewall\n(L1–L4)"]
    vals = [83.3, 6.7, 0.0]
    cols = [RED, GOLD, GREEN]
    base_y = 0.135
    max_h = 0.235
    xs = [0.255, 0.5, 0.745]
    bw = 0.15
    for x, v, c, lb in zip(xs, vals, cols, labels, strict=True):
        h = max(max_h * v / 100.0, 0.006)
        ax.add_patch(
            mpatches.FancyBboxPatch(
                (x - bw / 2, base_y),
                bw,
                h,
                boxstyle="round,pad=0.0005,rounding_size=0.006",
                facecolor=c,
                edgecolor="none",
                zorder=3,
            )
        )
        ax.text(
            x,
            base_y + h + 0.018,
            f"{v:.1f}%",
            fontsize=16,
            fontweight="bold",
            ha="center",
            va="center",
            color=c,
        )
        ax.text(
            x, base_y - 0.028, lb, fontsize=12, ha="center", va="center", color=INK, linespacing=1.2
        )
    ax.plot([0.16, 0.84], [base_y, base_y], color=HAIR, lw=1.4, zorder=2)
    ax.annotate(
        "detection alone still leaks\nadjudication-gaming attacks",
        xy=(0.575, base_y + max_h * 6.7 / 100),
        xytext=(0.635, 0.315),
        fontsize=11.5,
        color="#8a5a12",
        ha="left",
        va="center",
        arrowprops=dict(arrowstyle="->", color="#8a5a12", lw=1.4, connectionstyle="arc3,rad=-0.15"),
    )

    ax.plot([0.075, 0.925], [0.075, 0.075], color=HAIR, lw=1.2)
    ax.text(
        0.5,
        0.05,
        "L3 closes it.  Controlled offline benchmark, reproduce with  make offline",
        fontsize=12.5,
        ha="center",
        va="center",
        color=MUTED,
    )
    ax.text(
        0.5,
        0.025,
        "github.com/adivishall/sentinel",
        fontsize=12.5,
        ha="center",
        va="center",
        color=MUTED,
    )

    fig.savefig(f"{OUT}/sentinel-results.png", dpi=100)
    plt.close(fig)
    print("wrote sentinel-results.png")


architecture()
results()
