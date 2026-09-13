"""Generate the GitHub social preview image (1280x640, 2:1) for Sentinel.

Same restrained design system as the LinkedIn figures: ink on off-white, a single
trust-boundary motif, no stock art / neon / clutter. Run from the repo root:
    python3 social/github/make_preview.py
"""

import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt

OUT = os.path.dirname(os.path.abspath(__file__))

BG = "#FBFBFD"
INK = "#1B2130"
MUTED = "#6B7280"
HAIR = "#D9DEE6"
RED = "#BC4B3C"
RED_BG = "#F7ECE9"
BLUE = "#2A6098"
BLUE_BG = "#EAF1F8"
GOLD = "#B07D18"
GREEN = "#2E7D57"
GREEN_BG = "#E7F2EC"

plt.rcParams.update({"font.family": "DejaVu Sans", "text.color": INK})


def make():
    fig = plt.figure(figsize=(12.8, 6.4), dpi=100)  # 1280 x 640
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    ax.add_patch(mpatches.Rectangle((0, 0), 1, 1, color=BG, zorder=-10))
    # subtle top accent rule
    ax.add_patch(mpatches.Rectangle((0, 0.965), 1, 0.035, color=INK, zorder=1))
    ax.add_patch(mpatches.Rectangle((0, 0.963), 0.32, 0.002, color=GOLD, zorder=2))

    # wordmark: minimal shield + SENTINEL
    sx, sy, w, h = 0.062, 0.812, 0.028, 0.072
    ax.add_patch(
        mpatches.FancyBboxPatch(
            (sx, sy),
            w,
            h,
            boxstyle="round,pad=0.001,rounding_size=0.008",
            linewidth=2.6,
            edgecolor=INK,
            facecolor="none",
            zorder=5,
        )
    )
    ax.plot(
        [sx + w * 0.26, sx + w * 0.46, sx + w * 0.76],
        [sy + h * 0.52, sy + h * 0.32, sy + h * 0.68],
        color=GOLD,
        lw=3.0,
        solid_capstyle="round",
        zorder=6,
    )
    ax.text(
        0.104,
        0.848,
        "SENTINEL",
        fontsize=33,
        fontweight="bold",
        va="center",
        ha="left",
        color=INK,
        zorder=6,
    )
    ax.text(
        0.938,
        0.848,
        "github.com/adivishall/sentinel",
        fontsize=14,
        va="center",
        ha="right",
        color=MUTED,
    )

    # title (two lines, left aligned)
    ax.text(
        0.062,
        0.665,
        "AI Firewall for High-Stakes\nLLM Decisions",
        fontsize=46,
        fontweight="bold",
        va="center",
        ha="left",
        color=INK,
        linespacing=1.12,
    )

    # subtitle
    ax.text(
        0.063,
        0.455,
        "Authoritative decisions from verified facts, not attacker-controlled text.",
        fontsize=21,
        va="center",
        ha="left",
        color=MUTED,
    )

    # secondary keyword line
    ax.text(
        0.063,
        0.382,
        "Prompt Injection   ·   Adjudication Gaming   ·   Trusted Data",
        fontsize=15.5,
        va="center",
        ha="left",
        color=GOLD,
        fontweight="bold",
    )

    # trust-boundary motif: a single split bar
    x0, x1 = 0.062, 0.938
    y0, bh = 0.135, 0.10
    split = 0.560  # boundary position (fraction across the bar)
    xb = x0 + (x1 - x0) * split
    # left (untrusted) segment
    ax.add_patch(
        mpatches.FancyBboxPatch(
            (x0, y0),
            xb - x0 - 0.006,
            bh,
            boxstyle="round,pad=0.002,rounding_size=0.014",
            facecolor=RED_BG,
            edgecolor=RED,
            lw=2.0,
            zorder=3,
        )
    )
    ax.text(
        (x0 + xb) / 2 - 0.003,
        y0 + bh / 2,
        "ATTACKER-CONTROLLED TEXT",
        fontsize=15,
        fontweight="bold",
        ha="center",
        va="center",
        color=RED,
        zorder=4,
    )
    # right (trusted) segment
    ax.add_patch(
        mpatches.FancyBboxPatch(
            (xb + 0.006, y0),
            x1 - xb - 0.006,
            bh,
            boxstyle="round,pad=0.002,rounding_size=0.014",
            facecolor=BLUE_BG,
            edgecolor=BLUE,
            lw=2.0,
            zorder=3,
        )
    )
    ax.text(
        (xb + x1) / 2 + 0.003,
        y0 + bh / 2,
        "VERIFIED FACTS  →  DECISION",
        fontsize=15,
        fontweight="bold",
        ha="center",
        va="center",
        color=BLUE,
        zorder=4,
    )
    # dashed trust boundary divider
    ax.plot([xb, xb], [y0 - 0.035, y0 + bh + 0.035], color=INK, lw=2.2, ls=(0, (5, 3)), zorder=5)
    ax.text(
        xb,
        y0 + bh + 0.058,
        "TRUST BOUNDARY",
        fontsize=12,
        fontweight="bold",
        ha="center",
        va="center",
        color=INK,
        zorder=6,
        bbox=dict(boxstyle="round,pad=0.3", fc=BG, ec="none"),
    )

    fig.savefig(f"{OUT}/social-preview.png", dpi=100)
    plt.close(fig)
    print("wrote social-preview.png")


if __name__ == "__main__":
    make()
