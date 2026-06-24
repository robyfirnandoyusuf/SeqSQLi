"""
tools/fig_relatedwork_taxonomy.py
=================================
Generate Figure 1 for Related Work: a clean taxonomy of adversarial SQLi
WAF-evasion methods, with this work highlighted. No network.
Output: figures/fig_relatedwork_taxonomy.png
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

INK   = "#000000"
MUT   = "#555555"
ACC   = "#000000"
LINE  = "#333333"
CARD  = "#FFFFFF"
HILITE= "#CFCFCF"
HILED = "#000000"

fig, ax = plt.subplots(figsize=(11, 6.2), dpi=200)
ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")


def box(x, y, w, h, text, fill=CARD, edge=LINE, tcol=INK, bold=False, fs=10):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=2",
                       linewidth=1.1, edgecolor=edge, facecolor=fill)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            fontsize=fs, color=tcol, fontweight=("bold" if bold else "normal"),
            wrap=True)


def connect(x1, y1, x2, y2):
    ax.plot([x1, x2], [y1, y2], color=LINE, lw=1.1, zorder=0)


# Root
box(34, 88, 32, 9, "Adversarial SQLi\nWAF-Evasion Methods", fill="#E6E6E6",
    edge=ACC, tcol=INK, bold=True, fs=12)

# Three category nodes
cats = [
    (4,  64, "Mutation\nFuzzing"),
    (39, 64, "Grammar-Guided\nSearch"),
    (74, 64, "Reinforcement\nLearning"),
]
for x, y, t in cats:
    box(x, y, 22, 9, t, fill="#E6E6E6", edge=ACC, tcol=ACC, bold=True, fs=11)
    connect(50, 88, x + 11, y + 9)

# Leaves under each category
leaves = {
    (4, 64): ["WAF-A-MoLE [4]", "Appelt et al. [14]"],
    (39, 64): ["AdvSQLi [5]", "BWAFSQLi [9]"],
    (74, 64): ["Hemmati &\nHadavi [13] (DQN)", "SSQLi [7] (SAC)",
               "XploitSQL [8]\n(LLM+AC)", "SeqSQLi (this work)\n(PPO/TRPO/A2C)"],
}
for (cx, cy), items in leaves.items():
    n = len(items)
    top = 56
    for i, it in enumerate(items):
        ly = top - i * 11.5
        hi = it.startswith("SeqSQLi")
        box(cx, ly, 22, 8.2, it,
            fill=(HILITE if hi else CARD),
            edge=(HILED if hi else LINE),
            tcol=(HILED if hi else INK),
            bold=hi, fs=9)
        connect(cx + 11, cy, cx + 11, ly + 8.2)

os.makedirs("figures", exist_ok=True)
out = "figures/fig_relatedwork_taxonomy.png"
plt.savefig(out, bbox_inches="tight", facecolor="white")
print("[*] saved", out)
