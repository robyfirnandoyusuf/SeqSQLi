"""
tools/fig_two_paradigms.py
==========================
Figure 1 for Related Work: the two WAF detection paradigms and the shared
adversary (a semantics-preserving mutation that defeats both). No network.
Output: figures/fig_two_paradigms.png
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

INK="#000000"; MUT="#555555"; ACC="#000000"; LINE="#333333"
CARD="#FFFFFF"; HI="#E6E6E6"; RED="#000000"

fig, ax = plt.subplots(figsize=(11, 6.0), dpi=200)
ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis("off")


def box(x, y, w, h, lines, fill=CARD, edge=LINE, bold0=True):
    p = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.6,rounding_size=2.2",
                       linewidth=1.1, edgecolor=edge, facecolor=fill)
    p.set_zorder(2); ax.add_patch(p)
    try: p.set_path_effects([])
    except Exception: pass
    n = len(lines)
    for i, (txt, fs, col, bd) in enumerate(lines):
        ax.text(x + w/2, y + h - (h/(n+1))*(i+1), txt, ha="center", va="center",
                fontsize=fs, color=col, fontweight=("bold" if bd else "normal"), zorder=3)


def arrow(x1, y1, x2, y2, col=LINE):
    a = FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12,
                        lw=1.3, color=col, zorder=1)
    ax.add_patch(a)


# Shared adversary (top center)
box(33, 84, 34, 11, [
    ("Semantics-preserving mutation", 12, INK, True),
    ("attack meaning fixed, surface form altered", 9.5, MUT, False),
], fill=HI, edge=ACC)

# Two paradigm boxes
box(7, 47, 36, 24, [
    ("Signature WAF", 13, ACC, True),
    ("ModSecurity / OWASP CRS", 10, MUT, False),
    ("rule set  R = {r1, ..., rn}", 10.5, INK, False),
    ("block if any  ri  matches the request", 10.5, INK, False),
    ("decision by fixed pattern", 9.5, MUT, False),
], fill=CARD, edge=LINE)

box(57, 47, 36, 24, [
    ("Learning WAF", 13, ACC, True),
    ("Chaitin Safeline", 10, MUT, False),
    ("classifier  f(x)  on traffic features", 10.5, INK, False),
    ("block if  f(x) > threshold", 10.5, INK, False),
    ("decision by learned boundary", 9.5, MUT, False),
], fill=CARD, edge=LINE)

arrow(42, 84, 25, 71)   # adversary -> signature
arrow(58, 84, 75, 71)   # adversary -> learning

# Verdicts (bottom)
box(10, 22, 30, 11, [
    ("Verdict: ALLOW", 12, RED, True),
    ("regex no longer matches", 9.5, MUT, False),
], fill="#DDDDDD", edge=RED)
box(60, 22, 30, 11, [
    ("Verdict: ALLOW", 12, RED, True),
    ("features shifted below threshold", 9.5, MUT, False),
], fill="#DDDDDD", edge=RED)
arrow(25, 47, 25, 33)
arrow(75, 47, 75, 33)

# Bottom unifying label
box(28, 6, 44, 9, [
    ("Both paradigms yield a false negative", 12, INK, True),
], fill=HI, edge=ACC)
arrow(25, 22, 42, 15)
arrow(75, 22, 58, 15)

os.makedirs("figures", exist_ok=True)
out = "figures/fig_two_paradigms.png"
plt.savefig(out, bbox_inches="tight", facecolor="white")
print("[*] saved", out)
